"""VPN Service — Business logic extracted from app.py.

Orchestrates proton_api, router_api, profile_store, lan_sync, and
tunnel_strategy into high-level operations (create, update, delete,
connect, disconnect, switch_server, device assignment, LAN access).

This module has NO Flask dependency. Callers (Flask routes, CLI) handle
HTTP/UI concerns; this module raises exceptions on error.
"""

import json
import logging
import time
import threading
from datetime import datetime, timezone
from pathlib import Path

import persistence.profile_store as ps
import router.noint_sync as noint_sync
from consts import (
    HEALTH_RED,
    PROFILE_TYPE_VPN,
    PROFILE_TYPE_NO_VPN,
    PROFILE_TYPE_NO_INTERNET,
    PROTO_OPENVPN,
    PROTO_WIREGUARD,
    PROTO_WIREGUARD_TCP,
    PROTO_WIREGUARD_TLS,
)
from vpn.tunnel_strategy import get_strategy
from vpn.protocol_limits import (
    MAX_WG_GROUPS, MAX_OVPN_GROUPS, MAX_PWG_GROUPS,
    check_protocol_slot, require_protocol_slot,
)
from router.ipset_ops import IpsetOps
from vpn.smart_protocol import SmartProtocolManager
from services.device_service import DeviceService
from vpn.profile_keys import local_router_key, router_rule_key
from vpn.profile_healer import ProfileHealer

log = logging.getLogger("flintvpn")

# ── Backup constants ─────────────────────────────────────────────────────────

ROUTER_BACKUP_PATH = "/etc/fvpn/profile_store.bak.json"
BACKUP_FORMAT_VERSION = 1

# ── Custom exceptions ────────────────────────────────────────────────────────


class NotFoundError(Exception):
    pass


class ConflictError(Exception):
    pass


class LimitExceededError(Exception):
    pass


class NotLoggedInError(Exception):
    pass


# ── Module-level helpers ─────────────────────────────────────────────────────


# Backward-compatible aliases for imports from other modules / tests.
# Canonical implementations live in profile_keys.py.
_local_router_key = local_router_key
_router_rule_key = router_rule_key


# ── Standalone backup / restore functions ────────────────────────────────────


def backup_local_state_to_router(router, store_path: Path):
    """Push profile_store.json to the router as a static backup file.

    Wraps the JSON in a small ``_meta`` envelope (timestamp, router
    fingerprint, format version) so the auto-restore path on unlock can
    verify it before overwriting local state.

    Best-effort: SSH failures log a warning and never propagate.
    """
    try:
        if not store_path.exists():
            return
        try:
            content = store_path.read_text()
            data = json.loads(content)
        except Exception as e:
            log.warning(f"Backup skipped (local store unreadable): {e}")
            return

        try:
            fingerprint = router.get_router_fingerprint()
        except Exception:
            fingerprint = ""

        wrapped = {
            "_meta": {
                "version": BACKUP_FORMAT_VERSION,
                "saved_at": datetime.now(timezone.utc).isoformat(),
                "router_fingerprint": fingerprint,
            },
            "data": data,
        }

        # Make sure /etc/fvpn/ exists (idempotent)
        try:
            router.exec("mkdir -p /etc/fvpn 2>/dev/null || true")
        except Exception:
            pass

        router.write_file(ROUTER_BACKUP_PATH, json.dumps(wrapped, indent=2))
    except Exception as e:
        log.warning(f"Backup to router failed: {e}")


def check_and_auto_restore(router):
    """On unlock, restore profile_store.json from the router backup if newer.

    Comparison rules:
      - If no backup file on the router -> no-op.
      - If backup ``_meta.version`` doesn't match current -> log warning, no-op.
      - If router fingerprint mismatches the live router -> log warning, no-op
        (the backup belongs to a different router).
      - If local profile_store.json is missing/unparseable -> restore.
      - Else compare backup ``_meta.saved_at`` with local file mtime:
          backup newer  -> restore
          local newer   -> push local back to router (self-heal stale backup)
          equal         -> no-op

    Both timestamps are sourced from the same machine's clock (this Surface
    Go), so there's no clock-skew issue.

    Silent operation per user instruction -- no UX, no toasts, no banners.
    """
    try:
        try:
            raw = router.read_file(ROUTER_BACKUP_PATH)
        except Exception as e:
            log.warning(f"Auto-restore: read failed: {e}")
            return
        if not raw:
            return  # No backup to restore from
        try:
            wrapped = json.loads(raw)
        except json.JSONDecodeError as e:
            log.warning(f"Auto-restore: backup file is unparseable: {e}")
            return

        meta = wrapped.get("_meta") or {}
        if meta.get("version") != BACKUP_FORMAT_VERSION:
            log.warning(
                f"Auto-restore: backup version {meta.get('version')} != "
                f"{BACKUP_FORMAT_VERSION}, skipping"
            )
            return

        # Fingerprint check -- if it doesn't match, the backup is from a
        # different router and we should NOT silently overwrite.
        try:
            current_fingerprint = router.get_router_fingerprint()
        except Exception:
            current_fingerprint = ""
        backup_fp = meta.get("router_fingerprint", "")
        if current_fingerprint and backup_fp and current_fingerprint != backup_fp:
            log.warning(
                f"Auto-restore: router fingerprint mismatch "
                f"(backup={backup_fp}, current={current_fingerprint}), skipping"
            )
            return

        backup_data = wrapped.get("data") or {}
        backup_saved_at = meta.get("saved_at", "")
        try:
            backup_dt = datetime.fromisoformat(backup_saved_at)
        except (ValueError, TypeError):
            log.warning(f"Auto-restore: invalid saved_at {backup_saved_at!r}")
            return

        # Compare to local file mtime
        if not ps.STORE_FILE.exists():
            local_dt = datetime.fromtimestamp(0, tz=timezone.utc)
            local_state = "missing"
        else:
            try:
                # Verify local is parseable; if not, treat as missing
                _ = json.loads(ps.STORE_FILE.read_text())
                local_dt = datetime.fromtimestamp(
                    ps.STORE_FILE.stat().st_mtime, tz=timezone.utc
                )
                local_state = "valid"
            except Exception:
                local_dt = datetime.fromtimestamp(0, tz=timezone.utc)
                local_state = "unparseable"

        if backup_dt > local_dt:
            log.info(
                f"Auto-restore: backup ({backup_saved_at}) is newer than "
                f"local ({local_state}), restoring"
            )
            ps.save(backup_data)
            # The save() call would normally fire the backup callback; but
            # because the data is identical to the backup, the next backup
            # push is essentially a no-op (idempotent).
        elif backup_dt < local_dt:
            log.info(
                "Auto-restore: local is newer than backup, self-healing by "
                "pushing local state to router"
            )
            try:
                backup_local_state_to_router(router, ps.STORE_FILE)
            except Exception as e:
                log.warning(f"Auto-restore self-heal failed: {e}")
        # else: equal -- no-op
    except Exception as e:
        log.warning(f"Auto-restore check failed: {e}")


# ── VPNService class ─────────────────────────────────────────────────────────


class VPNService:
    """Orchestrates VPN profile lifecycle, device management, and LAN access.

    All methods raise exceptions on error (NotFoundError, ConflictError,
    LimitExceededError, NotLoggedInError, ValueError, RuntimeError) instead
    of returning HTTP responses.
    """

    # Kept as class attrs for backward compatibility (tests reference VPNService.MAX_WG_GROUPS).
    # Canonical values live in protocol_limits.py.
    MAX_WG_GROUPS = MAX_WG_GROUPS
    MAX_OVPN_GROUPS = MAX_OVPN_GROUPS
    MAX_PWG_GROUPS = MAX_PWG_GROUPS

    def __init__(self, router, proton, strategies: dict = None):
        self.router = router
        self.proton = proton
        self.strategies = strategies or {}  # {protocol_str: TunnelStrategy}
        self._ipset = IpsetOps(router)
        self._devices = DeviceService(router, self._ipset)
        self._healer = ProfileHealer(self._ipset)
        self._switch_locks = {}
        self._smart = SmartProtocolManager(
            change_protocol_fn=self.change_protocol,
            get_switch_lock_fn=lambda pid: self._switch_locks.setdefault(pid, threading.RLock()),
        )

    # ── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _local_display_order(store_data, profile_id, default=None):
        """Look up display_order from the local store for any profile."""
        if not profile_id:
            return default
        for p in store_data.get("profiles", []):
            if p.get("id") == profile_id:
                return p.get("display_order", default)
        return default

    def _resolve_server_live(self, local_profile: dict) -> dict:
        """Resolve server info from Proton API by id with cache fallback.

        Reads server_id from local profile (top-level or nested under
        server.id for legacy data), then calls proton.get_server_by_id() to
        get the live server dict (name, country, city, load, etc.). Falls
        back to the locally cached server dict if Proton is unavailable or
        the server is gone.

        Preserves the cached ``endpoint`` and ``physical_server_domain``
        fields if they exist (these come from the WG/OVPN config generation
        and aren't re-derivable from the Proton server list alone).
        """
        cached = local_profile.get("server") or {}
        server_id = local_profile.get("server_id") or cached.get("id")
        if not server_id:
            return cached
        if not self.proton or not self.proton.is_logged_in:
            return cached
        try:
            server_obj = self.proton.get_server_by_id(server_id)
            if server_obj is None:
                return cached
            live = self.proton.server_to_dict(server_obj)
            # Preserve fields that come from the physical-server selection at
            # config-generation time (not in the logical server list)
            if cached.get("endpoint"):
                live["endpoint"] = cached["endpoint"]
            if cached.get("physical_server_domain"):
                live["physical_server_domain"] = cached["physical_server_domain"]
            if cached.get("protocol"):
                live["protocol"] = cached["protocol"]
            return live
        except Exception:
            return cached

    # ── Self-Heal ────────────────────────────────────────────────────────────

    def _heal_duplicate_tunnel_ids(self, store_data: dict, router) -> None:
        """Fix proton-wg tunnel ID collisions — delegates to ProfileHealer."""
        self._healer.heal_duplicate_tunnel_ids(store_data, router)

    # ── Profile List ─────────────────────────────────────────────────────────

    def build_profile_list(self, store_data: dict = None) -> list:
        """Build the canonical profile list, merging router state with local metadata.

        This is THE source of truth for ``/api/profiles``. It iterates the
        router's route_policy rules first (so manual SSH or GL.iNet UI changes
        are visible) and merges in local UI metadata (color, icon, options,
        lan_access) by matching on the stable (vpn_protocol, peer_id|client_id)
        key.

        Server info (name, country, city, load) is resolved live from Proton
        via server_id rather than read from a local cache. Falls back to cached
        values if Proton is unavailable or the server is gone.

        Self-heals anonymous '@rule[N]' sections back to their fvpn_rule_NNNN
        names when matched to a local profile, so subsequent calls use the
        canonical name.
        """
        if store_data is None:
            store_data = ps.load()

        router = self.router
        proton = self.proton

        # Index local profiles for quick lookup by (protocol, id)
        local_vpn_by_key = {}
        local_non_vpn = []
        for p in store_data.get("profiles", []):
            if p.get("type") == PROFILE_TYPE_VPN:
                key = _local_router_key(p)
                if key[1]:  # only if we have a peer/client id
                    local_vpn_by_key[key] = p
            else:
                local_non_vpn.append(p)

        # Live router data -- batched into a few SSH calls
        try:
            router_rules = router.policy.get_flint_vpn_rules()  # one SSH call
        except Exception as e:
            log.error(f"build_profile_list: failed to read router rules: {e}")
            router_rules = []

        try:
            vpn_assignments_raw = router.devices.get_device_assignments()  # {mac: rule_name (router section)}
        except Exception:
            vpn_assignments_raw = {}

        vpn_profiles = []
        matched_local_keys = set()
        healed_count = 0
        rule_name_remap = {}  # router section name -> canonical fvpn_rule name (for assignment count)

        for rule in router_rules:
            router_section = rule.get("rule_name", "")
            key = _router_rule_key(rule)
            local = local_vpn_by_key.get(key, {})

            # Self-heal: if router has anonymized our section, rename it back
            canonical_rule_name = router_section
            if local and router_section.startswith("@rule"):
                local_section = (local.get("router_info") or {}).get("rule_name", "")
                if local_section and local_section.startswith("fvpn_rule"):
                    try:
                        router.policy.heal_anonymous_rule_section(router_section, local_section)
                        canonical_rule_name = local_section
                        healed_count += 1
                        log.info(f"Healed anonymous section {router_section} -> {local_section}")
                    except Exception as e:
                        log.warning(f"Failed to heal {router_section}: {e}")
            rule_name_remap[router_section] = canonical_rule_name

            if local:
                matched_local_keys.add(key)

            # Tunnel health is per-profile and can't be batched (queries wg show / ifstatus)
            try:
                health = router.tunnel.get_tunnel_health(canonical_rule_name)
            except Exception:
                health = "loading"

            # router_info bridges local UI and router operations
            ri = local.get("router_info") or {}
            ri = dict(ri)  # don't mutate the local profile
            ri["rule_name"] = canonical_rule_name
            ri["vpn_protocol"] = PROTO_OPENVPN if rule.get("via_type") == PROTO_OPENVPN else PROTO_WIREGUARD
            if rule.get("peer_id"):
                ri.setdefault("peer_id", rule["peer_id"])
            if rule.get("client_id"):
                ri.setdefault("client_id", rule["client_id"])

            merged = {
                "id": local.get("id") or canonical_rule_name,
                "type": PROFILE_TYPE_VPN,
                "name": rule.get("name") or local.get("name") or canonical_rule_name,
                "color": local.get("color", "#3498db"),
                "icon": local.get("icon", "\U0001f512"),
                "is_guest": local.get("is_guest", False),
                "kill_switch": rule.get("killswitch") == "1",
                "health": health,
                "server": self._resolve_server_live(local),
                "server_scope": ps.normalize_server_scope(local.get("server_scope")),
                "options": local.get("options", {}),
                "adblock": local.get("adblock", False),
                "router_info": ri,
                "device_count": 0,  # filled below
            }
            if not local:
                merged["_orphan"] = True
            vpn_profiles.append(merged)

        # Compute device counts using the (possibly remapped) canonical rule names
        device_counts = {}
        for mac, router_section in vpn_assignments_raw.items():
            canonical = rule_name_remap.get(router_section, router_section)
            device_counts[canonical] = device_counts.get(canonical, 0) + 1
        for p in vpn_profiles:
            p["device_count"] = device_counts.get(p["router_info"]["rule_name"], 0)

        # Self-heal duplicate tunnel_ids (can happen after router reboot races)
        self._heal_duplicate_tunnel_ids(store_data, router)

        # proton-wg profiles (wireguard-tcp / wireguard-tls): managed outside
        # vpn-client, so they don't appear in router route_policy rules.
        # Handle them separately from the ghost detection.
        for key, local in local_vpn_by_key.items():
            ri = local.get("router_info", {})
            proto = ri.get("vpn_protocol", "")
            if not proto.startswith("wireguard-"):
                continue  # Not a proton-wg profile
            matched_local_keys.add(key)  # Don't treat as ghost

            p = dict(local)
            iface = ri.get("tunnel_name", "")
            try:
                p["health"] = router.proton_wg.get_proton_wg_health(iface) if iface else HEALTH_RED
            except Exception:
                p["health"] = HEALTH_RED
            p["kill_switch"] = True  # Always on for proton-wg (blackhole route)
            if proton:
                try:
                    p["server"] = self._resolve_server_live(local)
                except Exception:
                    pass
            p["device_count"] = 0
            vpn_profiles.append(p)

        # Ghost: local VPN profile whose router rule no longer exists
        for key, local in local_vpn_by_key.items():
            if key in matched_local_keys:
                continue
            ghost = dict(local)
            ghost["health"] = HEALTH_RED
            ghost["kill_switch"] = False
            ghost["_ghost"] = True
            ghost.pop("status", None)
            ghost["device_count"] = 0
            vpn_profiles.append(ghost)

        # Non-VPN profiles (local-only)
        for p in local_non_vpn:
            p = dict(p)  # don't mutate the original
            p.pop("status", None)
            p["device_count"] = sum(
                1 for mac, pid in store_data.get("device_assignments", {}).items()
                if pid == p["id"]
            )
            vpn_profiles.append(p)

        # Unified sort: if any profile has display_order, sort the whole list by it.
        # Profiles without display_order keep their current position (high sentinel).
        if any(self._local_display_order(store_data, p.get("id")) is not None for p in vpn_profiles):
            by_id = {pp["id"]: pp for pp in store_data.get("profiles", [])}
            vpn_profiles.sort(key=lambda p: self._local_display_order(store_data, p.get("id"), default=999))

        return vpn_profiles

    # ── Profile CRUD ─────────────────────────────────────────────────────────

    def create_profile(self, name, profile_type, vpn_protocol=PROTO_WIREGUARD,
                       server_id=None, options=None, color="#3498db",
                       icon="\U0001f512", is_guest=False, kill_switch=True,
                       server_scope=None, ovpn_protocol="udp", adblock=False):
        """Create a new profile (VPN, NoVPN, or NoInternet).

        For VPN profiles: generates the tunnel config via the appropriate
        strategy, uploads to the router, and creates a local profile_store
        entry.

        Raises:
            LimitExceededError: If the per-protocol group limit is exceeded.
            NotLoggedInError: If Proton is not logged in (VPN profiles).
            ValueError: If required fields are missing.
            RuntimeError: If router config upload fails.
        """
        # Normalize: wireguard-tcp and wireguard-tls are both proton-wg tunnels
        is_proton_wg = vpn_protocol in (PROTO_WIREGUARD_TCP, PROTO_WIREGUARD_TLS)
        wg_transport = {PROTO_WIREGUARD_TCP: "tcp", PROTO_WIREGUARD_TLS: "tls"}.get(vpn_protocol, "udp")

        # Enforce VPN group limits per protocol (centralized in protocol_limits.py)
        if profile_type == PROFILE_TYPE_VPN:
            require_protocol_slot(vpn_protocol)

        router_info = None
        server_info = None
        wg_key = None
        cert_expiry = None

        # For VPN profiles: generate config and upload to router
        if profile_type == PROFILE_TYPE_VPN:
            if not server_id:
                raise ValueError("server_id required for VPN profiles")

            if not self.proton.is_logged_in:
                raise NotLoggedInError("Not logged into ProtonVPN")

            server = self.proton.get_server_by_id(server_id)
            opts = options or {}
            opts["ovpn_protocol"] = ovpn_protocol

            try:
                strategy = get_strategy(vpn_protocol)
                router_info, server_info, wg_key, cert_expiry = strategy.create(
                    self.router, self.proton, name, server, opts, transport=wg_transport,
                )
            except Exception as e:
                log.error(f"Failed to create VPN profile: {e}", exc_info=True)
                raise RuntimeError(f"Failed to configure router: {e}") from e

        # wg_key + cert_expiry are set for WG profiles (persistent cert path)
        extra_fields = {}
        if profile_type == PROFILE_TYPE_VPN and vpn_protocol.startswith("wireguard") and wg_key:
            extra_fields["wg_key"] = wg_key
            extra_fields["cert_expiry"] = cert_expiry

        profile = ps.create_profile(
            name=name,
            profile_type=profile_type,
            color=color,
            icon=icon,
            is_guest=is_guest,
            server=server_info,
            options=options,
            router_info=router_info,
            server_scope=ps.normalize_server_scope(server_scope),
            adblock=adblock,
            **extra_fields,
        )

        # Apply requested kill_switch state to the router (router is the source of truth).
        # upload_*_config writes killswitch='1' by default; only override if the caller asked for off.
        # proton-wg profiles always have kill switch on (blackhole route) -- skip UCI operations.
        if profile_type == PROFILE_TYPE_VPN and router_info and router_info.get("rule_name") and not is_proton_wg:
            if not kill_switch:
                try:
                    self.router.policy.set_kill_switch(router_info["rule_name"], False)
                except Exception as e:
                    log.warning(f"Failed to apply initial kill_switch=False for {profile['name']}: {e}")
            # Reflect live router state in the response
            try:
                profile["kill_switch"] = self.router.policy.get_kill_switch(router_info["rule_name"])
            except Exception:
                pass

        log.info(f"Created profile '{profile['name']}' (type={profile['type']}, id={profile['id']})")

        if adblock:
            self.sync_adblock_to_router()

        return profile

    def update_profile(self, profile_id, **data):
        """Update profile metadata (name, color, icon, options, kill_switch).

        Kill switch is router-canonical: writes go directly to UCI, not to
        local store.

        Raises:
            NotFoundError: If the profile is not found.
        """
        # Pull kill_switch out before writing to local store -- it lives on the router only
        new_kill_switch = data.pop("kill_switch", None)

        profile = ps.update_profile(profile_id, **data)
        if profile is None:
            raise NotFoundError("Profile not found")

        ri = profile.get("router_info", {})
        rule_name = ri.get("rule_name")
        proto = ri.get("vpn_protocol", PROTO_WIREGUARD)
        is_pwg = proto.startswith("wireguard-")

        # Apply kill_switch change to the router (source of truth).
        # proton-wg always has kill switch on (blackhole route) -- skip UCI ops.
        if new_kill_switch is not None and rule_name and not is_pwg:
            try:
                self.router.policy.set_kill_switch(rule_name, bool(new_kill_switch))
                profile["kill_switch"] = self.router.policy.get_kill_switch(rule_name)
            except Exception as e:
                log.error(f"Failed to set kill switch on {rule_name}: {e}")

        # Sync name to router if this is a VPN profile (router is the source of truth).
        # proton-wg profiles have no route_policy rule -- name is local-only.
        if "name" in data and rule_name and not is_pwg:
            try:
                self.router.policy.rename_profile(
                    rule_name=rule_name,
                    new_name=data["name"],
                    peer_id=ri.get("peer_id", "") if proto != PROTO_OPENVPN else "",
                    client_uci_id=ri.get("client_uci_id", "") if proto == PROTO_OPENVPN else "",
                )
                profile["name"] = self.router.policy.get_profile_name(rule_name) or data["name"]
            except Exception as e:
                log.warning(f"Failed to rename profile on router: {e}")

        # Always include live kill_switch in the response so the UI is in sync
        if rule_name and not is_pwg:
            try:
                profile["kill_switch"] = self.router.policy.get_kill_switch(rule_name)
            except Exception:
                pass
        elif is_pwg:
            profile["kill_switch"] = True  # Always on

        if "adblock" in data:
            self.sync_adblock_to_router()

        return profile

    def delete_profile(self, profile_id):
        """Delete a profile and tear down its tunnel if VPN.

        Acquires the per-profile switch lock (blocking) to wait for any
        in-progress smart protocol switch to finish before deleting.

        Raises:
            NotFoundError: If the profile is not found.
        """
        self._smart_cancel(profile_id)

        # Wait for any in-progress smart protocol switch to finish
        lock = self._switch_locks.setdefault(profile_id, threading.RLock())
        lock.acquire()
        try:
            profile = ps.get_profile(profile_id)
            if not profile:
                raise NotFoundError("Profile not found")

            # Tear down router resources (reads fresh router_info after lock)
            if profile["type"] == PROFILE_TYPE_VPN and profile.get("router_info"):
                ri = profile["router_info"]
                proto = ri.get("vpn_protocol", PROTO_WIREGUARD)
                try:
                    strategy = get_strategy(proto)
                    strategy.delete(self.router, ri)
                except Exception:
                    pass  # Best effort cleanup

            log.info(f"Deleted profile '{profile['name']}' (id={profile_id})")

            ps.delete_profile(profile_id)
        finally:
            lock.release()
            self._switch_locks.pop(profile_id, None)

        # Sync router LAN state -- handles ipset removal, rule deletion, and
        # NoInternet reconciliation in a single pass via the new UCI execution
        # layer (membership + structural diff against live router state).
        try:
            self.sync_noint_to_router()
        except Exception as e:
            log.warning(f"LAN sync after delete failed: {e}")

        self.sync_adblock_to_router()

    # ── Type Change ──────────────────────────────────────────────────────────

    def change_type(self, profile_id: str, new_type: str,
                    vpn_protocol: str = PROTO_WIREGUARD,
                    server_id: str = None, options: dict = None,
                    kill_switch: bool = True, server_scope: dict = None,
                    ovpn_protocol: str = "udp"):
        """Change a profile's group type (VPN ↔ NoVPN ↔ NoInternet).

        Three cases:
        - NoVPN ↔ NoInternet: metadata + LAN sync only.
        - VPN → non-VPN: tear down tunnel, clear router fields.
        - Non-VPN → VPN: create a tunnel (requires server_id + Proton login).

        Returns the updated profile dict.
        """
        self._smart_cancel(profile_id)

        profile = ps.get_profile(profile_id)
        if not profile:
            raise NotFoundError("Profile not found")

        old_type = profile["type"]
        if old_type == new_type:
            raise ValueError(f"Profile is already type '{new_type}'")
        if new_type not in (PROFILE_TYPE_VPN, PROFILE_TYPE_NO_VPN, PROFILE_TYPE_NO_INTERNET):
            raise ValueError(f"Invalid type: {new_type}")

        # ── Case 1: non-VPN ↔ non-VPN ───────────────────────────────────
        if old_type != PROFILE_TYPE_VPN and new_type != PROFILE_TYPE_VPN:
            ps.update_profile(profile_id, type=new_type)
            log.info(f"Changed type for '{profile['name']}' from {old_type} to {new_type}")
            try:
                self.sync_noint_to_router()
            except Exception as e:
                log.warning(f"LAN sync after type change failed: {e}")
            return ps.get_profile(profile_id)

        # ── Case 2: VPN → non-VPN ───────────────────────────────────────
        if old_type == PROFILE_TYPE_VPN:
            # Wait for any in-progress smart protocol switch before tearing down
            lock = self._switch_locks.setdefault(profile_id, threading.RLock())
            lock.acquire()
            try:
                # Re-read profile under lock to get current router_info
                profile = ps.get_profile(profile_id)
                ri = (profile.get("router_info") or {}) if profile else {}
                if ri:
                    proto = ri.get("vpn_protocol", PROTO_WIREGUARD)
                    try:
                        strategy = get_strategy(proto)
                        strategy.delete(self.router, ri)
                    except Exception as e:
                        log.warning(f"change_type: tunnel teardown failed: {e}")
            finally:
                lock.release()

            # Clear VPN-specific fields
            ps.update_profile(profile_id,
                type=new_type,
                router_info=None,
                server_id=None,
                server=None,
                options=None,
                server_scope=None,
                wg_key=None,
                cert_expiry=None,
            )
            log.info(f"Changed type for '{profile['name']}' from VPN to {new_type}")
            try:
                self.sync_noint_to_router()
            except Exception as e:
                log.warning(f"LAN sync after type change failed: {e}")
            return ps.get_profile(profile_id)

        # ── Case 3: non-VPN → VPN ───────────────────────────────────────
        if not server_id:
            raise ValueError("server_id required when changing to VPN type")
        if not self.proton.is_logged_in:
            raise NotLoggedInError("Not logged into ProtonVPN")

        is_proton_wg = vpn_protocol in (PROTO_WIREGUARD_TCP, PROTO_WIREGUARD_TLS)
        wg_transport = {PROTO_WIREGUARD_TCP: "tcp", PROTO_WIREGUARD_TLS: "tls"}.get(vpn_protocol, "udp")

        # Check limits (centralized in protocol_limits.py)
        require_protocol_slot(vpn_protocol, exclude_profile_id=profile_id)

        # Create tunnel
        server = self.proton.get_server_by_id(server_id)
        opts = options or {}
        opts["ovpn_protocol"] = ovpn_protocol

        strategy = get_strategy(vpn_protocol)
        try:
            router_info, server_info, wg_key, cert_expiry = strategy.create(
                self.router, self.proton, profile["name"], server, opts,
                transport=wg_transport,
            )
        except Exception as e:
            log.error(f"change_type: tunnel creation failed: {e}", exc_info=True)
            raise RuntimeError(f"Failed to create tunnel: {e}") from e

        # Migrate any device assignments from local store to router
        store_data = ps.load()
        local_assignments = store_data.get("device_assignments", {})
        macs_to_move = [mac for mac, pid in local_assignments.items() if pid == profile_id]
        for mac in macs_to_move:
            try:
                if is_proton_wg:
                    ipset_name = router_info.get("ipset_name", f"src_mac_{router_info.get('tunnel_id', 0)}")
                    self._ipset.ensure_and_add(ipset_name, mac)
                else:
                    self.router.devices.set_device_vpn(mac, router_info["rule_name"])
            except Exception as e:
                log.warning(f"change_type: reassign {mac} failed: {e}")
            # Remove from local assignments (VPN assignments are router-canonical)
            del local_assignments[mac]
        if macs_to_move:
            ps.save(store_data)

        # Update profile
        update_kwargs = {
            "type": PROFILE_TYPE_VPN,
            "router_info": router_info,
            "server_id": server_info.get("id", server_id),
            "server": {k: server_info[k] for k in ("id", "endpoint", "physical_server_domain", "protocol") if server_info.get(k)},
            "options": opts,
            "server_scope": ps.normalize_server_scope(server_scope),
        }
        if wg_key:
            update_kwargs["wg_key"] = wg_key
        if cert_expiry:
            update_kwargs["cert_expiry"] = cert_expiry
        ps.update_profile(profile_id, **update_kwargs)

        # Apply kill switch
        if router_info and router_info.get("rule_name") and not is_proton_wg and not kill_switch:
            try:
                self.router.policy.set_kill_switch(router_info["rule_name"], False)
            except Exception as e:
                log.warning(f"change_type: set kill_switch failed: {e}")

        log.info(f"Changed type for '{profile['name']}' from {old_type} to VPN ({vpn_protocol})")
        try:
            self.sync_noint_to_router()
        except Exception as e:
            log.warning(f"LAN sync after type change failed: {e}")
        self.sync_adblock_to_router()
        return ps.get_profile(profile_id)

    # ── Server Switch ────────────────────────────────────────────────────────

    def switch_server(self, profile_id: str, server_id: str, options: dict = None,
                      server_scope: dict = None) -> dict:
        """Core server-switch logic. Used by API endpoint and auto-optimizer.

        Two paths depending on protocol:

        WireGuard (fast path, no flicker):
          - Update the peer's UCI config in place
          - Atomic peer swap on the running wgclient interface via ``wg set``

        OpenVPN (delete + recreate path, brief flicker):
          - openvpn doesn't support hot config reload, so we have to actually
            recreate the instance

        Returns the updated profile dict. Raises on error.

        Raises:
            ValueError: If the profile is not found or not VPN.
            RuntimeError: If a switch is already in progress.
        """
        # Per-profile lock to prevent concurrent switches
        lock = self._switch_locks.setdefault(profile_id, threading.RLock())

        if not lock.acquire(blocking=False):
            raise RuntimeError("Server switch already in progress for this profile")

        try:
            profile = ps.get_profile(profile_id)
            if not profile:
                raise ValueError("Profile not found")
            if profile["type"] != PROFILE_TYPE_VPN:
                raise ValueError("Not a VPN profile")

            old_ri = profile.get("router_info", {}) or {}
            rule_name = old_ri.get("rule_name", "")
            vpn_protocol = old_ri.get("vpn_protocol", PROTO_WIREGUARD)
            if not rule_name:
                raise ValueError("Profile has no router_info.rule_name")

            server = self.proton.get_server_by_id(server_id)
            opts = options or profile.get("options", {})

            # If cert-relevant VPN options changed, re-register the persistent
            # certificate BEFORE generating the new config. These features are
            # baked into the cert at registration time — without refresh, the
            # Proton server continues enforcing the old features.
            if vpn_protocol.startswith("wireguard") and profile.get("wg_key") and options:
                old_opts = profile.get("options") or {}
                cert_keys = ("netshield", "moderate_nat", "nat_pmp", "vpn_accelerator")
                old_cert = {k: old_opts.get(k) for k in cert_keys}
                new_cert = {k: opts.get(k) for k in cert_keys}
                if old_cert != new_cert:
                    log.info(f"Refreshing WG cert for '{profile['name']}' — options changed: {old_cert} → {new_cert}")
                    cert_expiry_new = self.proton.refresh_wireguard_cert(
                        profile["wg_key"],
                        profile_name=profile.get("name", "Unnamed"),
                        netshield=opts.get("netshield", 0),
                        moderate_nat=opts.get("moderate_nat", False),
                        nat_pmp=opts.get("nat_pmp", False),
                        vpn_accelerator=opts.get("vpn_accelerator", True),
                    )
                    ps.update_profile(profile_id, cert_expiry=cert_expiry_new)

            strategy = get_strategy(vpn_protocol)
            new_ri, server_info, wg_key, cert_expiry = strategy.switch_server(
                self.router, self.proton, profile, server, opts, old_ri,
            )

            # Normalize the new scope (handles legacy shape + enforces cascade).
            if server_scope is not None:
                scope = ps.normalize_server_scope(server_scope)
            else:
                scope = ps.normalize_server_scope(profile.get("server_scope"))

            # Persist updated server reference + new scope.
            server_cache = {}
            for k in ("id", "endpoint", "physical_server_domain", "protocol"):
                if server_info.get(k):
                    server_cache[k] = server_info[k]

            update_kwargs = {
                "server_id": server_info.get("id", ""),
                "server": server_cache,
                "options": opts,
                "server_scope": scope,
            }
            # router_info only changes for OVPN (delete+recreate gets a new
            # rule_name/client_uci_id). WG keeps the same router_info.
            if new_ri is not None:
                update_kwargs["router_info"] = new_ri
            # Persist the WG key + cert expiry for persistent-cert profiles.
            if wg_key:
                update_kwargs["wg_key"] = wg_key
            if cert_expiry:
                update_kwargs["cert_expiry"] = cert_expiry
            ps.update_profile(profile_id, **update_kwargs)
            return ps.get_profile(profile_id)

        finally:
            lock.release()

    # ── Protocol Change ─────────────────────────────────────────────────────

    def change_protocol(self, profile_id: str, new_vpn_protocol: str,
                        server_id: str = None, options: dict = None,
                        server_scope: dict = None, ovpn_protocol: str = "udp"):
        """Change a VPN profile's protocol (e.g. WireGuard → OpenVPN).

        Tears down the old tunnel, creates a new one with the new protocol,
        and re-assigns all devices. Preserves name, color, icon, LAN access,
        and other local metadata.

        Raises:
            NotFoundError: If the profile is not found.
            ValueError: If the profile is not VPN or the protocol is unchanged.
            LimitExceededError: If the new protocol's group limit is exceeded.
            RuntimeError: If tunnel creation fails.
        """
        # Per-profile lock to prevent concurrent operations
        lock = self._switch_locks.setdefault(profile_id, threading.RLock())

        if not lock.acquire(blocking=False):
            raise RuntimeError("Another operation is in progress for this profile")

        try:
            profile = ps.get_profile(profile_id)
            if not profile:
                raise NotFoundError("Profile not found")
            if profile["type"] != PROFILE_TYPE_VPN:
                raise ValueError("Not a VPN profile")

            old_ri = profile.get("router_info", {}) or {}
            old_proto = old_ri.get("vpn_protocol", PROTO_WIREGUARD)

            # Normalize wireguard-tcp/tls: the base protocol for limit checks
            is_new_proton_wg = new_vpn_protocol in (PROTO_WIREGUARD_TCP, PROTO_WIREGUARD_TLS)
            is_old_proton_wg = old_proto.startswith("wireguard-")
            wg_transport = {PROTO_WIREGUARD_TCP: "tcp", PROTO_WIREGUARD_TLS: "tls"}.get(new_vpn_protocol, "udp")

            if new_vpn_protocol == old_proto:
                # OpenVPN UDP ↔ TCP is allowed (same vpn_protocol, different transport)
                old_ovpn = "tcp" if (profile.get("server") or {}).get("protocol", "").endswith("tcp") else "udp"
                is_ovpn_transport_change = new_vpn_protocol == PROTO_OPENVPN and ovpn_protocol != old_ovpn
                if not is_ovpn_transport_change:
                    raise ValueError("Protocol is already " + old_proto)

            # Check limits for the new protocol (centralized in protocol_limits.py)
            require_protocol_slot(new_vpn_protocol, exclude_profile_id=profile_id)

            # 1. Capture assigned devices before teardown
            assigned_macs = []
            if is_old_proton_wg:
                ipset_name = old_ri.get("ipset_name", f"src_mac_{old_ri.get('tunnel_id', 0)}")
                try:
                    assigned_macs = [m.lower() for m in self._ipset.list_members(ipset_name)]
                except Exception as e:
                    log.warning(f"change_protocol: failed to read ipset {ipset_name}: {e}")
            elif old_ri.get("rule_name"):
                try:
                    assigned_macs = [t.lower() for t in self.router.policy.from_mac_tokens(old_ri["rule_name"])]
                except Exception as e:
                    log.warning(f"change_protocol: failed to read from_mac: {e}")

            # 2. Tear down old tunnel
            old_strategy = get_strategy(old_proto)
            try:
                old_strategy.delete(self.router, old_ri)
            except Exception as e:
                log.warning(f"change_protocol: old tunnel teardown failed: {e}")

            # 3. Resolve server — use provided server_id or keep the current one
            effective_server_id = server_id or profile.get("server_id") or (profile.get("server") or {}).get("id")
            if not effective_server_id:
                raise ValueError("No server_id available for new tunnel")
            if not self.proton.is_logged_in:
                raise NotLoggedInError("Not logged into ProtonVPN")
            server = self.proton.get_server_by_id(effective_server_id)
            opts = options or profile.get("options", {})
            opts["ovpn_protocol"] = ovpn_protocol

            # 4. Create new tunnel with new protocol
            new_strategy = get_strategy(new_vpn_protocol)
            try:
                new_ri, server_info, wg_key, cert_expiry = new_strategy.create(
                    self.router, self.proton, profile["name"], server, opts,
                    transport=wg_transport,
                )
            except Exception as e:
                log.error(f"change_protocol: new tunnel creation failed: {e}", exc_info=True)
                raise RuntimeError(f"Failed to create new tunnel: {e}") from e

            # 5. Re-assign devices to the new tunnel
            for mac in assigned_macs:
                try:
                    if is_new_proton_wg:
                        new_ipset = new_ri.get("ipset_name", f"src_mac_{new_ri.get('tunnel_id', 0)}")
                        self._ipset.ensure_and_add(new_ipset, mac)
                    else:
                        self.router.devices.set_device_vpn(mac, new_ri["rule_name"])
                except Exception as e:
                    log.warning(f"change_protocol: reassign {mac} failed: {e}")

            # 6. Update local profile store
            update_kwargs = {
                "router_info": new_ri,
                "server_id": server_info.get("id", effective_server_id),
                "server": {k: server_info[k] for k in ("id", "endpoint", "physical_server_domain", "protocol") if server_info.get(k)},
                "options": opts,
            }
            if server_scope is not None:
                update_kwargs["server_scope"] = ps.normalize_server_scope(server_scope)
            if wg_key:
                update_kwargs["wg_key"] = wg_key
            if cert_expiry:
                update_kwargs["cert_expiry"] = cert_expiry
            # Clear WG key fields when switching away from WireGuard
            if not new_vpn_protocol.startswith("wireguard") and profile.get("wg_key"):
                update_kwargs["wg_key"] = None
                update_kwargs["cert_expiry"] = None
            ps.update_profile(profile_id, **update_kwargs)

            log.info(f"Changed protocol for '{profile['name']}' from {old_proto} to {new_vpn_protocol}")

            # 7. Sync LAN rules
            try:
                self.sync_noint_to_router()
            except Exception as e:
                log.warning(f"LAN sync after protocol change failed: {e}")

            return ps.get_profile(profile_id)

        finally:
            lock.release()

    # ── Tunnel Control ───────────────────────────────────────────────────────

    # ── Smart Protocol (delegates to SmartProtocolManager) ─────────────────

    def connect_profile(self, profile_id):
        """Bring a VPN profile's tunnel up. Returns immediately.

        If the profile has ``smart_protocol`` enabled in its options, registers
        it for background monitoring. The SSE tick calls
        ``tick_smart_protocol()`` every 10s to check health and switch
        protocols if the tunnel doesn't establish.

        Returns dict with success and health.

        Raises:
            NotFoundError: If the profile is not found or not VPN.
            ValueError: If no tunnel is configured.
        """
        profile = ps.get_profile(profile_id)
        if not profile or profile.get("type") != PROFILE_TYPE_VPN:
            raise NotFoundError("VPN profile not found")

        ri = profile.get("router_info", {})
        if not ri.get("rule_name"):
            raise ValueError("No tunnel configured. Try changing the server to recreate it.")

        proto = ri.get("vpn_protocol", PROTO_WIREGUARD)

        try:
            log.info(f"Connecting profile '{profile['name']}' (rule={ri['rule_name']}, protocol={proto})")
            strategy = get_strategy(proto)
            health = strategy.connect(self.router, ri)
            log.info(f"Profile '{profile['name']}' connect issued (health={health})")

            # vpn-client restart (kernel WG / OVPN) flushes ALL src_mac_* ipsets
            # including proton-wg ones. Re-add members from local store.
            if not proto.startswith("wireguard-"):
                self._reconcile_proton_wg_ipset_members()

            # Register for smart protocol monitoring if enabled
            opts = profile.get("options") or {}
            if opts.get("smart_protocol") and not self._smart.is_pending(profile_id):
                self._smart.register(profile_id, proto)

            return {"success": True, "health": health}
        except Exception as e:
            log.error(f"Failed to connect profile '{profile['name']}': {e}", exc_info=True)
            raise

    def _smart_cancel(self, profile_id):
        """Cancel smart protocol monitoring for a profile."""
        self._smart.cancel(profile_id)

    def tick_smart_protocol(self):
        """Called every SSE tick (~10s). Delegates to SmartProtocolManager."""
        self._smart.tick(self.router)

    def get_smart_protocol_status(self):
        """Return smart protocol retry status for SSE streaming."""
        return self._smart.get_status()

    def disconnect_profile(self, profile_id):
        """Bring a VPN profile's tunnel down.

        Also cancels any pending smart protocol retry for this profile.

        Returns dict with success and health.

        Raises:
            NotFoundError: If the profile is not found or not VPN.
            ValueError: If no tunnel is configured.
        """
        self._smart_cancel(profile_id)

        profile = ps.get_profile(profile_id)
        if not profile or profile.get("type") != PROFILE_TYPE_VPN:
            raise NotFoundError("VPN profile not found")

        ri = profile.get("router_info", {})
        if not ri.get("rule_name"):
            raise ValueError("No tunnel configured")

        proto = ri.get("vpn_protocol", PROTO_WIREGUARD)

        try:
            log.info(f"Disconnecting profile '{profile['name']}' (rule={ri['rule_name']})")
            strategy = get_strategy(proto)
            strategy.disconnect(self.router, ri)
            log.info(f"Profile '{profile['name']}' disconnected")

            # vpn-client restart (kernel WG / OVPN) flushes ALL src_mac_* ipsets
            # including proton-wg ones. Re-add members from local store.
            if not proto.startswith("wireguard-"):
                self._reconcile_proton_wg_ipset_members()

            return {"success": True, "health": HEALTH_RED}
        except Exception as e:
            log.error(f"Failed to disconnect profile '{profile['name']}': {e}", exc_info=True)
            raise

    # ── Profile Ordering ─────────────────────────────────────────────────────

    def reorder_profiles(self, profile_ids):
        """Reorder profiles.

        Sets ``display_order`` on ALL profiles (VPN and non-VPN alike) so the
        dashboard can freely interleave them. VPN profiles also get their
        relative order synced to the router via ``uci reorder`` (so routing
        priority stays consistent with the visual order).
        """
        if not profile_ids:
            raise ValueError("profile_ids required")

        store_data = ps.load()
        by_id = {p["id"]: p for p in store_data.get("profiles", [])}

        # 1. Set display_order on ALL profiles in the requested order
        vpn_rule_names = []
        for i, pid in enumerate(profile_ids):
            p = by_id.get(pid)
            if not p:
                continue
            p["display_order"] = i
            # Collect VPN rule names (in the requested order) for router sync
            if p.get("type") == PROFILE_TYPE_VPN:
                rn = (p.get("router_info") or {}).get("rule_name")
                if rn:
                    vpn_rule_names.append(rn)

        ps.save(store_data)

        # 2. Sync VPN relative order to router (for routing priority)
        if vpn_rule_names:
            try:
                self.router.policy.reorder_vpn_rules(vpn_rule_names)
            except Exception as e:
                log.warning(f"reorder_vpn_rules failed: {e}")

    # ── DNS Ad Block Sync ───────────────────────────────────────────────────

    def sync_adblock_to_router(self):
        """Sync DNS ad-block ipset + iptables rules to the router.

        Collects all MACs from adblock-enabled groups and rebuilds the
        fvpn_adblock_macs ipset. If no groups have adblock, cleans up.
        """
        try:
            store_data = ps.load()
            assignments = self._resolve_device_assignments(store_data)

            # Build {profile_id: profile} for quick lookup
            profiles_by_id = {
                p["id"]: p for p in store_data.get("profiles", [])
            }

            # Collect MACs where the assigned profile has adblock=True
            adblock_macs = set()
            for mac, pid in assignments.items():
                p = profiles_by_id.get(pid)
                if p and p.get("adblock") and p.get("type") != PROFILE_TYPE_NO_INTERNET:
                    adblock_macs.add(mac.lower())

            if not adblock_macs:
                self.router.adblock.cleanup_adblock()
            else:
                self.router.adblock.ensure_adblock_dnsmasq()
                self.router.adblock.sync_adblock_rules(adblock_macs)
        except Exception as e:
            log.warning(f"Adblock sync failed: {e}")

    # ── Guest Profile ────────────────────────────────────────────────────────

    def set_guest_profile(self, profile_id):
        """Set this profile as the guest profile.

        Raises:
            NotFoundError: If the profile is not found.
        """
        if not ps.set_guest_profile(profile_id):
            raise NotFoundError("Profile not found")

    # ── Device Assignment Resolution ─────────────────────────────────────────

    # ── Device operations (delegate to DeviceService) ─────────────────────

    def _resolve_device_assignments(self, store_data: dict) -> dict:
        """Return {mac: profile_id} — delegates to DeviceService."""
        return self._devices.resolve_assignments(store_data)

    def build_devices_live(self) -> list:
        """Build device list from live router data — delegates to DeviceService."""
        return self._devices.build_devices_live()

    def get_devices_cached(self) -> list:
        """5-second TTL device cache — delegates to DeviceService."""
        return self._devices.get_devices_cached()

    def invalidate_device_cache(self):
        """Invalidate the in-memory device cache."""
        self._devices.invalidate_cache()

    def assign_device(self, mac, profile_id):
        """Assign a device to a profile — delegates to DeviceService."""
        self._devices.assign_device(
            mac, profile_id,
            sync_noint_fn=self.sync_noint_to_router,
            sync_adblock_fn=self.sync_adblock_to_router,
        )

    def set_device_label(self, mac, label, device_class=""):
        """Set a custom label / device class — delegates to DeviceService."""
        self._devices.set_device_label(mac, label, device_class)

    # ── proton-wg ipset reconciliation ──────────────────────────────────────

    def _reconcile_proton_wg_ipset_members(self):
        """Re-add proton-wg device MACs to their ipsets from local store.

        Delegates to IpsetOps. Called after vpn-client restart.
        """
        self._ipset.reconcile_proton_wg_members()

    def reconcile_proton_wg_ipsets(self):
        """Ensure proton-wg ipsets exist, populate, and rebuild mangle rules.

        Delegates to IpsetOps. Called on app unlock.
        """
        self._ipset.reconcile_proton_wg_full()

    # ── LAN Access Control ───────────────────────────────────────────────────

    # ── NoInternet Sync ────────────────────────────────────────────────────

    def sync_noint_to_router(self):
        """Reconcile the NoInternet ipset on the router with local intent.

        Delegates to ``noint_sync.sync_noint_to_router``.
        Best-effort: any exception is logged but doesn't propagate.
        """
        try:
            result = noint_sync.sync_noint_to_router(self.router, store=ps.load())
            if result.get("applied"):
                log.info(
                    f"NoInternet sync applied: adds={result.get('adds', 0)}, "
                    f"removes={result.get('removes', 0)}, "
                    f"reload={result.get('reload', False)}"
                )
        except Exception as e:
            log.warning(f"NoInternet sync failed: {e}")
