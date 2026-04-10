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

import profile_store as ps
import lan_sync
from consts import (
    HEALTH_RED,
    LAN_ALLOWED,
    PROFILE_TYPE_VPN,
    PROFILE_TYPE_NO_VPN,
    PROFILE_TYPE_NO_INTERNET,
    PROTO_OPENVPN,
    PROTO_WIREGUARD,
    PROTO_WIREGUARD_TCP,
    PROTO_WIREGUARD_TLS,
)
from tunnel_strategy import get_strategy

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


def _local_router_key(local_profile: dict) -> tuple:
    """Stable key for matching a local profile to a router rule.

    Uses (vpn_protocol, peer_id) for WG and (vpn_protocol, client_id) for OVPN.
    For proton-wg (wireguard-tcp/tls), uses (protocol, tunnel_name) since they
    don't have peer_id (managed outside vpn-client).
    """
    ri = local_profile.get("router_info") or {}
    vpn_protocol = ri.get("vpn_protocol", PROTO_WIREGUARD)
    if vpn_protocol.startswith("wireguard-"):
        # proton-wg: keyed by tunnel_name (protonwg0, protonwg1, etc.)
        return (vpn_protocol, ri.get("tunnel_name", ""))
    if vpn_protocol == PROTO_OPENVPN:
        cid = str(ri.get("client_id", "")).lstrip("peer_").lstrip("client_")
        return (PROTO_OPENVPN, cid)
    pid = str(ri.get("peer_id", "")).lstrip("peer_").lstrip("client_")
    return (PROTO_WIREGUARD, pid)


def _router_rule_key(rule: dict) -> tuple:
    """Stable key for a router rule (matches _local_router_key)."""
    via = rule.get("via_type", PROTO_WIREGUARD)
    if via == PROTO_OPENVPN:
        return (PROTO_OPENVPN, str(rule.get("client_id", "")))
    return (PROTO_WIREGUARD, str(rule.get("peer_id", "")))


def _default_device(mac: str, profile_id=None) -> dict:
    """Return a device dict with all fields initialized to defaults."""
    return {
        "mac": mac, "ip": "", "hostname": "", "label": "",
        "device_class": "", "profile_id": profile_id, "router_online": False,
        "iface": "", "rx_speed": 0, "tx_speed": 0, "total_rx": 0,
        "total_tx": 0, "signal_dbm": None, "link_speed_mbps": None,
    }


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

    MAX_WG_GROUPS = 5
    MAX_OVPN_GROUPS = 5
    MAX_PWG_GROUPS = 4  # proton-wg TCP/TLS: limited by fwmark address space

    def __init__(self, router, proton, strategies: dict = None):
        self.router = router
        self.proton = proton
        self.strategies = strategies or {}  # {protocol_str: TunnelStrategy}
        self._switch_locks = {}
        self._device_cache = {"data": None, "ts": 0.0}
        self._DEVICE_CACHE_TTL = 5
        # Smart Protocol: in-memory state for pending retries.
        # {profile_id: {started_at, chain, attempt_idx, original_proto}}
        self._smart_pending = {}
        self._smart_lock = threading.Lock()

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _normalize_lan_access(self, lan):
        """Always return a dict with all four LAN access fields present.

        Used when surfacing profile data to the API so the frontend can rely
        on a stable shape (state + allow lists) regardless of when the
        profile was created.
        """
        lan = lan or {}
        return {
            "outbound": lan.get("outbound", LAN_ALLOWED),
            "inbound": lan.get("inbound", LAN_ALLOWED),
            "outbound_allow": list(lan.get("outbound_allow", [])),
            "inbound_allow": list(lan.get("inbound_allow", [])),
        }

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
            router_rules = router.get_flint_vpn_rules()  # one SSH call
        except Exception as e:
            log.error(f"build_profile_list: failed to read router rules: {e}")
            router_rules = []

        try:
            vpn_assignments_raw = router.get_device_assignments()  # {mac: rule_name (router section)}
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
                        router.heal_anonymous_rule_section(router_section, local_section)
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
                health = router.get_tunnel_health(canonical_rule_name)
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
                "lan_access": self._normalize_lan_access(local.get("lan_access")),
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
                p["health"] = router.get_proton_wg_health(iface) if iface else HEALTH_RED
            except Exception:
                p["health"] = HEALTH_RED
            p["kill_switch"] = True  # Always on for proton-wg (blackhole route)
            if proton:
                try:
                    p["server"] = self._resolve_server_live(local)
                except Exception:
                    pass
            p["lan_access"] = self._normalize_lan_access(p.get("lan_access"))
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
            ghost["lan_access"] = self._normalize_lan_access(ghost.get("lan_access"))
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
            p["lan_access"] = self._normalize_lan_access(p.get("lan_access"))
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
                       server_scope=None, ovpn_protocol="udp"):
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

        # Enforce VPN group limits per protocol
        if profile_type == PROFILE_TYPE_VPN:
            existing_profiles = ps.get_profiles()
            if is_proton_wg:
                count = len([p for p in existing_profiles if p["type"] == PROFILE_TYPE_VPN
                             and p.get("router_info", {}).get("vpn_protocol", "").startswith("wireguard-")])
                if count >= self.MAX_PWG_GROUPS:
                    raise LimitExceededError(
                        f"Cannot create more than {self.MAX_PWG_GROUPS} WireGuard TCP/TLS groups "
                        "(limited by router fwmark address space)."
                    )
            elif vpn_protocol == PROTO_WIREGUARD:
                count = len([p for p in existing_profiles if p["type"] == PROFILE_TYPE_VPN
                             and p.get("router_info", {}).get("vpn_protocol") == PROTO_WIREGUARD])
                if count >= self.MAX_WG_GROUPS:
                    raise LimitExceededError(
                        f"Cannot create more than {self.MAX_WG_GROUPS} WireGuard UDP groups. "
                        "Try WireGuard TCP/TLS or OpenVPN instead."
                    )
            elif vpn_protocol == PROTO_OPENVPN:
                count = len([p for p in existing_profiles if p.get("router_info", {}).get("vpn_protocol") == PROTO_OPENVPN])
                if count >= self.MAX_OVPN_GROUPS:
                    raise LimitExceededError(
                        f"Cannot create more than {self.MAX_OVPN_GROUPS} OpenVPN groups. "
                        "Try WireGuard instead, or delete an existing OpenVPN group."
                    )

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
            **extra_fields,
        )

        # Apply requested kill_switch state to the router (router is the source of truth).
        # upload_*_config writes killswitch='1' by default; only override if the caller asked for off.
        # proton-wg profiles always have kill switch on (blackhole route) -- skip UCI operations.
        if profile_type == PROFILE_TYPE_VPN and router_info and router_info.get("rule_name") and not is_proton_wg:
            if not kill_switch:
                try:
                    self.router.set_kill_switch(router_info["rule_name"], False)
                except Exception as e:
                    log.warning(f"Failed to apply initial kill_switch=False for {profile['name']}: {e}")
            # Reflect live router state in the response
            try:
                profile["kill_switch"] = self.router.get_kill_switch(router_info["rule_name"])
            except Exception:
                pass

        log.info(f"Created profile '{profile['name']}' (type={profile['type']}, id={profile['id']})")
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
                self.router.set_kill_switch(rule_name, bool(new_kill_switch))
                profile["kill_switch"] = self.router.get_kill_switch(rule_name)
            except Exception as e:
                log.error(f"Failed to set kill switch on {rule_name}: {e}")

        # Sync name to router if this is a VPN profile (router is the source of truth).
        # proton-wg profiles have no route_policy rule -- name is local-only.
        if "name" in data and rule_name and not is_pwg:
            try:
                self.router.rename_profile(
                    rule_name=rule_name,
                    new_name=data["name"],
                    peer_id=ri.get("peer_id", "") if proto != PROTO_OPENVPN else "",
                    client_uci_id=ri.get("client_uci_id", "") if proto == PROTO_OPENVPN else "",
                )
                profile["name"] = self.router.get_profile_name(rule_name) or data["name"]
            except Exception as e:
                log.warning(f"Failed to rename profile on router: {e}")

        # Always include live kill_switch in the response so the UI is in sync
        if rule_name and not is_pwg:
            try:
                profile["kill_switch"] = self.router.get_kill_switch(rule_name)
            except Exception:
                pass
        elif is_pwg:
            profile["kill_switch"] = True  # Always on

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
            self.sync_lan_to_router()
        except Exception as e:
            log.warning(f"LAN sync after delete failed: {e}")

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
                self.sync_lan_to_router()
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
                self.sync_lan_to_router()
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

        # Check limits
        existing = ps.get_profiles()
        if is_proton_wg:
            count = len([p for p in existing
                         if p["type"] == PROFILE_TYPE_VPN
                         and p.get("router_info", {}).get("vpn_protocol", "").startswith("wireguard-")
                         and p["id"] != profile_id])
            if count >= self.MAX_PWG_GROUPS:
                raise LimitExceededError(f"WireGuard TCP/TLS limit reached ({self.MAX_PWG_GROUPS})")
        elif vpn_protocol == PROTO_WIREGUARD:
            count = len([p for p in existing
                         if p["type"] == PROFILE_TYPE_VPN
                         and p.get("router_info", {}).get("vpn_protocol") == PROTO_WIREGUARD
                         and p["id"] != profile_id])
            if count >= self.MAX_WG_GROUPS:
                raise LimitExceededError(f"WireGuard UDP limit reached ({self.MAX_WG_GROUPS})")
        elif vpn_protocol == PROTO_OPENVPN:
            count = len([p for p in existing
                         if p.get("router_info", {}).get("vpn_protocol") == PROTO_OPENVPN
                         and p["id"] != profile_id])
            if count >= self.MAX_OVPN_GROUPS:
                raise LimitExceededError(f"OpenVPN limit reached ({self.MAX_OVPN_GROUPS})")

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
                    self.router.exec(f"ipset create {ipset_name} hash:mac -exist")
                    self.router.exec(f"ipset add {ipset_name} {mac} -exist")
                else:
                    self.router.set_device_vpn(mac, router_info["rule_name"])
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
                self.router.set_kill_switch(router_info["rule_name"], False)
            except Exception as e:
                log.warning(f"change_type: set kill_switch failed: {e}")

        log.info(f"Changed type for '{profile['name']}' from {old_type} to VPN ({vpn_protocol})")
        try:
            self.sync_lan_to_router()
        except Exception as e:
            log.warning(f"LAN sync after type change failed: {e}")
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
                raise ValueError("Protocol is already " + old_proto)

            # Check limits for the new protocol (don't count current profile)
            existing = ps.get_profiles()
            if is_new_proton_wg:
                count = len([p for p in existing
                             if p["type"] == PROFILE_TYPE_VPN
                             and p.get("router_info", {}).get("vpn_protocol", "").startswith("wireguard-")
                             and p["id"] != profile_id])
                if count >= self.MAX_PWG_GROUPS:
                    raise LimitExceededError(f"WireGuard TCP/TLS limit reached ({self.MAX_PWG_GROUPS})")
            elif new_vpn_protocol == PROTO_WIREGUARD:
                count = len([p for p in existing
                             if p["type"] == PROFILE_TYPE_VPN
                             and p.get("router_info", {}).get("vpn_protocol") == PROTO_WIREGUARD
                             and p["id"] != profile_id])
                if count >= self.MAX_WG_GROUPS:
                    raise LimitExceededError(f"WireGuard UDP limit reached ({self.MAX_WG_GROUPS})")
            elif new_vpn_protocol == PROTO_OPENVPN:
                count = len([p for p in existing
                             if p.get("router_info", {}).get("vpn_protocol") == PROTO_OPENVPN
                             and p["id"] != profile_id])
                if count >= self.MAX_OVPN_GROUPS:
                    raise LimitExceededError(f"OpenVPN limit reached ({self.MAX_OVPN_GROUPS})")

            # 1. Capture assigned devices before teardown
            assigned_macs = []
            if is_old_proton_wg:
                ipset_name = old_ri.get("ipset_name", f"src_mac_{old_ri.get('tunnel_id', 0)}")
                try:
                    members = self.router.exec(
                        f"ipset list {ipset_name} 2>/dev/null | awk 'p{{print}} /^Members:/{{p=1}}'"
                    ).strip()
                    assigned_macs = [m.strip().lower() for m in members.splitlines() if m.strip()]
                except Exception as e:
                    log.warning(f"change_protocol: failed to read ipset {ipset_name}: {e}")
            elif old_ri.get("rule_name"):
                try:
                    assigned_macs = [t.lower() for t in self.router.from_mac_tokens(old_ri["rule_name"])]
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
                        self.router.exec(f"ipset create {new_ipset} hash:mac -exist")
                        self.router.exec(f"ipset add {new_ipset} {mac} -exist")
                    else:
                        self.router.set_device_vpn(mac, new_ri["rule_name"])
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
                self.sync_lan_to_router()
            except Exception as e:
                log.warning(f"LAN sync after protocol change failed: {e}")

            return ps.get_profile(profile_id)

        finally:
            lock.release()

    # ── Tunnel Control ───────────────────────────────────────────────────────

    # ── Smart Protocol ──────────────────────────────────────────────────────
    #
    # Non-blocking protocol fallback. connect_profile() returns immediately;
    # tick_smart_protocol() is called every SSE tick (10s) to monitor pending
    # retries and switch protocols when a tunnel doesn't establish.

    SMART_PROTOCOL_CHAIN = [
        (PROTO_WIREGUARD, "udp"),
        (PROTO_OPENVPN, "udp"),
        (PROTO_OPENVPN, "tcp"),
        (PROTO_WIREGUARD_TCP, "tcp"),
        (PROTO_WIREGUARD_TLS, "tls"),
    ]

    SMART_CONNECT_TIMEOUT = 45  # seconds before trying next protocol

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

            # Register for smart protocol monitoring if enabled
            opts = profile.get("options") or {}
            if opts.get("smart_protocol") and profile_id not in self._smart_pending:
                self._smart_register(profile_id, proto)

            return {"success": True, "health": health}
        except Exception as e:
            log.error(f"Failed to connect profile '{profile['name']}': {e}", exc_info=True)
            raise

    def _smart_register(self, profile_id, current_proto):
        """Register a profile for smart protocol monitoring."""
        chain = [
            (p, t) for p, t in self.SMART_PROTOCOL_CHAIN
            if p != current_proto
        ]
        # Tor and Secure Core servers are WireGuard-only on Proton —
        # exclude OpenVPN from the fallback chain for these profiles
        profile = ps.get_profile(profile_id)
        if profile:
            features = (profile.get("server_scope") or {}).get("features") or {}
            if features.get("tor") or features.get("secure_core"):
                chain = [(p, t) for p, t in chain if p != PROTO_OPENVPN]
        with self._smart_lock:
            self._smart_pending[profile_id] = {
                "started_at": time.time(),
                "chain": chain,
                "attempt_idx": -1,  # -1 = still on original protocol
                "original_proto": current_proto,
            }

    def _smart_cancel(self, profile_id):
        """Cancel smart protocol monitoring for a profile."""
        with self._smart_lock:
            self._smart_pending.pop(profile_id, None)

    def _smart_has_slot(self, profile_id, proto):
        """Check if there's an available slot for a protocol."""
        existing = ps.get_profiles()
        if proto == PROTO_WIREGUARD:
            count = len([p for p in existing
                         if p["type"] == PROFILE_TYPE_VPN
                         and p.get("router_info", {}).get("vpn_protocol") == PROTO_WIREGUARD
                         and p["id"] != profile_id])
            return count < self.MAX_WG_GROUPS
        if proto in (PROTO_WIREGUARD_TCP, PROTO_WIREGUARD_TLS):
            count = len([p for p in existing
                         if p["type"] == PROFILE_TYPE_VPN
                         and (p.get("router_info", {}).get("vpn_protocol") or "").startswith("wireguard-")
                         and p["id"] != profile_id])
            return count < self.MAX_PWG_GROUPS
        if proto == PROTO_OPENVPN:
            count = len([p for p in existing
                         if p.get("router_info", {}).get("vpn_protocol") == PROTO_OPENVPN
                         and p["id"] != profile_id])
            return count < self.MAX_OVPN_GROUPS
        return False

    def tick_smart_protocol(self):
        """Called every SSE tick (~10s). Check pending smart protocol retries.

        For each pending profile:
        - If connected (green/amber): done, remove from pending.
        - If still connecting and timeout not reached: wait.
        - If timeout reached: disconnect, switch to next protocol, connect.
        - If all protocols exhausted: remove from pending, log warning.
        """
        with self._smart_lock:
            pending_ids = list(self._smart_pending)
        if not pending_ids:
            return

        for profile_id in pending_ids:
            state = self._smart_pending.get(profile_id)
            if state is None:
                continue  # Cancelled by disconnect_profile between snapshot and access
            profile = ps.get_profile(profile_id)
            if not profile or profile.get("type") != PROFILE_TYPE_VPN:
                self._smart_cancel(profile_id)
                continue

            ri = profile.get("router_info", {})
            if not ri.get("rule_name"):
                self._smart_cancel(profile_id)
                continue

            proto = ri.get("vpn_protocol", PROTO_WIREGUARD)
            try:
                strategy = get_strategy(proto)
                health = strategy.get_health(self.router, ri)
            except Exception:
                continue  # SSH error — retry next tick

            if health in ("green", "amber"):
                log.info(f"Smart Protocol: {profile_id} connected on {proto}")
                self._smart_cancel(profile_id)
                continue

            elapsed = time.time() - state["started_at"]
            if elapsed < self.SMART_CONNECT_TIMEOUT:
                continue  # Still waiting for current protocol

            # Timeout — try next protocol. Use per-profile switch lock to
            # prevent concurrent SSE tabs from double-switching.
            lock = self._switch_locks.setdefault(profile_id, threading.RLock())
            if not lock.acquire(blocking=False):
                continue  # Another thread (SSE tab or user action) is switching this profile

            try:
                # Re-check under lock: user may have disconnected/deleted
                with self._smart_lock:
                    if profile_id not in self._smart_pending:
                        continue

                state["attempt_idx"] += 1
                idx = state["attempt_idx"]

                # Skip protocols without available slots
                while idx < len(state["chain"]):
                    next_proto, _ = state["chain"][idx]
                    if self._smart_has_slot(profile_id, next_proto):
                        break
                    idx += 1
                    state["attempt_idx"] = idx

                if idx >= len(state["chain"]):
                    log.warning(f"Smart Protocol: all protocols exhausted for {profile_id}")
                    self._smart_cancel(profile_id)
                    continue

                next_proto, next_transport = state["chain"][idx]
                log.info(f"Smart Protocol: switching {profile_id} from {proto} to {next_proto}")

                # Clear port + custom_dns — ports differ per protocol, and
                # custom DNS only works with kernel WireGuard (UCI-managed)
                profile = ps.get_profile(profile_id)
                if not profile:
                    self._smart_cancel(profile_id)
                    continue
                opts = dict(profile.get("options") or {})
                opts.pop("port", None)
                if next_proto != PROTO_WIREGUARD:
                    opts.pop("custom_dns", None)
                ps.update_profile(profile_id, options=opts)

                # change_protocol handles disconnect + teardown + recreate.
                # We hold _switch_locks[profile_id] (RLock), so change_protocol's
                # acquire will succeed (reentrant).
                self.change_protocol(
                    profile_id, next_proto,
                    ovpn_protocol=next_transport if next_proto == PROTO_OPENVPN else "udp",
                )

                # Connect with new protocol
                profile = ps.get_profile(profile_id)
                if not profile:
                    self._smart_cancel(profile_id)
                    continue
                new_ri = profile.get("router_info", {})
                new_strategy = get_strategy(next_proto)
                new_strategy.connect(self.router, new_ri)

                # Reset timer for the new protocol attempt
                with self._smart_lock:
                    if profile_id in self._smart_pending:
                        self._smart_pending[profile_id]["started_at"] = time.time()
            except Exception as e:
                log.warning(f"Smart Protocol: failed for {profile_id}: {e}")
                with self._smart_lock:
                    if profile_id in self._smart_pending:
                        self._smart_pending[profile_id]["started_at"] = time.time()
            finally:
                lock.release()

    def get_smart_protocol_status(self):
        """Return smart protocol retry status for SSE streaming.

        Returns:
            Dict of {profile_id: {attempting, attempt, total, elapsed}}.
        """
        with self._smart_lock:
            snapshot = dict(self._smart_pending)
        result = {}
        for pid, state in snapshot.items():
            idx = state["attempt_idx"]
            chain = state["chain"]
            if idx < 0:
                attempting = state["original_proto"]
            elif idx < len(chain):
                attempting = chain[idx][0]
            else:
                attempting = None
            result[pid] = {
                "attempting": attempting,
                "attempt": max(idx + 2, 1),  # +1 for original, +1 for 0-index
                "total": len(chain) + 1,
                "elapsed": int(time.time() - state["started_at"]),
            }
        return result

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
                self.router.reorder_vpn_rules(vpn_rule_names)
            except Exception as e:
                log.warning(f"reorder_vpn_rules failed: {e}")

    # ── Guest Profile ────────────────────────────────────────────────────────

    def set_guest_profile(self, profile_id):
        """Set this profile as the guest profile.

        Raises:
            NotFoundError: If the profile is not found.
        """
        if not ps.set_guest_profile(profile_id):
            raise NotFoundError("Profile not found")

    # ── Device Assignment Resolution ─────────────────────────────────────────

    def _resolve_device_assignments(self, store_data: dict) -> dict:
        """Return {mac: profile_id} merging router VPN assignments + local non-VPN.

        VPN assignments come from router.from_mac (canonical). Matching is by
        stable (vpn_protocol, peer_id|client_id) key -- survives section
        renames by the GL.iNet UI.
        Non-VPN/NoInternet assignments come from local profile_store.
        """
        # (protocol, id) -> local profile_id  AND  router_section_name -> local profile_id
        key_to_pid = {}
        rule_section_to_pid = {}
        for p in store_data.get("profiles", []):
            if p.get("type") == PROFILE_TYPE_VPN:
                k = _local_router_key(p)
                if k[1]:
                    key_to_pid[k] = p["id"]
                rn = (p.get("router_info") or {}).get("rule_name")
                if rn:
                    rule_section_to_pid[rn] = p["id"]

        try:
            rules = self.router.get_flint_vpn_rules()
        except Exception:
            rules = []
        # router section name -> local profile_id, resolved via stable key
        section_to_pid = {}
        for rule in rules:
            section = rule.get("rule_name", "")
            if not section:
                continue
            key = _router_rule_key(rule)
            pid = key_to_pid.get(key) or rule_section_to_pid.get(section)
            if pid:
                section_to_pid[section] = pid

        try:
            vpn_assignments_raw = self.router.get_device_assignments()
        except Exception:
            vpn_assignments_raw = {}

        out = {}
        for mac, section in vpn_assignments_raw.items():
            pid = section_to_pid.get(section)
            if pid:
                out[mac] = pid
            # Else: orphan rule on router -- device shows as unassigned

        # proton-wg profiles: read ipset membership directly
        for p in store_data.get("profiles", []):
            ri = p.get("router_info") or {}
            if not ri.get("vpn_protocol", "").startswith("wireguard-"):
                continue
            ipset_name = ri.get("ipset_name", f"src_mac_{ri.get('tunnel_id', 0)}")
            try:
                members = self.router.exec(
                    f"ipset list {ipset_name} 2>/dev/null | awk 'p{{print}} /^Members:/{{p=1}}'"
                ).strip()
                for mac_line in members.splitlines():
                    mac_val = mac_line.strip().lower()
                    if mac_val:
                        out[mac_val] = p["id"]
            except Exception:
                pass

        # Non-VPN: local store
        for mac, pid in store_data.get("device_assignments", {}).items():
            if pid is None:
                continue
            for p in store_data.get("profiles", []):
                if p.get("id") == pid and p.get("type") != PROFILE_TYPE_VPN:
                    out[mac] = pid
                    break
        return out

    # ── Device List ──────────────────────────────────────────────────────────

    def build_devices_live(self) -> list:
        """Build the device list from live router data.

        Sources:
          - DHCP leases (router /tmp/dhcp.leases): mac, ip, hostname
          - GL.iNet client tracking (ubus call gl-clients list): online, speeds,
            signal, alias (= user-set label), device_class
          - Router from_mac lists: VPN profile assignment (via _resolve_device_assignments)
          - Local store: non-VPN profile assignment + LAN access overrides

        Hostname / IP / online / class / label / speeds are NEVER cached on disk.
        Display name precedence: gl-client.alias > DHCP hostname > MAC.
        """
        router = self.router
        try:
            leases = router.get_dhcp_leases()
        except Exception:
            leases = []
        try:
            client_details = router.get_client_details()
        except Exception:
            client_details = {}

        store_data = ps.load()
        assignment_map = self._resolve_device_assignments(store_data)

        devices = {}
        for lease in leases:
            mac = lease["mac"].lower()
            d = _default_device(mac, assignment_map.get(mac))
            d["ip"] = lease.get("ip", "")
            d["hostname"] = lease.get("hostname", "")
            devices[mac] = d

        for mac, details in client_details.items():
            mac = mac.lower()
            d = devices.setdefault(mac, _default_device(mac, assignment_map.get(mac)))
            d["router_online"] = bool(details.get("online", False))
            d["device_class"] = details.get("device_class", "")
            d["label"] = details.get("alias", "")  # router-canonical custom label
            d["rx_speed"] = details.get("rx_speed", 0)
            d["tx_speed"] = details.get("tx_speed", 0)
            d["total_rx"] = details.get("total_rx", 0)
            d["total_tx"] = details.get("total_tx", 0)
            d["signal_dbm"] = details.get("signal_dbm")
            d["link_speed_mbps"] = details.get("link_speed_mbps")
            d["iface"] = details.get("iface", "")
            if details.get("ip") and not d.get("ip"):
                d["ip"] = details["ip"]
            # gl-clients exposes a 'name' field (mDNS/Bonjour discovered hostname)
            # for devices not currently in DHCP leases. Use it as a hostname fallback
            # so offline / recently-departed devices still display their name.
            if not d.get("hostname") and details.get("name"):
                d["hostname"] = details["name"]

        # Router-only MACs (e.g. assigned via SSH but never seen via DHCP)
        for mac, pid in assignment_map.items():
            if mac not in devices:
                devices[mac] = _default_device(mac, pid)

        # Display name precedence and effective LAN access
        out = []
        for mac, d in sorted(devices.items()):
            d["display_name"] = d.get("label") or d.get("hostname") or mac
            eff = ps.get_effective_lan_access(mac, store_data)
            d["lan_outbound"] = eff["outbound"]
            d["lan_inbound"] = eff["inbound"]
            d["lan_inherited"] = eff["inherited"]
            d["lan_outbound_allow"] = eff.get("outbound_allow", [])
            d["lan_inbound_allow"] = eff.get("inbound_allow", [])
            d["last_seen"] = None  # legacy field, no longer tracked
            out.append(d)
        return out

    def get_devices_cached(self) -> list:
        """5-second TTL wrapper around build_devices_live to throttle SSH calls."""
        now = time.time()
        if self._device_cache["data"] is not None and (now - self._device_cache["ts"]) < self._DEVICE_CACHE_TTL:
            return self._device_cache["data"]
        self._device_cache["data"] = self.build_devices_live()
        self._device_cache["ts"] = now
        return self._device_cache["data"]

    def invalidate_device_cache(self):
        """Invalidate the in-memory device cache."""
        self._device_cache["data"] = None
        self._device_cache["ts"] = 0.0

    # ── Device Assignment ────────────────────────────────────────────────────

    def assign_device(self, mac, profile_id):
        """Assign a device to a profile.

        VPN assignments are written ONLY to the router (source of truth).
        Non-VPN/NoInternet assignments are written to local profile_store.

        Raises:
            ValueError: If the MAC address is invalid.
            NotFoundError: If the target profile is not found.
        """
        mac = ps.validate_mac(mac)

        store_data = ps.load()

        # Always clear any router VPN rule containing this MAC (idempotent).
        # NoInternet membership is handled by the LAN sync at the end (single
        # ipset, derived from local assignments).
        try:
            self.router.remove_device_from_all_vpn(mac)
        except Exception as e:
            log.warning(f"remove_device_from_all_vpn({mac}) failed: {e}")

        # Apply new assignment
        if profile_id:
            new_profile = ps.get_profile(profile_id)
            if not new_profile:
                raise NotFoundError("Profile not found")

            if new_profile["type"] == PROFILE_TYPE_VPN and new_profile.get("router_info"):
                ri = new_profile["router_info"]
                proto = ri.get("vpn_protocol", PROTO_WIREGUARD)
                # Router is the source for VPN assignments. Drop any local
                # entry so we don't double-track (and so a future unassign
                # can write a fresh sticky-None marker).
                if mac in store_data.get("device_assignments", {}):
                    del store_data["device_assignments"][mac]
                    ps.save(store_data)
                if proto.startswith("wireguard-"):
                    # proton-wg: add MAC to ipset directly (no route_policy rule)
                    ipset_name = ri.get("ipset_name", f"src_mac_{ri.get('tunnel_id', 0)}")
                    self.router.exec(f"ipset create {ipset_name} hash:mac -exist")
                    self.router.exec(f"ipset add {ipset_name} {mac} -exist")
                else:
                    # Kernel WG / OpenVPN: use route_policy rule
                    self.router.set_device_vpn(mac, ri["rule_name"])
            else:
                # no_vpn / no_internet -- local store; LAN sync below applies the
                # router-side execution (NoInternet ipset membership).
                ps.assign_device(mac, profile_id)
        else:
            # Explicit unassign. Write a sticky-None marker so the device tracker
            # won't auto-reassign this MAC to the guest group on the next unlock
            # or restart (the in-memory _known_macs set is wiped on every fresh
            # tracker instance, so the local store is the only durable signal).
            ps.assign_device(mac, None)

        target = ps.get_profile(profile_id)["name"] if profile_id and ps.get_profile(profile_id) else "Unassigned"
        log.info(f"Device {mac} assigned to '{target}'")

        # Single sync handles both LAN access (per-group ipsets) and NoInternet
        # (the global fvpn_noint_ips ipset).
        try:
            self.sync_lan_to_router()
        except Exception as e:
            log.warning(f"LAN sync after assignment failed: {e}")

        # Invalidate the device cache so the next /api/devices call sees the new assignment
        self.invalidate_device_cache()

    # ── Device Label ─────────────────────────────────────────────────────────

    def set_device_label(self, mac, label, device_class=""):
        """Set a custom label and/or device class for a device.

        gl-client.alias and gl-client.class are router-canonical.
        No local cache write -- build_devices_live reads them from the router live.
        """
        mac_upper = mac.upper()
        existing = self.router.exec(
            f"uci show gl-client 2>/dev/null | grep -B1 \"mac='{mac_upper}'\" | "
            "grep '=client' | head -1 | cut -d. -f2 | cut -d= -f1"
        ).strip()
        if existing:
            section = existing
        else:
            self.router.exec(f"uci add gl-client client")
            section = self.router.exec(
                "uci show gl-client 2>/dev/null | grep '=client' | tail -1 | "
                "cut -d. -f2 | cut -d= -f1"
            ).strip()
            self.router.exec(f"uci set gl-client.{section}.mac='{mac_upper}'")

        cmds = [f"uci set gl-client.{section}.alias='{label}'"]
        if device_class:
            cmds.append(f"uci set gl-client.{section}.class='{device_class}'")
        cmds.append("uci commit gl-client")
        self.router.exec(" && ".join(cmds))

        # Invalidate cache so next device query picks up the change
        self.invalidate_device_cache()

    # ── LAN Access Control ───────────────────────────────────────────────────

    def set_profile_lan_access(self, profile_id, outbound, inbound,
                               outbound_allow=None, inbound_allow=None):
        """Set LAN access rules for a profile.

        Raises:
            NotFoundError: If the profile is not found.
            ValueError: If the LAN access values are invalid.
        """
        result = ps.set_profile_lan_access(
            profile_id, outbound, inbound,
            outbound_allow=outbound_allow or [],
            inbound_allow=inbound_allow or [],
        )

        if not result:
            raise NotFoundError("Profile not found")

        try:
            self.sync_lan_to_router()
        except Exception as e:
            log.warning(f"LAN sync failed: {e}")

        log.info(f"LAN access for profile '{result['name']}': out={outbound}, in={inbound}")
        return result

    def set_device_lan_override(self, mac, outbound=None, inbound=None,
                                outbound_allow=None, inbound_allow=None):
        """Set per-device LAN access override.

        null values mean inherit from group.

        Raises:
            ValueError: If the LAN access values are invalid.
        """
        ps.set_device_lan_override(
            mac, outbound, inbound,
            outbound_allow=outbound_allow or [],
            inbound_allow=inbound_allow or [],
        )

        try:
            self.sync_lan_to_router()
        except Exception as e:
            log.warning(f"LAN sync failed: {e}")

        log.info(f"LAN override for {mac}: out={outbound}, in={inbound}")

    # ── LAN Sync ─────────────────────────────────────────────────────────────

    def sync_lan_to_router(self):
        """Reconcile router LAN execution state with local intent.

        Delegates to ``lan_sync.sync_lan_to_router`` which:
          - Reads live DHCP leases for device IPs
          - Reads router VPN device assignments from from_mac
          - Computes desired UCI ipset/rule sections from local intent
          - Diffs against current router state
          - Applies via uci batch (+ firewall reload if structural changes)

        Best-effort: any exception is logged but doesn't propagate.
        """
        try:
            result = lan_sync.sync_lan_to_router(self.router, store=ps.load())
            if result.get("applied"):
                log.info(
                    f"LAN sync applied: uci_lines={result.get('uci_lines', 0)}, "
                    f"membership_ops={result.get('membership_ops', 0)}, "
                    f"reload={result.get('reload', False)}"
                )
        except Exception as e:
            log.warning(f"LAN sync failed: {e}")
