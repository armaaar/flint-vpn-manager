"""VPN Service — Top-level orchestrator facade.

Composes ProfileService, DeviceService, IpsetOps, SmartProtocolManager,
and profile_list_builder into a unified interface. Owns tunnel control
(connect/disconnect), cross-cutting sync operations, and device delegation.

All callers (Flask routes, CLI, background threads) use VPNService as the
single entry point. No Flask dependency.
"""

import logging
import threading

import persistence.profile_store as ps
import persistence.secrets_manager as sm
import router.noint_sync as noint_sync
from consts import (
    HEALTH_RED,
    PROFILE_TYPE_NO_INTERNET,
    PROFILE_TYPE_NO_VPN,
    PROFILE_TYPE_VPN,
    PROTO_WIREGUARD,
    PROTO_WIREGUARD_TCP,
    PROTO_WIREGUARD_TLS,
)
from vpn.tunnel_strategy import get_strategy
from vpn.protocol_limits import MAX_WG_GROUPS, MAX_OVPN_GROUPS, MAX_PWG_GROUPS
from router.ipset_ops import IpsetOps
from vpn.smart_protocol import SmartProtocolManager
from services.device_service import DeviceService
from vpn.profile_keys import local_router_key, router_rule_key
from vpn.profile_healer import ProfileHealer
from services.profile_service import (
    ProfileService, require_vpn_profile,
    NotFoundError, ConflictError, LimitExceededError, NotLoggedInError,
)
import services.profile_list_builder as profile_list_builder

log = logging.getLogger("flintvpn")

# ── Re-exports (backward compatibility) ─────────────────────────────────────

from services.backup_service import (  # noqa: E402, F401
    backup_local_state_to_router,
    check_and_auto_restore,
    ROUTER_BACKUP_PATH,
)

# Backward-compatible aliases for imports from other modules / tests.
_local_router_key = local_router_key
_router_rule_key = router_rule_key


# ── VPNService class ────────────────────────────────────────────────────────


class VPNService:
    """Top-level orchestrator. Composes focused services.

    All methods raise exceptions on error (NotFoundError, ConflictError,
    LimitExceededError, NotLoggedInError, ValueError, RuntimeError) instead
    of returning HTTP responses.
    """

    # Kept as class attrs for backward compatibility (tests reference VPNService.MAX_WG_GROUPS).
    MAX_WG_GROUPS = MAX_WG_GROUPS
    MAX_OVPN_GROUPS = MAX_OVPN_GROUPS
    MAX_PWG_GROUPS = MAX_PWG_GROUPS

    def __init__(self, router, proton, strategies: dict = None):
        self.router = router
        self.proton = proton
        self.strategies = strategies or {}
        self._ipset = IpsetOps(router)
        self._devices = DeviceService(router, self._ipset)
        self._healer = ProfileHealer(self._ipset)
        self._switch_locks = {}
        self._smart = SmartProtocolManager(
            change_protocol_fn=self.change_protocol,
            get_switch_lock_fn=lambda pid: self._switch_locks.setdefault(pid, threading.RLock()),
        )
        self._profiles = ProfileService(
            router, proton, self._ipset, self._switch_locks,
            cancel_smart_fn=self._smart_cancel,
            sync_noint_fn=self.sync_noint_to_router,
            sync_adblock_fn=self.sync_adblock_to_router,
            reconcile_ipset_fn=self._reconcile_proton_wg_ipset_members,
        )

    # ── Profile List (delegates to profile_list_builder) ────────────────────

    def build_profile_list(self, store_data: dict = None) -> list:
        return profile_list_builder.build_profile_list(
            self.router, self.proton, self._healer, store_data,
        )

    # ── Profile CRUD + Mutations (delegates to ProfileService) ──────────────

    def create_profile(self, *args, **kwargs):
        return self._profiles.create_profile(*args, **kwargs)

    def update_profile(self, *args, **kwargs):
        return self._profiles.update_profile(*args, **kwargs)

    def delete_profile(self, *args, **kwargs):
        return self._profiles.delete_profile(*args, **kwargs)

    def change_type(self, *args, **kwargs):
        return self._profiles.change_type(*args, **kwargs)

    def switch_server(self, *args, **kwargs):
        return self._profiles.switch_server(*args, **kwargs)

    def change_protocol(self, *args, **kwargs):
        return self._profiles.change_protocol(*args, **kwargs)

    def reorder_profiles(self, *args, **kwargs):
        return self._profiles.reorder_profiles(*args, **kwargs)

    def set_guest_profile(self, *args, **kwargs):
        return self._profiles.set_guest_profile(*args, **kwargs)

    # ── Tunnel Control ──────────────────────────────────────────────────────

    def connect_profile(self, profile_id):
        """Bring a VPN profile's tunnel up. Returns immediately.

        If the profile has ``smart_protocol`` enabled in its options, registers
        it for background monitoring. The SSE tick calls
        ``tick_smart_protocol()`` every 10s to check health and switch
        protocols if the tunnel doesn't establish.
        """
        profile = require_vpn_profile(profile_id)

        ri = profile.get("router_info", {})
        if not ri.get("rule_name"):
            raise ValueError("No tunnel configured. Try changing the server to recreate it.")

        proto = ri.get("vpn_protocol", PROTO_WIREGUARD)

        try:
            log.info(f"Connecting profile '{profile['name']}' (rule={ri['rule_name']}, protocol={proto})")
            strategy = get_strategy(proto)
            health = strategy.connect(self.router, ri)
            log.info(f"Profile '{profile['name']}' connect issued (health={health})")

            # vpn-client restart (kernel WG / OVPN) flushes src_mac_* ipsets.
            # proton-wg now uses pwg_mac_* prefix (immune), but run the
            # mangle script for robustness in case of any ipset drift.
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

    def disconnect_profile(self, profile_id):
        """Bring a VPN profile's tunnel down.

        Also cancels any pending smart protocol retry for this profile.
        """
        self._smart_cancel(profile_id)

        profile = require_vpn_profile(profile_id)

        ri = profile.get("router_info", {})
        if not ri.get("rule_name"):
            raise ValueError("No tunnel configured")

        proto = ri.get("vpn_protocol", PROTO_WIREGUARD)

        try:
            log.info(f"Disconnecting profile '{profile['name']}' (rule={ri['rule_name']})")
            strategy = get_strategy(proto)
            strategy.disconnect(self.router, ri)
            log.info(f"Profile '{profile['name']}' disconnected")

            # vpn-client restart (kernel WG / OVPN) flushes src_mac_* ipsets.
            # proton-wg uses pwg_mac_* (immune), but reconcile for robustness.
            if not proto.startswith("wireguard-"):
                self._reconcile_proton_wg_ipset_members()

            return {"success": True, "health": HEALTH_RED}
        except Exception as e:
            log.error(f"Failed to disconnect profile '{profile['name']}': {e}", exc_info=True)
            raise

    # ── Smart Protocol ──────────────────────────────────────────────────────

    def _smart_cancel(self, profile_id):
        """Cancel smart protocol monitoring for a profile."""
        self._smart.cancel(profile_id)

    def tick_smart_protocol(self):
        """Called every SSE tick (~10s). Delegates to SmartProtocolManager."""
        self._smart.tick(self.router)

    def get_smart_protocol_status(self):
        """Return smart protocol retry status for SSE streaming."""
        return self._smart.get_status()

    # ── DNS Ad Block Sync ───────────────────────────────────────────────────

    def sync_adblock_to_router(self):
        """Sync DNS ad-block by injecting blocklists into per-tunnel dnsmasq instances."""
        try:
            store_data = ps.load()
            profiles = store_data.get("profiles", [])

            # Prefetch all route_policy rules in one SSH call
            rp_rules = self.router.uci.show("route_policy")

            adblock_ifaces = set()
            for p in profiles:
                if not p.get("adblock"):
                    continue
                ptype = p.get("type")
                if ptype == PROFILE_TYPE_NO_INTERNET:
                    continue
                if ptype == PROFILE_TYPE_VPN:
                    ri = p.get("router_info", {})
                    vpn_proto = ri.get("vpn_protocol", "")
                    if vpn_proto in (PROTO_WIREGUARD_TCP, PROTO_WIREGUARD_TLS):
                        # proton-wg tunnels have their own per-tunnel dnsmasq
                        tunnel_name = ri.get("tunnel_name")
                        if tunnel_name:
                            adblock_ifaces.add(tunnel_name)
                    else:
                        rule_name = ri.get("rule_name")
                        if rule_name:
                            via = rp_rules.get(rule_name, {}).get("via", "")
                            if via and via != "novpn":
                                adblock_ifaces.add(via)
                elif ptype == PROFILE_TYPE_NO_VPN:
                    adblock_ifaces.add("main")

            # If profiles want adblock but the blocklist is missing on the
            # router (e.g. after a router replacement), re-download it from
            # the configured sources before syncing.
            if adblock_ifaces and not self.router.adblock._blocklist_has_content():
                self._redownload_blocklist()

            self.router.adblock.sync_adblock(adblock_ifaces)
        except Exception as e:
            log.warning(f"Adblock sync failed: {e}")

    def _redownload_blocklist(self):
        """Re-download and upload the blocklist from configured sources."""
        from services.adblock_service import download_and_merge_blocklists
        try:
            content, count, failed = download_and_merge_blocklists()
            if content:
                import hashlib
                self.router.adblock.upload_blocklist(content)
                # Persist hash so auto-optimizer can skip redundant uploads
                adblock = sm.get_config().get("adblock", {})
                adblock["blocklist_hash"] = hashlib.sha256(content.encode()).hexdigest()
                adblock["domain_count"] = count
                sm.update_config(adblock=adblock)
                log.info(f"Adblock: re-downloaded blocklist ({count} domains)")
            if failed:
                log.warning(f"Adblock: some sources failed: {failed}")
        except Exception as e:
            log.warning(f"Adblock: blocklist re-download failed: {e}")

    # ── Device operations (delegate to DeviceService) ───────────────────────

    def _resolve_device_assignments(self, store_data: dict) -> dict:
        return self._devices.resolve_assignments(store_data)

    def build_devices_live(self) -> list:
        return self._devices.build_devices_live()

    def get_devices_cached(self) -> list:
        return self._devices.get_devices_cached()

    def invalidate_device_cache(self):
        self._devices.invalidate_cache()

    def assign_device(self, mac, profile_id):
        self._devices.assign_device(
            mac, profile_id,
            sync_noint_fn=self.sync_noint_to_router,
            sync_adblock_fn=self.sync_adblock_to_router,
        )

    def set_device_label(self, mac, label, device_class=""):
        self._devices.set_device_label(mac, label, device_class)

    # ── proton-wg ipset reconciliation ──────────────────────────────────────

    def _reconcile_proton_wg_ipset_members(self):
        """Re-add proton-wg device MACs to their ipsets from local store."""
        self._ipset.reconcile_proton_wg_members()

    def reconcile_proton_wg_ipsets(self):
        """Ensure proton-wg ipsets exist, populate, and rebuild mangle rules."""
        self._ipset.reconcile_proton_wg_full()

    # ── NoInternet Sync ─────────────────────────────────────────────────────

    def sync_noint_to_router(self):
        """Reconcile the NoInternet ipset on the router with local intent."""
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
