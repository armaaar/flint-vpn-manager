"""Ipset Ops — Centralized MAC-based ipset operations for proton-wg.

All proton-wg ipset mutations (create, add, list, reconcile) go through
this module so the logic lives in one place instead of being scattered
across vpn_service.py, change_type, change_protocol, and assign_device.

noint_sync.py and router_adblock.py manage their own ipsets (hash:ip and
separate hash:mac respectively) and are already self-contained.
"""

import logging

import profile_store as ps

log = logging.getLogger("flintvpn")


class IpsetOps:
    """Centralized ipset operations for proton-wg MAC-based sets."""

    def __init__(self, router):
        self._router = router

    def ensure_mac_set(self, ipset_name):
        """Create a hash:mac ipset if it doesn't already exist."""
        self._router.exec(f"ipset create {ipset_name} hash:mac -exist")

    def add_mac(self, ipset_name, mac):
        """Add a MAC address to an ipset (idempotent)."""
        self._router.exec(f"ipset add {ipset_name} {mac} -exist")

    def list_members(self, ipset_name):
        """Return the list of MAC members in an ipset.

        Returns an empty list if the ipset doesn't exist.
        """
        try:
            raw = self._router.exec(
                f"ipset list {ipset_name} 2>/dev/null | "
                f"awk 'p{{print}} /^Members:/{{p=1}}'"
            ).strip()
            return [m.strip() for m in raw.splitlines() if m.strip()]
        except Exception:
            return []

    def ensure_and_add(self, ipset_name, mac):
        """Create ipset if needed, then add MAC. Common two-step pattern."""
        self.ensure_mac_set(ipset_name)
        self.add_mac(ipset_name, mac)

    def reconcile_proton_wg_members(self, store_data=None):
        """Re-add proton-wg device MACs to their ipsets from local store.

        Called after vpn-client restart, which flushes ALL src_mac_* ipsets
        (including proton-wg ones managed by FlintVPN, not vpn-client).
        Lightweight: only does ipset add, no mangle rebuild.
        """
        if store_data is None:
            store_data = ps.load()
        for p in store_data.get("profiles", []):
            ri = p.get("router_info") or {}
            if not ri.get("vpn_protocol", "").startswith("wireguard-"):
                continue
            tunnel_id = ri.get("tunnel_id", 0)
            ipset_name = ri.get("ipset_name", f"src_mac_{tunnel_id}")
            for mac, pid in store_data.get("device_assignments", {}).items():
                if pid == p["id"]:
                    self.add_mac(ipset_name, mac)

    def reconcile_proton_wg_full(self, store_data=None):
        """Ensure proton-wg ipsets exist, populate members, and rebuild mangle rules.

        Ipsets are ephemeral — they vanish on firewall reload or app restart.
        This recreates them from device assignments in the local store and
        rebuilds the mangle rules script. Called on app unlock.
        """
        if store_data is None:
            store_data = ps.load()
        for p in store_data.get("profiles", []):
            ri = p.get("router_info") or {}
            if not ri.get("vpn_protocol", "").startswith("wireguard-"):
                continue
            tunnel_id = ri.get("tunnel_id", 0)
            ipset_name = ri.get("ipset_name", f"src_mac_{tunnel_id}")
            self.ensure_mac_set(ipset_name)
            for mac, pid in store_data.get("device_assignments", {}).items():
                if pid == p["id"]:
                    self.add_mac(ipset_name, mac)
        self._router._rebuild_proton_wg_mangle_rules()
