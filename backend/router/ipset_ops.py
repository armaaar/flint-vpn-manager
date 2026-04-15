"""Ipset Ops — Centralized MAC-based ipset operations for proton-wg.

All proton-wg ipset mutations (create, add, list, reconcile) go through
this module so the logic lives in one place instead of being scattered
across vpn_service.py, change_type, change_protocol, and assign_device.

Delegates to ``router.ipset_tool`` (tool layer) for ipset commands and
``router.proton_wg`` for mangle rule rebuilds.
"""

import logging

import persistence.profile_store as ps

log = logging.getLogger("flintvpn")


class IpsetOps:
    """Centralized ipset operations for proton-wg MAC-based sets."""

    def __init__(self, router):
        self._router = router

    def ensure_mac_set(self, ipset_name):
        """Create a hash:mac ipset if it doesn't already exist."""
        self._router.ipset_tool.create(ipset_name, "hash:mac")

    def add_mac(self, ipset_name, mac):
        """Add a MAC address to an ipset (idempotent)."""
        self._router.ipset_tool.add(ipset_name, mac)

    def list_members(self, ipset_name):
        """Return the list of MAC members in an ipset."""
        try:
            return self._router.ipset_tool.members(ipset_name)
        except Exception:
            return []

    def ensure_and_add(self, ipset_name, mac):
        """Create ipset if needed, then add MAC. Common two-step pattern."""
        self.ensure_mac_set(ipset_name)
        self.add_mac(ipset_name, mac)

    def reconcile_proton_wg_members(self, store_data=None):
        """Sync persistent .macs files on router and repopulate ipsets.

        Called after vpn-client restart (which flushes src_mac_* ipsets).
        Writes .macs files from local store (the durable source), then runs
        the mangle script which creates ipsets and populates from those files.
        """
        if store_data is None:
            store_data = ps.load()
        self._sync_macs_to_router(store_data)
        self._run_mangle_script()

    def reconcile_proton_wg_full(self, store_data=None):
        """Full reconciliation: sync .macs files, rebuild mangle rules + ipsets.

        Called on app unlock. Writes .macs files from local store, then
        rebuilds the entire mangle rules script (which includes ipset
        creation and population from those files).
        """
        if store_data is None:
            store_data = ps.load()
        self._sync_macs_to_router(store_data)
        self._router.proton_wg._rebuild_proton_wg_mangle_rules()

    def _sync_macs_to_router(self, store_data):
        """Write .macs files on the router from local store assignments.

        For each proton-wg profile, collect assigned MACs from the local
        device_assignments and write them to the corresponding .macs file.
        This ensures the router has a persistent copy even if the app dies.
        """
        for p in store_data.get("profiles", []):
            ri = p.get("router_info") or {}
            if not ri.get("vpn_protocol", "").startswith("wireguard-"):
                continue
            iface = ri.get("tunnel_name", "")
            if not iface:
                continue
            macs = [
                mac for mac, pid in store_data.get("device_assignments", {}).items()
                if pid == p["id"]
            ]
            try:
                self._router.proton_wg.write_tunnel_macs(iface, macs)
            except Exception as e:
                log.warning(f"Failed to sync .macs for {iface}: {e}")

    def _run_mangle_script(self):
        """Run the proton-wg mangle script on the router.

        The script creates ipsets, populates them from .macs files, and
        applies mangle rules. This is the single recovery action for any
        ipset flush event.
        """
        from router.facades.proton_wg import PROTON_WG_DIR
        try:
            self._router.exec(
                f"[ -x {PROTON_WG_DIR}/mangle_rules.sh ] && "
                f"sh {PROTON_WG_DIR}/mangle_rules.sh || true"
            )
        except Exception as e:
            log.warning(f"Failed to run mangle script: {e}")
