"""Profile Healer — Startup self-healing for proton-wg tunnel ID collisions.

Extracted from VPNService. Runs during build_profile_list to detect and
fix tunnel_id duplicates that arise when two proton-wg profiles are created
between reboots (ipsets are ephemeral, so _next_tunnel_id() can't detect
the collision until the next app start).
"""

import logging

import profile_store as ps

log = logging.getLogger("flintvpn")


class ProfileHealer:
    """Self-healing for proton-wg tunnel ID collisions."""

    def __init__(self, ipset_ops):
        self._ipset = ipset_ops

    def heal_duplicate_tunnel_ids(self, store_data: dict, router) -> None:
        """Fix proton-wg profiles that share a tunnel_id due to reboot-time races.

        _next_tunnel_id() checks live ipsets on the router, but ipsets vanish on
        reboot.  If two profiles were created between reboots, the second may have
        received the same tunnel_id, causing device assignments to bleed between
        groups.  This method detects collisions and allocates fresh IDs.
        """
        seen = set()
        for p in store_data.get("profiles", []):
            ri = p.get("router_info") or {}
            tid = ri.get("tunnel_id")
            if tid is not None and not ri.get("vpn_protocol", "").startswith("wireguard-"):
                seen.add(tid)

        for p in store_data.get("profiles", []):
            ri = p.get("router_info") or {}
            if not ri.get("vpn_protocol", "").startswith("wireguard-"):
                continue
            tid = ri.get("tunnel_id")
            if tid is None:
                continue
            if tid not in seen:
                seen.add(tid)
                continue
            self._reassign_tunnel_id(store_data, p, ri, tid, router)
            seen.add(ri["tunnel_id"])

    def _reassign_tunnel_id(self, store_data, profile, ri, old_tid, router):
        """Allocate a fresh tunnel_id for a proton-wg profile and update router state."""
        try:
            new_tid = router._next_tunnel_id()
        except RuntimeError:
            log.error("No free tunnel_id to heal duplicate %d", old_tid)
            return

        iface = ri.get("tunnel_name", "")
        old_ipset = ri.get("ipset_name", f"src_mac_{old_tid}")
        new_ipset = f"src_mac_{new_tid}"
        log.warning(
            "Healing duplicate tunnel_id %d for profile %s (%s) -> %d",
            old_tid, profile.get("id", "?")[:8], iface, new_tid,
        )

        # Create new ipset and migrate any existing MACs
        self._ipset.ensure_mac_set(new_ipset)
        try:
            members = self._ipset.list_members(old_ipset)
            for mac_val in members:
                self._ipset.add_mac(new_ipset, mac_val)
        except Exception:
            pass

        # Update .env file on router
        if iface:
            env_path = f"{router.PROTON_WG_DIR}/{iface}.env"
            router.exec(
                f"sed -i 's/^FVPN_TUNNEL_ID=.*/FVPN_TUNNEL_ID={new_tid}/' {env_path}; "
                f"sed -i 's/^FVPN_IPSET=.*/FVPN_IPSET={new_ipset}/' {env_path}"
            )

        ri["tunnel_id"] = new_tid
        ri["ipset_name"] = new_ipset
        ps.save(store_data)
