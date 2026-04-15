"""NoInternet group enforcement — blocks WAN access for assigned devices.

Manages a single global ``fvpn_noint_macs`` hash:mac ipset + one fw3 REJECT
rule that drops all traffic from NoInternet devices to the WAN zone.

Uses hash:mac instead of hash:ip so the rule applies to both IPv4 and IPv6
traffic without needing to track volatile SLAAC addresses.

Execution model:
  1. Collect MACs of devices assigned to NoInternet profiles.
  2. Diff against the live kernel ipset membership.
  3. Apply adds/removes via ``ipset add/del`` (immediate, no reload).
  4. If the UCI ipset+rule sections don't exist yet, create them and reload.
"""

from typing import Optional

import persistence.profile_store as profile_store
from consts import PROFILE_TYPE_NO_INTERNET


NOINT_IPSET = "fvpn_noint_macs"
NOINT_RULE = "fvpn_noint_block"
# Legacy ipset name — detected and migrated on first sync
_LEGACY_IPSET = "fvpn_noint_ips"


def sync_noint_to_router(
    router,
    store: Optional[dict] = None,
) -> dict:
    """Reconcile the NoInternet ipset on the router with local intent.

    Args:
        router: RouterAPI instance
        store: profile_store dict (loaded if None)

    Returns:
        {"applied": bool, "reload": bool, "adds": int, "removes": int}
    """
    if store is None:
        store = profile_store.load()

    # Migrate from legacy hash:ip ipset if present
    _migrate_legacy_ipset(router)

    profiles = {p["id"]: p for p in store.get("profiles", [])}
    noint_pids = {
        pid for pid, p in profiles.items()
        if p.get("type") == PROFILE_TYPE_NO_INTERNET
    }

    assignments = store.get("device_assignments", {})

    desired_macs = set()
    for mac, pid in assignments.items():
        if pid in noint_pids:
            desired_macs.add(mac.upper())

    # Read live kernel ipset membership
    try:
        live_macs = {m.upper() for m in router.ipset_tool.members(NOINT_IPSET)}
    except Exception:
        live_macs = set()

    add = sorted(desired_macs - live_macs)
    remove = sorted(live_macs - desired_macs)
    applied = False
    needs_reload = False

    # Ensure the UCI ipset + rule sections exist
    try:
        check = router.uci.get(f"firewall.{NOINT_RULE}", "MISSING").strip()
    except Exception:
        check = "MISSING"

    if check == "MISSING" and (noint_pids or desired_macs):
        uci = _build_uci_sections(desired_macs)
        router.firewall.fvpn_uci_apply(uci, reload=True)
        needs_reload = True
        applied = True
        add = []
        remove = []
    elif not noint_pids and check != "MISSING":
        # No NoInternet groups left — remove the sections.
        uci = (
            f"delete firewall.{NOINT_IPSET}\n"
            f"delete firewall.{NOINT_RULE}\n"
        )
        router.firewall.fvpn_uci_apply(uci, reload=True)
        router.ipset_tool.destroy(NOINT_IPSET)
        return {"applied": True, "reload": True, "adds": 0, "removes": len(live_macs)}

    # Apply membership diff (immediate kernel effect, no reload).
    if add or remove:
        try:
            router.ipset_tool.membership_batch(NOINT_IPSET, add=add, remove=remove)
            applied = True
        except Exception:
            pass
        # Dual-write to UCI for persistence across reboots.
        uci_lines = []
        for mac in remove:
            uci_lines.append(f"del_list firewall.{NOINT_IPSET}.entry='{mac}'")
        for mac in add:
            uci_lines.append(f"add_list firewall.{NOINT_IPSET}.entry='{mac}'")
        if uci_lines:
            try:
                router.firewall.fvpn_uci_apply("\n".join(uci_lines) + "\n", reload=False)
            except Exception:
                pass

    return {
        "applied": applied,
        "reload": needs_reload,
        "adds": len(add),
        "removes": len(remove),
    }


def _migrate_legacy_ipset(router) -> None:
    """Delete the legacy hash:ip ipset and UCI sections if present."""
    try:
        check = router.uci.get(f"firewall.{_LEGACY_IPSET}", "MISSING").strip()
    except Exception:
        return
    if check == "MISSING":
        return
    try:
        router.uci.delete(f"firewall.{_LEGACY_IPSET}")
        router.uci.commit("firewall")
        router.ipset_tool.destroy(_LEGACY_IPSET)
    except Exception:
        pass


def wipe_noint(router) -> None:
    """Remove all NoInternet UCI sections and kernel ipset.

    Remove all NoInternet firewall config and kernel ipset from the router.
    """
    try:
        router.uci.delete(f"firewall.{NOINT_IPSET}")
        router.uci.delete(f"firewall.{NOINT_RULE}")
        router.uci.commit("firewall")
        router.ipset_tool.destroy(NOINT_IPSET)
        router.service_ctl.reload("firewall")
    except Exception:
        pass
    # Also clean up legacy ipset
    try:
        router.uci.delete(f"firewall.{_LEGACY_IPSET}")
        router.uci.commit("firewall")
        router.ipset_tool.destroy(_LEGACY_IPSET)
    except Exception:
        pass


def _build_uci_sections(desired_macs: set) -> str:
    """Build UCI batch to create the ipset + rule sections from scratch."""
    lines = [
        f"set firewall.{NOINT_IPSET}=ipset",
        f"set firewall.{NOINT_IPSET}.name='{NOINT_IPSET}'",
        f"set firewall.{NOINT_IPSET}.match='mac'",
        f"set firewall.{NOINT_IPSET}.storage='hash'",
    ]
    for mac in sorted(desired_macs):
        lines.append(f"add_list firewall.{NOINT_IPSET}.entry='{mac}'")
    lines.extend([
        f"set firewall.{NOINT_RULE}=rule",
        f"set firewall.{NOINT_RULE}.name='fvpn NoInternet block WAN'",
        f"set firewall.{NOINT_RULE}.src='lan'",
        f"set firewall.{NOINT_RULE}.dest='wan'",
        f"set firewall.{NOINT_RULE}.proto='all'",
        f"set firewall.{NOINT_RULE}.ipset='{NOINT_IPSET} src'",
        f"set firewall.{NOINT_RULE}.target='REJECT'",
    ])
    return "\n".join(lines) + "\n"
