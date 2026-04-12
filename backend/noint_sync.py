"""NoInternet group enforcement — blocks WAN access for assigned devices.

Manages a single global ``fvpn_noint_ips`` hash:ip ipset + one fw3 REJECT
rule that drops all traffic from NoInternet devices to the WAN zone.

Extracted from the old ``lan_sync.py`` LAN access layer so that NoInternet
continues to work independently of the (removed) per-group LAN firewall.

Execution model:
  1. Collect IPs of devices assigned to NoInternet profiles.
  2. Diff against the live kernel ipset membership.
  3. Apply adds/removes via ``ipset add/del`` (immediate, no reload).
  4. If the UCI ipset+rule sections don't exist yet, create them and reload.
"""

from typing import Optional

import profile_store
from consts import PROFILE_TYPE_NO_INTERNET


NOINT_IPSET = "fvpn_noint_ips"
NOINT_RULE = "fvpn_noint_block"


def sync_noint_to_router(
    router,
    store: Optional[dict] = None,
    device_ips: Optional[dict] = None,
) -> dict:
    """Reconcile the NoInternet ipset on the router with local intent.

    Args:
        router: RouterAPI instance (needs .exec, .fvpn_ipset_membership,
                .fvpn_uci_apply, .get_dhcp_leases)
        store: profile_store dict (loaded if None)
        device_ips: {mac_lower: ip} from live DHCP (queried if None)

    Returns:
        {"applied": bool, "reload": bool, "adds": int, "removes": int}
    """
    if store is None:
        store = profile_store.load()

    if device_ips is None:
        try:
            leases = router.get_dhcp_leases()
            device_ips = {l["mac"].lower(): l.get("ip", "") for l in leases}
        except Exception:
            device_ips = {}

    profiles = {p["id"]: p for p in store.get("profiles", [])}
    noint_pids = {
        pid for pid, p in profiles.items()
        if p.get("type") == PROFILE_TYPE_NO_INTERNET
    }

    # NoInternet groups are always non-VPN, so local device_assignments
    # is the complete source of truth (no router VPN rules to merge).
    assignments = store.get("device_assignments", {})

    desired_ips = set()
    for mac, pid in assignments.items():
        if pid in noint_pids:
            ip = device_ips.get(mac.lower(), "")
            if ip:
                desired_ips.add(ip)

    # Read live kernel ipset membership
    try:
        raw = router.exec(
            f"ipset list {NOINT_IPSET} 2>/dev/null | "
            "awk 'p{print} /^Members:/{p=1}' || true"
        )
        live_ips = {l.strip() for l in raw.strip().splitlines() if l.strip()}
    except Exception:
        live_ips = set()

    add = sorted(desired_ips - live_ips)
    remove = sorted(live_ips - desired_ips)
    applied = False
    needs_reload = False

    # Ensure the UCI ipset + rule sections exist (creates on first run,
    # no-ops thereafter).  We check by looking for the rule section.
    try:
        check = router.exec(
            f"uci -q get firewall.{NOINT_RULE} 2>/dev/null || echo MISSING"
        ).strip()
    except Exception:
        check = "MISSING"

    if check == "MISSING" and (noint_pids or desired_ips):
        uci = _build_uci_sections(desired_ips)
        router.fvpn_uci_apply(uci, reload=True)
        needs_reload = True
        applied = True
        # After reload the kernel ipset is populated from UCI entries,
        # so skip the membership diff — it's already in sync.
        add = []
        remove = []
    elif not noint_pids and check != "MISSING":
        # No NoInternet groups left — remove the sections.
        uci = (
            f"delete firewall.{NOINT_IPSET}\n"
            f"delete firewall.{NOINT_RULE}\n"
        )
        router.fvpn_uci_apply(uci, reload=True)
        router.fvpn_ipset_destroy(NOINT_IPSET)
        return {"applied": True, "reload": True, "adds": 0, "removes": len(live_ips)}

    # Apply membership diff (immediate kernel effect, no reload).
    if add or remove:
        try:
            router.fvpn_ipset_membership(NOINT_IPSET, add=add, remove=remove)
            applied = True
        except Exception:
            pass
        # Dual-write to UCI for persistence across reboots.
        uci_lines = []
        for ip in remove:
            uci_lines.append(f"del_list firewall.{NOINT_IPSET}.entry='{ip}'")
        for ip in add:
            uci_lines.append(f"add_list firewall.{NOINT_IPSET}.entry='{ip}'")
        if uci_lines:
            try:
                router.fvpn_uci_apply("\n".join(uci_lines) + "\n", reload=False)
            except Exception:
                pass

    return {
        "applied": applied,
        "reload": needs_reload,
        "adds": len(add),
        "removes": len(remove),
    }


def wipe_noint(router) -> None:
    """Remove all NoInternet UCI sections and kernel ipset.

    Used by ``cli.py reset-local-state``.
    """
    try:
        router.exec(
            f"uci -q delete firewall.{NOINT_IPSET}; "
            f"uci -q delete firewall.{NOINT_RULE}; "
            "uci commit firewall; "
            f"ipset destroy {NOINT_IPSET} 2>/dev/null; "
            "true"
        )
        router.exec("/etc/init.d/firewall reload >/dev/null 2>&1; true")
    except Exception:
        pass


def _build_uci_sections(desired_ips: set) -> str:
    """Build UCI batch to create the ipset + rule sections from scratch."""
    lines = [
        f"set firewall.{NOINT_IPSET}=ipset",
        f"set firewall.{NOINT_IPSET}.name='{NOINT_IPSET}'",
        f"set firewall.{NOINT_IPSET}.match='ip'",
        f"set firewall.{NOINT_IPSET}.storage='hash'",
    ]
    for ip in sorted(desired_ips):
        lines.append(f"add_list firewall.{NOINT_IPSET}.entry='{ip}'")
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
