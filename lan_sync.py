"""LAN access execution layer — UCI-native rules + ipsets.

Replaces the old imperative `fvpn_lan` iptables chain (router_api.lan_*)
and the per-MAC `fvpn_noinet_*` UCI rules with a single declarative model:

- Per-group `config ipset` (hash:ip) holds the live IPs of group members.
- Per-group `config rule` sections express DROP / group_only via
  `option ipset` and `option extra '-m set ! --match-set ...'` (negation).
- Per-(group, direction) "extras" ipsets hold IPs for MAC-string allow-list
  exceptions; profile-UUID exceptions reference target groups' ipsets directly.
- Per-device LAN overrides emit their own per-device rules in front of the
  group rules (UCI section order = iptables evaluation order). Outbound uses
  `option src_mac` (MAC-based, no IP needed); inbound uses `option dest_ip`.
- A single global `fvpn_noint_ips` ipset + `fvpn_noint_block` rule handles
  ALL no-internet groups (the local store distinguishes groups; the router
  only needs membership).

The execution model is:
  1. `serialize_lan_state(store, device_ips, assignment_map)` — pure function,
     produces a deterministic dict of desired ipsets + rule sections.
  2. `sync_lan_to_router(router, ...)` — reads live state via
     `router.fvpn_lan_full_state()`, diffs against desired, applies via
     `uci batch` + `firewall reload` (if structural changes) or just
     `ipset add/del` + UCI dual-write (if membership-only).

Spike-validated on Flint 2 firmware 4.8.4: `firewall reload` is ~0.22s
with no VPN tunnel disruption.
"""

from typing import Optional

import profile_store


# UCI section name constants — kept short to fit within UCI's 14-char-ish
# section name comfort zone (no hard limit, but readability).
NOINT_IPSET = "fvpn_noint_ips"
NOINT_RULE = "fvpn_noint_block"


def _short_id(profile_id: str) -> str:
    """First 8 chars of a profile UUID, used as the per-group prefix."""
    return profile_id[:8]


def _mac_no_colons(mac: str) -> str:
    return mac.lower().replace(":", "")


def _group_ipset(short_id: str) -> str:
    return f"fvpn_lan_{short_id}_ips"


def _extras_ipset(short_id: str, direction: str) -> str:
    """direction: 'out' | 'in'"""
    return f"fvpn_extra_{short_id}_{direction}_ips"


def _devovr_extras_ipset(mac_no_colons: str, direction: str) -> str:
    return f"fvpn_devovr_{mac_no_colons}_{direction}_ips"


def _make_rule(
    name: str,
    src: str = "lan",
    dest: str = "lan",
    proto: str = "all",
    src_mac=None,
    dest_ip=None,
    ipset=None,
    extra=None,
    target: str = "DROP",
) -> dict:
    """Build a desired rule dict for serialize_lan_state output.

    Fields with `None` are omitted in the UCI batch.
    """
    rule = {"_type": "rule", "src": src, "dest": dest, "proto": proto, "target": target}
    if src_mac is not None:
        rule["src_mac"] = src_mac
    if dest_ip is not None:
        rule["dest_ip"] = dest_ip
    if ipset is not None:
        rule["ipset"] = ipset
    if extra is not None:
        rule["extra"] = extra
    rule["name"] = name
    return rule


def _make_ipset(set_name: str, entries: list) -> dict:
    """Build a desired ipset section dict (config ipset)."""
    return {
        "_type": "ipset",
        "name": set_name,
        "match": "ip",
        "storage": "hash",
        "entry": list(entries),
    }


def serialize_lan_state(
    store: dict,
    device_ips: dict,
    assignment_map: Optional[dict] = None,
) -> dict:
    """Pure function: compute the desired LAN execution state.

    Args:
        store: profile_store.load() result
        device_ips: {mac_lowercase: ip_string} from live DHCP leases
        assignment_map: {mac_lowercase: profile_id} merging router VPN
            assignments + local non-VPN assignments. If None, only the local
            non-VPN assignments are considered (so VPN groups appear empty).

    Returns:
        {
            "ipsets": {section_name: {"_type": "ipset", "name": ..., "entry": [...]}},
            "rules":  {section_name: {"_type": "rule", "src": ..., ...}},
            "rule_order": [section_name, ...]   # explicit ordering for fw3 chain order
        }

    Section ordering:
        1. Per-device override rules (ACCEPT-before-DROP per device)
        2. Per-group exception ACCEPT rules (referencing target group ipsets / extras)
        3. Per-group DROP rules
        4. NoInternet block rule

    Sections / ipsets named with `fvpn_` prefix so they're easy to wipe.
    """
    profiles = {p["id"]: p for p in store.get("profiles", [])}
    overrides = store.get("device_lan_overrides", {}) or {}

    # Use the merged assignment map if provided; otherwise fall back to local
    # store (for unit tests that don't have a router).
    if assignment_map is None:
        assignment_map = {}
        for mac, pid in store.get("device_assignments", {}).items():
            if pid:
                assignment_map[mac.lower()] = pid

    # Build group membership (live IPs per group)
    group_members = {}  # profile_id -> [(mac, ip), ...]
    for mac, pid in assignment_map.items():
        if not pid or pid not in profiles:
            continue
        ip = device_ips.get(mac, "")
        group_members.setdefault(pid, []).append((mac.lower(), ip))

    ipsets = {}  # section_name -> ipset dict
    rules = {}  # section_name -> rule dict
    rule_order = []  # ordered list of section names

    # ── Helper to register an ipset (one per unique set_name)
    def _register_ipset(set_name: str, ips: list):
        if set_name not in ipsets:
            ipsets[set_name] = _make_ipset(set_name, sorted(set(ip for ip in ips if ip)))
        else:
            # Merge with existing entries (for shared sets — currently each
            # set_name should be unique, but be defensive)
            existing = set(ipsets[set_name]["entry"])
            existing.update(ip for ip in ips if ip)
            ipsets[set_name]["entry"] = sorted(existing)

    # ── First pass: build per-group ipsets for ALL groups whose members are
    #    referenced by ANY rule (their own state OR an exception list of another
    #    group). We do this in two phases: identify referenced groups, then build.
    # Phase 1a: groups whose own state is non-allowed
    referenced_groups = set()
    for pid, p in profiles.items():
        if p.get("type") == "no_internet":
            continue
        lan = p.get("lan_access") or {}
        out_state = lan.get("outbound", "allowed")
        in_state = lan.get("inbound", "allowed")
        if out_state != "allowed" or in_state != "allowed":
            referenced_groups.add(pid)
        # Also: if any other profile or override references this group as an
        # exception target, we need its ipset. Phase 1b below.
    # Phase 1b: scan all profiles + overrides for profile-UUID exception entries
    for pid, p in profiles.items():
        lan = p.get("lan_access") or {}
        for key in ("outbound_allow", "inbound_allow"):
            for entry in lan.get(key, []) or []:
                if entry in profiles and profiles[entry].get("type") != "no_internet":
                    referenced_groups.add(entry)
    for mac, ovr in overrides.items():
        for key in ("outbound_allow", "inbound_allow"):
            for entry in ovr.get(key, []) or []:
                if entry in profiles and profiles[entry].get("type") != "no_internet":
                    referenced_groups.add(entry)

    # Phase 2: build ipsets for referenced groups
    for pid in referenced_groups:
        members = group_members.get(pid, [])
        ips = [ip for _, ip in members if ip]
        _register_ipset(_group_ipset(_short_id(pid)), ips)

    # ── Second pass: emit per-device override sections (FIRST in order so
    #    they take precedence over group rules in the iptables chain)
    overridden_macs = []
    for mac, ovr in overrides.items():
        if not ovr:
            continue
        has_override = (
            ovr.get("outbound") is not None
            or ovr.get("inbound") is not None
            or (ovr.get("outbound_allow") or [])
            or (ovr.get("inbound_allow") or [])
        )
        if not has_override:
            continue
        overridden_macs.append(mac.lower())

    for mac in sorted(overridden_macs):
        eff = profile_store.get_effective_lan_access(mac, store)
        ip = device_ips.get(mac, "")
        mac_id = _mac_no_colons(mac)

        # ── OUTBOUND override (uses src_mac, no IP needed)
        out_state = eff["outbound"]
        out_allow_raw = [e["value"] for e in eff.get("outbound_allow", []) or []]
        if out_state in ("blocked", "group_only"):
            # Emit ACCEPT exceptions BEFORE the DROP
            extras_ips_set = []
            for entry in out_allow_raw:
                if ":" in entry and len(entry) == 17:
                    # MAC entry — resolve to peer IP, add to extras ipset
                    peer = entry.lower()
                    peer_ip = device_ips.get(peer, "")
                    if peer_ip and peer != mac:
                        extras_ips_set.append(peer_ip)
                elif entry in profiles and profiles[entry].get("type") != "no_internet":
                    # Profile-UUID entry — emit ACCEPT rule referencing target group
                    target_set = _group_ipset(_short_id(entry))
                    sec = f"fvpn_devovr_{mac_id}_outacc_{_short_id(entry)}"
                    rules[sec] = _make_rule(
                        name=f"fvpn devovr {mac} out -> grp {_short_id(entry)}",
                        src_mac=mac,
                        extra=f"-m set --match-set {target_set} dst",
                        target="ACCEPT",
                    )
                    rule_order.append(sec)
            if extras_ips_set:
                extras_set = _devovr_extras_ipset(mac_id, "out")
                _register_ipset(extras_set, extras_ips_set)
                sec = f"fvpn_devovr_{mac_id}_outacc_extra"
                rules[sec] = _make_rule(
                    name=f"fvpn devovr {mac} out -> mac extras",
                    src_mac=mac,
                    extra=f"-m set --match-set {extras_set} dst",
                    target="ACCEPT",
                )
                rule_order.append(sec)
            # The DROP rule
            sec = f"fvpn_devovr_{mac_id}_outdrop"
            if out_state == "blocked":
                rules[sec] = _make_rule(
                    name=f"fvpn devovr {mac} out blocked",
                    src_mac=mac,
                    target="DROP",
                )
            else:  # group_only
                # Find the device's group's ipset for the dst-side check
                pid = assignment_map.get(mac)
                if pid and pid in profiles:
                    grp_set = _group_ipset(_short_id(pid))
                    rules[sec] = _make_rule(
                        name=f"fvpn devovr {mac} out group_only",
                        src_mac=mac,
                        extra=f"-m set ! --match-set {grp_set} dst",
                        target="DROP",
                    )
                    # Make sure that group's ipset is registered
                    if grp_set not in ipsets:
                        members = group_members.get(pid, [])
                        ips = [m_ip for _, m_ip in members if m_ip]
                        _register_ipset(grp_set, ips)
            if sec in rules:
                rule_order.append(sec)

        # ── INBOUND override (uses dest_ip, needs live IP)
        in_state = eff["inbound"]
        in_allow_raw = [e["value"] for e in eff.get("inbound_allow", []) or []]
        if ip and in_state in ("blocked", "group_only"):
            # Emit ACCEPT exceptions BEFORE the DROP
            extras_ips_set = []
            for entry in in_allow_raw:
                if ":" in entry and len(entry) == 17:
                    peer = entry.lower()
                    peer_ip = device_ips.get(peer, "")
                    if peer_ip and peer != mac:
                        extras_ips_set.append(peer_ip)
                elif entry in profiles and profiles[entry].get("type") != "no_internet":
                    target_set = _group_ipset(_short_id(entry))
                    sec = f"fvpn_devovr_{mac_id}_inacc_{_short_id(entry)}"
                    rules[sec] = _make_rule(
                        name=f"fvpn devovr {mac} in <- grp {_short_id(entry)}",
                        dest_ip=ip,
                        extra=f"-m set --match-set {target_set} src",
                        target="ACCEPT",
                    )
                    rule_order.append(sec)
            if extras_ips_set:
                extras_set = _devovr_extras_ipset(mac_id, "in")
                _register_ipset(extras_set, extras_ips_set)
                sec = f"fvpn_devovr_{mac_id}_inacc_extra"
                rules[sec] = _make_rule(
                    name=f"fvpn devovr {mac} in <- mac extras",
                    dest_ip=ip,
                    extra=f"-m set --match-set {extras_set} src",
                    target="ACCEPT",
                )
                rule_order.append(sec)
            # The DROP rule
            sec = f"fvpn_devovr_{mac_id}_indrop"
            if in_state == "blocked":
                rules[sec] = _make_rule(
                    name=f"fvpn devovr {mac} in blocked",
                    dest_ip=ip,
                    target="DROP",
                )
            else:  # group_only
                pid = assignment_map.get(mac)
                if pid and pid in profiles:
                    grp_set = _group_ipset(_short_id(pid))
                    rules[sec] = _make_rule(
                        name=f"fvpn devovr {mac} in group_only",
                        dest_ip=ip,
                        extra=f"-m set ! --match-set {grp_set} src",
                        target="DROP",
                    )
                    if grp_set not in ipsets:
                        members = group_members.get(pid, [])
                        ips_list = [m_ip for _, m_ip in members if m_ip]
                        _register_ipset(grp_set, ips_list)
            if sec in rules:
                rule_order.append(sec)

    # ── Third pass: emit per-group rules (after device overrides so they
    #    take lower precedence)
    for pid, p in profiles.items():
        if p.get("type") == "no_internet":
            continue  # Handled separately below
        lan = p.get("lan_access") or {}
        out_state = lan.get("outbound", "allowed")
        in_state = lan.get("inbound", "allowed")
        out_allow = lan.get("outbound_allow", []) or []
        in_allow = lan.get("inbound_allow", []) or []
        if out_state == "allowed" and in_state == "allowed":
            continue  # No rules needed for fully-allowed groups

        short = _short_id(pid)
        grp_set = _group_ipset(short)
        # Make sure the group ipset exists (already added in phase 2 if non-allowed)
        if grp_set not in ipsets:
            members = group_members.get(pid, [])
            ips = [m_ip for _, m_ip in members if m_ip]
            _register_ipset(grp_set, ips)

        # ── OUTBOUND group rules
        if out_state in ("blocked", "group_only"):
            # ACCEPT exceptions first
            extras_ips_set = []
            for entry in out_allow:
                if ":" in entry and len(entry) == 17:
                    peer = entry.lower()
                    peer_ip = device_ips.get(peer, "")
                    if peer_ip:
                        extras_ips_set.append(peer_ip)
                elif entry in profiles and profiles[entry].get("type") != "no_internet":
                    target_set = _group_ipset(_short_id(entry))
                    sec = f"fvpn_lan_{short}_outacc_{_short_id(entry)}"
                    rules[sec] = _make_rule(
                        name=f"fvpn grp {short} out -> grp {_short_id(entry)}",
                        ipset=f"{grp_set} src",
                        extra=f"-m set --match-set {target_set} dst",
                        target="ACCEPT",
                    )
                    rule_order.append(sec)
            if extras_ips_set:
                extras_set = _extras_ipset(short, "out")
                _register_ipset(extras_set, extras_ips_set)
                sec = f"fvpn_lan_{short}_outacc_extra"
                rules[sec] = _make_rule(
                    name=f"fvpn grp {short} out -> mac extras",
                    ipset=f"{grp_set} src",
                    extra=f"-m set --match-set {extras_set} dst",
                    target="ACCEPT",
                )
                rule_order.append(sec)
            # DROP rule
            sec = f"fvpn_lan_{short}_outdrop"
            if out_state == "blocked":
                rules[sec] = _make_rule(
                    name=f"fvpn grp {short} out blocked",
                    ipset=f"{grp_set} src",
                    target="DROP",
                )
            else:  # group_only
                rules[sec] = _make_rule(
                    name=f"fvpn grp {short} out group_only",
                    ipset=f"{grp_set} src",
                    extra=f"-m set ! --match-set {grp_set} dst",
                    target="DROP",
                )
            rule_order.append(sec)

        # ── INBOUND group rules
        if in_state in ("blocked", "group_only"):
            extras_ips_set = []
            for entry in in_allow:
                if ":" in entry and len(entry) == 17:
                    peer = entry.lower()
                    peer_ip = device_ips.get(peer, "")
                    if peer_ip:
                        extras_ips_set.append(peer_ip)
                elif entry in profiles and profiles[entry].get("type") != "no_internet":
                    target_set = _group_ipset(_short_id(entry))
                    sec = f"fvpn_lan_{short}_inacc_{_short_id(entry)}"
                    rules[sec] = _make_rule(
                        name=f"fvpn grp {short} in <- grp {_short_id(entry)}",
                        ipset=f"{grp_set} dst",
                        extra=f"-m set --match-set {target_set} src",
                        target="ACCEPT",
                    )
                    rule_order.append(sec)
            if extras_ips_set:
                extras_set = _extras_ipset(short, "in")
                _register_ipset(extras_set, extras_ips_set)
                sec = f"fvpn_lan_{short}_inacc_extra"
                rules[sec] = _make_rule(
                    name=f"fvpn grp {short} in <- mac extras",
                    ipset=f"{grp_set} dst",
                    extra=f"-m set --match-set {extras_set} src",
                    target="ACCEPT",
                )
                rule_order.append(sec)
            sec = f"fvpn_lan_{short}_indrop"
            if in_state == "blocked":
                rules[sec] = _make_rule(
                    name=f"fvpn grp {short} in blocked",
                    ipset=f"{grp_set} dst",
                    target="DROP",
                )
            else:  # group_only
                rules[sec] = _make_rule(
                    name=f"fvpn grp {short} in group_only",
                    ipset=f"{grp_set} dst",
                    extra=f"-m set ! --match-set {grp_set} src",
                    target="DROP",
                )
            rule_order.append(sec)

    # ── Fourth pass: NoInternet (single global ipset + rule)
    no_int_pids = {
        pid for pid, p in profiles.items() if p.get("type") == "no_internet"
    }
    no_int_ips = set()
    for mac, pid in assignment_map.items():
        if pid in no_int_pids:
            ip = device_ips.get(mac, "")
            if ip:
                no_int_ips.add(ip)
    if no_int_ips or no_int_pids:
        # Always emit the ipset + rule if there's at least one no_internet
        # group, even if empty (so the rule is in place when devices get IPs).
        _register_ipset(NOINT_IPSET, list(no_int_ips))
        rules[NOINT_RULE] = _make_rule(
            name="fvpn NoInternet block WAN",
            src="lan",
            dest="wan",
            ipset=f"{NOINT_IPSET} src",
            target="REJECT",
        )
        rule_order.append(NOINT_RULE)

    return {
        "ipsets": ipsets,
        "rules": rules,
        "rule_order": rule_order,
    }


# ── Diff + apply ──────────────────────────────────────────────────────────


def _format_uci_value(val) -> str:
    """Quote a UCI value for `uci batch` consumption.

    Single-quoted; embedded single quotes escaped.
    """
    s = str(val)
    return "'" + s.replace("'", "'\\''") + "'"


def _emit_ipset_section(section: str, info: dict) -> list:
    """Emit `uci batch` lines for a single config ipset section."""
    lines = [f"set firewall.{section}=ipset"]
    lines.append(f"set firewall.{section}.name={_format_uci_value(info['name'])}")
    lines.append(f"set firewall.{section}.match={_format_uci_value(info.get('match', 'ip'))}")
    lines.append(f"set firewall.{section}.storage={_format_uci_value(info.get('storage', 'hash'))}")
    for ip in info.get("entry", []):
        lines.append(f"add_list firewall.{section}.entry={_format_uci_value(ip)}")
    return lines


def _emit_rule_section(section: str, rule: dict) -> list:
    """Emit `uci batch` lines for a single config rule section."""
    lines = [f"set firewall.{section}=rule"]
    # Order matters for readability but not correctness
    field_order = ["name", "src", "dest", "proto", "src_mac", "dest_ip", "ipset", "extra", "target"]
    for k in field_order:
        if k not in rule or rule[k] is None:
            continue
        v = rule[k]
        if k == "src_mac" and isinstance(v, list):
            for mac in v:
                lines.append(f"add_list firewall.{section}.src_mac={_format_uci_value(mac)}")
        else:
            lines.append(f"set firewall.{section}.{k}={_format_uci_value(v)}")
    return lines


def diff_state(live: dict, desired: dict) -> dict:
    """Compute the diff between live router state and desired state.

    Args:
        live: result of `router.fvpn_lan_full_state()`
        desired: result of `serialize_lan_state(...)`

    Returns:
        {
          "uci_batch": str,                              # full uci-batch script
          "membership_ops": {set_name: (add_list, remove_list)},  # for ipsets that exist on both sides
          "needs_reload": bool,
        }

    The membership_ops are split out so the caller can apply them via
    `ipset add/del` for immediate effect (kernel ipset) BEFORE the firewall
    reload re-applies the UCI rules.
    """
    desired_ipset_sections = {
        # section name = ipset name (we make them match)
        info["name"]: info for info in desired["ipsets"].values()
    }
    desired_set_names = set(desired_ipset_sections.keys())
    desired_rule_names = list(desired["rule_order"])
    desired_rules_set = set(desired_rule_names)

    live_set_names = set(live.get("ipsets", {}).keys())
    live_rule_names = set(live.get("rules", {}).keys())
    live_set_uci_sections = live.get("ipset_uci", {})  # set_name -> uci section name
    live_set_uci_entries = live.get("ipset_uci_entries", {})  # set_name -> entries list

    uci_lines = []
    membership_ops = {}
    needs_reload = False

    # 1. Delete obsolete ipset sections
    for set_name in live_set_names - desired_set_names:
        section = live_set_uci_sections.get(set_name, set_name)
        uci_lines.append(f"delete firewall.{section}")
        needs_reload = True

    # 2. Delete obsolete rule sections
    for rule_name in live_rule_names - desired_rules_set:
        uci_lines.append(f"delete firewall.{rule_name}")
        needs_reload = True

    # 3. For ipsets present in BOTH live and desired:
    #    - if entries match, no-op
    #    - if entries differ, compute membership add/remove (no reload needed)
    #      and dual-write to UCI list
    for set_name in live_set_names & desired_set_names:
        live_entries = set(live.get("ipsets", {}).get(set_name, []))
        live_uci_entries = set(live_set_uci_entries.get(set_name, []))
        desired_entries = set(desired_ipset_sections[set_name].get("entry", []))
        # Membership diff = kernel state vs desired
        add = sorted(desired_entries - live_entries)
        remove = sorted(live_entries - desired_entries)
        if add or remove:
            membership_ops[set_name] = (add, remove)
        # UCI dual-write: bring the persistent entry list in line with desired
        uci_add = sorted(desired_entries - live_uci_entries)
        uci_remove = sorted(live_uci_entries - desired_entries)
        section = live_set_uci_sections.get(set_name, set_name)
        for ip in uci_remove:
            uci_lines.append(f"del_list firewall.{section}.entry={_format_uci_value(ip)}")
        for ip in uci_add:
            uci_lines.append(f"add_list firewall.{section}.entry={_format_uci_value(ip)}")

    # 4. Add new ipset sections (in desired but not in live)
    for set_name in desired_set_names - live_set_names:
        # Use ipset name as the UCI section name (they match by convention)
        info = desired_ipset_sections[set_name]
        uci_lines.extend(_emit_ipset_section(set_name, info))
        needs_reload = True

    # 5. For rules present in BOTH live and desired: check if they differ
    #    Rules don't have memberships — they're either equal or replaced wholesale.
    for rule_name in live_rule_names & desired_rules_set:
        live_rule = live.get("rules", {}).get(rule_name, {})
        desired_rule = desired["rules"][rule_name]
        if not _rules_equal(live_rule, desired_rule):
            # Replace by deleting + re-adding
            uci_lines.append(f"delete firewall.{rule_name}")
            uci_lines.extend(_emit_rule_section(rule_name, desired_rule))
            needs_reload = True

    # 6. Add new rule sections (in desired order)
    for rule_name in desired_rule_names:
        if rule_name in live_rule_names:
            continue
        rule = desired["rules"][rule_name]
        uci_lines.extend(_emit_rule_section(rule_name, rule))
        needs_reload = True

    return {
        "uci_batch": "\n".join(uci_lines) + "\n" if uci_lines else "",
        "membership_ops": membership_ops,
        "needs_reload": needs_reload,
    }


def _rules_equal(live: dict, desired: dict) -> bool:
    """Compare a live rule (parsed from `uci show`) to a desired rule.

    Live values come from `uci show` so they're all strings (or lists for
    multi-value fields). Desired values may be strings or None.

    We compare on the *meaningful* fields only: src, dest, proto, src_mac,
    dest_ip, ipset, extra, target. The `name` field is informational and
    ignored.
    """
    fields = ["src", "dest", "proto", "src_mac", "dest_ip", "ipset", "extra", "target"]
    for f in fields:
        live_val = live.get(f)
        desired_val = desired.get(f)
        if isinstance(live_val, list):
            live_val = sorted(live_val)
        if isinstance(desired_val, list):
            desired_val = sorted(desired_val)
        if (live_val or None) != (desired_val or None):
            return False
    return True


def sync_lan_to_router(
    router,
    store: Optional[dict] = None,
    device_ips: Optional[dict] = None,
    assignment_map: Optional[dict] = None,
) -> dict:
    """Reconcile router LAN execution state with local intent.

    Args:
        router: RouterAPI instance
        store: profile_store dict (loads if None)
        device_ips: {mac_lower: ip} from live DHCP (queried if None)
        assignment_map: {mac_lower: profile_id} merging router VPN + local
            non-VPN assignments (queried if None — see _resolve_assignment_map)

    Returns:
        {
          "applied": bool,
          "reload": bool,
          "membership_ops": int,  # count of ipsets with membership changes
          "uci_lines": int,
        }
    """
    if store is None:
        store = profile_store.load()

    if device_ips is None:
        try:
            leases = router.get_dhcp_leases()
            device_ips = {l["mac"].lower(): l.get("ip", "") for l in leases}
        except Exception:
            device_ips = {}

    if assignment_map is None:
        assignment_map = _resolve_assignment_map(router, store)

    desired = serialize_lan_state(store, device_ips, assignment_map)
    live = router.fvpn_lan_full_state()
    diff = diff_state(live, desired)

    # Apply kernel ipset membership changes (immediate effect, no reload).
    # Done BEFORE the UCI batch so the kernel reflects the new entries; the
    # UCI batch then dual-writes for persistence.
    for set_name, (add, remove) in diff["membership_ops"].items():
        try:
            router.fvpn_ipset_membership(set_name, add=add, remove=remove)
        except Exception:
            pass  # best-effort; firewall reload below would re-create from UCI

    # Apply UCI batch + reload if needed
    if diff["uci_batch"] or diff["needs_reload"]:
        router.fvpn_uci_apply(diff["uci_batch"], reload=diff["needs_reload"])

    return {
        "applied": bool(diff["uci_batch"] or diff["membership_ops"]),
        "reload": diff["needs_reload"],
        "membership_ops": len(diff["membership_ops"]),
        "uci_lines": len(diff["uci_batch"].splitlines()) if diff["uci_batch"] else 0,
    }


def _resolve_assignment_map(router, store: dict) -> dict:
    """Merge router VPN device assignments with local non-VPN assignments.

    Returns {mac_lower: profile_id}. VPN assignments take their profile_id by
    matching the router rule's stable (vpn_protocol, peer_id|client_id) key
    against local profiles' router_info. Non-VPN assignments come from the
    local store.
    """
    profiles = store.get("profiles", [])

    # Build (vpn_protocol, peer/client_id) -> local profile id index
    key_to_pid = {}
    for p in profiles:
        if p.get("type") != "vpn":
            continue
        ri = p.get("router_info") or {}
        vpn_protocol = "openvpn" if ri.get("vpn_protocol") == "openvpn" else "wireguard"
        if vpn_protocol == "openvpn":
            cid = str(ri.get("client_id", "")).lstrip("peer_").lstrip("client_")
            key = ("openvpn", cid)
        else:
            pid = str(ri.get("peer_id", "")).lstrip("peer_").lstrip("client_")
            key = ("wireguard", pid)
        if key[1]:
            key_to_pid[key] = p["id"]

    # Get router VPN rules → match by stable key → resolve to local profile id
    try:
        rules = router.get_flint_vpn_rules()
    except Exception:
        rules = []
    section_to_pid = {}
    for rule in rules:
        section = rule.get("rule_name", "")
        if not section:
            continue
        via = rule.get("via_type", "wireguard")
        if via == "openvpn":
            key = ("openvpn", str(rule.get("client_id", "")))
        else:
            key = ("wireguard", str(rule.get("peer_id", "")))
        pid = key_to_pid.get(key)
        if pid:
            section_to_pid[section] = pid

    # Get router from_mac → mac → section → profile id
    try:
        vpn_assignments_raw = router.get_device_assignments()
    except Exception:
        vpn_assignments_raw = {}

    out = {}
    for mac, section in vpn_assignments_raw.items():
        pid = section_to_pid.get(section)
        if pid:
            out[mac.lower()] = pid

    # Merge in local non-VPN assignments
    for mac, pid in store.get("device_assignments", {}).items():
        if not pid:
            continue
        for p in profiles:
            if p.get("id") == pid and p.get("type") != "vpn":
                out[mac.lower()] = pid
                break

    return out
