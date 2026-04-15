"""Profile List Builder — Merges router state with local metadata.

Read-only module. Builds the canonical profile list for /api/profiles
by merging router route_policy rules, local profile_store metadata,
and live Proton server data.

Extracted from VPNService.build_profile_list() for separation of
concerns: this module has no mutation side-effects.
"""

import logging

import persistence.profile_store as ps
from consts import (
    HEALTH_RED,
    PROFILE_TYPE_VPN,
    PROTO_OPENVPN,
    PROTO_WIREGUARD,
)
from vpn.profile_keys import local_router_key, router_rule_key

log = logging.getLogger("flintvpn")

_local_router_key = local_router_key
_router_rule_key = router_rule_key


def _local_display_order(store_data, profile_id, default=None):
    """Look up display_order from the local store for any profile."""
    if not profile_id:
        return default
    for p in store_data.get("profiles", []):
        if p.get("id") == profile_id:
            return p.get("display_order", default)
    return default


def _resolve_server_live(proton, local_profile: dict) -> dict:
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
    if not proton or not proton.is_logged_in:
        return cached
    try:
        server_obj = proton.get_server_by_id(server_id)
        if server_obj is None:
            return cached
        live = proton.server_to_dict(server_obj)
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


def build_profile_list(router, proton, healer, store_data=None):
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
            "server": _resolve_server_live(proton, local),
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
    healer.heal_duplicate_tunnel_ids(store_data, router)

    # proton-wg profiles (wireguard-tcp / wireguard-tls): managed outside
    # vpn-client, so they don't appear in router route_policy rules.
    # Only treat as "matched" (non-ghost) if the tunnel .conf exists on
    # the router — otherwise let it fall through to ghost detection.
    try:
        pwg_confs = router.proton_wg.list_tunnel_confs()
    except Exception:
        pwg_confs = set()

    for key, local in local_vpn_by_key.items():
        ri = local.get("router_info", {})
        proto = ri.get("vpn_protocol", "")
        if not proto.startswith("wireguard-"):
            continue  # Not a proton-wg profile

        iface = ri.get("tunnel_name", "")
        if not iface or iface not in pwg_confs:
            continue  # .conf missing on router — will be flagged as ghost

        matched_local_keys.add(key)

        p = dict(local)
        try:
            p["health"] = router.proton_wg.get_proton_wg_health(iface)
        except Exception:
            p["health"] = HEALTH_RED
        p["kill_switch"] = True  # Always on for proton-wg (blackhole route)
        if proton:
            try:
                p["server"] = _resolve_server_live(proton, local)
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
    if any(_local_display_order(store_data, p.get("id")) is not None for p in vpn_profiles):
        vpn_profiles.sort(key=lambda p: _local_display_order(store_data, p.get("id"), default=999))

    return vpn_profiles
