"""Profile Keys — Shared key-matching helpers for profile ↔ router rule correlation.

Used by both vpn_service.py (build_profile_list) and device_service.py
(_resolve_device_assignments) to match local profiles to router rules
via a stable (vpn_protocol, peer_id|client_id) key.
"""

from consts import PROTO_OPENVPN, PROTO_WIREGUARD


def local_router_key(local_profile: dict) -> tuple:
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


def router_rule_key(rule: dict) -> tuple:
    """Stable key for a router rule (matches local_router_key)."""
    via = rule.get("via_type", PROTO_WIREGUARD)
    if via == PROTO_OPENVPN:
        return (PROTO_OPENVPN, str(rule.get("client_id", "")))
    return (PROTO_WIREGUARD, str(rule.get("peer_id", "")))


def default_device(mac: str, profile_id=None) -> dict:
    """Return a device dict with all fields initialized to defaults."""
    return {
        "mac": mac, "ip": "", "hostname": "", "label": "",
        "device_class": "", "profile_id": profile_id, "router_online": False,
        "iface": "", "rx_speed": 0, "tx_speed": 0, "total_rx": 0,
        "total_tx": 0, "signal_dbm": None, "link_speed_mbps": None,
        "reserved_ip": None,
    }


def build_ip_to_network_map(router, leases=None) -> dict:
    """Build {ip_string: {"label": ..., "zone": ...}} from LAN access networks.

    Best-effort — returns empty dict on failure.  Pass *leases* to avoid a
    duplicate SSH call when the caller already has them.
    """
    import ipaddress
    try:
        networks = router.lan_access.get_networks()
    except Exception:
        return {}
    subnets = []
    for n in networks:
        subnet_str = n.get("subnet", "")
        label = " / ".join(s["name"] for s in n.get("ssids", []) if s.get("name")) or n.get("zone", "")
        zone_id = n.get("id", "")
        if subnet_str:
            try:
                subnets.append((ipaddress.IPv4Network(subnet_str, strict=False), label, zone_id))
            except ValueError:
                pass
    def _map_ip(ip_str, result):
        try:
            ip = ipaddress.IPv4Address(ip_str)
            for net, label, zone_id in subnets:
                if ip in net:
                    result[ip_str] = {"label": label, "zone": zone_id}
                    break
        except ValueError:
            pass

    result = {}
    try:
        if leases is None:
            leases = router.devices.get_dhcp_leases()
        for lease in leases:
            ip_str = lease.get("ip", "")
            if ip_str:
                _map_ip(ip_str, result)
        # Also map IPs from ARP table (devices with static IPs / expired leases)
        for entry in router.devices.get_arp_entries():
            ip_str = entry.get("ip", "")
            if ip_str and ip_str not in result:
                _map_ip(ip_str, result)
    except Exception:
        pass
    return result
