"""Typed dictionaries for router data structures.

Provides type hints for the dicts returned by RouterAPI facades, improving
IDE autocompletion and catching field-name mismatches at the type level.
"""

from typing import Optional, TypedDict


class WgRouterInfo(TypedDict):
    """Returned by ``RouterWireguard.upload_wireguard_config()``."""
    peer_id: str
    peer_num: str
    group_id: str
    tunnel_id: int
    rule_name: str
    vpn_protocol: str  # "wireguard"


class OvpnRouterInfo(TypedDict):
    """Returned by ``RouterOpenvpn.upload_openvpn_config()``."""
    client_id: str
    client_uci_id: str
    group_id: str
    tunnel_id: int
    rule_name: str
    vpn_protocol: str  # "openvpn"


class ProtonWgRouterInfo(TypedDict):
    """Returned by ``RouterProtonWG.upload_proton_wg_config()``."""
    tunnel_name: str
    tunnel_id: int
    mark: str
    table_num: int
    ipset_name: str
    socket_type: str  # "tcp" or "tls"
    vpn_protocol: str  # "wireguard-tcp" or "wireguard-tls"
    rule_name: str


class TunnelStatus(TypedDict):
    """Returned by ``RouterTunnel.get_tunnel_status()``."""
    up: bool
    connecting: bool
    interface: Optional[str]
    handshake_seconds_ago: Optional[int]
    rx_bytes: int
    tx_bytes: int


class DhcpLease(TypedDict):
    """Returned by ``RouterDevices.get_dhcp_leases()`` (list items)."""
    expiry: int
    mac: str
    ip: str
    hostname: str


class FlintVpnRule(TypedDict, total=False):
    """Returned by ``RouterPolicy.get_flint_vpn_rules()`` (list items).

    Uses ``total=False`` because not all fields are present on every rule
    (e.g. ``peer_id`` only on WG rules, ``client_id`` only on OVPN).
    """
    rule_name: str
    _section_type: str
    name: str
    enabled: str
    tunnel_id: str
    via_type: str
    via: str
    killswitch: str
    from_mac: str | list[str]
    from_type: str
    peer_id: str
    client_id: str
    group_id: str
