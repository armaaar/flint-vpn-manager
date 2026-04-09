"""Shared constants for FlintVPN Manager.

Centralizes magic strings used across multiple modules to eliminate
connascence of meaning.
"""

# Profile types
PROFILE_TYPE_VPN = "vpn"
PROFILE_TYPE_NO_VPN = "no_vpn"
PROFILE_TYPE_NO_INTERNET = "no_internet"
VALID_PROFILE_TYPES = {PROFILE_TYPE_VPN, PROFILE_TYPE_NO_VPN, PROFILE_TYPE_NO_INTERNET}

# LAN access states
LAN_ALLOWED = "allowed"
LAN_GROUP_ONLY = "group_only"
LAN_BLOCKED = "blocked"
VALID_LAN_STATES = {LAN_ALLOWED, LAN_GROUP_ONLY, LAN_BLOCKED}

# VPN protocols
PROTO_WIREGUARD = "wireguard"
PROTO_WIREGUARD_TCP = "wireguard-tcp"
PROTO_WIREGUARD_TLS = "wireguard-tls"
PROTO_OPENVPN = "openvpn"

# Tunnel health states
HEALTH_GREEN = "green"
HEALTH_AMBER = "amber"
HEALTH_RED = "red"
HEALTH_CONNECTING = "connecting"
