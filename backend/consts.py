"""Shared constants for FlintVPN Manager.

Centralizes magic strings used across multiple modules to eliminate
connascence of meaning.
"""

# Profile types
PROFILE_TYPE_VPN = "vpn"
PROFILE_TYPE_NO_VPN = "no_vpn"
PROFILE_TYPE_NO_INTERNET = "no_internet"
VALID_PROFILE_TYPES = {PROFILE_TYPE_VPN, PROFILE_TYPE_NO_VPN, PROFILE_TYPE_NO_INTERNET}

# VPN protocols
PROTO_WIREGUARD = "wireguard"
PROTO_WIREGUARD_TCP = "wireguard-tcp"
PROTO_WIREGUARD_TLS = "wireguard-tls"
PROTO_OPENVPN = "openvpn"

# DNS ad blocking
ADBLOCK_HOSTS_PATH = "/etc/fvpn/blocklist.hosts"
ADBLOCK_RULES_SCRIPT = "/etc/fvpn/adblock_rules.sh"

BLOCKLIST_PRESETS = {
    "hagezi-light": {
        "name": "HaGeZi Light",
        "description": "Balanced — minimal false positives (~140K domains)",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/light.txt",
        "info_url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/light.txt",
    },
    "hagezi-multi": {
        "name": "HaGeZi Multi",
        "description": "Recommended — ads, trackers, analytics (~320K domains)",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/multi.txt",
        "info_url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/multi.txt",
    },
    "hagezi-pro": {
        "name": "HaGeZi Pro",
        "description": "Aggressive — comprehensive blocking (~420K domains)",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/pro.txt",
        "info_url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/pro.txt",
    },
    "hagezi-ultimate": {
        "name": "HaGeZi Ultimate",
        "description": "Maximum blocking — may have false positives (~580K domains)",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/ultimate.txt",
        "info_url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/ultimate.txt",
    },
    "hagezi-tif": {
        "name": "HaGeZi Threat Intelligence",
        "description": "Malware, cryptojacking, scam, phishing (~1.1M domains)",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/tif.txt",
        "info_url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/tif.txt",
    },
    "steven-black": {
        "name": "Steven Black Unified",
        "description": "Popular community list — ads + malware (~90K domains)",
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "info_url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    },
}

# IPv6 dual-stack support
IPV6_FWD_SCRIPT = "/etc/fvpn/ipv6_forward.sh"
IPV6_MANGLE_SCRIPT = "/etc/fvpn/ipv6_mangle_rules.sh"
PROTON_WG_IPV6_ADDR = "2a07:b944::2:2/128"
PROTON_IPV6_DNS = "2a07:b944::2:1"

# Tunnel health states
HEALTH_GREEN = "green"
HEALTH_AMBER = "amber"
HEALTH_RED = "red"
HEALTH_CONNECTING = "connecting"
