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
ADBLOCK_PORT = 5354  # 5353 is taken by avahi-daemon (mDNS)
ADBLOCK_CONF_PATH = "/etc/fvpn/dnsmasq-adblock.conf"
ADBLOCK_HOSTS_PATH = "/etc/fvpn/blocklist.hosts"
ADBLOCK_RULES_SCRIPT = "/etc/fvpn/adblock_rules.sh"
ADBLOCK_MACS_FILE = "/etc/fvpn/adblock_macs.txt"
ADBLOCK_IPSET = "fvpn_adblock_macs"
ADBLOCK_CHAIN = "fvpn_adblock"
ADBLOCK_INIT_SCRIPT = "/etc/init.d/fvpn-adblock"

BLOCKLIST_PRESETS = {
    "hagezi-light": {
        "name": "HaGeZi Light",
        "description": "Balanced — minimal false positives (~80K domains)",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/light.txt",
    },
    "hagezi-multi": {
        "name": "HaGeZi Multi",
        "description": "Recommended — ads, trackers, analytics (~180K domains)",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/multi.txt",
    },
    "hagezi-pro": {
        "name": "HaGeZi Pro",
        "description": "Aggressive — comprehensive blocking (~250K domains)",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/pro.txt",
    },
    "steven-black": {
        "name": "Steven Black Unified",
        "description": "Popular community list — ads + malware (~130K domains)",
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    },
}

# Tunnel health states
HEALTH_GREEN = "green"
HEALTH_AMBER = "amber"
HEALTH_RED = "red"
HEALTH_CONNECTING = "connecting"
