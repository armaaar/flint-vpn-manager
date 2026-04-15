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

# VPN Bypass Exceptions
BYPASS_MARK = "0x8000"
BYPASS_MASK = "0xf000"
BYPASS_TABLE = 1008
BYPASS_PRIORITY = 100
BYPASS_CHAIN = "FVPN_BYPASS"
BYPASS_IPSET_PREFIX = "fvpn_byp_"
BYPASS_SCRIPT_PATH = "/etc/fvpn/vpn_bypass.sh"
BYPASS_DNSMASQ_CONF = "/etc/dnsmasq.d/fvpn_bypass.conf"

# Riot Games AS6507 + AS62830 — all announced IPv4 prefixes (2026-04)
_RIOT_CIDRS = [
    # NA
    {"type": "cidr", "value": "104.160.128.0/19"},
    {"type": "cidr", "value": "162.249.72.0/21"},
    {"type": "cidr", "value": "192.64.168.0/21"},
    {"type": "cidr", "value": "192.207.0.0/24"},
    {"type": "cidr", "value": "192.91.144.0/24"},   # AS62830
    # EU
    {"type": "cidr", "value": "185.40.64.0/22"},
    {"type": "cidr", "value": "151.106.246.0/24"},
    {"type": "cidr", "value": "151.106.247.0/24"},
    {"type": "cidr", "value": "151.106.248.0/24"},
    {"type": "cidr", "value": "151.106.249.0/24"},
    {"type": "cidr", "value": "151.106.250.0/23"},
    {"type": "cidr", "value": "151.106.252.0/24"},
    {"type": "cidr", "value": "151.106.253.0/24"},
    {"type": "cidr", "value": "151.106.254.0/24"},
    # LATAM
    {"type": "cidr", "value": "45.7.36.0/22"},
    {"type": "cidr", "value": "138.0.12.0/23"},
    {"type": "cidr", "value": "138.0.14.0/24"},
    {"type": "cidr", "value": "138.0.15.0/24"},
    # APAC
    {"type": "cidr", "value": "43.229.64.0/22"},
    {"type": "cidr", "value": "45.250.208.0/22"},
    {"type": "cidr", "value": "103.219.128.0/22"},
    {"type": "cidr", "value": "103.240.224.0/22"},
]

VPN_BYPASS_PRESETS: dict[str, dict] = {
    "lol": {
        "name": "League of Legends",
        "rule_blocks": [
            {
                "label": "Riot IP ranges (AS6507 + AS62830)",
                "rules": list(_RIOT_CIDRS),
            },
            {
                "label": "Riot + LoL domains",
                "rules": [
                    {"type": "domain", "value": "riotgames.com"},
                    {"type": "domain", "value": "pvp.net"},
                    {"type": "domain", "value": "riotcdn.net"},
                    {"type": "domain", "value": "riotcdn.com"},
                    {"type": "domain", "value": "leagueoflegends.com"},
                    {"type": "domain", "value": "vivox.com"},
                    {"type": "domain", "value": "lolstatic.com"},
                    {"type": "domain", "value": "rgpub.io"},
                    {"type": "domain", "value": "lolesports.com"},
                    {"type": "domain", "value": "rdatasrv.net"},
                ],
            },
        ],
    },
    "valorant": {
        "name": "Valorant",
        "rule_blocks": [
            {
                "label": "Riot IP ranges (AS6507 + AS62830)",
                "rules": list(_RIOT_CIDRS),
            },
            {
                "label": "Riot + Valorant domains",
                "rules": [
                    {"type": "domain", "value": "riotgames.com"},
                    {"type": "domain", "value": "pvp.net"},
                    {"type": "domain", "value": "playvalorant.com"},
                    {"type": "domain", "value": "riotcdn.net"},
                    {"type": "domain", "value": "riotcdn.com"},
                    {"type": "domain", "value": "vivox.com"},
                    {"type": "domain", "value": "rgpub.io"},
                    {"type": "domain", "value": "rdatasrv.net"},
                ],
            },
        ],
    },
}
