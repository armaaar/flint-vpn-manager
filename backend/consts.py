"""Shared constants for Flint VPN Manager.

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

# Per-protocol tunnel MTU (bytes). The wg-tls / wg-tcp values account for
# Proton's TCP+TLS re-encapsulation overhead (~120B vs ~60B for plain WG).
# Used at create-time; stored per-tunnel in the proton-wg .env so it
# survives reconnects and informs MSS clamping in mangle_rules.sh.
# Override per-profile via profile.options["mtu"].
PROTO_DEFAULT_MTU = {
    PROTO_WIREGUARD: 1420,      # plain UDP — current default
    PROTO_WIREGUARD_TCP: 1380,  # TCP framing, no TLS
    PROTO_WIREGUARD_TLS: 1320,  # TLS-over-TCP — needs the most headroom
}
# IPv6 minimum MTU; never clamp below this on a v6-enabled tunnel.
MTU_FLOOR_V6 = 1280

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
BYPASS_DNSMASQ_CONF = "/tmp/dnsmasq.d/fvpn_bypass.conf"

# Split VPNs — third-party VPNs (e.g. a work Barracuda VPN) that carry only
# selected destinations for selected groups, on top of the group's Proton
# tunnel. Each runs in its own network namespace on the router.
# Marks 0xa000..0xd000 are unused by vpn-client (0x1000-0x5000), proton-wg
# (0x6000/0x7000/0x9000/0xf000) and bypass (0x8000).
SPLITVPN_MAX = 4
SPLITVPN_MARK_BASE = 0xA000          # slot N → mark 0xA000 + N*0x1000
SPLITVPN_MASK = "0xf000"
SPLITVPN_TABLE_BASE = 1010           # slot N → table 1010 + N
SPLITVPN_PRIORITY = 90               # before bypass (100) and tunnels (6000)
SPLITVPN_CHAIN = "FVPN_SPLITVPN"
SPLITVPN_FWD_CHAIN = "FVPN_SPLITVPN_FWD"
SPLITVPN_IPSET_PREFIX = "fvpn_sv"    # fvpn_sv{N}_dst
SPLITVPN_DIR = "/etc/fvpn/splitvpn"
SPLITVPN_BIN_DIR = "/etc/fvpn/splitvpn/bin"
SPLITVPN_CTL = "/etc/fvpn/splitvpn/svctl.sh"
SPLITVPN_SCRIPT_PATH = "/etc/fvpn/splitvpn_rules.sh"
SPLITVPN_DNSMASQ_SNIPPET = "fvpn-splitvpn.conf"
SPLITVPN_TYPES = ("barracuda",)

# Pinned third-party runtime for the Barracuda (TINA) client. The client is
# x86-64 only, so it runs under qemu user-mode emulation on the ARM64 router.
SPLITVPN_RUNTIME = {
    "qemu-x86_64": {
        # Debian trixie qemu-user (static binaries); file inside the .deb
        "url": "https://deb.debian.org/debian/pool/main/q/qemu/qemu-user_10.0.13+ds-0+deb13u1_arm64.deb",
        "sha256": "c73711af02b97cd5e2667e735d9c06890c57165517110ca4e646c95a7083158d",
        "member": "./usr/bin/qemu-x86_64",
        "binary_sha256": "9af86352fd463ad9ec25bdd6a4b891ac6b6a7f3d46a7db3da6f23e2c09094a59",
    },
    "barracudavpn": {
        # Barracuda VPN Client 5.1.4 for Linux (statically linked x86-64),
        # same tarball the AUR `barracudavpn` package pins.
        "url": "https://raw.githubusercontent.com/RomarQ/barracudavpn-archlinux/master/tarball/barracudavpn-5.1.4.tar.gz",
        "sha256": "66128019ca60c0b028b3e99293aea3c6cca1dd57d5d2d8fe51cf31994764fab7",
        "member": "barracudavpn/barracudavpn",
        "binary_sha256": "a80cacc0c0594db28d5befcbad9c6927b824d83614efb73785641a399397442c",
    },
}

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
            {
                "label": "Chat + voice ports (Cloudflare-proxied)",
                "rules": [
                    {"type": "port", "value": "5222:5223", "protocol": "tcp"},
                ],
            },
        ],
    },
    # Miles & More / Lufthansa is fronted by Cloudflare Bot Management. The OAuth
    # login host (account.miles-and-more.com) serves a managed challenge that never
    # clears from a ProtonVPN exit IP, so the login page 403s with "Just a moment...".
    #
    # Domain rules only. Each zone gets its own Cloudflare anycast pair (account ->
    # 104.18.4.123/5.123, www -> 104.18.24.236/25.236, ...), so a domain rule puts
    # only that zone's IPs in the bypass ipset. A CIDR rule over 104.18.0.0/16 would
    # sweep in every unrelated zone in the same block.
    #
    # Deliberately NOT included: challenges.cloudflare.com. The cf_clearance cookie
    # that actually unblocks the site is issued same-origin, by
    # account.miles-and-more.com/cdn-cgi/challenge-platform/, which the domain rule
    # below already covers. challenges.cloudflare.com only serves the widget and its
    # own telemetry. Bypassing it would route Turnstile traffic for *every* site on
    # the network out the WAN while those sites stay on the tunnel.
    "milesandmore": {
        "name": "Lufthansa Miles & More",
        "rule_blocks": [
            {
                "label": "Miles & More (login, API, account, consent)",
                "rules": [
                    {"type": "domain", "value": "miles-and-more.com"},
                ],
            },
            {
                "label": "Lufthansa (design system assets, booking)",
                "rules": [
                    {"type": "domain", "value": "lufthansa.com"},
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
