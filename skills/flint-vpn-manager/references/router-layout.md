# Router Layout

The full inventory of what Flint VPN Manager creates on the router, how it's named, and where to find it. Load this when you need to translate a feature the user talked about into a specific router artifact, or when you see something on the router and need to identify what feature owns it.

## Table of contents

1. [UCI section prefixes](#1-uci-section-prefixes)
2. [Tunnel-ID allocation & fwmark map](#2-tunnel-id-allocation--fwmark-map)
3. [ipset prefixes](#3-ipset-prefixes)
4. [Routing tables](#4-routing-tables)
5. [File tree under `/etc/fvpn/`](#5-file-tree-under-etcfvpn)
6. [iptables / ip6tables chains](#6-iptables--ip6tables-chains)
7. [Firewall include scripts](#7-firewall-include-scripts)
8. [Per-feature artifact map](#8-per-feature-artifact-map)
9. [Reverse index: given an artifact, find the owner](#9-reverse-index)

---

## 1. UCI section prefixes

| Prefix | UCI config | Purpose |
|---|---|---|
| `peer_9001`–`peer_9050` | `wireguard` | Kernel WireGuard UDP peers |
| `28216_9051`–`28216_9099` | `ovpnclient` | OpenVPN clients (`group_id=28216`) |
| `fvpn_rule_<N>` | `route_policy` | Kernel WG route policy rule |
| `fvpn_rule_ovpn_<N>` | `route_policy` | OVPN route policy rule |
| `fvpn_zone_<iface>` | `firewall` | Proton-wg firewall zone |
| `fvpn_fwd_<iface>` | `firewall` | Proton-wg lan→tunnel forwarding |
| `fvpn_zone_<zone_id>` | `firewall` | User-created LAN zone |
| `fvpn_<name>` | `network` / `wireless` / `dhcp` | User-created LAN network (≤11 chars total) |
| `fvpn_<mac_no_colons>` | `dhcp` (host section) | Reserved IP (DHCP static lease) |
| `fvpn_noint_include` | `firewall` (include) | NoInternet firewall script |
| `fvpn_vpn_bypass` | `firewall` (include) | VPN bypass firewall script |
| `fvpn_adblock` | `firewall` (include) | Adblock firewall script |
| `fvpn_pwg_mangle` | `firewall` (include) | Proton-wg mangle rules script |
| `fvpn_lan_access` | `firewall` (include) | LAN access device-exceptions script |
| `fvpn_ipv6_mangle` | `firewall` (include) | IPv6 mangle MARK rules |
| `fvpn_ipv6_fwd` | `firewall` (include) | IPv6 FORWARD/leak-prevention script |

**GL.iNet group-id markers** (so Flint VPN Manager configs appear in the stock GL.iNet UI as "FromApp"):

- `1957` → WireGuard (Flint VPN Manager-created)
- `28216` → OpenVPN (Flint VPN Manager-created)

## 2. Tunnel-ID allocation & fwmark map

A `tunnel_id` is an integer **300–399** used to derive ipset names and fwmarks. Flint VPN Manager allocates from three sources to avoid collisions:

- `uci show route_policy | grep tunnel_id=` (kernel WG + OVPN)
- `ipset list -n | grep -E '^(pwg_mac_|src_mac_)'` (runtime ipsets)
- `grep -h '^FVPN_TUNNEL_ID=' /etc/fvpn/protonwg/*.env` (proton-wg persistent)

### Protocol → slot → fwmark → table

| Family | Iface slots | Fwmark range | ip rule priority | Routing table(s) |
|---|---|---|---|---|
| Kernel WG (UDP) | `wgclient1..5` | `0x1000..0x5000` | 1000 | 100..104 |
| OpenVPN (UDP/TCP) | `ovpnclient1..5` | `0xa000..0xe000` | 2000 | 200..204 |
| Proton-wg (TCP/TLS) | `protonwg0..3` | `0x6000, 0x7000, 0x9000, 0xf000` | 6000 | 1006, 1007, 1009, 1015 |
| VPN Bypass | (no iface — WAN) | `0x8000` | 100 | 1008 |

Fwmark mask is always `/0xf000`. Proton-wg table number = `1000 + (mark >> 12)`.

Slot limits:
- 5 kernel WG tunnels (GL.iNet vpn-client)
- 5 OpenVPN tunnels (GL.iNet vpn-client)
- 4 proton-wg tunnels (Flint VPN Manager)
- 14 total simultaneous (fwmark space)

## 3. ipset prefixes

| Name pattern | Hash type | Owner | Key property |
|---|---|---|---|
| `src_mac_<tunnel_id>` | `hash:mac` | vpn-client (kernel WG + OVPN) | **Flushed by `/etc/init.d/vpn-client restart`**; rebuilt from `route_policy.*.from_mac` UCI list |
| `pwg_mac_<tunnel_id>` | `hash:mac` | Flint VPN Manager (proton-wg) | **Immune** to vpn-client restart; rebuilt from `/etc/fvpn/protonwg/<iface>.macs` on firewall reload |
| `fvpn_byp_<exc_id>_b<N>` | `hash:net` | VPN bypass | One per exception's rule block; CIDRs added statically, domain-resolved IPs added by dnsmasq at query time |
| `fvpn_noint_macs` | `hash:mac` | NoInternet | Populated from `/etc/fvpn/noint.macs` by firewall include |

The `src_mac_` vs `pwg_mac_` distinction is load-bearing safety — see SKILL.md invariant #3.

## 4. Routing tables

- `100–104` — kernel WG tunnels (`wgclient1..5`)
- `200–204` — OpenVPN tunnels (`ovpnclient1..5`)
- `1006, 1007, 1009, 1015` — proton-wg tunnels (`protonwg0..3`)
- `1008` — VPN bypass (routes `0x8000`-marked traffic via WAN)

Each per-tunnel table has two routes:
```
default dev <iface>                     # primary
blackhole default metric 254            # kill switch — wins when iface goes down
```

The blackhole has a higher metric, so while the tunnel is up it loses to the `dev <iface>` route. When the interface disappears, only blackhole remains → packets dropped. That's the kill-switch mechanism for proton-wg, and (via vpn-client) for kernel WG/OVPN when `route_policy.killswitch='1'`.

## 5. File tree under `/etc/fvpn/`

```
/etc/fvpn/
├── profile_store.bak.json       # SOURCE OF TRUTH for the app's profile store (pulled on unlock)
├── blocklist.hosts              # merged adblock hosts file (dual-stack 0.0.0.0 + :: entries)
├── adblock_rules.sh             # firewall include: re-injects addn-hosts snippets + SIGHUP dnsmasq
├── adblock_ifaces.txt           # list of ifaces (one per line) with adblock active
├── vpn_bypass.sh                # firewall include: rebuilds bypass ipsets, chain, routing table 1008
├── lan_access_rules.sh          # firewall include: device forwarding exceptions + global fwmark ACCEPT
├── noint_rules.sh               # firewall include: rebuilds FVPN_NOINT chain + ipset from .macs
├── noint.macs                   # MACs assigned to NoInternet groups (one per line, uppercase)
├── ipv6_forward.sh              # firewall include: IPv6 FORWARD rules (leak prevention + per-tunnel ACCEPT)
├── ipv6_mangle_rules.sh         # firewall include: IPv6 mangle MARK rules per active tunnel
└── protonwg/
    ├── protonwg0.conf           # WireGuard config (Interface + Peer sections)
    ├── protonwg0.env            # PROTON_WG_* + FVPN_TUNNEL_ID/MARK/IPSET/IPV6
    ├── protonwg0.macs           # persistent MAC list (one per line, lowercase)
    ├── … (protonwg1..protonwg3 same)
    └── mangle_rules.sh          # firewall include: regenerated on every tunnel/device change
```

Also outside `/etc/fvpn/`:

```
/etc/init.d/fvpn-protonwg        # procd boot-time starter for proton-wg tunnels (enabled)
/usr/bin/proton-wg               # proton-wg binary (wireguard-go fork, ARM64)
/etc/sysctl.d/99-fvpn-ipv6.conf  # persists kernel-level IPv6 enable

/tmp/dnsmasq.d/
  fvpn-adblock                   # main-dnsmasq adblock snippet (addn-hosts=…)
  fvpn_bypass.conf               # dnsmasq ipset= lines for bypass domains

/tmp/dnsmasq.d.<iface>/
  fvpn-adblock                   # per-tunnel adblock snippet (wgclient1..4, protonwg0..3)

/var/etc/
  dnsmasq.conf.<iface>           # per-tunnel dnsmasq config (proton-wg only)
  dnsmasq.conf.cfg01411c         # main dnsmasq config (the UUID-ish suffix is GL.iNet-generated, stable)

/tmp/resolv.conf.d/resolv.conf.<iface>   # per-tunnel resolv file (proton-wg only)
/tmp/<iface>.log                 # proton-wg process stderr/stdout (ephemeral)
```

## 6. iptables / ip6tables chains

| Chain | Table | Owner | Purpose |
|---|---|---|---|
| `ROUTE_POLICY` | mangle | GL.iNet | Master mangle chain — every LAN packet evaluated here |
| `FVPN_BYPASS` | mangle | Flint VPN Manager | Pre-marks bypass packets with `0x8000` (inserted at ROUTE_POLICY position 1) |
| `TUNNEL<tid>_ROUTE_POLICY` | mangle | Flint VPN Manager (proton-wg) | Per-tunnel MAC-src → MARK rule |
| `FVPN_NOINT` | filter | Flint VPN Manager | NoInternet REJECT rule jumped from FORWARD position 1 |
| `fvpn_lan_exc` | filter | Flint VPN Manager | LAN access device exceptions (dual-stack) |
| `FVPN_V6_<tid>` | mangle (ip6tables) | Flint VPN Manager | Per-tunnel IPv6 MARK rule |
| `forwarding_rule` | filter | GL.iNet | Flint VPN Manager appends: `-m mark ! --mark 0x0/0xf000 -j ACCEPT` (global VPN pass-through) + jump to `fvpn_lan_exc` |
| `policy_redirect` | nat | GL.iNet | Flint VPN Manager appends per-tunnel DNS REDIRECT rules (proton-wg only) |
| `pre_dns_deal_conn_zone` / `out_dns_deal_conn_zone` | raw | GL.iNet | Flint VPN Manager appends per-tunnel CT zone rules (proton-wg only) |

### `ROUTE_POLICY` chain order (critical)

Rules are evaluated top-down, so order encodes precedence:

```
ROUTE_POLICY
  1  -j FVPN_BYPASS                  # bypass marks 0x8000 first, tunnel rules skip marked traffic
  2  -j TUNNEL303_ROUTE_POLICY       # proton-wg tunnels (one jump per active tunnel)
  3  -j TUNNEL304_ROUTE_POLICY
  4  -m set --match-set src_mac_305 src -j MARK --set-xmark 0x1000/0xf000   # vpn-client WG
  5  -m set --match-set src_mac_306 src -j MARK --set-xmark 0xa000/0xf000   # vpn-client OVPN
```

The proton-wg per-tunnel chains contain `-m mark --mark 0x0/0xf000` to skip already-marked packets (bypass).

`FVPN_BYPASS` at position 1 is a hard invariant. If bypass doesn't work, check:
```sh
iptables -t mangle -L ROUTE_POLICY --line-numbers -n -v | head -10
```

## 7. Firewall include scripts

Every Flint VPN Manager-owned include uses `option reload '1'` so it re-runs on every `firewall reload`. GL.iNet's own `vpnclient` include uses `reload='0'` — it only runs on `firewall start`. This is why `reload` is safe but `restart` is not.

| UCI section | Script path | Recreates |
|---|---|---|
| `firewall.fvpn_pwg_mangle` | `/etc/fvpn/protonwg/mangle_rules.sh` | Proton-wg mangle chains + DNS REDIRECT rules |
| `firewall.fvpn_vpn_bypass` | `/etc/fvpn/vpn_bypass.sh` | FVPN_BYPASS chain + ipsets + routing table 1008 |
| `firewall.fvpn_adblock` | `/etc/fvpn/adblock_rules.sh` | Adblock addn-hosts snippets + SIGHUP dnsmasq |
| `firewall.fvpn_noint_include` | `/etc/fvpn/noint_rules.sh` | FVPN_NOINT ipset + FORWARD REJECT rule |
| `firewall.fvpn_lan_access` | `/etc/fvpn/lan_access_rules.sh` | fvpn_lan_exc chain + global VPN ACCEPT |
| `firewall.fvpn_ipv6_fwd` | `/etc/fvpn/ipv6_forward.sh` | ip6tables FORWARD policy + per-tunnel ACCEPT |
| `firewall.fvpn_ipv6_mangle` | `/etc/fvpn/ipv6_mangle_rules.sh` | ip6tables mangle per-tunnel MARK rules |

If a firewall reload didn't take effect the way you expected, run the relevant script manually with `sh -x` to see what it did:

```sh
ssh root@192.168.8.1 'sh -x /etc/fvpn/vpn_bypass.sh 2>&1 | head -50'
```

## 8. Per-feature artifact map

### VPN tunnel (kernel WG)

Lifetime artifacts:
- `wireguard.peer_<NNNN>` (UCI peer config, fields: private_key/public_key/end_point/dns/mtu/persistent_keepalive/allowed_ips)
- `route_policy.fvpn_rule_<NNNN>` (UCI rule, fields: tunnel_id/via_type=wireguard/peer_id/from=src_mac_<tid>/killswitch/enabled)
- `src_mac_<tunnel_id>` ipset (device assignments)

Runtime (created by vpn-client when enabled):
- `wgclient1..5` interface
- routing table 100..104 with `default dev wgclientN` + blackhole
- ip rule `fwmark 0x<tid>000/0xf000 lookup <table>`
- iptables MARK rule in ROUTE_POLICY

### VPN tunnel (OpenVPN)

Lifetime:
- `ovpnclient.28216_<NNNN>` (UCI client, fields: group_id=28216/client_id/path/proto/client_auth)
- `/etc/openvpn/profiles/28216_<NNNN>/config.ovpn`
- `/etc/openvpn/profiles/28216_<NNNN>/auth/username_password.txt` (chmod 600)
- `route_policy.fvpn_rule_ovpn_<NNNN>` (via_type=openvpn)
- `src_mac_<tunnel_id>` ipset

### VPN tunnel (proton-wg)

**No route_policy entry.** All state lives in files:
- `/etc/fvpn/protonwg/<iface>.conf` (WG config)
- `/etc/fvpn/protonwg/<iface>.env` (FVPN_TUNNEL_ID, FVPN_MARK, FVPN_IPSET, FVPN_IPV6, PROTON_WG_*)
- `/etc/fvpn/protonwg/<iface>.macs` (persistent MAC list)
- `pwg_mac_<tunnel_id>` ipset
- `firewall.fvpn_zone_<iface>` + `firewall.fvpn_fwd_<iface>`
- Per-tunnel dnsmasq instance (`/var/etc/dnsmasq.conf.<iface>`, port 2653/2753/2953/3553)
- Mangle chain `TUNNEL<tid>_ROUTE_POLICY` (from `mangle_rules.sh`)

### Kill switch

- **Kernel WG + OVPN**: `route_policy.<rule>.killswitch='0'|'1'`. vpn-client reads it and inserts a blackhole route into the per-tunnel table when the tunnel is down.
- **Proton-wg**: Always on. Not a UCI flag — implemented as a permanent blackhole route in the per-tunnel table, metric 254.

### Device assignment

- **Kernel WG / OVPN**: both `route_policy.<rule>.from_mac` (UCI list, durable) AND `src_mac_<tid>` ipset (kernel, cache). Ipset is a cache; UCI is the source.
- **Proton-wg**: `/etc/fvpn/protonwg/<iface>.macs` (file, durable source of truth) + `pwg_mac_<tid>` ipset (kernel, rebuilt from `.macs` by `mangle_rules.sh` on any firewall reload).
- **NoVPN (direct route)**: local app store only — no router artifact.
- **NoInternet**: `/etc/fvpn/noint.macs` + `fvpn_noint_macs` ipset.

### NoInternet groups

- Single ipset + single FORWARD REJECT rule covers all zones (designed to survive zone expansion without per-zone rules).
- Rule shape: `iptables -A FVPN_NOINT -m set --match-set fvpn_noint_macs src -o <wan_dev> -j REJECT --reject-with icmp-port-unreachable`.
- `wan_dev` is discovered at runtime from `uci get network.wan.device`.

### LAN network (zone + bridge)

Eight UCI sections per network (`fvpn_<zid>` where zid ≤ 6 chars for the 11-char fw3 limit):
- `wireless.fvpn_<zid>_2g` (wifi-iface, device=mt798611)
- `wireless.fvpn_<zid>_5g` (wifi-iface, device=mt798612)
- `network.fvpn_<zid>` (interface, proto=static, type=bridge)
- `firewall.fvpn_<zid>_zone` (zone, input=REJECT/output=ACCEPT/forward=REJECT)
- `firewall.fvpn_<zid>_dhcp` (rule, allow DHCP udp 67-68)
- `firewall.fvpn_<zid>_dns` (rule, allow DNS tcpudp 53)
- `firewall.fvpn_<zid>_mdns` (rule, allow mDNS udp 5353)
- `firewall.fvpn_<zid>_wan` (forwarding, src=fvpn_<zid> dest=wan)
- `dhcp.fvpn_<zid>` (dhcp server: start=100 limit=150 leasetime=12h + dhcpv6 + ra)

Plus a full MediaTek WiFi driver reload to pick up the new `ra<N>`/`rax<N>` interfaces. **This causes a ~15s WiFi outage on all bands** — unavoidable.

### Adblock

- `/etc/fvpn/blocklist.hosts` — merged hosts file, dual-stack (`0.0.0.0 <domain>` + `:: <domain>`).
- For each iface with adblock enabled: `addn-hosts=/etc/fvpn/blocklist.hosts` snippet at `/tmp/dnsmasq.d[.<iface>]/fvpn-adblock`.
- `/etc/fvpn/adblock_ifaces.txt` records active ifaces for the firewall include to rebuild after reload.
- Main dnsmasq conf-dir: `/tmp/dnsmasq.d/`. Per-tunnel conf-dirs: `/tmp/dnsmasq.d.<iface>/`.

### VPN Bypass

- `FVPN_BYPASS` mangle chain with one rule per (exception × block × source-target).
- Per-block ipset `fvpn_byp_<short_exc_id>_b<block_index>` (hash:net).
- Routing: `ip rule fwmark 0x8000/0xf000 lookup 1008 priority 100` + `ip route add default via <WAN_GW> dev <WAN_DEV> table 1008`.
- Domain rules: `/tmp/dnsmasq.d/fvpn_bypass.conf` with `ipset=/domain.com/fvpn_byp_id_bN` lines.
  - **Requires `dnsmasq-full`** (default dnsmasq-mini doesn't support `ipset=`).
  - dnsmasq `ipset=` changes need a **full restart** (not SIGHUP) to take effect.

## 9. Reverse index

Given an artifact name on the router, identify which feature owns it.

| You found… | It belongs to… |
|---|---|
| `route_policy.fvpn_rule_<N>` | Kernel WG tunnel (peer_id = N in `wireguard.peer_<N>`) |
| `route_policy.fvpn_rule_ovpn_<N>` | OpenVPN tunnel |
| `route_policy.@rule[N]` (anonymous) | An fvpn_rule edited via GL.iNet UI — self-healed on unlock |
| `wireguard.peer_<9001..9050>` | Kernel WG peer |
| `ovpnclient.28216_<9051..9099>` | OpenVPN client |
| `protonwg0..3` iface + `/etc/fvpn/protonwg/…` | proton-wg tunnel (TCP/TLS) |
| `firewall.fvpn_zone_<zid>` where zid ≠ protonwg* | User-created LAN network |
| `firewall.fvpn_zone_protonwg<N>` | Proton-wg firewall zone |
| `dhcp.fvpn_<mac>` (host section) | Reserved IP for that MAC |
| `dhcp.fvpn_<zid>` (dhcp section) | DHCP pool for a user-created LAN network |
| `gl-client.<section>.alias` / `.class` | Device custom label + device type |
| `src_mac_<N>` ipset | Kernel WG or OVPN device assignment (flushed by vpn-client restart) |
| `pwg_mac_<N>` ipset | Proton-wg device assignment (immune to vpn-client restart) |
| `fvpn_noint_macs` ipset | NoInternet group MACs |
| `fvpn_byp_<id>_b<N>` ipset | VPN bypass rule block (CIDRs + dnsmasq-resolved domain IPs) |
| `FVPN_BYPASS` chain (mangle) | VPN bypass marker |
| `TUNNEL<N>_ROUTE_POLICY` chain (mangle) | Proton-wg per-tunnel MARK rule |
| `FVPN_NOINT` chain (filter) | NoInternet REJECT |
| `fvpn_lan_exc` chain (filter) | LAN access device exceptions |
| `FVPN_V6_<N>` chain (ip6tables mangle) | IPv6 per-tunnel MARK |
| `/etc/fvpn/protonwg/<iface>.macs` | Persistent device list for that proton-wg tunnel |
| `/etc/fvpn/noint.macs` | Persistent NoInternet MAC list |
| `/etc/fvpn/blocklist.hosts` | Adblock merged hosts |
| `/etc/fvpn/profile_store.bak.json` | Authoritative backup of the app's profile store |
| Port 2653/2753/2953/3553 listener | Per-tunnel dnsmasq (proton-wg: port = 2000 + (mark>>12)*100 + 53) |
| Fwmark `0x1000..0x5000` | Kernel WG tunnel 1–5 |
| Fwmark `0x6000/0x7000/0x9000/0xf000` | Proton-wg tunnel 0–3 |
| Fwmark `0x8000` | VPN bypass |
| Fwmark `0xa000..0xe000` | OpenVPN tunnel 1–5 |
| Routing table 100–104 | Kernel WG |
| Routing table 200–204 | OVPN |
| Routing table 1006/1007/1009/1015 | Proton-wg |
| Routing table 1008 | VPN bypass → WAN |
