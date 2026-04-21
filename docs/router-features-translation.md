# Router Features Translation

A complete reference mapping every FlintVPN Manager feature to the exact router-level artifacts it creates, reads, and modifies on the GL.iNet Flint 2 (GL-MT6000, OpenWrt 21.02) router.

**Intended audience**: a Claude/debug session that needs to inspect or repair router state over SSH without the full FlintVPN codebase in scope. Every feature section lists *what it is*, *where it lives on the router*, *how it was put there*, *how to inspect it*, and *what is safe vs unsafe to touch*.

Router default address: **192.168.8.1**. Root login via SSH key at `~/.ssh/id_ed25519`.

---

## Table of Contents

1. [Global Naming, ID Ranges, and Fwmark Map](#1-global-naming-id-ranges-and-fwmark-map)
2. [Groups / Profiles (VPN / NoVPN / NoInternet)](#2-groups--profiles)
3. [VPN Tunnel Lifecycle (3 protocol families)](#3-vpn-tunnel-lifecycle)
4. [Route Policy Rules and Fwmark Routing](#4-route-policy-rules-and-fwmark-routing)
5. [Kill Switch](#5-kill-switch)
6. [Device Assignments (VPN + Non-VPN)](#6-device-assignments)
7. [Device Metadata (Labels, Type, Private MAC)](#7-device-metadata)
8. [Reserved IP / DHCP Static Lease](#8-reserved-ip--dhcp-static-lease)
9. [NoInternet Groups (WAN Block)](#9-nointernet-groups)
10. [Server Selection, Switching, and Port Override](#10-server-selection-switching-and-port-override)
11. [Custom DNS per profile](#11-custom-dns-per-profile)
12. [VPN Options (NetShield, Accelerator, Moderate NAT, NAT-PMP, Secure Core, Tor)](#12-vpn-options)
13. [Smart Protocol](#13-smart-protocol)
14. [VPN Bypass Exceptions](#14-vpn-bypass-exceptions)
15. [Adblock (per-tunnel DNS filtering)](#15-adblock)
16. [Per-tunnel Dnsmasq (proton-wg DNS isolation)](#16-per-tunnel-dnsmasq)
17. [LAN / Networks (Zones, SSIDs, Bridges, Subnets)](#17-lan--networks)
18. [AP Isolation](#18-ap-isolation)
19. [Cross-Network Access Rules (Zone Forwarding)](#19-cross-network-access-rules)
20. [Device Exceptions (LAN access)](#20-device-exceptions-lan-access)
21. [mDNS Reflection](#21-mdns-reflection)
22. [IPv6 Dual-Stack](#22-ipv6-dual-stack)
23. [Profile Store Backup on Router](#23-profile-store-backup)
24. [Firewall Include Scripts & Reload Safety](#24-firewall-include-scripts)
25. [Logs and where they live](#25-logs)
26. [Safe vs Unsafe Router Commands (quick reference)](#26-safe-vs-unsafe-commands)
27. [Router Artifact Index (cross-reference)](#27-router-artifact-index)
28. [Common debug recipes](#28-common-debug-recipes)

---

## 1. Global Naming, ID Ranges, and Fwmark Map

All FlintVPN artifacts use predictable prefixes so they can be distinguished from GL.iNet's own config and from user-created config done via the stock UI.

### UCI section prefixes

| Prefix | UCI config | Purpose |
|---|---|---|
| `peer_9001`–`peer_9050` | `wireguard` | Kernel WireGuard UDP peers |
| `28216_9051`–`28216_9099` | `ovpnclient` | OpenVPN clients (`group_id=28216`) |
| `fvpn_rule_<N>` | `route_policy` | WG route policy rule |
| `fvpn_rule_ovpn_<N>` | `route_policy` | OVPN route policy rule |
| `fvpn_pwg_<iface>` | `route_policy` (logical) | There is **no** UCI rule for proton-wg — this is only a virtual rule_name string |
| `fvpn_zone_<iface>` | `firewall` | Proton-wg firewall zone |
| `fvpn_fwd_<iface>` | `firewall` | Proton-wg lan→tunnel forwarding |
| `fvpn_zone_<zone_id>` | `firewall` | User-created LAN zone |
| `fvpn_<name>` | `network`/`wireless`/`dhcp` | User-created LAN network (≤11 chars) |
| `fvpn_<mac_no_colons>` | `dhcp` (host section) | Reserved IP (DHCP static lease) |
| `fvpn_noint_include` | `firewall` (include) | NoInternet firewall script registration |
| `fvpn_vpn_bypass` | `firewall` (include) | VPN bypass firewall script registration |
| `fvpn_adblock` | `firewall` (include) | Adblock firewall script registration |
| `fvpn_pwg_mangle` | `firewall` (include) | Proton-wg mangle rules script registration |
| `fvpn_lan_access` | `firewall` (include) | LAN access device-exceptions script registration |
| `fvpn_ipv6_mangle` | `firewall` (include) | IPv6 mangle script registration |
| `fvpn_ipv6_fwd` | `firewall` (include) | IPv6 forward/leak script registration |

### `group_id` marker values (used by GL.iNet dashboard to mark "FromApp" configs):
- `1957` → WireGuard (FlintVPN)
- `28216` → OpenVPN (FlintVPN)

### Tunnel slot / ID allocation

`tunnel_id` is a single integer in the range **300–399** used by all three tunnel families to derive ipset names and fwmarks. It is allocated by `next_tunnel_id(ssh)` in [backend/router/tunnel_id_alloc.py](backend/router/tunnel_id_alloc.py#L8-L55), which scans three sources to avoid collisions:

1. `uci show route_policy | grep tunnel_id=` (kernel WG + OVPN)
2. `ipset list -n | grep -E '^(pwg_mac_|src_mac_)'` (runtime ipsets)
3. `grep -h '^FVPN_TUNNEL_ID=' /etc/fvpn/protonwg/*.env` (proton-wg persistent)

### Interface / slot / fwmark map

```
Protocol family        Iface slots       Fwmark range        IP rule priority   Routing table
---------------------  ----------------  ------------------  -----------------  ---------------
Kernel WG (UDP)        wgclient1..5      0x1000..0x5000      1000               100..104
OpenVPN                ovpnclient1..5    0xa000..0xe000      2000               200..204
Proton-wg (TCP/TLS)    protonwg0..3      0x6000,0x7000,      6000               1006,1007,
                                         0x9000,0xf000                          1009,1015
VPN Bypass             (no iface — WAN)  0x8000              100                1008
WAN (no FlintVPN mark) n/a               0x0000              —                  main
```

Fwmark mask is always `/0xf000` — the 4 high bits of the lower 16 bits encode the slot.

Proton-wg table numbers are computed as `1000 + (mark >> 12)` — i.e. `1000 + 0x6`=1006, `1000 + 0x7`=1007, `1000 + 0x9`=1009, `1000 + 0xf`=1015.

### ipset prefixes

| Prefix | Type | Owner | Notes |
|---|---|---|---|
| `src_mac_<tunnel_id>` | `hash:mac` | vpn-client (kernel WG + OVPN) | Flushed by `/etc/init.d/vpn-client restart`; rebuilt from `from_mac` UCI list |
| `pwg_mac_<tunnel_id>` | `hash:mac` | FlintVPN (proton-wg) | Immune to vpn-client restart; rebuilt from `/etc/fvpn/protonwg/<iface>.macs` on firewall reload |
| `fvpn_byp_<exc_id>_b<N>` | `hash:net` | VPN bypass | One per rule block; CIDRs added statically, domain IPs added by dnsmasq |
| `fvpn_noint_macs` | `hash:mac` | NoInternet | Populated from `/etc/fvpn/noint.macs` |

### Key paths

```
/etc/fvpn/
├── profile_store.bak.json       # source of truth for local profile store (see §23)
├── blocklist.hosts              # merged hosts file for adblock (§15)
├── adblock_rules.sh             # firewall include that re-injects adblock snippets
├── adblock_ifaces.txt           # interfaces with adblock active
├── vpn_bypass.sh                # firewall include: rebuilds bypass ipsets/rules
├── lan_access_rules.sh          # firewall include: device forwarding exceptions + global VPN accept
├── noint_rules.sh               # firewall include: rebuilds NoInternet chain
├── noint.macs                   # MACs assigned to NoInternet groups
├── ipv6_forward.sh              # firewall include: IPv6 FORWARD rules (leak prevention/forwarding)
├── ipv6_mangle_rules.sh         # firewall include: IPv6 mangle MARK rules
└── protonwg/
    ├── protonwg0.conf           # WireGuard peer config
    ├── protonwg0.env            # PROTON_WG_* vars + FVPN_TUNNEL_ID/MARK/IPSET/IPV6
    ├── protonwg0.macs           # persistent MAC list for this tunnel (one per line)
    ├── (protonwg1..protonwg3 same)
    └── mangle_rules.sh          # firewall include: proton-wg mangle + DNS rules (regenerated on every change)

/etc/init.d/
├── fvpn-protonwg                # boot-time starter for proton-wg processes
├── vpn-client                   # GL.iNet-provided; manages kernel WG + OVPN
└── fvpn-adblock                 # LEGACY — cleaned up on first sync (ignore)

/usr/bin/proton-wg               # proton-wg binary (wireguard-go fork)

/etc/sysctl.d/99-fvpn-ipv6.conf  # persists IPv6 kernel enable

/tmp/
├── dnsmasq.d/                   # main dnsmasq conf-dir
│   ├── fvpn-adblock             # main adblock snippet (if adblock enabled for no-VPN)
│   └── fvpn_bypass.conf         # dnsmasq ipset= lines for bypass domains
├── dnsmasq.d.<iface>/           # per-tunnel dnsmasq conf-dir (wgclient1..4, protonwg0..3)
│   └── fvpn-adblock             # per-tunnel adblock snippet (if adblock enabled on that profile)
├── resolv.conf.d/
│   └── resolv.conf.<iface>      # per-tunnel resolv file (proton-wg only)
└── <iface>.log                  # proton-wg process stderr/stdout

/var/etc/
└── dnsmasq.conf.<iface>         # per-tunnel dnsmasq config file (proton-wg only)
```

---

## 2. Groups / Profiles

Groups are the central abstraction. Each group is one of three types.

### 2.1 VPN group
Routes assigned devices through a ProtonVPN tunnel.

**Router-side artifacts** (vary by protocol — see §3 for details):
- A UCI entry in `wireguard` or `ovpnclient` (kernel WG / OVPN only) — protonwg has no UCI entry, only files in `/etc/fvpn/protonwg/`.
- A `route_policy.fvpn_rule_<N>` rule (kernel WG / OVPN only — protonwg has no route_policy rule).
- An ipset: `src_mac_<tunnel_id>` or `pwg_mac_<tunnel_id>`.
- `from_mac` UCI list (kernel WG / OVPN) OR `.macs` file (protonwg).
- Per-tunnel dnsmasq instance with its own conf-dir (§16).

### 2.2 NoVPN group (direct / default route)
Devices use the normal WAN path with no fwmark.
- **No router artifacts.** The profile exists only in `profile_store.json`.
- Device-to-NoVPN assignment is stored in the local `device_assignments` dict (see §23).

### 2.3 NoInternet group
LAN-only; WAN blocked. See §9 for full details.

### Where name, health, kill switch live

Per [docs/source-of-truth.md](source-of-truth.md):
- **Profile name** (router-canonical, atomic 3-write): `route_policy.<rule>.name` + `wireguard.<peer>.name` + `ovpnclient.<client>.name`. For proton-wg there is no route_policy rule; the name lives only in `profile_store.json`.
- **Profile health**: derived live from `wg show <iface> latest-handshakes` or `ifstatus <iface>` at request time — never cached.
- **Kill switch**: `route_policy.<rule>.killswitch='0'|'1'`. Proton-wg has no UCI killswitch flag — kill switch is always-on via the per-tunnel blackhole route (§5).
- **Color, icon, options, server_scope, wg_key, cert_expiry, display_order**: local only.

---

## 3. VPN Tunnel Lifecycle

Three protocol families use three different mechanisms on the router.

### 3.1 Kernel WireGuard UDP (`wireguard`) — managed by GL.iNet `vpn-client`

Slots: `wgclient1`..`wgclient5`. Fwmarks `0x1000`..`0x5000`. Tables 100..104. Peer IDs `peer_9001`..`peer_9050`.

**Create** (`RouterWireguard.upload_wireguard_config`, [backend/router/facades/wireguard.py:36-92](backend/router/facades/wireguard.py#L36-L92)):
```sh
# 1. Write peer config
uci set wireguard.peer_9001=peers
uci set wireguard.peer_9001.group_id='1957'
uci set wireguard.peer_9001.name='<profile name>'
uci set wireguard.peer_9001.address_v4='10.2.0.2/32'
uci set wireguard.peer_9001.private_key='<X25519>'
uci set wireguard.peer_9001.public_key='<X25519 peer pubkey>'
uci set wireguard.peer_9001.end_point='<host>:<port>'
uci set wireguard.peer_9001.allowed_ips='0.0.0.0/0'
uci set wireguard.peer_9001.dns='10.2.0.1'        # or Custom DNS (§11)
uci set wireguard.peer_9001.mtu='1420'
uci set wireguard.peer_9001.persistent_keepalive='25'
uci commit wireguard

# 2. Create route policy rule
uci set route_policy.fvpn_rule_9001=rule
uci set route_policy.fvpn_rule_9001.name='<profile name>'
uci set route_policy.fvpn_rule_9001.enabled='0'
uci set route_policy.fvpn_rule_9001.killswitch='1'
uci set route_policy.fvpn_rule_9001.tunnel_id='300'
uci set route_policy.fvpn_rule_9001.via_type='wireguard'
uci set route_policy.fvpn_rule_9001.peer_id='9001'
uci set route_policy.fvpn_rule_9001.group_id='1957'
uci set route_policy.fvpn_rule_9001.from_type='ipset'
uci set route_policy.fvpn_rule_9001.from='src_mac_300'
uci commit route_policy
```

**Connect** (`RouterTunnel.bring_tunnel_up`, [backend/router/facades/tunnel.py:28-51](backend/router/facades/tunnel.py#L28-L51)):
```sh
uci set route_policy.fvpn_rule_9001.enabled='1'
uci commit route_policy
/etc/init.d/vpn-client restart
```

`vpn-client` (`/etc/init.d/vpn-client`) runs `setup_instance_via.lua` which:
- creates the `wgclient1` network interface,
- starts the kernel WireGuard tunnel,
- inserts the `MARK` iptables rule into the `ROUTE_POLICY` mangle chain,
- creates the routing table + ip rule.

**Disconnect**: set `enabled='0'` → `vpn-client restart`. The facade temporarily sets `killswitch='0'` during the restart to avoid devices losing internet.

**Switch server** — zero-flicker hot-swap. The existing interface and key are kept; only the endpoint/peer pubkey change. See `update_wireguard_peer_live` in [backend/router/facades/wireguard.py:94-147](backend/router/facades/wireguard.py#L94-L147):
```sh
uci set wireguard.peer_9001.private_key='...'
uci set wireguard.peer_9001.public_key='<NEW>'
uci set wireguard.peer_9001.end_point='<NEW>:<port>'
uci commit wireguard
wg set wgclient1 peer <NEW_pubkey> allowed-ips 0.0.0.0/0 endpoint <NEW>:<port> persistent-keepalive 25
wg set wgclient1 peer <OLD_pubkey> remove
```

**Delete**: disable rule → `vpn-client restart` → delete `route_policy.fvpn_rule_*` + `wireguard.peer_*` → `vpn-client restart`.

### 3.2 OpenVPN UDP/TCP (`ovpnclient`) — managed by GL.iNet `vpn-client`

Slots: `ovpnclient1`..`ovpnclient5`. Fwmarks `0xa000`..`0xe000`. Tables 200..204. Client IDs `9051`..`9099` with UCI section name `28216_<N>`.

**Create** ([backend/router/facades/openvpn.py:38-93](backend/router/facades/openvpn.py#L38-L93)):
- Creates `/etc/openvpn/profiles/28216_<N>/config.ovpn` and `/etc/openvpn/profiles/28216_<N>/auth/username_password.txt` (chmod 600).
- Creates `ovpnclient.28216_<N>` UCI section with `group_id='28216'`, `client_id=<N>`, `name`, `path`, `proto`, `client_auth='1'`.
- Creates `route_policy.fvpn_rule_ovpn_<N>` with `via_type='openvpn'`, `client_id=<N>`, `group_id='28216'`, `from='src_mac_<tunnel_id>'`.

**Connect**: same `route_policy.enabled=1` → `vpn-client restart` flow as WG.

**Switch server**: OpenVPN cannot hot-swap. The strategy captures current `from_mac`, section position, and enabled state; deletes the old config; recreates; restores order and device assignments; only re-enables if previously enabled. See [docs/server-switch-internals.md](server-switch-internals.md).

### 3.3 proton-wg (TCP / TLS) — managed entirely by FlintVPN, NOT vpn-client

Slots: `protonwg0`..`protonwg3`. Fwmarks `0x6000`, `0x7000`, `0x9000`, `0xf000`. Tables 1006, 1007, 1009, 1015.

**Critical distinction**: proton-wg has **no `route_policy` rule**. It doesn't appear in `get_flint_vpn_rules()`. Kill switch is always-on via a blackhole route. Device assignments are persisted in `.macs` files on the router, not UCI lists.

**Create** (`RouterProtonWG.upload_proton_wg_config`, [backend/router/facades/proton_wg.py:147-205](backend/router/facades/proton_wg.py#L147-L205)):

Writes three files per tunnel under `/etc/fvpn/protonwg/`:
- `<iface>.conf` — WireGuard config (Interface+Peer sections).
- `<iface>.env` — env vars:
  ```
  PROTON_WG_INTERFACE_NAME=protonwg0
  PROTON_WG_SOCKET_TYPE=tcp      # or tls
  PROTON_WG_SERVER_NAME_STRATEGY=1
  FVPN_TUNNEL_ID=303
  FVPN_MARK=0x6000
  FVPN_IPSET=pwg_mac_303
  FVPN_IPV6=0
  ```
- `<iface>.macs` — empty file; device MACs get appended here.
- Creates `pwg_mac_<tunnel_id>` ipset (`hash:mac`).
- Installs `/etc/init.d/fvpn-protonwg` for boot persistence (see §3.3.1).

**Connect** (`start_proton_wg_tunnel`, [backend/router/facades/proton_wg.py:207-312](backend/router/facades/proton_wg.py#L207-L312)):
```sh
# 1. Sanity check
[ -x /usr/bin/proton-wg ] || fail

# 2. Start proton-wg process in background
( . /etc/fvpn/protonwg/protonwg0.env && \
  export PROTON_WG_INTERFACE_NAME PROTON_WG_SOCKET_TYPE PROTON_WG_SERVER_NAME_STRATEGY && \
  /usr/bin/proton-wg > /tmp/protonwg0.log 2>&1 ) &

# 3. Wait for ip link (up to 5s)

# 4. Apply WG config
wg setconf protonwg0 /etc/fvpn/protonwg/protonwg0.conf

# 5. IP config
ip addr add 10.2.0.2/32 dev protonwg0
ip link set protonwg0 up
# IPv6 (if FVPN_IPV6=1): ip -6 addr add 2a07:b944::2:2/128 dev protonwg0

# 6. Routing table + ip rule
ip route add default dev protonwg0 table 1006
ip route add blackhole default metric 254 table 1006     # KILL SWITCH
ip rule add fwmark 0x6000/0xf000 lookup 1006 priority 6000

# 7. Firewall zone + forwarding via UCI
uci set firewall.fvpn_zone_protonwg0=zone
uci set firewall.fvpn_zone_protonwg0.name='protonwg0'
uci add_list firewall.fvpn_zone_protonwg0.device='protonwg0'
uci set firewall.fvpn_zone_protonwg0.input='DROP'
uci set firewall.fvpn_zone_protonwg0.output='ACCEPT'
uci set firewall.fvpn_zone_protonwg0.forward='REJECT'
uci set firewall.fvpn_zone_protonwg0.masq='1'
uci set firewall.fvpn_zone_protonwg0.mtu_fix='1'
uci set firewall.fvpn_fwd_protonwg0=forwarding
uci set firewall.fvpn_fwd_protonwg0.src='lan'
uci set firewall.fvpn_fwd_protonwg0.dest='protonwg0'
uci commit firewall
/etc/init.d/firewall reload

# 8. Rebuild ALL proton-wg mangle rules (§4, §16)
#    Writes /etc/fvpn/protonwg/mangle_rules.sh and executes it.
# 9. Start per-tunnel dnsmasq (§16)
# 10. Wait for WG handshake
```

**Process targeting** — `pidof proton-wg` returns every proton-wg process. Always filter by env var to identify a specific tunnel:
```sh
pid=$(for p in $(pidof proton-wg); do
  grep -qz 'PROTON_WG_INTERFACE_NAME=protonwg0' /proc/$p/environ && echo $p && break
done)
kill $pid
```
**Never use `killall proton-wg`** — it kills all co-running tunnels.

**Disconnect** (`stop_proton_wg_tunnel`): reverse order — tear down per-tunnel dnsmasq → delete mangle chain `TUNNEL<tid>_ROUTE_POLICY` → remove ip rule + flush table → kill the specific proton-wg process → `ip link del <iface>` → remove firewall zone+forwarding → rebuild mangle script → `firewall reload`.

**Switch server**: rewrite `.conf` file + `wg setconf <iface> <conf>` on live interface (zero-flicker).

**Delete**: best-effort stop → `rm /etc/fvpn/protonwg/<iface>.{conf,env,macs}` → `ipset destroy pwg_mac_<tid>` → rebuild mangle script.

#### 3.3.1 Boot persistence init script

`/etc/init.d/fvpn-protonwg` (START=99, procd-based). On boot:
1. Iterates every `/etc/fvpn/protonwg/*.env` file.
2. Source env, validate `.conf` exists, open procd instance named after the iface.
3. After 3s sleep (detached): `wg setconf`, `ip addr`, `ip link up`, create routing table + ip rule, IPv6 if `FVPN_IPV6=1`, start per-tunnel dnsmasq.
4. After 5s sleep: run `/etc/fvpn/protonwg/mangle_rules.sh` to restore mangle + DNS iptables rules.

Enabled via `ServiceCtl.enable("fvpn-protonwg")`. Check with `/etc/init.d/fvpn-protonwg enabled && echo yes`.

---

## 4. Route Policy Rules and Fwmark Routing

### The `ROUTE_POLICY` mangle chain

Lives in the `mangle` table (created by GL.iNet's `vpn-client` / `rtp2.sh`). Every LAN-side packet is evaluated here. Rule order matters:

```
ROUTE_POLICY
  1  -j FVPN_BYPASS                 # §14 — pre-mark bypass packets with 0x8000 (if enabled)
  2  -j TUNNEL303_ROUTE_POLICY      # proton-wg mangle chain (if protonwg0 UP)
  3  -j TUNNEL304_ROUTE_POLICY
  4  -m set --match-set src_mac_305 src -j MARK --set-xmark 0x1000/0xf000   # vpn-client (WG)
  5  -m set --match-set src_mac_306 src -j MARK --set-xmark 0xa000/0xf000   # vpn-client (OVPN)
  ...
```

Each `TUNNEL<tid>_ROUTE_POLICY` chain (proton-wg only) contains:
```
-m mark --mark 0x0/0xf000 -m set --match-set pwg_mac_303 src -j MARK --set-xmark 0x6000/0xf000
```
The `--mark 0x0/0xf000` condition prevents double-marking (bypass-marked packets keep the bypass mark).

### IP rules (fwmark → table)

```
100:   from all fwmark 0x8000/0xf000 lookup 1008          # VPN bypass (§14)
1000:  from all fwmark 0x1000/0xf000 lookup 100           # wgclient1 (vpn-client)
1000:  from all fwmark 0x2000/0xf000 lookup 101           # wgclient2
...
2000:  from all fwmark 0xa000/0xf000 lookup 200           # ovpnclient1
...
6000:  from all fwmark 0x6000/0xf000 lookup 1006          # protonwg0 (FlintVPN)
6000:  from all fwmark 0x7000/0xf000 lookup 1007
6000:  from all fwmark 0x9000/0xf000 lookup 1009
6000:  from all fwmark 0xf000/0xf000 lookup 1015
```

### Per-tunnel routing tables

Each table contains two routes:
```
default dev <iface>                     # tunnel route
blackhole default metric 254            # kill switch (§5)
```

The blackhole has a higher metric, so while the tunnel interface is up, `default dev <iface>` wins. If the interface goes down, only the blackhole remains → packets are dropped (kill switch).

### Anonymous section self-healing

When the GL.iNet UI edits a `route_policy` rule it may replace `fvpn_rule_9001` with `@rule[4]`. `RouterPolicy.heal_anonymous_rule_section` ([backend/router/facades/policy.py:61-75](backend/router/facades/policy.py#L61-L75)) calls `uci rename route_policy.@rule[4]=fvpn_rule_9001`. Triggered when the backend sees an anon section whose `group_id` matches `1957` or `28216`.

### Rule order (display order)

`route_policy` section order = VPN display order. `reorder_vpn_rules` calls `uci reorder route_policy.<rule>=<index>`. Proton-wg is not in route_policy → has no section order; display order is local-only.

### Global `forwarding_rule` iptables ACCEPT

Because zones other than `lan` don't have forwarding entries to the VPN tunnel zones (`wgclient*`, `ovpnclient*`, `protonwgN`), a global catch-all in `forwarding_rule` allows all fwmark-marked traffic through:
```
-m mark ! --mark 0x0/0xf000 -j ACCEPT
```
Written by `/etc/fvpn/lan_access_rules.sh` (§20) and inserted into the `forwarding_rule` filter chain.

---

## 5. Kill Switch

### Kernel WG + OpenVPN
UCI-based: `route_policy.<rule>.killswitch='1'`. vpn-client reads this and inserts a blackhole route into the per-tunnel table when the tunnel is down. The `route_policy.killswitch` flag is also the SSE source of truth.

**Inspect**: `uci get route_policy.fvpn_rule_9001.killswitch`

**Gotcha**: `bring_tunnel_down` temporarily sets killswitch='0' during the `vpn-client restart` so devices don't lose internet if the user is just stopping the tunnel, then restores it. See [backend/router/facades/tunnel.py:53-77](backend/router/facades/tunnel.py#L53-L77).

### Proton-wg
**Always on.** No UCI flag. Enforced by the blackhole route in the tunnel's table:
```sh
ip route add blackhole default metric 254 table 1006
```
If `protonwg0` goes down, `default dev protonwg0` disappears → blackhole wins → fwmark-marked packets are dropped (no WAN leak).

**Inspect**: `ip route show table 1006` → expect `blackhole default metric 254`.

---

## 6. Device Assignments

Device-to-profile links. Three paths depending on target profile type.

### 6.1 VPN (kernel WG / OVPN) — router-canonical

State lives in **both** the UCI `from_mac` list and the kernel ipset. Changes touch both for persistence + immediate effect:

```sh
# Add
uci add_list route_policy.fvpn_rule_9001.from_mac='aa:bb:cc:dd:ee:ff'
uci commit route_policy
ipset add src_mac_300 aa:bb:cc:dd:ee:ff -exist

# Remove (case of token in from_mac must match exactly!)
uci del_list route_policy.fvpn_rule_9001.from_mac='<exact-case>'
uci commit route_policy
ipset del src_mac_300 <mac> 2>/dev/null
```

Code: `RouterDevices.set_device_vpn` / `remove_device_from_vpn` ([backend/router/facades/devices.py:262-330](backend/router/facades/devices.py#L262-L330)).

**Case sensitivity gotcha**: UCI `del_list` requires exact case match. GL.iNet UI may store upper-case; we store lower-case. `from_mac_tokens()` preserves case.

**vpn-client restart flushes `src_mac_*`** — on restart, vpn-client re-populates them from UCI `from_mac`. So `from_mac` is the durable source; ipset is a cache.

### 6.2 VPN (proton-wg) — router .macs file + ipset

`src_mac_*` ipsets are flushed by vpn-client restart. To insulate proton-wg device assignments, they use `pwg_mac_*` (distinct prefix) plus a persistent `.macs` file:

```sh
# Add
echo 'aa:bb:cc:dd:ee:ff' >> /etc/fvpn/protonwg/protonwg0.macs   # idempotent with grep -qxF check
ipset add pwg_mac_303 aa:bb:cc:dd:ee:ff -exist

# Remove
sed -i '/^aa:bb:cc:dd:ee:ff$/d' /etc/fvpn/protonwg/protonwg0.macs
ipset del pwg_mac_303 aa:bb:cc:dd:ee:ff 2>/dev/null
```

The `.macs` file is the source of truth: `/etc/fvpn/protonwg/mangle_rules.sh` (firewall include, `reload='1'`) rebuilds the ipset from `.macs` on every firewall reload:
```sh
ipset create pwg_mac_303 hash:mac -exist
ipset flush pwg_mac_303
while IFS= read -r mac; do [ -n "$mac" ] && ipset add pwg_mac_303 "$mac" -exist; done < /etc/fvpn/protonwg/protonwg0.macs
```

Code: `RouterProtonWG.{add,remove,write}_tunnel_macs` ([backend/router/facades/proton_wg.py:47-83](backend/router/facades/proton_wg.py#L47-L83)).

### 6.3 Non-VPN (NoVPN / NoInternet) — local store

`profile_store.json` → `device_assignments: {"aa:bb:cc:dd:ee:ff": "<profile_uuid>"}`.

Only NoInternet propagates to the router (via `fvpn_noint_macs` ipset — see §9). NoVPN is entirely local; the router doesn't know about it.

### 6.4 Reconciliation

`RouterDevices.get_device_assignments()` returns `{mac: rule_name}` merged from `route_policy.*.from_mac` across all FlintVPN rules. `remove_device_from_all_vpn` ([backend/router/facades/devices.py:295-329](backend/router/facades/devices.py#L295-L329)) iterates every rule + every `pwg_mac_*` / `src_mac_*` ipset to strip a MAC everywhere.

---

## 7. Device Metadata

### Labels + device class
UCI `gl-client.<section>.alias` + `gl-client.<section>.class`. Canonical on the router — GL.iNet's own UI reads/writes these, so labels round-trip.

Device class values (15 known): `computer`, `phone`, `pad`, `camera`, `watch`, `laptop`, `printer`, `sound`, `television`, `smartappliances`, `games`, `gateway`, `nas`, `server`, `switch`.

**Inspect**: `uci show gl-client | grep -E 'mac|alias|class'`

### Live stats
`ubus call gl-clients list` returns rx/tx bytes, online status, iface (2.4G/5G/cable), IP, name, online_time.

### Signal strength + band detection
```sh
for iface in $(iwinfo | grep ESSID | awk '{print $1}'); do
  echo "IFACE:$iface"; iwinfo $iface assoclist
done
```
Interface naming: `ra*` = 2.4G, `rax*` = 5G.

### Private MAC detection
Done client-side. A MAC is "private" if 2nd hex char ∈ `{2, 6, A, E}` (locally-administered bit set).

### Display name precedence
`gl-client.alias` → DHCP hostname → MAC.

---

## 8. Reserved IP / DHCP Static Lease

User picks an IP → FlintVPN creates a `dhcp.host` UCI section so the MAC always gets that IP.

**Artifacts** ([backend/router/facades/devices.py:363-384](backend/router/facades/devices.py#L363-L384)):
```sh
# Remove any existing host sections for this MAC first (fvpn_ or GL.iNet UI-managed)
uci -q delete dhcp.fvpn_aabbccddeeff 2>/dev/null

# Create new
uci set dhcp.fvpn_aabbccddeeff=host
uci set dhcp.fvpn_aabbccddeeff.mac='aa:bb:cc:dd:ee:ff'
uci set dhcp.fvpn_aabbccddeeff.ip='192.168.8.123'
uci set dhcp.fvpn_aabbccddeeff.name='<hostname>'
uci commit dhcp
/etc/init.d/dnsmasq reload          # runs in background
```

Section name: `fvpn_<mac-without-colons>`. `get_static_leases()` lists them via `uci show dhcp` filtered to `_type=host`.

**Inspect**: `uci show dhcp | grep host` and `cat /tmp/dhcp.leases`.

---

## 9. NoInternet Groups

Assigned devices keep LAN access but cannot reach WAN. Multiple NoInternet profiles can coexist (they're distinguished by local `profile_id`, not by router state).

**Source file**: [backend/router/noint_sync.py](backend/router/noint_sync.py).

### Router artifacts

- **ipset**: `fvpn_noint_macs` (`hash:mac`, dual-stack capable).
- **MACs file**: `/etc/fvpn/noint.macs` — one MAC per line.
- **Include script**: `/etc/fvpn/noint_rules.sh` (`reload='1'`).
- **UCI registration**: `firewall.fvpn_noint_include`.
- **iptables chain**: `FVPN_NOINT` in filter table.
- **Jump**: `FORWARD -j FVPN_NOINT` at position 1.

### Include script content (generated)
```sh
#!/bin/sh
MACS_FILE=/etc/fvpn/noint.macs
IPSET=fvpn_noint_macs
CHAIN=FVPN_NOINT

ipset create "$IPSET" hash:mac -exist
ipset flush "$IPSET"
[ -f "$MACS_FILE" ] && while IFS= read -r mac; do
    [ -n "$mac" ] && ipset add "$IPSET" "$mac" -exist
done < "$MACS_FILE" || true

iptables -N "$CHAIN" 2>/dev/null
iptables -F "$CHAIN"
wan_dev=$(uci get network.wan.device 2>/dev/null || echo "eth1")
iptables -A "$CHAIN" -m set --match-set "$IPSET" src -o "$wan_dev" \
    -j REJECT --reject-with icmp-port-unreachable
iptables -C FORWARD -j "$CHAIN" 2>/dev/null || iptables -I FORWARD 1 -j "$CHAIN"
```

### Sync flow (`sync_noint_to_router`)
1. Collect MACs of devices whose local `profile_store.device_assignments` points to a NoInternet profile.
2. Diff against `ipset list fvpn_noint_macs`.
3. Apply adds/removes via `ipset add/del` (immediate, no reload).
4. Rewrite `/etc/fvpn/noint.macs` (one MAC per line, uppercase).
5. If include is missing, deploy script + `uci set firewall.fvpn_noint_include=include` and trigger `firewall reload`.

### Inspect
```sh
ipset list fvpn_noint_macs
cat /etc/fvpn/noint.macs
iptables -L FVPN_NOINT -n -v
uci show firewall.fvpn_noint_include
```

### Legacy migration
`_migrate_legacy()` deletes these stale names if present: `firewall.fvpn_noint_ips`, `firewall.fvpn_noint_macs`, `firewall.fvpn_noint_block`, `firewall.fvpn_noint_*` per-zone rules, and destroys the old `hash:ip` ipset `fvpn_noint_ips`.

---

## 10. Server Selection, Switching, and Port Override

### Server metadata source of truth
**Proton API**, resolved live by `server_id` (never cached more than ~15 min for loads, ~3h for the full list). The local profile store only keeps `server_id` plus a tiny per-physical-server cache (`endpoint`, `physical_server_domain`, `protocol`).

### Server scope
Three levels stored under `options.server_scope` in the local profile:
- `country_code` (e.g. `"DE"`)
- `city` (e.g. `"Berlin"`)
- `server_id` (pinned exact server)

Plus `features` filter: `streaming`, `p2p`, `secure_core`, `tor`, and (when `secure_core=true`) `entry_country_code`.

### Port override
Per-protocol whitelist (validated against Proton's advertised ports):
- **WG UDP**: 443, 88, 1224, 51820, 500, 4500
- **OpenVPN UDP**: 80, 51820, 4569, 1194, 5060
- **OpenVPN TCP**: 443, 7770, 8443

Writes to the endpoint: `uci set wireguard.peer_N.end_point='<ip>:<port>'` or the `remote` line in the `.ovpn`.

### Switch server
- **Kernel WG**: UCI update + `wg set` on live interface — zero-flicker. See [backend/router/facades/wireguard.py:94-147](backend/router/facades/wireguard.py#L94-L147).
- **OpenVPN**: capture `from_mac`, section order, enabled state → delete → recreate → restore → conditionally re-enable.
- **proton-wg**: rewrite `.conf` + `wg setconf` on live interface.

### Latency probe
Runs **from the router only** (never from Surface Go — it's behind VPN). Uses `curl -w "%{time_connect}"` on port 443 against server entry IPs via SSH.

---

## 11. Custom DNS per profile

**Kernel WireGuard UDP only.** Overrides Proton's 10.2.0.1 with a user-supplied single IPv4 (typically a Pi-hole/AdGuard).

Written to `wireguard.peer_N.dns='<ip>'`. When the tunnel is created the WG config uses this IP in the `[Interface] DNS` directive. On server switch, the same IP is preserved.

Not supported for:
- **proton-wg**: manages DNS separately (per-tunnel dnsmasq redirect, see §16).
- **OpenVPN**: DNS is pushed from the server.

Incompatible with NetShield DNS-level blocking (UI warns).

**Inspect**: `uci get wireguard.peer_9001.dns`

---

## 12. VPN Options

These are part of the Proton cert registration, baked into the WireGuard cert at registration time. Changing them forces a cert refresh on the next save.

- **NetShield** (0/1/2): DNS-level ad/malware blocking. Baked into cert.
- **VPN Accelerator**: Proton speed optimization. Baked into cert.
- **Moderate NAT**: better gaming/P2P. Baked into cert.
- **NAT-PMP**: UPnP-style port forwarding. Baked into cert.
- **Secure Core**: multi-hop (via CH/SE/IS). Baked into cert AND affects server selection.
- **Tor**: Tor exit. Affects server selection. Mutually exclusive with Secure Core.

None of these options have direct router-level UCI keys — they live only in `profile_store.json` under `options` and shape the cert/config generation at creation time. The router just sees the resulting WG or OVPN config.

---

## 13. Smart Protocol

Automatic protocol fallback. If the tunnel doesn't reach `green`/`amber` within 45s, cycle through: WG UDP → OVPN UDP → OVPN TCP → WG TCP → WG TLS.

Router-side effect: each attempt goes through the normal create/delete/connect flow for a protocol. Smart Protocol is orchestrated in `vpn_service.py` via the SSE tick; the router doesn't know it's happening. Slot availability (§3) is checked before each attempt.

Tor and Secure Core profiles skip Smart Protocol entirely (they're WG-only on Proton).

Cancel triggers (no retry): explicit disconnect, profile delete, type change away from VPN.

Reference: [docs/smart-protocol.md](smart-protocol.md).

---

## 14. VPN Bypass Exceptions

Route specific traffic (IP/CIDR, domain, or port) directly via WAN, bypassing any VPN tunnel.

Source: [backend/router/facades/vpn_bypass.py](backend/router/facades/vpn_bypass.py).

### Constants
- **Mark**: `0x8000` with mask `0xf000`
- **Table**: `1008`
- **Priority**: `100` (ip rule)
- **Chain**: `FVPN_BYPASS` (mangle)
- **ipset prefix**: `fvpn_byp_`
- **Script**: `/etc/fvpn/vpn_bypass.sh`
- **dnsmasq conf**: `/tmp/dnsmasq.d/fvpn_bypass.conf`

### Rule shape
Each exception contains rule_blocks. Rules **within** a block are ANDed (one iptables rule with multiple `-m` matches). Blocks **between** each other are ORed (separate iptables rules). Scope is `global`, `group`, `device`, or `custom` (mixed list of group UUIDs and MACs).

### Router flow (`apply_all`)
1. **ipsets** — one `hash:net` per rule block containing CIDRs (`fvpn_byp_<short_exc_id>_b<block_index>`).
2. **Jump chain** — drop old jump, create `FVPN_BYPASS`, flush it.
3. **Per-block rules** — generate `iptables -A FVPN_BYPASS <src_match> [-m set --match-set <ipset> dst] [-p tcp/udp -m multiport --dports ...] -j MARK --set-xmark 0x8000/0xf000`.
   - Source match: `""` (global) OR `-m mac --mac-source <MAC>` (device) OR `-m set --match-set <group_ipset> src` (group).
4. **Insert chain jump** — `iptables -t mangle -I ROUTE_POLICY 1 -j FVPN_BYPASS` (must be position 1 so it evaluates **before** any tunnel MARK).
5. **Routing**:
   ```sh
   ip rule add fwmark 0x8000/0xf000 lookup 1008 priority 100
   ip route flush table 1008
   WAN_GW=$(ip route show default | awk '{print $3}' | head -1)
   WAN_DEV=$(ip route show default | awk '{print $5}' | head -1)
   ip route add default via $WAN_GW dev $WAN_DEV table 1008
   ```
6. **Persistence** — write all commands to `/etc/fvpn/vpn_bypass.sh`, register via `uci ensure_firewall_include fvpn_vpn_bypass`.
7. **Domain rules** — write `/tmp/dnsmasq.d/fvpn_bypass.conf` with `ipset=/riotgames.com/pvp.net/.../fvpn_byp_<id>_bN`. **Requires `dnsmasq-full`** (installable via UI). Changes to `ipset=` need a full `/etc/init.d/dnsmasq restart` (SIGHUP isn't enough).

### Presets
Built-in: `lol` (League of Legends) and `valorant`, both bundling Riot AS6507+AS62830 CIDRs + domains + ports. Users can create custom presets stored in `config.json.vpn_bypass.custom_presets`.

### Inspect
```sh
iptables -t mangle -L FVPN_BYPASS -n -v --line-numbers
iptables -t mangle -L ROUTE_POLICY -n -v --line-numbers | head -5    # confirm FVPN_BYPASS at line 1
ipset list | grep fvpn_byp_
ip rule show | grep 0x8000
ip route show table 1008
cat /etc/fvpn/vpn_bypass.sh
cat /tmp/dnsmasq.d/fvpn_bypass.conf
opkg list-installed | grep dnsmasq-full
```

### Cleanup
`cleanup()` removes the `FVPN_BYPASS` chain, destroys every `fvpn_byp_*` ipset, removes the ip rule + flushes table 1008, deletes the dnsmasq conf and script + UCI include, and restarts dnsmasq.

---

## 15. Adblock

DNS-level blocking via hosts-file injection into each relevant dnsmasq instance. Per-profile opt-in via `adblock: true` in `profile_store.json`.

Source: [backend/router/facades/adblock.py](backend/router/facades/adblock.py) and [backend/services/adblock_service.py](backend/services/adblock_service.py).

### Blocklist construction
Downloads and merges selected presets (HaGeZi Light/Multi/Pro/Ultimate/TIF, Steven Black) plus user custom domains. Deduplicates. Writes to `/etc/fvpn/blocklist.hosts` with dual-stack entries:
```
0.0.0.0 <domain>
:: <domain>
```

### Sync (`sync_adblock(ifaces)`)
`ifaces` is a set like `{"wgclient1", "protonwg0", "main"}` where `"main"` means the main LAN dnsmasq (for NoVPN profiles with adblock on).

For each iface in the set:
```sh
echo 'addn-hosts=/etc/fvpn/blocklist.hosts' > /tmp/dnsmasq.d.<iface>/fvpn-adblock
# or /tmp/dnsmasq.d/fvpn-adblock for main
```

Ifaces removed from the set have their snippet deleted. The list of active ifaces is persisted to `/etc/fvpn/adblock_ifaces.txt` so the firewall include can restore snippets.

Firewall include `/etc/fvpn/adblock_rules.sh` (registered as `firewall.fvpn_adblock`, `reload='1'`) iterates `/etc/fvpn/adblock_ifaces.txt` and rewrites snippets on every reload. Then `killall -HUP dnsmasq`.

**Safety invariant**: if `/etc/fvpn/blocklist.hosts` is empty or missing, all snippets are removed — prevents stale blocking after a failed update.

### Reload strategy
- **Added / still active**: `killall -HUP dnsmasq` — picks up hosts file changes.
- **Removed**: `pgrep -f dnsmasq.*<conf> | xargs kill && /usr/sbin/dnsmasq -C /var/etc/<conf>` — a full restart because SIGHUP does not unload an `addn-hosts` directive loaded from a conf-dir file that has since been deleted.

### Main dnsmasq conf name
Main instance: config file is `/var/etc/dnsmasq.conf.cfg01411c` (pattern-matched — the UUID-ish suffix is GL.iNet-generated and stable per device).

### Inspect
```sh
cat /etc/fvpn/adblock_ifaces.txt
ls /tmp/dnsmasq.d.*/fvpn-adblock /tmp/dnsmasq.d/fvpn-adblock 2>/dev/null
wc -l /etc/fvpn/blocklist.hosts
head -5 /etc/fvpn/blocklist.hosts
```

### Legacy cleanup
`_cleanup_old_redirect_infra()` removes: `fvpn_adblock_macs` ipset, `fvpn_adblock` nat chain, `/etc/fvpn/dnsmasq-adblock.conf`, `/etc/init.d/fvpn-adblock`, `/etc/fvpn/adblock_macs.txt`. Runs once per session.

---

## 16. Per-tunnel Dnsmasq

Proton-wg tunnels need DNS isolation matching kernel WG/OVPN behaviour — so each protonwg tunnel gets its own dnsmasq instance on a dedicated port + conntrack zone + DNS REDIRECT.

### Port allocation
`port = 2000 + (mark >> 12) * 100 + 53`:
- `protonwg0` mark=0x6000 → **2653**
- `protonwg1` mark=0x7000 → **2753**
- `protonwg2` mark=0x9000 → **2953**
- `protonwg3` mark=0xf000 → **3553**

### Conntrack zone
`zone = int(mark, 16)` — decimal of the mark (e.g. 0x6000 → 24576).

### Per-tunnel config files
- `/var/etc/dnsmasq.conf.<iface>` — the dnsmasq config (`port=2653`, `bind-dynamic`, `cache-size=1000`, `resolv-file=/tmp/resolv.conf.d/resolv.conf.<iface>`, `conf-dir=/tmp/dnsmasq.d.<iface>`).
- `/tmp/resolv.conf.d/resolv.conf.<iface>` — contains `nameserver 10.2.0.1` (Proton's DNS via the tunnel).
- `/tmp/dnsmasq.d.<iface>/` — conf-dir for dynamic snippets (adblock, etc.).

### iptables DNS infrastructure (3 rules per tunnel)
In `/etc/fvpn/protonwg/mangle_rules.sh`:
```sh
iptables -t raw -A pre_dns_deal_conn_zone -p udp ! -i lo -m mark --mark 0x6000/0xf000 \
    -m addrtype --dst-type LOCAL -j CT --zone 24576
iptables -t raw -A out_dns_deal_conn_zone -p udp ! -o lo -m udp --sport 2653 \
    -j CT --zone 24576
iptables -t nat -A policy_redirect -p udp -m mark --mark 0x6000/0xf000 \
    -m addrtype --dst-type LOCAL --dport 53 -j REDIRECT --to-ports 2653
```

These redirect DNS queries from fwmark-marked packets to the per-tunnel dnsmasq, in the correct conntrack zone (so replies from the per-tunnel dnsmasq aren't mismatched by conntrack's default zone).

### Inspect
```sh
ps | grep dnsmasq | grep -E 'protonwg|cfg01411c'
netstat -lunp | grep -E '2653|2753|2953|3553'
iptables -t nat -L policy_redirect -n -v | grep REDIRECT
iptables -t raw -L pre_dns_deal_conn_zone -n -v
```

---

## 17. LAN / Networks

"Networks" = fw3 zones with their own bridge, subnet, DHCP pool, and 0+ SSIDs. Discovered from UCI `wireless`/`network`/`firewall`. Built-in: `lan`, `guest` (GL.iNet-provided). User-created via FlintVPN get the `fvpn_<zone_id>` prefix.

### Zone name limit — **11 characters**
fw3 **silently ignores** zones with names > 11 chars — no error, no warning, no NAT. FlintVPN format: `fvpn_` (5) + `zone_id` (≤6) = ≤11.

### Network creation (`RouterLanAccess.create_network`)
Atomic UCI batch ([backend/router/facades/lan_access.py:426-510](backend/router/facades/lan_access.py#L426-L510)). For zone_id `iot` creating network `IoT`:

```
wireless.fvpn_iot_2g  (wifi-iface, device=mt798611, network=fvpn_iot, ifname=ra<N>, ssid=IoT, encryption=psk2)
wireless.fvpn_iot_5g  (wifi-iface, device=mt798612, network=fvpn_iot, ifname=rax<N>, ssid=IoT-5G, encryption=psk2)
network.fvpn_iot       (interface, proto=static, type=bridge, ipaddr=192.168.<subnet>.1, netmask=255.255.255.0,
                        force_link=1, bridge_empty=1, ip6assign=64, ip6hint=<next>, ip6ifaceid=::1)
firewall.fvpn_iot_zone (zone, name=fvpn_iot, network=fvpn_iot, input=REJECT, output=ACCEPT, forward=REJECT)
firewall.fvpn_iot_dhcp (rule, Allow-DHCP-fvpn_iot, src=fvpn_iot, proto=udp, dest_port=67-68, target=ACCEPT)
firewall.fvpn_iot_dns  (rule, Allow-DNS-fvpn_iot, src=fvpn_iot, proto=tcpudp, dest_port=53, target=ACCEPT)
firewall.fvpn_iot_mdns (rule, Allow-mDNS-fvpn_iot, src=fvpn_iot, proto=udp, dest_port=5353, target=ACCEPT)
firewall.fvpn_iot_wan  (forwarding, src=fvpn_iot, dest=wan)
dhcp.fvpn_iot          (dhcp, interface=fvpn_iot, start=100, limit=150, leasetime=12h, dhcpv6=server, ra=server, ra_default=1)
```

Then: increment `BssidNum` in both `.dat` files, `ifup fvpn_iot`, and **full WiFi driver reload** (see below).

### Subnet picker
`_pick_subnet()` iterates `192.168.10.1` … `192.168.254.1` and returns the first third-octet not in use by an existing network.

### MediaTek WiFi driver constraint
MediaTek's `mt_wifi` kernel module reads `BssidNum` from `.dat` files **only at module load time**. `wifi reload` and `wifi down/up` do NOT re-load the module, so new `ra<N>`/`rax<N>` interfaces never appear.

**Required** on create/delete: full driver cycle:
```sh
wifi down
rmmod mtk_warp_proxy
rmmod mt_wifi
sleep 1
insmod mt_wifi
insmod mtk_warp_proxy
sleep 1
wifi up
/etc/init.d/firewall reload
/etc/init.d/dnsmasq reload
```
Consequence: **~15 s WiFi outage for all clients on all bands**. Unavoidable. Must run detached (`&`) over SSH — WiFi drop kills the SSH session.

**.dat paths** (MT7986, active):
- `/etc/wireless/mediatek/mt7986-ax6000.dbdc.b0.dat` (2.4G, `BssidNum=`)
- `/etc/wireless/mediatek/mt7986-ax6000.dbdc.b1.dat` (5G, `BssidNum=`)

Max BSSIDs per radio: 4 (`ra0`..`ra3`, `rax0`..`rax3`).

### Radio UCI device names (Flint 2)
- `mt798611` — 2.4 GHz radio
- `mt798612` — 5 GHz radio

### VPN routing across bridges
The VPN mangle chain matches `br-+` (bridge wildcard), so MAC-based ipset matching works on **any** bridge — no per-network change needed for VPN.

### Inspect
```sh
uci show network | grep -E 'interface|ipaddr|device'
uci show wireless | grep -E 'wifi-iface|ssid|device'
uci show firewall | grep -E 'zone|forwarding'
brctl show
ip -br addr
cat /tmp/dhcp.leases
grep BssidNum /etc/wireless/mediatek/mt7986-ax6000.dbdc.b*.dat
```

---

## 18. AP Isolation

Per-SSID `wireless.*.isolate='0'|'1'`. When enabled, WiFi clients on the same SSID cannot communicate at L2 — all traffic goes through the router. Applied to every SSID in a zone simultaneously.

```sh
uci set wireless.fvpn_iot_2g.isolate='1'
uci set wireless.fvpn_iot_5g.isolate='1'
uci commit wireless
wifi reload       # briefly reconnects affected bands; fast — no driver reload needed
```

---

## 19. Cross-Network Access Rules (Zone Forwarding)

Traffic between fw3 zones is controlled by `firewall.forwarding` UCI entries. Presence = allowed; absence = blocked.

### Add
```sh
uci add firewall forwarding
uci set firewall.@forwarding[-1].src='fvpn_iot'
uci set firewall.@forwarding[-1].dest='lan'
uci commit firewall
/etc/init.d/firewall reload
```

### Remove
```sh
uci delete firewall.<section_name>      # discovered from uci show
uci commit firewall
/etc/init.d/firewall reload
```

Code: `RouterLanAccess.set_zone_forwarding` ([backend/router/facades/lan_access.py:192-214](backend/router/facades/lan_access.py#L192-L214)).

Router UCI is the source of truth for forwarding state; `config.json.lan_access.rules` stores UI intent.

### Inspect
```sh
uci show firewall | grep -E 'forwarding|=zone' | head -50
```

---

## 20. Device Exceptions (LAN access)

When cross-network traffic is blocked at the zone level, specific device IP pairs can be exempted.

### Router artifacts
- Script: `/etc/fvpn/lan_access_rules.sh` (firewall include, `fvpn_lan_access`).
- iptables+ip6tables chain: `fvpn_lan_exc` in filter table.
- Jump into `forwarding_rule` filter chain:
  ```sh
  iptables -I forwarding_rule 1 -j fvpn_lan_exc
  iptables -I forwarding_rule -m mark ! --mark 0x0/0xf000 -j ACCEPT     # Global VPN pass-through
  ```

### Per-exception rule
For each exception with `from_ip`, `to_ip`, and `direction`:
```sh
iptables -A fvpn_lan_exc -s 192.168.8.42 -d 192.168.20.100 -j ACCEPT     # outbound/both
iptables -A fvpn_lan_exc -s 192.168.20.100 -d 192.168.8.42 -j ACCEPT     # inbound/both
```

IPv6 exceptions use `ip6tables` with the same structure.

### Persistence
Written to `/etc/fvpn/lan_access_rules.sh` and registered with fw3 via `ensure_firewall_include("fvpn_lan_access", ...)`. Re-applied by `LanAccessService.reapply_all()` on unlock.

### Stale exception pruning
On unlock, exceptions whose IPs no longer belong to any current subnet, and forwarding rules whose zones no longer exist, are pruned. See `_prune_stale_lan_config` in [backend/services/lan_access_service.py](backend/services/lan_access_service.py).

### Inspect
```sh
iptables -L fvpn_lan_exc -n -v
iptables -L forwarding_rule -n -v --line-numbers | head -5
cat /etc/fvpn/lan_access_rules.sh
```

---

## 21. mDNS Reflection

Allows devices on separate networks (e.g. printer on `fvpn_iot`, phone on `lan`) to discover each other via Bonjour/AirPrint.

Source: `RouterFirewall.setup_mdns_for_networks` ([backend/router/facades/firewall.py:167-253](backend/router/facades/firewall.py#L167-L253)). Runs on unlock and after network create/delete.

### Router artifacts
- **avahi-daemon config**: `/etc/avahi/avahi-daemon.conf`:
  - `enable-reflector=yes`
  - `allow-interfaces=br-lan,br-guest,br-fvpn_iot,...` (explicit whitelist — avoids duplicate packets on WiFi + bridge)
- **firewall rules**: `Allow-mDNS-<zone>` (udp dport 5353, target ACCEPT) for zones with `input=REJECT|DROP` (`lan` has `input=ACCEPT` so doesn't need one). Section name: `<zone>_mdns`.

### Apply
```sh
sed -i 's/enable-reflector=no/enable-reflector=yes/' /etc/avahi/avahi-daemon.conf
sed -i '/^allow-interfaces=/d' /etc/avahi/avahi-daemon.conf
sed -i '/^\[server\]/a allow-interfaces=br-lan,br-guest,br-fvpn_iot' /etc/avahi/avahi-daemon.conf
/etc/init.d/avahi-daemon restart
# Plus one firewall rule per reject-input zone, then firewall reload.
```

---

## 22. IPv6 Dual-Stack

Managed by FlintVPN because vpn-client is IPv4-only.

### Router-level IPv6
- Kernel enable: `sysctl net.ipv6.conf.all.disable_ipv6=0` persisted in `/etc/sysctl.d/99-fvpn-ipv6.conf`.
- WAN6: `network.wan6.disabled='0'`, `network.wan6.proto='dhcpv6'`, `network.wan.ipv6='1'`.
- Applied via `RouterFirewall.ensure_ipv6_router_enabled`.

### Per-network IPv6 (LAN side)
- `network.<iface>.ip6assign='64'` + `ip6hint=<next>` + `ip6ifaceid='::1'` (allocates a /64 from ULA).
- `dhcp.<iface>.dhcpv6='server'`, `ra='server'`, `ra_default='1'`, `ra_flags=['other-config','managed-config']`.

### IPv6 leak prevention
- FORWARD default DROP; only `ESTABLISHED,RELATED` allowed by default.
- Per-tunnel selective accept: `ip6tables -A FORWARD -m mark --mark <mark>/0xf000 -o <iface> -j ACCEPT`.
- Written to `/etc/fvpn/ipv6_forward.sh` (include `fvpn_ipv6_fwd`, `reload='1'`).

### IPv6 mangle
`ip6tables -t mangle` chain `FVPN_V6_<tid>` per tunnel, inserted into `ROUTE_POLICY` at position 1. Same MAC→mark logic as IPv4. Written to `/etc/fvpn/ipv6_mangle_rules.sh` (include `fvpn_ipv6_mangle`, `reload='1'`). Covers both proton-wg tunnels (`.env` driven) and vpn-client tunnels (mark computed as `0x1000 + tunnel_id`).

### Proton-wg IPv6
When `FVPN_IPV6=1` in a tunnel's `.env`: add `2a07:b944::2:2/128` on the interface, add `default dev <iface>` + blackhole in the v6 table, add `fwmark` v6 rule. DNS via Proton's `2a07:b944::2:1`.

---

## 23. Profile Store Backup

The router is the **source of truth** for `profile_store.json`. On every unlock, the app pulls `/etc/fvpn/profile_store.bak.json` and overwrites local. Rules:

- Backup exists + valid JSON → always restore (router wins).
- No backup on router → reset local to empty (new router = clean slate).
- Backup unparseable → leave local alone.
- SSH read failure → leave local alone.

During normal operation, every `profile_store.save()` pushes the updated store back to the router via a registered callback. See [docs/source-of-truth.md](source-of-truth.md) for full semantics.

---

## 24. Firewall Include Scripts

OpenWrt's fw3 supports external firewall include scripts. FlintVPN uses them so our rules survive every `firewall reload` without requiring the app to be running.

All FlintVPN includes use `option reload '1'` — they re-run on `firewall reload` (not just `firewall start`). GL.iNet's own `vpnclient` include uses `reload='0'` — it only runs on start — which is why:

- `/etc/init.d/firewall reload` is **safe**: ~0.22 s, our includes re-run, `vpnclient` include (rtp2.sh) does NOT, kernel WG interfaces survive.
- `/etc/init.d/firewall restart` is **dangerous**: full stop+start, re-runs `rtp2.sh`, which tears down our interfaces and corrupts WG handshakes. **Never use** restart.

### All FlintVPN includes

| UCI section | Path | Purpose |
|---|---|---|
| `firewall.fvpn_pwg_mangle` | `/etc/fvpn/protonwg/mangle_rules.sh` | Rebuild proton-wg mangle + DNS rules (§3.3, §16) |
| `firewall.fvpn_vpn_bypass` | `/etc/fvpn/vpn_bypass.sh` | Rebuild bypass chain + ipsets + routing (§14) |
| `firewall.fvpn_adblock` | `/etc/fvpn/adblock_rules.sh` | Re-inject adblock snippets + SIGHUP dnsmasq (§15) |
| `firewall.fvpn_noint_include` | `/etc/fvpn/noint_rules.sh` | Rebuild NoInternet chain (§9) |
| `firewall.fvpn_lan_access` | `/etc/fvpn/lan_access_rules.sh` | LAN access exceptions + global fwmark ACCEPT (§20) |
| `firewall.fvpn_ipv6_fwd` | `/etc/fvpn/ipv6_forward.sh` | IPv6 FORWARD rules (§22) |
| `firewall.fvpn_ipv6_mangle` | `/etc/fvpn/ipv6_mangle_rules.sh` | IPv6 mangle MARK rules (§22) |

Registration pattern (`Uci.ensure_firewall_include`, [backend/router/tools/uci.py:125-140](backend/router/tools/uci.py#L125-L140)):
```sh
uci -q get firewall.fvpn_* >/dev/null 2>&1 || (
  uci set firewall.fvpn_* = include && \
  uci set firewall.fvpn_*.type = 'script' && \
  uci set firewall.fvpn_*.path = '<path>' && \
  uci set firewall.fvpn_*.reload = '1' && \
  uci commit firewall
)
```

### Mangle chain ordering invariant

Every unlock / bypass apply / proton-wg start re-inserts `FVPN_BYPASS` and `TUNNEL<tid>_ROUTE_POLICY` chains at position 1 of `ROUTE_POLICY`. If you see bypass rules that aren't working, check:
```sh
iptables -t mangle -L ROUTE_POLICY --line-numbers -n -v | head -10
```
The jump into `FVPN_BYPASS` must be before any `MARK` rules. Proton-wg TUNNEL chains must also be before vpn-client's own `MARK` rules (so the fwmark precedence is respected).

---

## 25. Logs

### Router-side
- `/tmp/protonwg<N>.log` — proton-wg process stderr/stdout (ephemeral, cleared on reboot).
- `/tmp/dnsmasq.log` — DNS queries (if `log-queries` is enabled — default off).
- `/var/log/openvpn/<iface>.log` — OpenVPN tunnel logs.
- `logread` / `logread -f` — OpenWrt system log (dropbear, firewall, vpn-client, wifi events).
- `/tmp/wireguard/<iface>_state` — ephemeral state hint written by vpn-client (`connecting`, etc.).
- `/tmp/dhcp.leases` — current DHCP leases (`<expiry> <mac> <ip> <hostname> <client_id>`).

### App-side (on Surface Go, at `/home/armaaar/flint-vpn-manager/backend/logs/`)
- `app.log` — connect/disconnect, create/delete, assignments.
- `error.log` — exceptions and stack traces.
- `access.log` — HTTP API access.

---

## 26. Safe vs Unsafe Commands

### SAFE (read-only — run any time)
```
uci show <config>                       # e.g. uci show firewall
uci get <path>
wg show [<iface>] [latest-handshakes|transfer|peers]
ifstatus <iface>
ip link show
ip addr show
ip route show [table N]
ip rule show
ip -6 route / ip -6 rule
ipset list [<name>]
iptables -L [<chain>] -t [filter|nat|mangle|raw] -n -v
ip6tables -L / -S
ubus call gl-clients list
ubus call network.interface.<iface> status
cat /etc/config/<config>
cat /tmp/dhcp.leases
ls /etc/fvpn/
pidof proton-wg
ps / ps aux
iwinfo [<iface>] assoclist
logread | tail -200
opkg list-installed | grep <pkg>
```

### SAFE with caveats
```
uci set / uci delete / uci add_list / uci del_list / uci commit <config>
    — always commit after changes. No immediate effect on most kernel state —
    most UCI changes need a service reload (firewall / dnsmasq / network / vpn-client)
    to propagate, and not all reloads are safe.

/etc/init.d/firewall reload        # SAFE — ~0.22s, WG survives
/etc/init.d/dnsmasq reload         # SAFE — fast SIGHUP-equivalent
/etc/init.d/dnsmasq restart        # SAFE — needed after ipset= config changes or restarting per-tunnel instances
/etc/init.d/avahi-daemon restart   # SAFE — briefly interrupts mDNS
/etc/init.d/vpn-client restart     # SAFE only when no tunnels stuck connecting.
                                   # FLUSHES all src_mac_* ipsets (rebuilt from UCI from_mac).
                                   # Does NOT touch pwg_mac_* (proton-wg uses distinct prefix).
ipset add/del/create/destroy      # SAFE — idempotent when used with -exist / 2>/dev/null
wifi reload                        # SAFE — briefly reconnects affected bands
wg set/setconf <iface> ...         # SAFE — no tunnel teardown

/etc/init.d/fvpn-protonwg start|stop|restart|enable|disable   # SAFE
```

### UNSAFE — will disrupt the network
```
/etc/init.d/network reload / restart     # BRICKS routing, disconnects all clients
/etc/init.d/firewall restart             # RUNS rtp2.sh, tears down our interfaces, corrupts WG handshakes
rtp2.sh                                  # Same as firewall restart
ifup / ifdown <iface>                    # Bypasses vpn-client, can create catch-all routes
conntrack -D                             # Kills active connections
killall proton-wg                        # KILLS ALL proton-wg tunnels simultaneously
                                         # ALWAYS filter by PROTON_WG_INTERFACE_NAME via /proc/PID/environ
wifi down (without bringing it back up)  # Disconnects every WiFi client
```

### CRITICAL — data loss / brick potential
```
rm -rf /etc/config/*                     # Wipes all router config
rm -rf /etc/fvpn/*                       # Wipes FlintVPN state: profile backup, adblock, bypass, noint, protonwg
sysupgrade / firstboot / jffs2reset      # Factory reset / full wipe
uci delete route_policy                  # Removes every FlintVPN VPN rule
```

---

## 27. Router Artifact Index

Reverse lookup: given an artifact you found on the router, which feature owns it.

### UCI configs

| Config | Section pattern | Feature |
|---|---|---|
| `/etc/config/route_policy` | `fvpn_rule_<N>` | Kernel WG VPN group (§3.1, §4, §5, §6) |
| `/etc/config/route_policy` | `fvpn_rule_ovpn_<N>` | OpenVPN VPN group (§3.2, §4, §5, §6) |
| `/etc/config/wireguard` | `peer_9001..peer_9050` | Kernel WG peer config (§3.1) |
| `/etc/config/ovpnclient` | `28216_9051..28216_9099` | OpenVPN client config (§3.2) |
| `/etc/config/firewall` | `fvpn_zone_protonwg<N>` | Proton-wg firewall zone (§3.3) |
| `/etc/config/firewall` | `fvpn_fwd_protonwg<N>` | Proton-wg lan→tunnel forwarding (§3.3) |
| `/etc/config/firewall` | `fvpn_<zid>_zone` | User-created LAN zone (§17) |
| `/etc/config/firewall` | `fvpn_<zid>_{dhcp,dns,mdns,wan}` | User-created LAN firewall rules (§17, §21) |
| `/etc/config/firewall` | `fvpn_*_mdns` | mDNS reflection firewall rule (§21) |
| `/etc/config/firewall` | `fvpn_noint_include`, `fvpn_vpn_bypass`, `fvpn_adblock`, `fvpn_pwg_mangle`, `fvpn_lan_access`, `fvpn_ipv6_fwd`, `fvpn_ipv6_mangle` | Firewall include registrations (§24) |
| `/etc/config/network` | `fvpn_<zid>` | User-created LAN interface (§17) |
| `/etc/config/network` | `wan6` (managed) | IPv6 WAN (§22) |
| `/etc/config/wireless` | `fvpn_<zid>_2g`, `fvpn_<zid>_5g` | User-created SSIDs (§17) |
| `/etc/config/wireless` | `<iface>.isolate` | AP isolation (§18) |
| `/etc/config/dhcp` | `fvpn_<zid>` | User-created DHCP pool (§17) |
| `/etc/config/dhcp` | `fvpn_<mac>` (host) | Reserved IP (§8) |
| `/etc/config/gl-client` | `.alias`, `.class` | Device label + type (§7) |

### Files under `/etc/fvpn/`
See §1 for the full tree. Each file section cross-referenced above in §9, §14, §15, §20, §22, §24.

### iptables chains

| Chain | Table | Feature | Source |
|---|---|---|---|
| `ROUTE_POLICY` | mangle | VPN routing master chain (GL.iNet) | — |
| `FVPN_BYPASS` | mangle | VPN bypass pre-mark (§14) | `/etc/fvpn/vpn_bypass.sh` |
| `TUNNEL<tid>_ROUTE_POLICY` | mangle | Per-proton-wg-tunnel MARK (§3.3) | `/etc/fvpn/protonwg/mangle_rules.sh` |
| `FVPN_NOINT` | filter | NoInternet WAN block (§9) | `/etc/fvpn/noint_rules.sh` |
| `fvpn_lan_exc` | filter | LAN device exceptions (§20) | `/etc/fvpn/lan_access_rules.sh` |
| `FVPN_V6_<tid>` | mangle (ip6tables) | IPv6 per-tunnel MARK (§22) | `/etc/fvpn/ipv6_mangle_rules.sh` |
| `forwarding_rule` | filter | VPN fwmark accept + lan_exc jump | `/etc/fvpn/lan_access_rules.sh` |
| `policy_redirect` | nat | Per-tunnel DNS REDIRECT (GL.iNet chain, we append to it, §16) | `/etc/fvpn/protonwg/mangle_rules.sh` |
| `pre_dns_deal_conn_zone` / `out_dns_deal_conn_zone` | raw | DNS conntrack zones per tunnel (GL.iNet chains, we append, §16) | `/etc/fvpn/protonwg/mangle_rules.sh` |

### ipsets

| Name | Type | Feature |
|---|---|---|
| `src_mac_<300-399>` | hash:mac | Kernel WG/OVPN device assignment (§6.1) |
| `pwg_mac_<300-399>` | hash:mac | Proton-wg device assignment (§6.2) |
| `fvpn_noint_macs` | hash:mac | NoInternet MACs (§9) |
| `fvpn_byp_<id>_b<N>` | hash:net | VPN bypass CIDRs + domain-resolved IPs (§14) |

### Routing tables

| Table # | Feature |
|---|---|
| 100..104 | wgclient1..5 (vpn-client kernel WG) |
| 200..204 | ovpnclient1..5 (vpn-client OVPN) |
| 1006, 1007, 1009, 1015 | protonwg0..3 (FlintVPN) |
| 1008 | VPN bypass (§14) — routes 0x8000-marked via WAN |

### Fwmarks (lower 16 bits, mask 0xf000)

| Mark | Owner |
|---|---|
| 0x0000 | No FlintVPN involvement (WAN default) |
| 0x1000..0x5000 | vpn-client kernel WG tunnels 1..5 |
| 0x6000 | protonwg0 |
| 0x7000 | protonwg1 |
| 0x8000 | VPN bypass (pre-mark) |
| 0x9000 | protonwg2 |
| 0xa000..0xe000 | vpn-client OVPN tunnels 1..5 |
| 0xf000 | protonwg3 |

### Ports

| Port | Feature |
|---|---|
| 53 (UDP) | Main dnsmasq (DNS) |
| 2653 | protonwg0 per-tunnel dnsmasq |
| 2753 | protonwg1 per-tunnel dnsmasq |
| 2953 | protonwg2 per-tunnel dnsmasq |
| 3553 | protonwg3 per-tunnel dnsmasq |
| 5353 (UDP) | mDNS (avahi) |

---

## 28. Common Debug Recipes

### Is a VPN tunnel actually up?
```sh
# Kernel WG / OVPN
uci get route_policy.fvpn_rule_9001.enabled            # 1 = supposed to be up
uci get route_policy.fvpn_rule_9001.via                # wgclient1 or ovpnclient1 — empty means vpn-client hasn't claimed it
ifstatus wgclient1 | jsonfilter -e '@.up'              # true/false
wg show wgclient1 latest-handshakes                    # tab-separated; unix ts '0' = never
wg show wgclient1 transfer                             # rx/tx bytes

# Proton-wg
pidof proton-wg
for p in $(pidof proton-wg); do grep -z 'PROTON_WG_INTERFACE_NAME' /proc/$p/environ | tr '\0' '\n'; done
ip link show protonwg0
wg show protonwg0 latest-handshakes
```

### Is a device's traffic actually going through the tunnel?
```sh
# 1. Find the device
cat /tmp/dhcp.leases | grep <mac or hostname>
# 2. Is it in any FlintVPN VPN rule's from_mac?
uci show route_policy | grep -i <mac>
# 3. Is it in any VPN ipset?
for s in $(ipset list -n | grep -E 'src_mac_|pwg_mac_'); do
  ipset test $s <mac> 2>&1 | grep "is in set" && echo " └─ in $s"
done
# 4. From the router, trace routing for the device's IP:
ip route get <device_ip>
# 5. Check fwmark is being applied:
iptables -t mangle -L ROUTE_POLICY -n -v --line-numbers | head -10
```

### A feature "should be working" but isn't — mangle chain order
Bypass / tunnel precedence depends on position 1 of `ROUTE_POLICY`:
```sh
iptables -t mangle -L ROUTE_POLICY --line-numbers -n -v | head -10
# Line 1 should be FVPN_BYPASS (if bypass enabled).
# Lines 2..N should be TUNNEL<tid>_ROUTE_POLICY (proton-wg) BEFORE vpn-client MARK rules.
# If ordering is wrong: firewall reload will rebuild from firewall include scripts.
```

### Adblock seems stuck
```sh
# Is the blocklist present and non-empty?
wc -l /etc/fvpn/blocklist.hosts
head -5 /etc/fvpn/blocklist.hosts
# Which dnsmasq instances are configured for adblock?
cat /etc/fvpn/adblock_ifaces.txt
ls /tmp/dnsmasq.d*/fvpn-adblock 2>/dev/null
# Is dnsmasq loading it? (blocking a known adblock domain)
dig @192.168.8.1 doubleclick.net +short    # should return 0.0.0.0
# Force reload
killall -HUP dnsmasq
```

### Kill switch not working
```sh
# Kernel WG / OVPN:
uci get route_policy.fvpn_rule_9001.killswitch        # 1 = on
ip route show table 100                                # blackhole default metric 254 MUST be present
ip rule show | grep 0x1000
# Proton-wg:
ip route show table 1006                               # blackhole default metric 254 MUST be present
ip rule show | grep 0x6000
```

### Ghost / orphan rule cleanup
```sh
# Anonymous section (@rule[N]) that should be fvpn_rule_<peer_id>:
uci show route_policy | grep '=rule'
# Rename back (substitute correct index + target name):
uci rename route_policy.@rule[4]=fvpn_rule_9001 && uci commit route_policy
```

### vpn-client flushed my ipsets
Expected for `src_mac_*`. Check `from_mac` UCI list — that's the durable source:
```sh
uci show route_policy.fvpn_rule_9001.from_mac
# Rebuild ipset manually if vpn-client isn't doing it:
ipset create src_mac_300 hash:mac -exist
for m in $(uci -q get route_policy.fvpn_rule_9001.from_mac); do
  ipset add src_mac_300 "$m" -exist
done
```

For `pwg_mac_*` ipsets, run `/etc/fvpn/protonwg/mangle_rules.sh` to rebuild from the `.macs` files.

### A device disappeared from its proton-wg assignment after reboot
Check the `.macs` file:
```sh
cat /etc/fvpn/protonwg/*.macs
# Run the mangle script — it rebuilds ipsets from .macs:
/etc/fvpn/protonwg/mangle_rules.sh
ipset list pwg_mac_303
```

### Firewall include didn't run
```sh
# Is the include registered?
uci show firewall | grep '=include'
# Does the path exist + executable?
ls -la /etc/fvpn/*.sh /etc/fvpn/protonwg/mangle_rules.sh
# Run it manually to see errors:
sh -x /etc/fvpn/vpn_bypass.sh 2>&1 | head -50
```

### Network creation didn't produce new SSID
Most likely the MediaTek driver wasn't reloaded (see §17). Verify:
```sh
grep BssidNum /etc/wireless/mediatek/mt7986-ax6000.dbdc.b*.dat
iwinfo | grep ESSID              # count of interfaces
# If BssidNum was bumped but no new ra<N>/rax<N> appeared, full driver reload is needed:
# wifi down; rmmod mtk_warp_proxy; rmmod mt_wifi; sleep 1; insmod mt_wifi; insmod mtk_warp_proxy; sleep 1; wifi up
# (cause ~15s outage — user-visible)
```

### Route policy rule is disabled but tunnel is still up
vpn-client keeps interfaces until restart. After disabling a rule:
```sh
uci set route_policy.fvpn_rule_9001.enabled='0'
uci commit route_policy
/etc/init.d/vpn-client restart        # SAFE (see §26)
```

### Collect a diagnostic snapshot
```sh
# Run this one-liner over SSH to get a full picture:
echo "=== uci route_policy ==="; uci show route_policy
echo "=== uci wireguard (fvpn only) ==="; uci show wireguard | grep '\.peer_9'
echo "=== uci ovpnclient (fvpn only) ==="; uci show ovpnclient | grep '\.28216_'
echo "=== uci firewall (fvpn includes + zones) ==="; uci show firewall | grep -E 'fvpn_|include'
echo "=== wg show ==="; wg show
echo "=== ip rule ==="; ip rule show; echo "— ipv6:"; ip -6 rule show
echo "=== ip route (all tables) ==="; ip route show table all | head -100
echo "=== mangle ROUTE_POLICY ==="; iptables -t mangle -L ROUTE_POLICY -n -v --line-numbers
echo "=== FVPN_BYPASS ==="; iptables -t mangle -L FVPN_BYPASS -n -v --line-numbers 2>/dev/null
echo "=== FVPN_NOINT ==="; iptables -L FVPN_NOINT -n -v 2>/dev/null
echo "=== ipsets ==="; ipset list -n; for s in $(ipset list -n | grep -E '^(src_mac_|pwg_mac_|fvpn_)'); do echo "--- $s ---"; ipset list "$s"; done
echo "=== proton-wg processes ==="; for p in $(pidof proton-wg); do echo "PID $p:"; grep -a . /proc/$p/environ | tr '\0' '\n' | grep PROTON_WG; done
echo "=== /etc/fvpn/ ==="; find /etc/fvpn -maxdepth 3 -type f | xargs ls -la
echo "=== DHCP leases ==="; cat /tmp/dhcp.leases
```

---

## References

- [docs/project-overview.md](project-overview.md) — architecture overview
- [docs/terminology.md](terminology.md) — domain glossary
- [docs/source-of-truth.md](source-of-truth.md) — what's router-canonical, Proton-canonical, or local
- [docs/router-reference.md](router-reference.md) — concise naming and limits reference
- [docs/router-layer-internals.md](router-layer-internals.md) — three-layer backend architecture
- [docs/proton-wg-internals.md](proton-wg-internals.md) — proton-wg non-obvious constraints
- [docs/tunnel-strategy-internals.md](tunnel-strategy-internals.md) — Strategy pattern, per-protocol behaviour matrix
- [docs/server-switch-internals.md](server-switch-internals.md) — switch mechanisms
- [docs/smart-protocol.md](smart-protocol.md) — smart protocol fallback
- [docs/FEATURES_AND_SPECS.md](FEATURES_AND_SPECS.md) — user-facing feature specs
- [docs/proton-api-gotchas.md](proton-api-gotchas.md) — Proton library pitfalls
