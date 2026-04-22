# Router Reference

Technical reference for the GL.iNet Flint 2 (GL-MT6000) router integration.

## GL.iNet-Compatible Config Naming

| Protocol | UCI Section | ID Range | `group_id` |
|----------|-------------|----------|-----------|
| WireGuard | `wireguard.peer_NNNN` | 9001–9050 | `1957` (FromApp) |
| OpenVPN | `ovpnclient.28216_NNNN` | 9051–9099 | `28216` (FromApp) |
| Route Policy (WG) | `route_policy.fvpn_rule_NNNN` | — | — |
| Route Policy (OVPN) | `route_policy.fvpn_rule_ovpn_NNNN` | — | — |

These names make our configs visible in the GL.iNet router dashboard (http://192.168.8.1) as a fallback.

## Router Limits

- **5 WireGuard UDP tunnels** (`wgclient1`–`wgclient5`, marks `0x1000`–`0x5000`, vpn-client)
- **4 WireGuard TCP/TLS tunnels** (`protonwg0`–`protonwg3`, marks `0x6000`/`0x7000`/`0x9000`/`0xf000`, Flint VPN Manager)
- **5 OpenVPN tunnels** (`ovpnclient1`–`ovpnclient5`, marks `0xa000`–`0xe000`, vpn-client)
- **14 total simultaneous VPN tunnels** (limited by fwmark address space)
- **150 DHCP devices** (pool `.100`–`.249`)
- **65,536 MACs per ipset** (per-group device limit)

## File Transfer to Router

The router runs Dropbear (no SFTP). Use `write_file()` in `router_api.py` which pipes content through SSH stdin:

```python
router.write_file("/path/on/router", content_string)
# Uses: cat > /path via stdin pipe — no escaping issues
```

Never use heredocs or base64 — they corrupt certificates and keys.

## Tunnel Lifecycle (kernel WG + OpenVPN, via vpn-client)

1. Create WG peer (`/etc/config/wireguard`) or OVPN client (`/etc/config/ovpnclient` + `.ovpn` file under `/etc/openvpn/profiles/`)
2. Create a route_policy rule: `via_type='wireguard'|'openvpn'`, `peer_id`/`client_id`, `group_id`, `from='src_mac{tunnel_id}'`, `from_type='ipset'`
3. Connect: `uci set route_policy.{rule}.enabled='1'` + `uci commit` + `/etc/init.d/vpn-client restart`. vpn-client's `setup_instance_via.lua` reads our rule, creates the network interface, starts the tunnel, and sets up the iptables MARK rule.
4. Disconnect: disable kill switch, disable the rule, `vpn-client restart`, restore kill switch.

**proton-wg (TCP/TLS) tunnels have a completely different lifecycle** — see [proton-wg-internals.md](proton-wg-internals.md).

## Server Switch

- **Kernel WG**: in-place hot-swap via `wg set` (update UCI peer endpoint + `wg set` to add new peer / remove old peer on live interface). Zero-flicker — no tunnel teardown.
- **OpenVPN**: full delete + recreate (OVPN cannot hot-swap peers). Brief flicker during restart.
- **proton-wg**: `wg setconf` on the live interface.

All protocols: capture devices from the OLD rule's `from_mac` BEFORE any teardown (VPN device assignments are router-canonical), then re-add them to the new rule after switch.

See [server-switch-internals.md](server-switch-internals.md) for full details.

## Device Assignment

Uses `ipset`, never `rtp2.sh`. `router.set_device_vpn`, `remove_device_from_vpn`, `remove_device_from_all_vpn`, and `set_kill_switch` use `ipset add/del` for immediate effect plus `uci commit` for persistence. The `src_mac{tunnel_id}` ipset is referenced by an existing iptables MARK rule (set up at tunnel creation by vpn-client). Adding a MAC to the ipset takes effect on the next packet — no daemon restart needed.

**Case sensitivity gotcha**: UCI's `del_list` requires an EXACT-match value. `from_mac_tokens()` reads existing MACs preserving their case so `del_list` uses the stored case (uppercase from GL.iNet UI vs. lowercase from us).

## proton-wg (WireGuard TCP/TLS)

WireGuard over TCP/TLS, managed entirely by Flint VPN Manager (not vpn-client). Uses `proton-wg` — ProtonVPN's wireguard-go fork cross-compiled for ARM64.

```
Kernel WG (UDP):    vpn-client → wgclient1-5 → fwmark 0x1000-0x5000
proton-wg (TCP/TLS): Flint VPN Manager → protonwg0-3  → fwmark 0x6000,0x7000,0x9000,0xf000
OpenVPN:            vpn-client → ovpnclient1-5 → fwmark 0xa000-0xe000
```

Key differences from kernel WG: no route_policy rule, no vpn-client, kill switch always on (blackhole route), device assignment via ipset add (not `uci add_list from_mac`) + local store persistence, slot allocation checks both live interfaces AND config files.

Config files: `/etc/fvpn/protonwg/<iface>.{conf,env}`, `mangle_rules.sh` (firewall include), `/etc/init.d/fvpn-protonwg` (boot persistence).

**Mangle rules must include ALL configured tunnels**, not just those with live interfaces. The ipset-based matching works regardless of interface state. Skipping down tunnels produces empty `mangle_rules.sh` that persists and breaks routing after firewall reload. `_rebuild_proton_wg_mangle_rules()` also creates ipsets (`ipset create ... hash:mac -exist`) before the iptables rules that reference them, and these create commands are included in the persisted script.

See [proton-wg-internals.md](proton-wg-internals.md) for process targeting, mangle ordering, tunnel ID allocation, and other critical constraints.

## MediaTek WiFi Driver Constraints

**Critical**: MediaTek's `mt_wifi` kernel module reads `BssidNum` from `.dat` files ONLY at module load time. `wifi reload` and `wifi down/up` do NOT reload the module, so new wireless interfaces (e.g. `ra2`, `rax2`) are never created by those commands alone.

**Solution**: `router_lan_access.py`'s `_reload_wifi_driver()` performs a full driver reload:
`wifi down` → `rmmod mtk_warp_proxy` → `rmmod mt_wifi` → `insmod mt_wifi` → `insmod mtk_warp_proxy` → `wifi up` → firewall/dnsmasq reload

- Runs detached (`&`) via SSH so it survives the SSH disconnect (WiFi drop kills the SSH session)
- Causes **~15s WiFi outage for ALL clients on ALL bands** — unavoidable on MediaTek hardware
- Required only for network creation/deletion; other WiFi operations (enable/disable, SSID settings, isolation toggle) only need `wifi reload` which briefly reconnects the affected band(s)

**`.dat` file paths** (active on Flint 2 / MT7986):
- `/etc/wireless/mediatek/mt7986-ax6000.dbdc.b0.dat` (2.4G radio)
- `/etc/wireless/mediatek/mt7986-ax6000.dbdc.b1.dat` (5G radio)
- Referenced by `/etc/wireless/l1profile.dat`. Other `.dat` files in that directory are for different models and are NOT used.
- Max `BssidNum` is typically 4 per radio (`ra0`–`ra3`, `rax0`–`rax3`) on MT7986.

## fw3 Zone Name Limit (11 characters)

**Critical**: fw3 silently ignores zones with names longer than 11 characters. No error, no warning — just no firewall rules, no NAT, no internet for that zone.

Flint VPN Manager zone name format: `fvpn_` (5 chars) + `zone_id` → `zone_id` max 6 chars. `lan_access_service.py` truncates zone_id to 6 chars and handles collisions.

## VPN Routing Across Bridges

VPN `route_policy` mangle chain matches `br-+` (bridge wildcard), so MAC-based ipset routing works for devices on ANY network bridge (`br-lan`, `br-guest`, `br-fvpn_*`). No special handling needed when creating new networks.

**Zone forwarding for VPN traffic**: Custom network zones (`fvpn_*`) only forward to `wan` by default, not to VPN tunnel zones. A global `iptables -I forwarding_rule -m mark ! --mark 0x0/0xf000 -j ACCEPT` rule allows all fwmark-marked traffic from any zone to reach VPN tunnels. Covers all protocols (WG UDP `0x1000`-`0x5000`, WG TCP/TLS `0x6000`/`0x7000`/`0x9000`/`0xf000`, OVPN `0xa000`-`0xe000`, WAN `0x8000`). Written in `lan_access_rules.sh` for reboot persistence.

## Device Type Mapping (GL.iNet ↔ Dashboard)

Uses UCI `gl-client.{section}.class` strings: `computer`, `phone`, `pad`, `camera`, `watch`, `laptop`, `printer`, `sound`, `television`, `smartappliances`, `games`, `gateway`, `nas`, `server`, `switch`
