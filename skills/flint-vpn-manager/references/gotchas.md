# Gotchas & Hard Invariants

The non-obvious rules that bite if you don't know them. Every one here was learned from a real bug that cost time. Read before you act on the router.

## Router service lifecycle

### `firewall reload` is safe; `firewall restart` kills WireGuard
Every Flint VPN Manager firewall include uses `option reload '1'`, so it re-runs on reload. GL.iNet's `vpnclient` include uses `reload='0'` — it only runs on `firewall start`. `restart = stop + start`, which re-runs `rtp2.sh` which tears down our `wgclient*` interfaces and corrupts handshakes. **Always `reload`, never `restart`.**

### `vpn-client restart` flushes every `src_mac_*` ipset
It's a glob-based cleanup. `src_mac_*` ipsets get rebuilt from `route_policy.*.from_mac` UCI lists within a second. Proton-wg uses `pwg_mac_*` specifically so it's immune. **Don't use the `src_mac_` prefix for any new ipset** — it's vpn-client's namespace.

### `network reload`/`restart` bricks the LAN
Momentary, but every client on the network loses connectivity. Use `ubus call network.interface.<iface> up` if you need to poke a single interface.

## Proton-wg

### `killall proton-wg` kills ALL proton-wg tunnels
Multiple tunnels share one binary. Always target a specific tunnel's PID through its `PROTON_WG_INTERFACE_NAME` env var in `/proc/<pid>/environ`:
```sh
pid=$(for p in $(pidof proton-wg); do
  grep -qz 'PROTON_WG_INTERFACE_NAME=protonwg0' /proc/$p/environ && echo $p && break
done)
[ -n "$pid" ] && kill $pid
```

### `.macs` files are the source of truth
Kernel ipsets are ephemeral — a firewall reload flushes them. The include script `mangle_rules.sh` repopulates `pwg_mac_<tid>` from `/etc/fvpn/protonwg/<iface>.macs` on every reload. If device assignments vanish after a firewall event, check the `.macs` file, not the ipset.

### Proton-wg mangle rules must be created AFTER firewall reload
Creating mangle rules before a reload makes fw3 wipe them (fw3 only preserves its own `!fw3`-marked rules). The app's `start_proton_wg_tunnel` does reload first, then runs the include script.

### Proton-wg mangle rules must skip DOWN interfaces
If a proton-wg tunnel is disconnected but its `.env` file still exists, `_rebuild_proton_wg_mangle_rules()` must NOT include it. Otherwise the DNS REDIRECT rule sends port 53 traffic to a dead per-tunnel dnsmasq, and devices lose DNS silently. The current code checks `ip link show <iface> | grep UP` before including.

### Tunnel-ID allocator must scan three sources
`_next_tunnel_id()` checks (1) `route_policy` UCI, (2) `ipset -n | grep -E '(pwg_mac_|src_mac_)'`, (3) `grep FVPN_TUNNEL_ID= /etc/fvpn/protonwg/*.env`. Missing any one causes collisions. Proton-wg specifically has no route_policy entry, so skipping source (3) will double-allocate.

### Proton-wg has no `route_policy` entry
It's invisible to `uci show route_policy`. Don't assume a rule exists for every profile. Use `/etc/fvpn/protonwg/*.env` + `pwg_mac_*` ipsets as the discovery surface.

## UCI / fw3 quirks

### `uci del_list` is case-sensitive
GL.iNet UI writes uppercase MACs; Flint VPN Manager writes lowercase. `uci del_list route_policy.fvpn_rule_9001.from_mac='aa:bb:…'` silently no-ops if the stored token was `AA:BB:…`. Always read the stored token first:
```sh
uci get route_policy.fvpn_rule_9001.from_mac          # preserve exact case
uci del_list route_policy.fvpn_rule_9001.from_mac='<exact case>'
```

### fw3 silently ignores zone names > 11 chars
No error. No warning in `uci show`. Just no rules, no NAT, no internet for that zone. Flint VPN Manager uses `fvpn_` (5) + zone_id (≤6).

### fw3 silently drops rules referencing an invalid ipset
On OpenWrt 21.02 (fw3 2021-03-23), `hash:mac` ipsets defined via UCI emit:
```
Warning: Section '…' has an invalid combination of storage method and matches
```
And every rule referencing that ipset is dropped. **If a firewall rule doesn't take effect, always run `/etc/init.d/firewall reload 2>&1` and read the warnings** — fw3 is otherwise mute. The workaround for `hash:mac` is to create the ipset inside a firewall include script, not via UCI.

### UCI changes need a service reload to take effect
`uci set` + `uci commit` is persistent but doesn't affect runtime. Reload the owning service:

| Config | Reload with |
|---|---|
| `firewall` | `/etc/init.d/firewall reload` |
| `dhcp` | `/etc/init.d/dnsmasq reload` |
| `dnsmasq` | `/etc/init.d/dnsmasq reload` (or `restart` if conf-dir files changed) |
| `network` | **don't** — use `ubus call network.interface.<name> up` |
| `wireless` | `wifi reload` (or full driver reload for new `ra<N>` — see below) |
| `route_policy`, `wireguard`, `ovpnclient` | `/etc/init.d/vpn-client restart` |

### GL.iNet UI may replace `fvpn_rule_<N>` with `@rule[N]`
After editing a rule in the stock UI, the named section may become anonymous. The app self-heals on unlock via `heal_anonymous_rule_section`, matching by `group_id` (1957 or 28216) and `peer_id`/`client_id`. To fix manually:
```sh
uci rename route_policy.@rule[N]=fvpn_rule_<peer_id>
uci commit route_policy
```

## DNS & dnsmasq

### Main dnsmasq uses `/tmp/dnsmasq.d/`, not `/etc/dnsmasq.d/`
Flint 2's main dnsmasq config (`/var/etc/dnsmasq.conf.cfg01411c`) has `conf-dir=/tmp/dnsmasq.d`. Files in `/etc/dnsmasq.d/` are ignored. Confirm with:
```sh
grep conf-dir /var/etc/dnsmasq.conf.*
```

### dnsmasq `ipset=` directives need a full restart
SIGHUP (`killall -HUP dnsmasq`) picks up hosts-file changes but **not** `ipset=` directive additions/removals. Use `/etc/init.d/dnsmasq restart` (~12-15s) or restart the specific instance:
```sh
pgrep -f 'dnsmasq.*<conf>' | xargs kill
/usr/sbin/dnsmasq -C /var/etc/<conf>
```

### Removing `addn-hosts` snippets needs a full restart too
If you delete a file inside a dnsmasq conf-dir, SIGHUP doesn't unload the directive that file contained. dnsmasq keeps the old hosts cached. Restart the specific instance.

### Per-tunnel dnsmasq ports
Proton-wg tunnels have their own dnsmasq each, on port `2000 + (mark >> 12) * 100 + 53`:
- protonwg0 (0x6000) → 2653
- protonwg1 (0x7000) → 2753
- protonwg2 (0x9000) → 2953
- protonwg3 (0xf000) → 3553

Device queries to port 53 are REDIRECT'd to these ports by iptables + conntrack zones.

### ProtonVPN DNS returns NXDOMAIN for some legitimate chat endpoints
Example: `xmpp-edge.chat.si.riotgames.com` resolves to NXDOMAIN via Proton's DNS (10.2.0.1). If a specific app's DNS doesn't work through a VPN, the server may be filtering it. Bypass at the domain level (VPN bypass) or by port range.

## Adblock

### Blocklist file missing = silent disable
`sync_adblock()` checks `_blocklist_has_content()` before acting. If `/etc/fvpn/blocklist.hosts` is missing or empty, the snippets are removed and nothing is blocked — **without warning the user**. If the user thinks adblock is on but it isn't, check the file first.

### Entries are dual-stack
```
0.0.0.0 example.com
:: example.com
```
Both are required for IPv4 + IPv6. `addn-hosts=…` loads both.

## VPN bypass

### `dnsmasq-full` required for domain rules
Default dnsmasq-mini doesn't support `ipset=`. Without it, domain rules are written to `/tmp/dnsmasq.d/fvpn_bypass.conf` but dnsmasq ignores them. Check:
```sh
opkg list-installed | grep dnsmasq-full
```
Install via: the app's UI (Settings → VPN Bypass → Install dnsmasq-full), or manually: `opkg update && opkg install dnsmasq-full --force-overwrite`.

### `FVPN_BYPASS` must be at mangle ROUTE_POLICY position 1
If it's not, tunnel rules evaluate first and mark the packet; bypass never sees it. Every `apply_all()` drops the old jump and re-inserts at position 1. If you see bypass misbehaving after a firewall event, re-run `/etc/fvpn/vpn_bypass.sh`.

### Preset updates don't touch existing exceptions
Preset rules are **copied** into exceptions at creation time, not referenced. Editing a preset's rules doesn't update exceptions already based on that preset. Users must edit or recreate.

## LAN / networks

### MediaTek `mt_wifi` reads `BssidNum` only at module load
`wifi reload` and `wifi down/up` do NOT re-load the driver module. To pick up new `BssidNum` in `/etc/wireless/mediatek/mt7986-ax6000.dbdc.b*.dat`, do a full driver cycle: `rmmod mtk_warp_proxy; rmmod mt_wifi; insmod mt_wifi; insmod mtk_warp_proxy`. Causes a **~15s WiFi outage on all bands** — unavoidable.

### Only `br-*` interfaces should be treated as LAN
ARP/NDP tables on the router contain WAN-side neighbours too (e.g. the ISP gateway). Filter by `dev` starting with `br-`. The phantom ISP gateway bug was exactly this — a random locally-administered MAC from the ISP modem appearing as a "device" on the dashboard.

### Static-IP devices are invisible without ARP fallback
Devices with static IPs (no DHCP lease) don't appear in `/tmp/dhcp.leases`. Use `ip neigh show | grep br-` to supplement.

### Device exceptions cover unicast only — not mDNS/SSDP
Multicast traffic needs the avahi reflector. If cross-network device discovery isn't working, check `enable-reflector=yes` in `/etc/avahi/avahi-daemon.conf` + `allow-interfaces=<bridges>` + `Allow-mDNS-<zone>` rule for reject-input zones.

### Avahi reflector sees duplicate packets without `allow-interfaces`
Avahi listens on WiFi (`ra0`, `rax0`) AND their parent bridges (`br-lan`), doubling packets. Always restrict with `allow-interfaces=<explicit bridge list>`.

### Non-LAN zones don't forward fwmark-marked traffic by default
Custom zones forward to `wan` only. VPN tunnel traffic from a custom zone needs the global catch-all:
```
iptables -I forwarding_rule -m mark ! --mark 0x0/0xf000 -j ACCEPT
```
This lives in `/etc/fvpn/lan_access_rules.sh`.

## IPv6

### GL.iNet's VPN policy is IPv4-only
`route_policy` and `rtp2.sh` set up IPv4 fwmark rules. IPv6 packets skip the tunnel entirely without Flint VPN Manager's separate management — `/etc/fvpn/ipv6_mangle_rules.sh` + `/etc/fvpn/ipv6_forward.sh`. If a VPN user's IPv6 leaks their real address, check these includes exist.

### `disable_ipv6_router()` must remove the sysctl file, not just write sysctl at runtime
`sysctl -w net.ipv6.conf.all.disable_ipv6=1` is ephemeral. Persistence requires deleting `/etc/sysctl.d/99-fvpn-ipv6.conf` (for disable) or writing it (for enable). Missing either path leaves enable state wrong across reboots.

## Profile store / backup

### Router backup is unconditional source of truth on unlock
`/etc/fvpn/profile_store.bak.json` is pulled on every unlock and overwrites local. **Do not expect local `profile_store.json` edits to survive a restart** unless you force a save through the API (any PUT to `/api/profiles/<id>`) which pushes the new store up to the router as a backup.

No fingerprint or timestamp comparison. This is intentional — the router *is* the source of truth. No backup = clean slate (new router semantic).

## BusyBox limitations

The router's shell is ash; coreutils are BusyBox. Several standard flags are missing:

### `nc` has no `-z` or `-w`
For port reachability:
```sh
curl -sf -o /dev/null --max-time 1 tcp://<ip>:<port> && echo open
```

### `nslookup` takes no port
Only `HOST [DNS_SERVER]`. Run `dig` from the workstation instead:
```sh
dig @192.168.8.1 -p 5354 example.com
```

### `date` has no `+%N`
No nanoseconds. For latency measurement:
```sh
curl -sf -o /dev/null -w '%{time_connect}\n' --max-time 5 tcp://<ip>:<port>
```

### `netstat` flags differ from Linux
No `-ptn` shorthand; use `-lnpt` (TCP listeners) or `-lnpu` (UDP listeners). `ss` may not be installed.

## Python/backend surface (only relevant when reading Flint VPN Manager logs)

### `try: … except Exception: log.warning("…")` hides NameErrors
If a sync-to-router function silently fails, check `logs/error.log` with `repr(e)` — a Python NameError (e.g. after a refactor removed an import) looks like a router-side failure otherwise.

### Module-level state (globals, FileHandlers) leaks between tests
If you see `MagicMock` strings in production logs, tests are leaking. Check for:
- module-level callbacks never reset (`_save_callback`, observers)
- `@patch` decorators without `.return_value` (MagicMock's default is truthy, triggers log branches)
- `FileHandler` attached at `app.py` import time to `logs/*.log`

### Patch at the definition module, not the caller
`patch("router.facades.proton_wg.parse_handshake_age")` fails when `parse_handshake_age` is imported lazily inside a method. Patch at `router.tools.wg_show.parse_handshake_age` instead.

### Don't patch entire modules
`patch("vpn.smart_protocol.time")` replaces the whole module — any `time.time()` call stores a MagicMock as a number. Patch `patch("vpn.smart_protocol.time.time")` specifically.

## The core debugging heuristic

When something "should be working" but isn't:

1. **Read the system log**: `ssh root@192.168.8.1 'logread | tail -100'`. fw3 warnings, vpn-client errors, kernel messages.
2. **Re-run the relevant firewall include manually with `sh -x`**: see exactly what commands ran and which ones failed silently.
3. **Check chain order**: `iptables -t mangle -L ROUTE_POLICY --line-numbers -n -v | head`. FVPN_BYPASS must be position 1 if bypass is active.
4. **Check ipset membership** vs **UCI `from_mac` lists** — they should agree. If not, that's your bug.
5. **Check `conntrack -L`** for the specific client IP if DNS is misbehaving. `[UNREPLIED]` entries mean CT zone mismatches.
