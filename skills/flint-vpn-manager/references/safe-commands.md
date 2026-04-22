# Safe vs Unsafe Router Commands

Every router command, categorised by blast radius. Read this **before** running anything mutating.

## SAFE — read-only, run freely

These never mutate state. Use them liberally while diagnosing.

```bash
# UCI reads
uci show <config>                       # e.g. uci show firewall
uci get <path>

# WireGuard
wg show [<iface>] [latest-handshakes|transfer|peers|allowed-ips]

# Interface / routing
ifstatus <iface>                        # JSON interface state
ip link show
ip addr show / ip -6 addr show
ip route show [table N]
ip -6 route show [table N]
ip rule show / ip -6 rule show

# ipset
ipset list                               # all sets with members
ipset list -n                            # just names
ipset list <name>
ipset test <name> <mac|ip>              # returns 0 (yes) / 1 (no); no output by default

# iptables / ip6tables (read-only with -L / -S)
iptables -L [<chain>] -t [filter|nat|mangle|raw] -n -v --line-numbers
iptables -S [<chain>] -t [filter|nat|mangle|raw]
ip6tables -L / -S (same)

# ubus (GL.iNet's RPC)
ubus call gl-clients list
ubus call gl-clients status
ubus call network.interface.<iface> status

# File reads
cat /etc/config/<config>
cat /etc/fvpn/<anything>
cat /tmp/dhcp.leases
cat /tmp/protonwg0.log
ls /etc/fvpn/ /etc/fvpn/protonwg/
find /etc/fvpn -type f

# Processes
ps / ps aux
pidof <name>
pgrep -af <pattern>

# Network observability
netstat -lnpt / netstat -lnpu             # busybox netstat
ss -tlnp / ss -ulnp                       # if available
conntrack -L                              # if conntrack-tools installed
iwinfo [<iface>] [assoclist]              # WiFi signal, clients
logread | tail -<N>                       # openwrt system log
logread -f                                # follow

# Package query
opkg list-installed
opkg list-installed | grep <pkg>
opkg info <pkg>

# Misc
uptime; free -h; df -h
```

## SAFE with caveats — understand the side effects first

These mutate state but are designed to be run routinely as part of the app's normal operation.

### `uci set / delete / add_list / del_list / commit <config>`
- Always commit after changes (`uci commit <config>`), otherwise nothing persists across reboot.
- UCI changes to most configs don't take effect until the owning service reloads (`firewall`, `dnsmasq`, `network`, `vpn-client`, `wifi`).
- `uci del_list` is **case-sensitive**. See `gotchas.md`.

### `/etc/init.d/firewall reload` (NOT restart)
- ~0.22s. Re-runs our firewall include scripts (all tagged `reload='1'`).
- Does NOT re-run GL.iNet's `vpnclient` include (`reload='0'`), so kernel WG tunnels survive.
- Safe to run after any UCI firewall change, any ipset membership change, or when you need our include scripts to rebuild state.

### `/etc/init.d/dnsmasq reload`
- Fast SIGHUP equivalent. Picks up hosts file changes (including `/etc/fvpn/blocklist.hosts`).
- **Does NOT** pick up changes to conf files under `conf-dir=` that add or remove `addn-hosts`/`ipset=` directives — for those you need a full `restart`.

### `/etc/init.d/dnsmasq restart`
- Slower (~12–15s on Flint 2). Rebuilds all per-tunnel dnsmasq instances.
- Needed after adding/removing `ipset=` lines (VPN bypass domain rules).
- Run it in background if in a time-sensitive path: `/etc/init.d/dnsmasq restart >/dev/null 2>&1 &`.

### `/etc/init.d/vpn-client restart`
- **Flushes every `src_mac_*` ipset** — they get rebuilt from `route_policy.*.from_mac` UCI lists within a second.
- Leaves `pwg_mac_*` ipsets untouched — proton-wg is safe.
- Needed after changing kernel WG / OVPN enabled state, peer config, or route_policy structure.
- Don't run while a tunnel is stuck in connecting state — it may leave it stuck longer.

### `/etc/init.d/avahi-daemon restart`
- Briefly interrupts mDNS reflection. Safe.
- Needed after changes to `/etc/avahi/avahi-daemon.conf`.

### `ipset create/add/del/destroy ... -exist` / `... 2>/dev/null || true`
- Idempotent. Safe.
- `ipset flush <name>` clears members but keeps the set; safe during rebuilds.
- `ipset destroy <name>` removes the set entirely — fails if rules reference it.

### `wg set <iface> peer <pk> ...` / `wg setconf <iface> <file>`
- Live hot-swap on a WireGuard interface. Zero-flicker. Safe.
- Used by kernel WG + proton-wg server switches.

### `wifi reload`
- Briefly reconnects affected WiFi bands (2.4G / 5G).
- Safe for SSID settings changes, AP isolation toggle.
- **Does NOT** pick up `BssidNum` changes in MediaTek `.dat` files — see UNSAFE section below.

### `/etc/init.d/fvpn-protonwg start|stop|restart|enable|disable`
- Controls the procd service that starts proton-wg tunnels on boot.
- Safe to restart when proton-wg tunnels are behaving strangely after a reboot.

## UNSAFE — will disrupt the network

Don't run these without explicit user authorisation, and never as a "let's see what happens" experiment.

### `/etc/init.d/firewall restart`
**Tears down all WireGuard tunnels.** `restart = stop + start`, and `start` re-runs `/usr/bin/rtp2.sh` (GL.iNet's VPN setup script) which destroys our `wgclient*` interfaces. Active handshakes are lost; tunnels need time (sometimes minutes) to re-establish. **Always use `reload` instead.**

### `/etc/init.d/network reload` / `/etc/init.d/network restart`
**Bricks all routing momentarily.** Restarts netifd, which cycles every interface including `lan` and `wan`. Don't run unless you're prepared for every client on the network to lose connectivity.

### `rtp2.sh` (directly)
Same blast radius as `firewall restart` — it's the script that does the damage.

### `ifup` / `ifdown <iface>` on `lan`, `wan`, `wan6`, `wgclient*`, `ovpnclient*`, `protonwg*`
Bypasses vpn-client's lifecycle management. Can create catch-all routes, duplicate routes, or orphan interfaces. If you need to poke an interface, use `ubus call network.interface.<name> up` — scoped and safe.

### `killall proton-wg`
**Kills every proton-wg tunnel simultaneously.** Multiple tunnels share one binary. To stop a specific tunnel, target its PID via `/proc/<pid>/environ`:

```bash
pid=$(for p in $(pidof proton-wg); do
  grep -qz 'PROTON_WG_INTERFACE_NAME=<iface>' /proc/$p/environ && echo $p && break
done)
[ -n "$pid" ] && kill $pid
```

### `conntrack -D`
Flushes active connection tracking — breaks every established connection on the router. Use `conntrack -L` (read) or `conntrack -D -d <specific_ip>` if you must surgically drop a single flow.

### `wifi down` (without `wifi up`)
Disconnects every WiFi client. Do this only if you're going to `wifi up` immediately, or doing a full driver reload (see below).

### Full MediaTek WiFi driver reload (`rmmod mt_wifi`)
Required to pick up new `BssidNum` in `.dat` files. **Causes ~15s WiFi outage for all clients on all bands.** Must run detached over SSH (the WiFi drop kills the SSH session):

```bash
ssh root@192.168.8.1 'sh -c "
wifi down 2>/dev/null
rmmod mtk_warp_proxy 2>/dev/null
rmmod mt_wifi 2>/dev/null
sleep 1
insmod mt_wifi 2>/dev/null
insmod mtk_warp_proxy 2>/dev/null
sleep 1
wifi up 2>/dev/null
/etc/init.d/firewall reload >/dev/null 2>&1
/etc/init.d/dnsmasq reload >/dev/null 2>&1
" </dev/null >/dev/null 2>&1 &'
```

Only needed for LAN network create/delete. Other WiFi operations use `wifi reload`.

## CRITICAL — irreversible / data-loss

Do not run these. Seriously. If a user asks you to, confirm they understand what they're doing.

### `rm -rf /etc/config/*` or `rm -rf /etc/fvpn/*`
Wipes router config or Flint VPN Manager state. Recovering requires a factory reset or a profile-store backup restore.

### `sysupgrade` / `firstboot` / `jffs2reset`
Factory reset. All state lost. A new router from the app's perspective.

### `uci delete route_policy` (no suffix)
Removes the entire `route_policy` config. Every Flint VPN Manager VPN rule gone. Requires recreating every profile.

### Changing `route_policy.fvpn_rule_*.tunnel_id` on a running tunnel
Invalidates the ipset mapping. Devices stop being routed correctly until the rule is deleted and recreated.

## Commands you might be tempted to run — don't

### `nc -z host port` — **does not work**
BusyBox `nc` on OpenWrt has no `-z` or `-w` flag. For port reachability, use:
```bash
curl -sf -o /dev/null --max-time 1 tcp://<ip>:<port> && echo open
```

### `nslookup host dns_server port` — **does not work**
BusyBox `nslookup` accepts only `HOST [DNS_SERVER]` — no port. Use `dig` from the workstation (not the router):
```bash
dig @192.168.8.1 -p 5354 example.com
```

### `date +%N` — **returns literal `%N`**
BusyBox `date` has no nanosecond support. For latency measurement, use `curl -w '%{time_connect}\n' …`.

### `/etc/init.d/vpn-client stop` (without restart)
Leaves things in an inconsistent state. If you need to stop tunnels, disable the rules (`uci set route_policy.<rule>.enabled='0'; uci commit route_policy`) and then `vpn-client restart`.
