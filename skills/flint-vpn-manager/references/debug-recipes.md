# Debug Recipes

Symptom-driven cookbook. Look up the observed problem, run the suggested diagnostic commands, read the likely causes.

Every recipe here is distilled from a real bug that was debugged in Flint VPN Manager. The lesson — not just the specific fix — is what matters.

## Table of contents

1. [Is a VPN tunnel actually up?](#1-is-a-vpn-tunnel-actually-up)
2. [Is a device's traffic actually going through the tunnel?](#2-is-a-devices-traffic-actually-going-through-the-tunnel)
3. [Device has no internet at all](#3-device-has-no-internet-at-all)
4. [Tunnel is green but DNS doesn't work](#4-tunnel-is-green-but-dns-doesnt-work)
5. [Bypass / adblock / NoInternet looks set up but doesn't do anything](#5-bypass--adblock--nointernet-doesnt-take-effect)
6. [Proton-wg tunnel won't start / crashes after connect](#6-proton-wg-wont-start)
7. [Device missing from dashboard / Networks page / wrong zone](#7-device-missing-or-in-wrong-zone)
8. [After reboot: tunnel healthy but routing broken](#8-after-reboot)
9. [Anonymous `@rule[N]` appeared in `uci show route_policy`](#9-anonymous-rule-healing)
10. [Adblock "doesn't block" an obvious ad domain](#10-adblock-not-blocking)
11. [Smart Protocol won't stop retrying / stuck "Trying wireguard-tcp (3/5)"](#11-smart-protocol-stuck)
12. [Kill switch — is it actually blocking?](#12-kill-switch-check)
13. [Full router diagnostic snapshot](#13-diagnostic-snapshot)
14. [Latency probes — always run from the router](#14-latency-probes)

---

## 1. Is a VPN tunnel actually up?

```bash
# Kernel WG / OVPN (via vpn-client):
ssh root@192.168.8.1 '
uci get route_policy.fvpn_rule_9001.enabled          # 1 = should be up
uci get route_policy.fvpn_rule_9001.via              # wgclient1 etc — empty = vpn-client has not claimed it
ifstatus wgclient1 | jsonfilter -e "@.up"            # true/false
wg show wgclient1 latest-handshakes                  # tab-separated; unix ts "0" = never
wg show wgclient1 transfer
'

# Proton-wg:
ssh root@192.168.8.1 '
pidof proton-wg
for p in $(pidof proton-wg); do
  echo "PID $p:"
  cat /proc/$p/environ | tr "\0" "\n" | grep PROTON_WG
done
ip link show protonwg0
wg show protonwg0 latest-handshakes
'
```

**Interpretation**:
- `enabled=1` but `via` empty → vpn-client hasn't processed the rule yet (normal for a few seconds after enable; persistent = bug).
- `handshake 0 or missing` + interface up → tunnel negotiating or server unreachable.
- `handshake > 180s` → tunnel is in the amber zone (see `router-layout.md` for the green/amber/red thresholds).

## 2. Is a device's traffic actually going through the tunnel?

```bash
# 1. Find the device (by hostname or MAC):
ssh root@192.168.8.1 'grep -i "<hostname|mac>" /tmp/dhcp.leases'

# 2. Check it's in every place it should be:
ssh root@192.168.8.1 '
mac="<the mac>"
echo "--- route_policy from_mac ---"
uci show route_policy | grep -i "$mac"
echo "--- ipsets containing it ---"
for s in $(ipset list -n | grep -E "^(src_mac_|pwg_mac_|fvpn_noint_macs|fvpn_adblock)"); do
  ipset test "$s" "$mac" 2>&1 | grep -q "is in set" && echo " └─ $s"
done
echo "--- routing decision for its IP ---"
ip=$(grep -i "$mac" /tmp/dhcp.leases | awk "{print \$3}" | head -1)
[ -n "$ip" ] && ip route get "$ip"
'

# 3. Check the mangle chain order (fwmark precedence):
ssh root@192.168.8.1 'iptables -t mangle -L ROUTE_POLICY -n -v --line-numbers | head -15'
```

**Interpretation**:
- **In `from_mac` but not in `src_mac_*` ipset** → vpn-client restart hasn't rebuilt the ipset yet, or the rule isn't enabled. Fix: `uci commit route_policy && /etc/init.d/vpn-client restart`.
- **In `pwg_mac_*` but proton-wg interface is down** → the `.macs` file is intact, tunnel just isn't running. Starting the tunnel will route it.
- **In multiple ipsets** (e.g. kernel WG and proton-wg) → assignment conflict. Only one wins; depends on ROUTE_POLICY chain order.
- **In `fvpn_noint_macs`** → NoInternet blocks WAN. Device has LAN only. Check user expectations.

## 3. Device has no internet at all

```bash
ssh root@192.168.8.1 '
mac="<the mac>"
ip=$(grep -i "$mac" /tmp/dhcp.leases | awk "{print \$3}" | head -1)
echo "=== device $mac @ $ip ==="

echo "--- DHCP lease ---"
grep -i "$mac" /tmp/dhcp.leases || echo "no lease"

echo "--- NoInternet? ---"
ipset test fvpn_noint_macs "$mac" 2>&1

echo "--- assigned to which VPN? ---"
uci show route_policy | grep -i "$mac"
for s in $(ipset list -n | grep -E "^(src_mac_|pwg_mac_)"); do
  ipset test "$s" "$mac" 2>&1 | grep -q "is in set" && echo "in $s"
done

echo "--- routing decision ---"
[ -n "$ip" ] && ip route get "$ip"

echo "--- which zone is it in? ---"
ip neigh show | grep -i "$mac"
'
```

**Top causes (roughly in frequency order)**:
1. In a **NoInternet** group (`fvpn_noint_macs`). Intentional.
2. Assigned to a VPN tunnel whose interface is **down** and kill switch is **on** → blackhole catches traffic.
3. Assigned to a VPN tunnel that's still **connecting** — wait 15–30s.
4. On a custom LAN zone (`fvpn_iot`, `fvpn_guest`) where the zone → wan forwarding is missing. Check `uci show firewall | grep -A2 "=forwarding"`.
5. Has a randomised/private MAC and was assigned to a VPN under an old MAC. Check `ip neigh show` for the current MAC.

## 4. Tunnel is green but DNS doesn't work

DNS on this router is complicated — there's a main dnsmasq and a per-tunnel dnsmasq for every proton-wg tunnel. Device queries to port 53 are redirected by iptables to the correct per-tunnel instance based on fwmark.

```bash
ssh root@192.168.8.1 '
echo "=== main dnsmasq ==="
pgrep -af "dnsmasq.*cfg01411c"
echo "=== per-tunnel dnsmasq instances ==="
pgrep -af "dnsmasq.*protonwg|dnsmasq.*wgclient"
echo "=== DNS REDIRECT rules ==="
iptables -t nat -L policy_redirect -n -v | grep REDIRECT
echo "=== conntrack zones ==="
iptables -t raw -L pre_dns_deal_conn_zone -n -v
echo "=== per-tunnel ports ==="
netstat -lnup 2>/dev/null | grep -E ":26[0-9]{2}|:27[0-9]{2}|:29[0-9]{2}|:35[0-9]{2}"
'
```

**Port mapping for proton-wg**: `port = 2000 + (mark >> 12) * 100 + 53`. So protonwg0 (0x6000) = 2653; protonwg1 (0x7000) = 2753; protonwg2 (0x9000) = 2953; protonwg3 (0xf000) = 3553.

**Top causes**:
1. **Per-tunnel dnsmasq crashed** — REDIRECT points at a dead port. Check `pgrep` for the port number. Restart the specific instance: `/usr/sbin/dnsmasq -C /var/etc/dnsmasq.conf.protonwg0`.
2. **Tunnel is DOWN but mangle_rules.sh still installed stale REDIRECT** — because of an old bug. Run `/etc/fvpn/protonwg/mangle_rules.sh` to rebuild cleanly; the new code filters by interface-UP.
3. **Device is in both a VPN ipset and the legacy adblock ipset** — conntrack zone mismatch. See `gotchas.md`.
4. **Proton DNS blocks the specific domain** — try `dig @10.2.0.1 <domain>` from inside the tunnel's network. NXDOMAIN from ProtonVPN is real (e.g., certain Riot chat subdomains).

## 5. Bypass / adblock / NoInternet doesn't take effect

### VPN bypass

Common cause: rules written but `FVPN_BYPASS` chain isn't jumped from `ROUTE_POLICY` position 1, or domain rules written but `dnsmasq-full` isn't installed, or domain rules need a dnsmasq *restart* (not SIGHUP).

```bash
ssh root@192.168.8.1 '
echo "=== mangle ROUTE_POLICY (position 1 must be FVPN_BYPASS) ==="
iptables -t mangle -L ROUTE_POLICY --line-numbers -n -v | head -5
echo "=== FVPN_BYPASS chain ==="
iptables -t mangle -L FVPN_BYPASS -n -v --line-numbers
echo "=== bypass ipsets ==="
ipset list | grep -A2 fvpn_byp_
echo "=== ip rule ==="
ip rule show | grep 0x8000
echo "=== routing table 1008 ==="
ip route show table 1008
echo "=== dnsmasq-full installed? ==="
opkg list-installed | grep dnsmasq-full || echo "MISSING — domain rules wont work"
echo "=== bypass dnsmasq conf ==="
cat /tmp/dnsmasq.d/fvpn_bypass.conf 2>/dev/null || echo "missing"
'
```

Rebuild: `sh /etc/fvpn/vpn_bypass.sh`.

### Adblock

```bash
ssh root@192.168.8.1 '
echo "=== blocklist file ==="
wc -l /etc/fvpn/blocklist.hosts 2>/dev/null || echo "MISSING"
head -3 /etc/fvpn/blocklist.hosts 2>/dev/null
echo "=== active ifaces ==="
cat /etc/fvpn/adblock_ifaces.txt
echo "=== installed snippets ==="
ls -la /tmp/dnsmasq.d/fvpn-adblock /tmp/dnsmasq.d.*/fvpn-adblock 2>/dev/null
'
```

Test blocking by querying a known blocked domain:
```bash
dig @192.168.8.1 doubleclick.net +short
# should return 0.0.0.0 or NXDOMAIN
```

If snippet is in place but not blocking: `ssh root@192.168.8.1 killall -HUP dnsmasq`.
If snippet was removed and dnsmasq hasn't noticed: restart the specific instance (SIGHUP doesn't unload an `addn-hosts` that came from a deleted conf-dir file).

### NoInternet

```bash
ssh root@192.168.8.1 '
echo "=== macs file ==="
cat /etc/fvpn/noint.macs
echo "=== ipset members ==="
ipset list fvpn_noint_macs
echo "=== chain + jump ==="
iptables -L FORWARD --line-numbers -n | head -3
iptables -L FVPN_NOINT -n -v
echo "=== include registered ==="
uci show firewall.fvpn_noint_include
'
```

Rebuild: `sh /etc/fvpn/noint_rules.sh`.

**General debugging invariant**: If a Flint VPN Manager feature doesn't take effect after firewall reload, manually run the relevant include script with `sh -x` to see what it did (or failed to do):

```bash
ssh root@192.168.8.1 'sh -x /etc/fvpn/vpn_bypass.sh 2>&1 | head -50'
```

## 6. Proton-wg won't start

```bash
ssh root@192.168.8.1 '
iface="protonwg0"
echo "=== binary + env ==="
ls -la /usr/bin/proton-wg
cat /etc/fvpn/protonwg/$iface.env 2>/dev/null
echo "=== existing process? ==="
for p in $(pidof proton-wg 2>/dev/null); do
  cat /proc/$p/environ | tr "\0" "\n" | grep PROTON_WG
done
echo "=== conf ==="
cat /etc/fvpn/protonwg/$iface.conf 2>/dev/null | grep -v PrivateKey
echo "=== log ==="
tail -30 /tmp/$iface.log 2>/dev/null
echo "=== interface state ==="
ip link show $iface 2>/dev/null || echo "no iface"
'
```

**Top causes**:
1. **`/usr/bin/proton-wg` missing** (fresh router or corrupt firmware) — binary needs to be re-uploaded by the app's first-connect flow or manually installed (see the project's `docs/router-setup.md`).
2. **Stale `.env` from old tunnel but new `.macs`/`.conf` mismatch** — `FVPN_TUNNEL_ID` / `FVPN_IPSET` out of sync. Delete `.env` and reconnect via the app.
3. **Another proton-wg process owns the iface name** — see the "existing process" output. Kill the specific PID (don't `killall`).
4. **Endpoint unreachable** — Proton server down or firewall between router and server. Log will show handshake timeouts.

## 7. Device missing or in wrong zone

```bash
ssh root@192.168.8.1 '
mac="<the mac>"

echo "=== DHCP lease ==="
grep -i "$mac" /tmp/dhcp.leases

echo "=== ARP/neighbor table (all interfaces, LAN-side only) ==="
ip neigh show | grep -i "$mac" | grep "br-"

echo "=== gl-client alias + class ==="
uci show gl-client | grep -B1 -i "$mac"

echo "=== static lease? ==="
uci show dhcp | grep -B1 -i "$mac" | grep host

echo "=== live ubus client ==="
ubus call gl-clients list | jsonfilter -e "@.clients.\"$(echo $mac | tr a-f A-F)\""
'
```

**Why a device might be missing from the UI**:
1. No DHCP lease + not in ARP (only visible via ubus gl-clients) → device briefly online then went offline. Expected.
2. On a non-`br-*` interface (e.g. WAN) → **filtered out by design**. See `gotchas.md` about the phantom ISP gateway bug.
3. Has a randomised MAC that's cycled. Each new MAC = different device to the tracker.

**Why in the wrong zone**: Devices belong to the zone whose bridge they're attached to. `ip neigh show | grep <mac>` → the `dev` field tells you which bridge.

## 8. After reboot

Everything should work — boot sequence:
1. OpenWrt boots → runs all `/etc/init.d/*` scripts with `START=N` ordering.
2. `/etc/init.d/fvpn-protonwg` (START=99) reads every `/etc/fvpn/protonwg/*.env`, starts each proton-wg process via procd, sets up routing + per-tunnel dnsmasq.
3. `/etc/init.d/firewall` runs our includes; `mangle_rules.sh`, `vpn_bypass.sh`, `noint_rules.sh`, etc. rebuild their state from `.macs` files + UCI.
4. GL.iNet's `vpnclient` include runs `rtp2.sh` which sets up kernel WG / OVPN.

**If something's off after reboot**:

```bash
ssh root@192.168.8.1 '
echo "=== fvpn-protonwg status ==="
/etc/init.d/fvpn-protonwg enabled && echo enabled || echo DISABLED
echo "=== proton-wg procs ==="
for p in $(pidof proton-wg 2>/dev/null); do cat /proc/$p/environ | tr "\0" "\n" | grep INTERFACE; done
echo "=== kernel WG ifaces ==="
wg show interfaces
echo "=== our includes ==="
uci show firewall | grep "=include"
echo "=== recent openwrt log ==="
logread | grep -E "fvpn|protonwg|vpnclient|firewall" | tail -30
'
```

**If proton-wg tunnels didn't start**: `ls /etc/fvpn/protonwg/*.env` — any present `.env` is supposed to start. If empty, there are no configured tunnels (fresh router?). If `.env` present but no process: `/etc/init.d/fvpn-protonwg restart`.

## 9. Anonymous `@rule[N]` appeared

`uci show route_policy` showing `@rule[4]=rule` instead of `fvpn_rule_9001=rule`. GL.iNet's stock UI replaced a named section with an anonymous one after an edit.

The app self-heals on unlock via `router.policy.heal_anonymous_rule_section`. To fix manually:

```bash
ssh root@192.168.8.1 '
# Identify the @rule[N] and what it should be named:
uci show route_policy
# Look for group_id=1957 (WG) or 28216 (OVPN) to confirm it is ours.
# Recover name from peer_id (WG) or client_id (OVPN):
# fvpn_rule_<peer_id> for WG, fvpn_rule_ovpn_<client_id> for OVPN.

# Rename:
uci rename route_policy.@rule[4]=fvpn_rule_9001 && uci commit route_policy
'
```

## 10. Adblock not blocking

Specific domain should be blocked but isn't.

```bash
# From a LAN-connected client, not the router:
dig @192.168.8.1 doubleclick.net +short
# Expect 0.0.0.0 or NXDOMAIN.
```

Diagnostic:
```bash
ssh root@192.168.8.1 '
echo "=== snippet for main dnsmasq ==="
cat /tmp/dnsmasq.d/fvpn-adblock 2>/dev/null || echo "no snippet"
echo "=== blocklist contains the domain? ==="
grep -c " doubleclick.net\$" /etc/fvpn/blocklist.hosts 2>/dev/null
echo "=== dnsmasq is reading the conf-dir? ==="
grep -l "conf-dir=/tmp/dnsmasq.d" /var/etc/dnsmasq.conf.*
'
```

**If snippet is missing** but profile should have adblock enabled: unlock the app (SSE tick runs `sync_adblock`). Or manually:
```bash
ssh root@192.168.8.1 'echo "addn-hosts=/etc/fvpn/blocklist.hosts" > /tmp/dnsmasq.d/fvpn-adblock && killall -HUP dnsmasq'
```

**If blocklist is empty or missing**: Trigger a re-fetch via the app (Settings → Adblock → Update now), or manually download the selected sources.

## 11. Smart Protocol stuck

```bash
ssh root@192.168.8.1 '
wg show                              # which WG ifaces are up
ps aux | grep -E "openvpn|proton-wg" | grep -v grep
uci show route_policy | grep -E "enabled|via_type|name"
'
```

Smart Protocol runs in the backend on a 10s SSE tick. If it won't stop retrying:
- User explicitly disconnect the profile (MCP: `flint_disconnect`).
- Or restart the backend (kills the retry loop): `pkill -f "python backend/app.py"` then re-launch.

## 12. Kill switch check

```bash
ssh root@192.168.8.1 '
echo "=== route_policy killswitch flags ==="
uci show route_policy | grep killswitch
echo "=== per-tunnel blackhole routes ==="
for t in 100 101 102 103 104 200 201 202 203 204 1006 1007 1009 1015; do
  echo "table $t:"; ip route show table $t 2>/dev/null | grep blackhole
done
'
```

For kill switch to actually block: when the tunnel iface goes down, the `default dev <iface>` route disappears and only the `blackhole default metric 254` remains. If you don't see the blackhole, kill switch is off (for kernel WG/OVPN) or broken (for proton-wg, where it should always exist).

Test: disconnect the tunnel and try to ping 8.8.8.8 from the assigned device. Should fail.

## 13. Diagnostic snapshot

The "I don't know what's wrong, just show me everything" command. Use when the user says "something's wrong with the router" without specifics. See SKILL.md for the exact command.

Also log stuff:
```bash
ssh root@192.168.8.1 'logread | tail -100'                     # system log
ssh root@192.168.8.1 'ls -la /tmp/protonwg*.log /var/log/openvpn/*.log 2>/dev/null'
```

## 14. Latency probes

Always probe from the router, not from the host running the app (which may be behind a VPN and give misleading results).

```bash
# TCP connect-time to a server on port 443:
ssh root@192.168.8.1 "curl -sf -o /dev/null -w '%{time_connect}\n' --max-time 5 tcp://<server_ip>:443"
```

Don't use `ping`, `nc -z`, or `date +%N` — BusyBox limitations, see `safe-commands.md`.
