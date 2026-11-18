#!/usr/bin/env bash
# Read-only health check of every router-side artifact / GL.iNet internal Flint VPN Manager relies on.
# Run before an upgrade (must be all PASS) and after it (anything FAIL/WARN needs a look).
# Usage: verify.sh [router-host]
# Nothing here mutates router state.
set -uo pipefail
HOST=${1:-root@192.168.8.1}
R() { ssh -o ConnectTimeout=8 -o BatchMode=yes "$HOST" "$@" 2>/dev/null; }
pass=0; fail=0; warn=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
meh()  { printf '  \033[33mWARN\033[0m %s\n' "$1"; warn=$((warn+1)); }
chk()  { if R "$2" >/dev/null; then ok "$1"; else bad "$1"; fi; }   # chk <label> <remote test>

R true || { echo "cannot ssh to $HOST"; exit 2; }

echo "== Platform (app assumes OpenWrt 21.02 / kernel 5.4 / fw3 + legacy iptables)"
echo "   glversion=$(R cat /etc/glversion) $(R '. /etc/openwrt_release; echo $DISTRIB_RELEASE') kernel=$(R uname -r)"
chk "OpenWrt base is 21.02"                   'grep -q "21.02" /etc/openwrt_release'
chk "kernel 5.4.x"                            'uname -r | grep -q "^5\.4\."'
chk "fw3 present (not fw4/nftables)"          '[ -x /sbin/fw3 ] && ! [ -e /sbin/fw4 ]'
chk "iptables is legacy (not nft backend)"    '! iptables -V | grep -q nf_tables'

echo "== Flint VPN Manager files (must survive sysupgrade via /etc/sysupgrade.conf)"
chk "sysupgrade.conf keeps /etc/fvpn/"        'grep -qx "/etc/fvpn/" /etc/sysupgrade.conf'
chk "sysupgrade.conf keeps /usr/bin/proton-wg" 'grep -qx "/usr/bin/proton-wg" /etc/sysupgrade.conf'
chk "/usr/bin/proton-wg executable"           '[ -x /usr/bin/proton-wg ]'
chk "profile_store.bak.json present"          '[ -s /etc/fvpn/profile_store.bak.json ]'
for env in $(R 'ls /etc/fvpn/protonwg/*.env 2>/dev/null'); do
  conf=${env%.env}.conf; chk "proton-wg conf for $(basename "${env%.env}")" "[ -s $conf ]"
done
chk "fvpn-protonwg init enabled"              '/etc/init.d/fvpn-protonwg enabled'
chk "fvpn-eth-watchdog init enabled"          '/etc/init.d/fvpn-eth-watchdog enabled'
chk "sysctl 99-fvpn.conf present"             '[ -f /etc/sysctl.d/99-fvpn.conf ]'
for inc in $(R "uci show firewall | grep -o '^firewall\.fvpn_[a-z_]*=include' | cut -d. -f2 | cut -d= -f1"); do
  path=$(R "uci -q get firewall.$inc.path"); chk "firewall include $inc -> $path exists" "[ -f $path ]"
  [ "$(R "uci -q get firewall.$inc.reload")" = 1 ] && ok "include $inc reload=1" || bad "include $inc reload!=1"
done

echo "== Packages the app needs (sysupgrade drops anything opkg-installed outside ROM)"
for p in dnsmasq-full ipset kmod-veth kmod-tun openvpn-openssl wireguard-tools kmod-wireguard jsonfilter curl iptables-mod-extra; do
  chk "package $p" "opkg list-installed | grep -q '^$p '"
done

echo "== GL.iNet internals"
chk "/etc/init.d/vpn-client exists"           '[ -x /etc/init.d/vpn-client ]'
chk "rtp2.sh exists"                          '[ -x /usr/bin/rtp2.sh ]'
[ "$(R 'uci -q get firewall.vpnclient.reload')" = 0 ] && ok "firewall.vpnclient include reload=0 (firewall reload is safe)" \
  || bad "firewall.vpnclient reload != 0 -> 'firewall reload' may re-run rtp2.sh! Re-check proton-wg-internals.md"
chk "dns_mark.ko: /proc/dns_mark/create"      '[ -e /proc/dns_mark/create ]'
chk "dns_mark rule100 (0x8000 catch-all)"     '[ -d /proc/dns_mark/rule100 ]'
chk "ubus gl-clients list returns clients"    'ubus call gl-clients list | grep -q "\"clients\""'
chk "route_policy fvpn_rule_* sections"       'uci show route_policy | grep -q "^route_policy\.fvpn_rule_"'
chk "wireguard peer_90xx sections"            'uci show wireguard | grep -q "^wireguard\.peer_90"'
chk "main dnsmasq conf (adblock.py hardcodes cfg01411c)" '[ -f /var/etc/dnsmasq.conf.cfg01411c ]'
chk "dhcp leases at /tmp/dhcp.leases"         '[ -f /tmp/dhcp.leases ]'

echo "== Live routing / firewall plumbing"
chk "mangle ROUTE_POLICY chain"               'iptables -t mangle -S ROUTE_POLICY'
chk "raw pre_dns_deal_conn_zone chain"        'iptables -t raw -S pre_dns_deal_conn_zone'
chk "nat policy_redirect chain"               'iptables -t nat -S policy_redirect'
chk "filter forwarding_rule chain"            'iptables -S forwarding_rule'
chk "ip rule prio 100 fwmark 0x8000 (bypass/default)" 'ip rule | grep -q "^100:.*0x8000/0xf000"'
# vpn-client (rtp2.sh) kernel-WG/OVPN tunnels: prio 6000, fwmark 0x1000..0x5000 -> table 1001..1005 (seen live on 4.9.0)
chk "vpn-client ip rules (prio 6000 fwmark 0xN000 -> 100N)" 'ip rule | grep -qE "^6000:.*fwmark 0x[1-5]000/0xf000 lookup 100[1-5]"'
chk "kill-switch blackhole rule (prio 9910)"  'ip rule | grep -q "^9910:.*blackhole"'
if R 'ls /etc/fvpn/protonwg/*.env' >/dev/null; then
  chk "proton-wg ip rules (prio 6000)"        'ip rule | grep -q "^6000:"'
  chk "pwg_mac_* ipsets exist"                'ipset list -n | grep -q "^pwg_mac_"'
  chk "proton-wg process running"             'pgrep -f /usr/bin/proton-wg'
fi
chk "LAN table 9910 rules (prio 50)"          'ip rule | grep -q "lookup 9910"'
for ifc in $(R "wg show interfaces"); do
  age=$(R "now=\$(date +%s); wg show $ifc latest-handshakes | awk -v n=\$now '{print n-\$2}' | sort -n | head -1")
  if [ -n "$age" ] && [ "$age" -lt 300 ]; then ok "wg $ifc handshake ${age}s ago"; else meh "wg $ifc no handshake <300s (age=${age:-none})"; fi
done

echo "== WiFi (app bumps BssidNum in .dat files; NOT kept by sysupgrade)"
for b in 0 1; do
  f=/etc/wireless/mediatek/mt7986-ax6000.dbdc.b$b.dat; radio=$([ $b = 0 ] && echo mt798611 || echo mt798612)
  num=$(R "grep -o '^BssidNum=[0-9]*' $f | cut -d= -f2")
  # Only AP-mode ifaces take a BSS slot (disabled ones too); STA ifaces (apcli*, e.g. 4.11 mesh bsta5g) don't.
  # Required = max(#AP ifaces, highest ifname index + 1) — same rule as lan_access._required_bssid_num.
  need=$(R "for s in \$(uci show wireless | grep \"\.device='$radio'\" | cut -d. -f2); do
              [ \"\$(uci -q get wireless.\$s.mode)\" = sta ] && continue; echo \"\$(uci -q get wireless.\$s.ifname)\"; done" \
         | awk '{n++; sub(/^[a-z]+/,""); if ($0+0>m) m=$0+0} END{print (n>m+1?n:m+1)}')
  [ "${num:-0}" -ge "${need:-0}" ] && ok "radio $radio BssidNum=$num >= $need needed by AP ifaces" \
    || bad "radio $radio BssidNum=$num < $need needed -> extra SSIDs won't come up (sed + driver reload, see router-reference.md)"
done
for s in $(R "uci show wireless | grep \"=wifi-iface\" | cut -d. -f2 | cut -d= -f1"); do
  [ "$(R "uci -q get wireless.$s.disabled")" = 1 ] && continue
  ifn=$(R "uci -q get wireless.$s.ifname"); ssid=$(R "uci -q get wireless.$s.ssid")
  [ -z "$ifn" ] && continue
  chk "SSID '$ssid' up on $ifn" "ip link show $ifn | grep -q 'state UP\|UP,'"
done

echo; echo "PASS=$pass WARN=$warn FAIL=$fail"; [ $fail -eq 0 ]
