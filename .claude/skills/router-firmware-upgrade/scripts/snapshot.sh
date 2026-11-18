#!/usr/bin/env bash
# Capture a read-only snapshot of the router's state for pre/post firmware-upgrade diffing.
# Usage: snapshot.sh <output-dir> [router-host]
# Every command below is read-only on the router (sysupgrade -b only builds an archive to stdout).
# Output contains WiFi passwords and WG private keys inside the config backup — keep it out of git.
set -euo pipefail
OUT=${1:?usage: snapshot.sh <output-dir> [router-host]}
HOST=${2:-root@192.168.8.1}
mkdir -p "$OUT" && chmod 700 "$OUT"
R() { ssh -o ConnectTimeout=8 -o BatchMode=yes "$HOST" "$@"; }

# Router has no sftp-server, so plain `scp` fails — stream everything over ssh instead.
R 'sysupgrade -b - 2>/dev/null'                                   > "$OUT/sysupgrade-config-backup.tar.gz"
R 'tar czf - /etc/fvpn /usr/bin/proton-wg /etc/init.d/fvpn-* /etc/sysctl.d/99-*fvpn* /etc/sysctl.d/99-disable-ipv6.conf /etc/sysupgrade.conf 2>/dev/null; true' > "$OUT/fvpn-files.tar.gz"
R 'tar czf - /etc/init.d/vpn-client /usr/bin/rtp2.sh /etc/init.d/firewall /etc/firewall.* 2>/dev/null; true' > "$OUT/gl-scripts.tar.gz"
R 'cat /etc/glversion; cat /etc/openwrt_release; uname -a'          > "$OUT/version.txt"
R 'opkg list-installed'                                            > "$OUT/opkg-installed.txt"
comm -23 <(R 'awk "/^Package:/{print \$2}" /usr/lib/opkg/status' | sort) \
         <(R 'awk "/^Package:/{print \$2}" /rom/usr/lib/opkg/status' | sort) > "$OUT/opkg-added-beyond-rom.txt"
for c in route_policy wireguard ovpnclient network firewall wireless dhcp; do
  R "uci export $c" > "$OUT/uci-$c.txt" 2>/dev/null || true
done
R 'ip rule; echo ===V6; ip -6 rule'                                > "$OUT/ip-rules.txt"
R 'ip route show table all'                                        > "$OUT/ip-routes.txt"
R 'iptables-save; echo ===V6; ip6tables-save'                      > "$OUT/iptables.txt"
R 'ipset list -n | sort'                                           > "$OUT/ipsets.txt"
R 'wg show all | grep -v "private key"'                            > "$OUT/wg-show.txt" || true
R 'ls /proc/dns_mark 2>&1; echo ===; lsmod'                         > "$OUT/kmods.txt"
R 'ubus list | sort'                                               > "$OUT/ubus-list.txt"
R 'ps w'                                                           > "$OUT/ps.txt"
R 'cat /etc/sysupgrade.conf'                                       > "$OUT/sysupgrade.conf.txt"
chmod 600 "$OUT"/*
echo "snapshot written to $OUT"; head -1 "$OUT/version.txt"
