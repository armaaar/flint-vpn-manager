"""Split VPN facade — third-party VPNs that carry selected destinations only.

A split VPN (e.g. a company's Barracuda CloudGen VPN) runs **on the router**
next to the Proton tunnels, but only for chosen groups and only for chosen
destinations. Everything else keeps using the group's Proton tunnel.

Router layout per slot ``N`` (0..SPLITVPN_MAX-1)::

    LAN device ──► ROUTE_POLICY ─► FVPN_SPLITVPN (mark 0xA000+N*0x1000 if
                                    src ∈ group ipset AND dst ∈ fvpn_svN_dst)
               ──► ip rule prio 90 fwmark → table 1010+N
               ──► default via 10.250.N.2 dev fvsvNh   (veth into namespace)
                   blackhole default metric 10000      (fail closed)
    netns fvpn_svN:  fvsvNn ──FORWARD──► tun0 (client tunnel) + MASQUERADE
                     the client's own connection leaves via 10.250.N.1 → WAN

The VPN client (Barracuda ``barracudavpn``, x86-64 only) runs inside the
namespace under ``qemu-x86_64`` user-mode emulation, so whatever routes it
installs stay inside the namespace and can never touch the router's own
routing. Inside the namespace FORWARD only allows veth→tun, so when the
tunnel is down work traffic is dropped instead of leaking via WAN.

Destinations: static CIDRs + server-pushed routes go straight into
``fvpn_svN_dst``; domains are added by the group's dnsmasq instance
(``ipset=``) and resolved by the VPN's DNS server (``server=``) through the
tunnel.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from typing import TYPE_CHECKING

from consts import (
    SPLITVPN_BIN_DIR,
    SPLITVPN_CHAIN,
    SPLITVPN_CTL,
    SPLITVPN_DIR,
    SPLITVPN_DNSMASQ_SNIPPET,
    SPLITVPN_FWD_CHAIN,
    SPLITVPN_IPSET_PREFIX,
    SPLITVPN_MARK_BASE,
    SPLITVPN_MASK,
    SPLITVPN_MAX,
    SPLITVPN_PRIORITY,
    SPLITVPN_SCRIPT_PATH,
    SPLITVPN_TABLE_BASE,
)

if TYPE_CHECKING:
    from router.tools import SshExecutor
    from router.tools.uci import Uci

_SAFE_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
# Logins like DOMAIN\\user or user@domain are normal (AD); the value is
# shell-quoted end to end (shlex.quote → "$LOGIN"), so only control
# characters (newlines would break the stdin protocol) are refused.
_SAFE_LOGIN_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,128}$")
_SAFE_DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$"
)
_SAFE_IPSET_RE = re.compile(r"^[A-Za-z0-9_]{1,31}$")
_SAFE_IFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
_TUNNEL_MODES = ("TCP", "UDP", "HYBRID")


# ── Pure helpers (unit-tested) ────────────────────────────────────────────


def slot_mark(slot: int) -> str:
    return hex(SPLITVPN_MARK_BASE + slot * 0x1000)


def slot_table(slot: int) -> int:
    return SPLITVPN_TABLE_BASE + slot


def slot_ipset(slot: int) -> str:
    return f"{SPLITVPN_IPSET_PREFIX}{slot}_dst"


def slot_names(slot: int) -> dict:
    """Namespace / veth / addressing for a slot."""
    return {
        "netns": f"fvpn_sv{slot}",
        "host_if": f"fvsv{slot}h",
        "ns_if": f"fvsv{slot}n",
        "host_ip": f"10.250.{slot}.1",
        "ns_ip": f"10.250.{slot}.2",
        "dir": f"{SPLITVPN_DIR}/sv{slot}",
    }


def _check_slot(slot: int) -> int:
    if not isinstance(slot, int) or not 0 <= slot < SPLITVPN_MAX:
        raise ValueError(f"Invalid split VPN slot: {slot!r}")
    return slot


def normalize_cidr(value: str) -> str | None:
    """Return a canonical IPv4 network for a CIDR/IP, or None if invalid
    or a default route (a /0 would hijack all of the group's traffic)."""
    try:
        net = ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError:
        return None
    if net.version != 4 or net.prefixlen == 0:
        return None
    return str(net)


def parse_status(raw: str) -> dict:
    """Parse ``barracudavpn --status`` output.

    Example::

        Dumping connection Status:
        STATE:       CONNECTED
        IPv4:        10.20.30.40
        GWv4:        10.20.30.1
        DNSv4:       10.0.0.53 10.0.0.54
        ROUTESv4:    10.0.0.0/8 172.16.0.0/12
    """
    result: dict = {"state": "DOWN", "ip": "", "gateway": "", "dns": [], "routes": []}
    if not raw:
        return result
    current = None
    for line in raw.splitlines():
        m = re.match(r"^\s*(STATE|Status|IPv4|GWv4|DNSv4|ROUTESv4):\s*(.*)$", line)
        if m:
            current, val = m.group(1), m.group(2).strip()
        elif current in ("DNSv4", "ROUTESv4") and line.startswith((" ", "\t")):
            val = line.strip()
        else:
            current = None
            continue
        if current in ("STATE", "Status"):
            result["state"] = val.split()[0].upper() if val else "DOWN"
        elif current == "IPv4":
            result["ip"] = val
        elif current == "GWv4":
            result["gateway"] = val
        elif current == "DNSv4":
            result["dns"] += [
                d for d in re.split(r"[\s,]+", val) if _is_ipv4(d)
            ]
        elif current == "ROUTESv4":
            for tok in re.split(r"[\s,]+", val):
                cidr = normalize_cidr(tok) if "/" in tok or _is_ipv4(tok) else None
                if cidr and cidr not in result["routes"]:
                    result["routes"].append(cidr)
    return result


def _is_ipv4(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).version == 4
    except ValueError:
        return False


def build_client_config(cfg: dict) -> str:
    """Render ``barracudavpn.conf`` (``KEY = value`` lines, format written by
    the client's own configuration screen)."""
    server = str(cfg.get("server", "")).strip()
    if not _SAFE_HOST_RE.match(server):
        raise ValueError(f"Invalid server address: {server!r}")
    port = int(cfg.get("port") or 691)
    if not 1 <= port <= 65535:
        raise ValueError(f"Invalid port: {port}")
    mode = str(cfg.get("tunnel_mode") or "TCP").upper()
    if mode not in _TUNNEL_MODES:
        raise ValueError(f"Invalid tunnel mode: {mode}")
    values = {
        "BINDIP": "",
        "CERTFILE": "",
        "DYNSSA": "2",                # 2 = "User/Pass only" authentication
        "HANDSHAKETIMEOUT": "30",     # AD + OTP auth can take >10s
        "IPV6TUNNELING": "NO",
        "KEEPALIVE": "10",
        "KEYFILE": "",
        "PROXYADDR": "",
        "PROXYPORT": "8080",
        "PROXYTYPE": "NO PROXY",
        "PROXYUSER": "",
        "SERVER": server,
        "SERVERPORT": str(port),
        "SPECIAL": "NONE",
        "TAP": "/dev/net/tun",
        "TUNNELENC": "AES128-MD5",    # proposal; the gateway decides
        "TUNNELMODE": mode,
        "TUNNELREKEY": "20",
        "WRITEDNS": "NO",             # DNS is handled by the router's dnsmasq
    }
    return "".join(f"{k} = {v}\n" for k, v in values.items())


# Router-side runtime control script. Written on every connect so the router
# copy always matches this version of the app.
_CTL_SCRIPT = r"""#!/bin/sh
# Flint VPN Manager - split VPN runtime control (auto-generated, do not edit)
# Usage: svctl.sh up|start|stop|down|status <slot> [login]
#   start reads the server password and the one-time password from stdin.
BIN=__BIN__
ACT=$1; I=$2
case "$I" in [0-9]) ;; *) echo "ERR: bad slot"; exit 2 ;; esac
NS=fvpn_sv$I; H=fvsv${I}h; N=fvsv${I}n; DIR=__DIR__/sv$I
HIP=10.250.$I.1; NIP=10.250.$I.2

ns_alive() { [ -e /var/run/netns/$NS ] && [ -n "$(ip netns pids $NS 2>/dev/null)" ]; }

kill_ns() {
  for p in $(ip netns pids $NS 2>/dev/null); do kill $p 2>/dev/null; done
  sleep 1
  for p in $(ip netns pids $NS 2>/dev/null); do kill -9 $p 2>/dev/null; done
}

ns_up() {
  [ -e /var/run/netns/$NS ] || ip netns add $NS || return 1
  if ! ip link show $H >/dev/null 2>&1; then
    ip link add $H type veth peer name $N || return 1
    ip link set $N netns $NS || return 1
  fi
  ip addr replace $HIP/30 dev $H
  ip link set $H up
  # loose reverse-path check: replies from work hosts arrive on the veth
  echo 2 > /proc/sys/net/ipv4/conf/$H/rp_filter
  ip netns exec $NS sh -s <<EOF
ip link set lo up
ip addr replace $NIP/30 dev $N
ip link set $N up
ip route replace default via $HIP
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -P FORWARD DROP
iptables -F FORWARD
iptables -A FORWARD -i $N -o tun+ -j ACCEPT
iptables -A FORWARD -i tun+ -o $N -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -t nat -F POSTROUTING
iptables -t nat -A POSTROUTING -o tun+ -j MASQUERADE
iptables -t mangle -F FORWARD
iptables -t mangle -A FORWARD -o tun+ -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
EOF
  mkdir -p /etc/netns/$NS
  grep -h '^nameserver [0-9.]*$' /tmp/resolv.conf.d/resolv.conf.auto 2>/dev/null > /etc/netns/$NS/resolv.conf
  [ -s /etc/netns/$NS/resolv.conf ] || echo "nameserver 1.1.1.1" > /etc/netns/$NS/resolv.conf
  # route the namespace's own (outer) connection out of the WAN
  WAN=$(ip route show default | awk '{print $5; exit}')
  [ -n "$WAN" ] && {
    iptables -t nat -C POSTROUTING -s $NIP/32 -o $WAN -j MASQUERADE 2>/dev/null || \
      iptables -t nat -I POSTROUTING 1 -s $NIP/32 -o $WAN -j MASQUERADE
  }
  iptables -C FORWARD -i $H -s $NIP -j ACCEPT 2>/dev/null || \
    iptables -I FORWARD 1 -i $H -s $NIP -j ACCEPT
  iptables -C FORWARD -o $H -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
    iptables -I FORWARD 1 -o $H -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  ip route replace default via $NIP dev $H table __TABLE_BASE_EXPR__ 2>/dev/null
  return 0
}

client() { ip netns exec $NS $BIN/qemu-x86_64 $BIN/barracudavpn -c $DIR "$@"; }

case "$ACT" in
  up) ns_up && echo OK ;;
  start)
    LOGIN=$3
    [ -x $BIN/qemu-x86_64 ] && [ -x $BIN/barracudavpn ] || { echo "ERR: runtime not installed"; exit 3; }
    [ -f $DIR/barracudavpn.conf ] || { echo "ERR: no client config"; exit 4; }
    ns_up || { echo "ERR: namespace setup failed"; exit 5; }
    kill_ns
    cd $DIR || exit 6
    # Private /var/run per namespace: the client keeps a fixed pid file there.
    timeout 150 ip netns exec $NS sh -c 'mount -t tmpfs fvsvrun /var/run 2>/dev/null; exec "$@"' sh \
      $BIN/qemu-x86_64 $BIN/barracudavpn -c $DIR --start --login "$LOGIN" --verbose \
      > $DIR/connect.log 2>&1
    echo "RC: $?"
    ;;
  stop) ns_alive && client --stop >/dev/null 2>&1; kill_ns; echo OK ;;
  down)
    ns_alive && client --stop >/dev/null 2>&1; kill_ns
    iptables -D FORWARD -i $H -s $NIP -j ACCEPT 2>/dev/null
    iptables -D FORWARD -o $H -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
    WAN=$(ip route show default | awk '{print $5; exit}')
    [ -n "$WAN" ] && iptables -t nat -D POSTROUTING -s $NIP/32 -o $WAN -j MASQUERADE 2>/dev/null
    ip link del $H 2>/dev/null
    ip netns del $NS 2>/dev/null
    rm -rf /etc/netns/$NS
    echo OK ;;
  status)
    if ns_alive; then client --status 2>&1; else echo "STATE:       DOWN"; fi ;;
  *) echo "ERR: unknown action"; exit 2 ;;
esac
"""


def build_ctl_script() -> str:
    return (
        _CTL_SCRIPT
        .replace("__BIN__", SPLITVPN_BIN_DIR)
        .replace("__DIR__", SPLITVPN_DIR)
        .replace("__TABLE_BASE_EXPR__", f"$(({SPLITVPN_TABLE_BASE}+$I))")
    )


def build_routing_commands(instances: list[dict]) -> list[str]:
    """Shell commands that (re)build all host-side split-VPN plumbing.

    Each instance dict: ``slot``, ``group_ipsets`` (MAC ipset names),
    ``cidrs`` (destinations), ``dns_servers`` (VPN DNS, routed via the
    namespace). Idempotent: safe to run on every firewall reload.
    """
    cmds: list[str] = [
        f"iptables -t mangle -D ROUTE_POLICY -j {SPLITVPN_CHAIN} 2>/dev/null; true",
        f"iptables -t mangle -N {SPLITVPN_CHAIN} 2>/dev/null; true",
        f"iptables -t mangle -F {SPLITVPN_CHAIN}",
        f"iptables -D FORWARD -j {SPLITVPN_FWD_CHAIN} 2>/dev/null; true",
        f"iptables -N {SPLITVPN_FWD_CHAIN} 2>/dev/null; true",
        f"iptables -F {SPLITVPN_FWD_CHAIN}",
    ]
    for slot in range(SPLITVPN_MAX):
        mark, table = slot_mark(slot), slot_table(slot)
        cmds += [
            f"while ip rule del fwmark {mark}/{SPLITVPN_MASK} lookup {table} 2>/dev/null; do :; done",
            f"ip route flush table {table} 2>/dev/null; true",
        ]

    for inst in instances:
        slot = _check_slot(inst["slot"])
        n = slot_names(slot)
        mark, table, ipset = slot_mark(slot), slot_table(slot), slot_ipset(slot)
        cmds += [
            f"ipset create {ipset} hash:net -exist",
            f"ipset flush {ipset}",
        ]
        for cidr in sorted({c for c in (normalize_cidr(x) for x in inst.get("cidrs", [])) if c}):
            cmds.append(f"ipset add {ipset} {cidr} -exist")
        for gset in inst.get("group_ipsets", []):
            if not _SAFE_IPSET_RE.match(gset):
                continue
            cmds.append(
                f"iptables -t mangle -A {SPLITVPN_CHAIN} -m set --match-set {gset} src "
                f"-m set --match-set {ipset} dst -j MARK --set-xmark {mark}/{SPLITVPN_MASK}"
            )
        cmds += [
            f"ip rule add fwmark {mark}/{SPLITVPN_MASK} lookup {table} priority {SPLITVPN_PRIORITY}",
            # fail closed: without the namespace the marked traffic is dropped,
            # never silently sent through the group's normal tunnel
            f"ip route add blackhole default metric 10000 table {table}",
            f"ip route replace default via {n['ns_ip']} dev {n['host_if']} table {table} 2>/dev/null; true",
            f"iptables -A {SPLITVPN_FWD_CHAIN} -o {n['host_if']} -m mark --mark {mark}/{SPLITVPN_MASK} -j ACCEPT",
            f"iptables -A {SPLITVPN_FWD_CHAIN} -i {n['host_if']} -s {n['ns_ip']} -j ACCEPT",
            f"iptables -A {SPLITVPN_FWD_CHAIN} -i {n['host_if']} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
        ]
        # The VPN's DNS servers are only reachable through the tunnel; dnsmasq
        # queries them from the router itself, so give them a host route.
        for dns in inst.get("dns_servers", []):
            if _is_ipv4(dns):
                cmds.append(
                    f"ip route replace {dns}/32 via {n['ns_ip']} dev {n['host_if']} 2>/dev/null; true"
                )

    if instances:
        cmds += [
            f"iptables -t mangle -I ROUTE_POLICY 1 -j {SPLITVPN_CHAIN}",
            f"iptables -I FORWARD 1 -j {SPLITVPN_FWD_CHAIN}",
        ]
    else:
        cmds += [
            f"iptables -t mangle -X {SPLITVPN_CHAIN} 2>/dev/null; true",
            f"iptables -X {SPLITVPN_FWD_CHAIN} 2>/dev/null; true",
        ]
    return cmds


def build_dnsmasq_snippet(entries: list[dict]) -> str:
    """dnsmasq lines for one dnsmasq instance.

    Each entry: ``slot``, ``domains``, ``dns_servers``. Domains are resolved
    by the VPN's DNS (through the tunnel) and their answers are added to the
    slot's destination ipset so the traffic follows.
    """
    lines = ["# Flint VPN Manager split VPNs - auto-generated"]
    for e in entries:
        domains = [d.strip(".").lower() for d in e.get("domains", []) if _SAFE_DOMAIN_RE.match(d.strip("."))]
        if not domains:
            continue
        path = "/".join(domains)
        for dns in e.get("dns_servers", []):
            if _is_ipv4(dns):
                lines.append(f"server=/{path}/{dns}")
        lines.append(f"ipset=/{path}/{slot_ipset(_check_slot(e['slot']))}")
    return "\n".join(lines) + "\n"


class RouterSplitVpn:
    """Router-side lifecycle for split VPNs (runtime, tunnels, routing, DNS)."""

    def __init__(self, uci: Uci, ssh: SshExecutor):
        self._uci = uci
        self._ssh = ssh

    # ── Runtime (emulator + client binaries) ──────────────────────────────

    def runtime_status(self) -> dict:
        out = self._ssh.exec(
            f"cd {SPLITVPN_BIN_DIR} 2>/dev/null && sha256sum qemu-x86_64 barracudavpn 2>/dev/null; true"
        )
        hashes = {}
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 2:
                hashes[parts[1]] = parts[0]
        return hashes

    def install_runtime_file(self, name: str, data: bytes) -> None:
        if name not in ("qemu-x86_64", "barracudavpn"):
            raise ValueError(f"Unknown runtime file: {name}")
        self._ssh.exec(f"mkdir -p {SPLITVPN_BIN_DIR}")
        tmp = f"{SPLITVPN_BIN_DIR}/{name}.part"
        self._ssh.write_bytes(tmp, data)
        self._ssh.exec(f"chmod 755 {tmp} && mv {tmp} {SPLITVPN_BIN_DIR}/{name}")

    # ── Per-slot client configuration ─────────────────────────────────────

    def write_client_config(self, slot: int, cfg: dict) -> None:
        d = slot_names(_check_slot(slot))["dir"]
        self._ssh.exec(f"mkdir -p {d}/ca")
        self._ssh.write_file(f"{d}/barracudavpn.conf", build_client_config(cfg))

    def remove_slot_files(self, slot: int) -> None:
        d = slot_names(_check_slot(slot))["dir"]
        self._ssh.exec(f"rm -rf {d}")

    def _write_ctl(self) -> None:
        self._ssh.exec(f"mkdir -p {SPLITVPN_DIR}")
        self._ssh.write_file(SPLITVPN_CTL, build_ctl_script())
        self._ssh.exec(f"chmod 755 {SPLITVPN_CTL}")

    # ── Tunnel lifecycle ──────────────────────────────────────────────────

    def connect(self, slot: int, login: str, password: str, otp: str) -> dict:
        """Start the client in its namespace. The password and OTP go through
        a 0600 tmpfs file into the client's stdin — never on a command line."""
        slot = _check_slot(slot)
        if not _SAFE_LOGIN_RE.match(login or ""):
            raise ValueError("Invalid login name")
        if "\n" in password or "\n" in otp:
            raise ValueError("Password/OTP must be a single line")
        self._write_ctl()
        secret = f"/tmp/fvsv{slot}.in"
        self._ssh.exec(f"umask 077; : > {secret}")
        self._ssh.write_file(secret, f"{password}\n{otp}\n")
        try:
            out = self._ssh.exec(
                f"{SPLITVPN_CTL} start {slot} {shlex.quote(login)} < {secret}; rm -f {secret}",
                timeout=180,
            )
        finally:
            self._ssh.exec(f"rm -f {secret}")
        status = self.status(slot)
        status["log"] = self.connect_log(slot)
        status["rc"] = _parse_rc(out)
        return status

    def disconnect(self, slot: int, teardown: bool = False) -> None:
        slot = _check_slot(slot)
        self._write_ctl()
        self._ssh.exec(f"{SPLITVPN_CTL} {'down' if teardown else 'stop'} {slot}", timeout=60)

    def status(self, slot: int) -> dict:
        slot = _check_slot(slot)
        raw = self._ssh.exec(
            f"[ -x {SPLITVPN_CTL} ] && {SPLITVPN_CTL} status {slot} || echo 'STATE: DOWN'",
            timeout=60,
        )
        return parse_status(raw)

    def connect_log(self, slot: int, lines: int = 60) -> str:
        d = slot_names(_check_slot(slot))["dir"]
        return self._ssh.exec(f"tail -n {int(lines)} {d}/connect.log 2>/dev/null; true")

    # ── Host routing / firewall / DNS ─────────────────────────────────────

    def apply_routing(self, instances: list[dict]) -> None:
        """(Re)build marks, tables, forward rules and DNS for all instances.

        Each instance: ``slot``, ``group_ipsets``, ``cidrs``, ``dns_servers``,
        ``domains``, ``dnsmasq_ifaces`` (``main`` or tunnel iface names).
        """
        cmds = build_routing_commands(instances)
        self._ssh.exec("; ".join(cmds), timeout=60)
        if instances:
            self._write_firewall_include(cmds)
            self._uci.ensure_firewall_include("fvpn_splitvpn", SPLITVPN_SCRIPT_PATH)
        else:
            self._ssh.exec(f"rm -f {SPLITVPN_SCRIPT_PATH}")
            self._uci.delete("firewall.fvpn_splitvpn")
            self._uci.commit("firewall")
        self._sync_dnsmasq(instances)

    def _write_firewall_include(self, cmds: list[str]) -> None:
        script = "\n".join([
            "#!/bin/sh",
            "# Flint VPN Manager split VPNs - auto-generated, re-applied on firewall reload",
            "",
            *cmds,
        ]) + "\n"
        self._ssh.exec("mkdir -p /etc/fvpn")
        self._ssh.write_file(SPLITVPN_SCRIPT_PATH, script)
        self._ssh.exec(f"chmod +x {SPLITVPN_SCRIPT_PATH}")

    def _sync_dnsmasq(self, instances: list[dict]) -> None:
        per_iface: dict[str, list[dict]] = {}
        for inst in instances:
            if not inst.get("domains"):
                continue
            for iface in inst.get("dnsmasq_ifaces", []):
                if iface == "main" or _SAFE_IFACE_RE.match(iface):
                    per_iface.setdefault(iface, []).append(inst)

        wanted = {
            ("/tmp/dnsmasq.d" if iface == "main" else f"/tmp/dnsmasq.d.{iface}")
            + f"/{SPLITVPN_DNSMASQ_SNIPPET}": build_dnsmasq_snippet(entries)
            for iface, entries in per_iface.items()
        }
        current = self._read_snippets()
        if current == wanted:
            return  # unchanged: skip the restart (it blips DNS for everyone)
        self._ssh.exec(
            f"rm -f /tmp/dnsmasq.d/{SPLITVPN_DNSMASQ_SNIPPET} /tmp/dnsmasq.d.*/{SPLITVPN_DNSMASQ_SNIPPET}"
        )
        for path, content in wanted.items():
            self._ssh.exec(f"mkdir -p {path.rsplit('/', 1)[0]}")
            self._ssh.write_file(path, content)
        # ipset= needs a full restart (HUP is not enough); ~12s, so background
        self._ssh.exec("/etc/init.d/dnsmasq restart >/dev/null 2>&1 &")

    def _read_snippets(self) -> dict[str, str]:
        raw = self._ssh.exec(
            f"for f in /tmp/dnsmasq.d/{SPLITVPN_DNSMASQ_SNIPPET} /tmp/dnsmasq.d.*/{SPLITVPN_DNSMASQ_SNIPPET}; do "
            f"[ -f \"$f\" ] && {{ echo \"@@FILE $f\"; cat \"$f\"; }}; done; true"
        )
        result: dict[str, str] = {}
        path = None
        for line in raw.splitlines():
            if line.startswith("@@FILE "):
                path = line[7:].strip()
                result[path] = ""
            elif path:
                result[path] += line + "\n"
        return result


def _parse_rc(out: str) -> int | None:
    m = re.search(r"RC:\s*(\d+)", out or "")
    return int(m.group(1)) if m else None
