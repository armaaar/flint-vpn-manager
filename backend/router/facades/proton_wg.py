"""Router proton-wg facade — userspace WireGuard TCP/TLS tunnel lifecycle.

Extracted from router_api.py. Manages the full lifecycle of proton-wg
tunnels: process, interface, routing, firewall zones, mangle rules,
and init.d boot persistence.
"""

import time

from consts import (
    HEALTH_AMBER,
    HEALTH_CONNECTING,
    HEALTH_GREEN,
    HEALTH_RED,
    PROTO_WIREGUARD_TCP,
    PROTO_WIREGUARD_TLS,
)

PROTON_WG_MARKS = ["0x6000", "0x7000", "0x9000", "0xf000"]
PROTON_WG_DIR = "/etc/fvpn/protonwg"
PROTON_WG_BIN = "/usr/bin/proton-wg"


class RouterProtonWG:
    """Facade for proton-wg (WireGuard TCP/TLS) on the GL.iNet Flint 2."""

    def __init__(self, uci, ipset, iptables, iproute, service_ctl, alloc_tunnel_id, ssh):
        self._uci = uci
        self._ipset = ipset
        self._iptables = iptables
        self._iproute = iproute
        self._service_ctl = service_ctl
        self._alloc_tunnel_id = alloc_tunnel_id
        self._ssh = ssh  # raw exec for wg, pidof, kill, cat, ip link show, etc.; write_file for configs

    def _next_proton_wg_slot(self) -> tuple[str, str, int]:
        """Find the next available proton-wg slot (4 max)."""
        existing_ifaces = self._ssh.exec(
            "ip link show 2>/dev/null | grep protonwg | awk -F: '{print $2}' | tr -d ' '"
        ).strip().splitlines()
        live = set(x.strip() for x in existing_ifaces if x.strip())

        existing_configs = self._ssh.exec(
            f"ls {PROTON_WG_DIR}/protonwg*.conf {PROTON_WG_DIR}/protonwg*.env 2>/dev/null"
        ).strip()
        reserved = set()
        for path in existing_configs.splitlines():
            path = path.strip()
            fname = path.rsplit("/", 1)[-1].rsplit(".", 1)[0]
            if fname.startswith("protonwg"):
                reserved.add(fname)

        used = live | reserved

        for i, mark in enumerate(PROTON_WG_MARKS):
            iface = f"protonwg{i}"
            table_num = 1000 + (int(mark, 16) >> 12)

            if iface not in used:
                return iface, mark, table_num

            if iface in live and iface not in reserved:
                pid = self._ssh.exec(
                    f"for p in $(pidof proton-wg 2>/dev/null); do "
                    f"grep -qz 'PROTON_WG_INTERFACE_NAME={iface}' /proc/$p/environ 2>/dev/null && echo $p; "
                    f"done"
                ).strip()
                if not pid:
                    self._ssh.exec(f"ip link del {iface} 2>/dev/null; true")
                    return iface, mark, table_num

        raise RuntimeError("WireGuard TCP/TLS limit reached (4 max)")

    def upload_proton_wg_config(
        self,
        profile_name: str,
        private_key: str,
        public_key: str,
        endpoint: str,
        socket_type: str = "tcp",
        dns: str = "10.2.0.1",
    ) -> dict:
        """Write a proton-wg config and env file to the router."""
        iface, mark, table_num = self._next_proton_wg_slot()
        tunnel_id = self._alloc_tunnel_id(self._ssh)

        self._ssh.exec(f"mkdir -p {PROTON_WG_DIR}")
        self.ensure_proton_wg_initd()

        wg_conf = (
            f"[Interface]\n"
            f"PrivateKey = {private_key}\n"
            f"\n"
            f"[Peer]\n"
            f"PublicKey = {public_key}\n"
            f"AllowedIPs = 0.0.0.0/0\n"
            f"Endpoint = {endpoint}\n"
            f"PersistentKeepalive = 25\n"
        )
        self._ssh.write_file(f"{PROTON_WG_DIR}/{iface}.conf", wg_conf)

        env = (
            f"PROTON_WG_INTERFACE_NAME={iface}\n"
            f"PROTON_WG_SOCKET_TYPE={socket_type}\n"
            f"PROTON_WG_SERVER_NAME_STRATEGY=1\n"
            f"FVPN_TUNNEL_ID={tunnel_id}\n"
            f"FVPN_MARK={mark}\n"
            f"FVPN_IPSET=src_mac_{tunnel_id}\n"
        )
        self._ssh.write_file(f"{PROTON_WG_DIR}/{iface}.env", env)

        ipset_name = f"src_mac_{tunnel_id}"
        self._ipset.create(ipset_name, "hash:mac")

        return {
            "tunnel_name": iface,
            "tunnel_id": tunnel_id,
            "mark": mark,
            "table_num": table_num,
            "ipset_name": ipset_name,
            "socket_type": socket_type,
            "vpn_protocol": {"tcp": PROTO_WIREGUARD_TCP, "tls": PROTO_WIREGUARD_TLS}[socket_type],
            "rule_name": f"fvpn_pwg_{iface}",
        }

    def start_proton_wg_tunnel(self, iface: str, mark: str, table_num: int,
                                tunnel_id: int, dns: str = "10.2.0.1") -> None:
        """Start a proton-wg tunnel: process, interface, routing, firewall."""
        conf_path = f"{PROTON_WG_DIR}/{iface}.conf"
        env_path = f"{PROTON_WG_DIR}/{iface}.env"
        ipset_name = f"src_mac_{tunnel_id}"

        bin_check = self._ssh.exec(f"[ -x {PROTON_WG_BIN} ] && echo ok || echo missing").strip()
        if bin_check != "ok":
            raise RuntimeError(f"proton-wg binary not found at {PROTON_WG_BIN}")

        link = self._ssh.exec(f"ip link show {iface} 2>/dev/null | head -1")
        if iface in link:
            try:
                self.stop_proton_wg_tunnel(iface, mark, table_num, tunnel_id)
            except Exception:
                self._ssh.exec(f"ip link del {iface} 2>/dev/null; true")

        self._ipset.create(ipset_name, "hash:mac")

        env_exists = self._ssh.exec(f"[ -f {env_path} ] && echo yes || echo no").strip()
        if env_exists != "yes":
            socket_type = "tcp"
            conf_content = self._ssh.exec(f"cat {conf_path} 2>/dev/null").strip()
            if ":443" in conf_content:
                socket_type = "tcp"
            env = (
                f"PROTON_WG_INTERFACE_NAME={iface}\n"
                f"PROTON_WG_SOCKET_TYPE={socket_type}\n"
                f"PROTON_WG_SERVER_NAME_STRATEGY=1\n"
                f"FVPN_TUNNEL_ID={tunnel_id}\n"
                f"FVPN_MARK={mark}\n"
                f"FVPN_IPSET={ipset_name}\n"
            )
            self._ssh.write_file(env_path, env)

        # 1. Start proton-wg process
        self._ssh.exec(
            f"(. {env_path} && export PROTON_WG_INTERFACE_NAME PROTON_WG_SOCKET_TYPE "
            f"PROTON_WG_SERVER_NAME_STRATEGY && "
            f"{PROTON_WG_BIN} > /tmp/{iface}.log 2>&1) &"
        )

        # 2. Wait for interface
        for _ in range(10):
            out = self._ssh.exec(f"ip link show {iface} 2>/dev/null | head -1")
            if iface in out:
                break
            time.sleep(0.5)
        else:
            raise RuntimeError(f"proton-wg interface {iface} did not appear within 5s")

        # 3. Apply WG config
        self._ssh.exec(f"wg setconf {iface} {conf_path}")

        # 4. Set up IP + bring interface up
        self._iproute.addr_add("10.2.0.2/32", iface)
        self._iproute.link_set_up(iface)

        # 5. Routing table + ip rules
        self._iproute.route_add("default", iface, table_num)
        self._iproute.route_add_blackhole("default", table_num, metric=254)
        self._iproute.rule_add(mark, "0xf000", table_num, 6000)

        # 6. Firewall zone via UCI
        self._ssh.exec(
            f"uci set firewall.fvpn_zone_{iface}=zone && "
            f"uci set firewall.fvpn_zone_{iface}.name='{iface}' && "
            f"uci add_list firewall.fvpn_zone_{iface}.device='{iface}' && "
            f"uci set firewall.fvpn_zone_{iface}.input='DROP' && "
            f"uci set firewall.fvpn_zone_{iface}.output='ACCEPT' && "
            f"uci set firewall.fvpn_zone_{iface}.forward='REJECT' && "
            f"uci set firewall.fvpn_zone_{iface}.masq='1' && "
            f"uci set firewall.fvpn_zone_{iface}.mtu_fix='1' && "
            f"uci set firewall.fvpn_fwd_{iface}=forwarding && "
            f"uci set firewall.fvpn_fwd_{iface}.src='lan' && "
            f"uci set firewall.fvpn_fwd_{iface}.dest='{iface}' && "
            f"uci commit firewall && "
            f"/etc/init.d/firewall reload >/dev/null 2>&1"
        )

        # 7. Rebuild ALL proton-wg mangle MARK rules
        self._rebuild_proton_wg_mangle_rules()

        # 8. Wait for WG handshake
        for _ in range(15):
            hs = self._ssh.exec(f"wg show {iface} latest-handshakes 2>/dev/null")
            if hs.strip() and "\t0" not in hs:
                return
            time.sleep(1)

    def stop_proton_wg_tunnel(self, iface: str, mark: str, table_num: int,
                               tunnel_id: int) -> None:
        """Stop a proton-wg tunnel: kill process, clean up routing + firewall."""
        chain = f"TUNNEL{tunnel_id}_ROUTE_POLICY"

        # 1. Remove mangle chain
        self._iptables.delete_chain("mangle", "ROUTE_POLICY", chain)

        # 2. Remove ip rules + routes
        self._iproute.rule_del(mark, "0xf000", table_num)
        self._iproute.route_flush_table(table_num)

        # 3. Kill ONLY this tunnel's proton-wg process
        pid = self._ssh.exec(
            f"for p in $(pidof proton-wg); do "
            f"grep -qz 'PROTON_WG_INTERFACE_NAME={iface}' /proc/$p/environ 2>/dev/null && echo $p; "
            f"done"
        ).strip()
        if pid:
            self._ssh.exec(f"kill {pid} 2>/dev/null; true")
        time.sleep(1)

        # 4. Remove the interface
        self._iproute.link_delete(iface)

        # 5. Remove firewall zone + forwarding, rebuild mangle
        self._uci.delete(f"firewall.fvpn_zone_{iface}")
        self._uci.delete(f"firewall.fvpn_fwd_{iface}")
        self._uci.commit("firewall")
        self._service_ctl.reload("firewall")
        self._rebuild_proton_wg_mangle_rules()

        # 6. Clean up log
        self._ssh.exec(f"rm -f /tmp/{iface}.log")

    def _rebuild_proton_wg_mangle_rules(self) -> None:
        """Rebuild mangle MARK rules for ALL active proton-wg tunnels."""
        envs = self._ssh.exec(f"ls {PROTON_WG_DIR}/*.env 2>/dev/null || true").strip()
        if not envs:
            self._ssh.exec(
                f"rm -f {PROTON_WG_DIR}/mangle_rules.sh; "
                f"uci delete firewall.fvpn_pwg_mangle 2>/dev/null; "
                f"uci commit firewall 2>/dev/null; true"
            )
            stale = self._ssh.exec(
                "iptables -t mangle -S ROUTE_POLICY 2>/dev/null | "
                "grep -oP 'TUNNEL\\d+_ROUTE_POLICY' | sort -u"
            ).strip()
            for chain in stale.splitlines():
                chain = chain.strip()
                if not chain or chain == "TUNNEL100_ROUTE_POLICY":
                    continue
                self._iptables.delete_chain("mangle", "ROUTE_POLICY", chain)
            return

        tunnels = []
        for env_path in envs.splitlines():
            env_path = env_path.strip()
            if not env_path:
                continue
            env_content = self._ssh.exec(f"cat {env_path} 2>/dev/null").strip()
            vals = {}
            for line in env_content.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    vals[k] = v
            iface = vals.get("PROTON_WG_INTERFACE_NAME", "")
            tid = vals.get("FVPN_TUNNEL_ID", "")
            mark = vals.get("FVPN_MARK", "")
            ipset_name = vals.get("FVPN_IPSET", "")
            if not (iface and tid and mark and ipset_name):
                continue
            tunnels.append((iface, mark, ipset_name, tid))

        cmds = []
        for iface, mark, ipset_name, tid in tunnels:
            cmds.append(f"ipset create {ipset_name} hash:mac -exist")
        for iface, mark, ipset_name, tid in tunnels:
            chain = f"TUNNEL{tid}_ROUTE_POLICY"
            cmds.append(f"iptables -t mangle -N {chain} 2>/dev/null")
            cmds.append(f"iptables -t mangle -F {chain}")
            cmds.append(
                f"iptables -t mangle -A {chain} -m comment --comment '{iface}' "
                f"-m mark --mark 0x0/0xf000 -m set --match-set {ipset_name} src "
                f"-j MARK --set-xmark {mark}/0xf000"
            )
            cmds.append(
                f"iptables -t mangle -C ROUTE_POLICY -j {chain} 2>/dev/null || "
                f"iptables -t mangle -I ROUTE_POLICY 1 -j {chain}"
            )

        if cmds:
            self._ssh.exec("; ".join(cmds))

        script = "#!/bin/sh\n# Auto-generated by FlintVPN — proton-wg mangle rules\n"
        script += "# Re-applied on every firewall reload\n\n"
        for cmd in cmds:
            script += cmd + "\n"
        self._ssh.write_file(f"{PROTON_WG_DIR}/mangle_rules.sh", script)
        self._ssh.exec(f"chmod +x {PROTON_WG_DIR}/mangle_rules.sh")

        self._uci.ensure_firewall_include(
            "fvpn_pwg_mangle", f"{PROTON_WG_DIR}/mangle_rules.sh"
        )

    def delete_proton_wg_config(self, iface: str, tunnel_id: int) -> None:
        """Delete proton-wg config files, ipset, and rebuild mangle rules."""
        ipset_name = f"src_mac_{tunnel_id}"
        self._ssh.exec(
            f"rm -f {PROTON_WG_DIR}/{iface}.conf {PROTON_WG_DIR}/{iface}.env"
        )
        self._ipset.destroy(ipset_name)
        self._rebuild_proton_wg_mangle_rules()

    def ensure_proton_wg_initd(self) -> None:
        """Install the proton-wg init.d service for boot persistence."""
        script = r"""#!/bin/sh /etc/rc.common
START=99
STOP=10
USE_PROCD=1

PROTON_WG_DIR="/etc/fvpn/protonwg"
PROTON_WG_BIN="/usr/bin/proton-wg"

start_service() {
    [ -x "$PROTON_WG_BIN" ] || return
    for envfile in "$PROTON_WG_DIR"/*.env; do
        [ -f "$envfile" ] || continue
        . "$envfile"
        iface="$PROTON_WG_INTERFACE_NAME"
        [ -z "$iface" ] && continue
        conffile="$PROTON_WG_DIR/$iface.conf"
        [ -f "$conffile" ] || continue

        procd_open_instance "$iface"
        procd_set_param env $(cat "$envfile" | tr '\n' ' ')
        procd_set_param command "$PROTON_WG_BIN"
        procd_set_param stdout 1
        procd_set_param stderr 1
        procd_close_instance

        # Wait for interface, then set up networking + routing
        (sleep 3 && \
         wg setconf "$iface" "$conffile" 2>/dev/null && \
         ip addr add 10.2.0.2/32 dev "$iface" 2>/dev/null && \
         ip link set "$iface" up 2>/dev/null && \
         # Routing table + ip rule (from env metadata)
         tid="$FVPN_TUNNEL_ID" && \
         mark="$FVPN_MARK" && \
         table_num=$((1000 + 0x$(echo "$mark" | sed 's/0x//;s/000//'))) && \
         ip route add default dev "$iface" table "$table_num" 2>/dev/null && \
         ip route add blackhole default metric 254 table "$table_num" 2>/dev/null && \
         ip rule add fwmark "$mark"/0xf000 lookup "$table_num" priority 6000 2>/dev/null \
        ) &
    done

    # Apply mangle rules (firewall include handles subsequent reloads)
    if [ -x "$PROTON_WG_DIR/mangle_rules.sh" ]; then
        (sleep 5 && "$PROTON_WG_DIR/mangle_rules.sh") &
    fi
}
"""
        self._ssh.write_file("/etc/init.d/fvpn-protonwg", script)
        self._ssh.exec("chmod +x /etc/init.d/fvpn-protonwg")
        self._service_ctl.enable("fvpn-protonwg")

    def get_proton_wg_health(self, iface: str) -> str:
        """Get health of a proton-wg tunnel. Same semantics as get_tunnel_health."""
        if not self._iproute.link_exists(iface):
            return HEALTH_RED
        link = self._ssh.exec(f"ip link show {iface} 2>/dev/null | head -1")
        if "UP" not in link:
            return HEALTH_RED

        from router.tools.wg_show import parse_handshake_age
        age = parse_handshake_age(self._ssh, iface)
        if age is None:
            return HEALTH_CONNECTING
        if age <= 180:
            return HEALTH_GREEN
        if age <= 600:
            return HEALTH_AMBER
        return HEALTH_RED

    def update_config_live(self, iface: str, wg_conf_content: str) -> None:
        """Rewrite the WG config and apply via wg setconf (zero-flicker switch).

        Called by ProtonWGStrategy.switch_server() — absorbs the leaked
        router.write_file + router.exec("wg setconf") calls.
        """
        conf_path = f"{PROTON_WG_DIR}/{iface}.conf"
        self._ssh.write_file(conf_path, wg_conf_content)
        self._ssh.exec(f"wg setconf {iface} {conf_path}")

    def update_tunnel_env(self, iface: str, tunnel_id: int) -> None:
        """Update the FVPN_TUNNEL_ID in a proton-wg .env file.

        Called by ProfileHealer when healing duplicate tunnel IDs.
        """
        env_path = f"{PROTON_WG_DIR}/{iface}.env"
        self._ssh.exec(
            f"sed -i 's/^FVPN_TUNNEL_ID=.*/FVPN_TUNNEL_ID={tunnel_id}/' {env_path}; "
            f"sed -i 's/^FVPN_IPSET=.*/FVPN_IPSET=src_mac_{tunnel_id}/' {env_path}"
        )
