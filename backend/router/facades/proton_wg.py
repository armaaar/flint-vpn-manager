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

    def list_tunnel_confs(self) -> set[str]:
        """Return the set of proton-wg interface names that have a .conf on the router.

        A missing .conf means the tunnel was never provisioned (or the router
        was replaced).  Used by profile_list_builder to decide ghost status.
        Single SSH call.
        """
        raw = self._ssh.exec(
            f"ls {PROTON_WG_DIR}/*.conf 2>/dev/null || true"
        ).strip()
        if not raw:
            return set()
        # "/etc/fvpn/protonwg/protonwg0.conf" -> "protonwg0"
        result = set()
        for line in raw.splitlines():
            line = line.strip()
            if line:
                fname = line.rsplit("/", 1)[-1]
                if fname.endswith(".conf"):
                    result.add(fname[:-5])
        return result

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
        ipv6: bool = False,
    ) -> dict:
        """Write a proton-wg config and env file to the router."""
        iface, mark, table_num = self._next_proton_wg_slot()
        tunnel_id = self._alloc_tunnel_id(self._ssh)

        self._ssh.exec(f"mkdir -p {PROTON_WG_DIR}")
        self.ensure_proton_wg_initd()

        allowed_ips = "0.0.0.0/0, ::/0" if ipv6 else "0.0.0.0/0"
        wg_conf = (
            f"[Interface]\n"
            f"PrivateKey = {private_key}\n"
            f"\n"
            f"[Peer]\n"
            f"PublicKey = {public_key}\n"
            f"AllowedIPs = {allowed_ips}\n"
            f"Endpoint = {endpoint}\n"
            f"PersistentKeepalive = 25\n"
        )
        self._ssh.write_file(f"{PROTON_WG_DIR}/{iface}.conf", wg_conf)

        ipv6_flag = "1" if ipv6 else "0"
        env = (
            f"PROTON_WG_INTERFACE_NAME={iface}\n"
            f"PROTON_WG_SOCKET_TYPE={socket_type}\n"
            f"PROTON_WG_SERVER_NAME_STRATEGY=1\n"
            f"FVPN_TUNNEL_ID={tunnel_id}\n"
            f"FVPN_MARK={mark}\n"
            f"FVPN_IPSET=src_mac_{tunnel_id}\n"
            f"FVPN_IPV6={ipv6_flag}\n"
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
            "ipv6": ipv6,
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
            env = (
                f"PROTON_WG_INTERFACE_NAME={iface}\n"
                f"PROTON_WG_SOCKET_TYPE=tcp\n"
                f"PROTON_WG_SERVER_NAME_STRATEGY=1\n"
                f"FVPN_TUNNEL_ID={tunnel_id}\n"
                f"FVPN_MARK={mark}\n"
                f"FVPN_IPSET={ipset_name}\n"
                f"FVPN_IPV6=0\n"
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

        # Check if IPv6 is enabled (read env from disk only if we didn't just write it)
        if env_exists == "yes":
            env_content = self._ssh.exec(f"cat {env_path} 2>/dev/null").strip()
            _ipv6_enabled = "FVPN_IPV6=1" in env_content
        else:
            _ipv6_enabled = False  # Reconstructed env defaults to FVPN_IPV6=0

        if _ipv6_enabled:
            from consts import PROTON_WG_IPV6_ADDR
            self._iproute.addr_add_v6(PROTON_WG_IPV6_ADDR, iface)

        # 5. Routing table + ip rules
        self._iproute.route_add("default", iface, table_num)
        self._iproute.route_add_blackhole("default", table_num, metric=254)
        self._iproute.rule_add(mark, "0xf000", table_num, 6000)

        if _ipv6_enabled:
            self._iproute.route_add_v6("default", iface, table_num)
            self._iproute.route_add_blackhole_v6("default", table_num, metric=254)
            self._iproute.rule_add_v6(mark, "0xf000", table_num, 6000)

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

        # 8. Per-tunnel dnsmasq (DNS isolation + adblock support)
        self._start_proton_wg_dnsmasq(iface, mark, dns)

        # 9. Wait for WG handshake
        for _ in range(15):
            hs = self._ssh.exec(f"wg show {iface} latest-handshakes 2>/dev/null")
            if hs.strip() and "\t0" not in hs:
                return
            time.sleep(1)

    def stop_proton_wg_tunnel(self, iface: str, mark: str, table_num: int,
                               tunnel_id: int) -> None:
        """Stop a proton-wg tunnel: kill process, clean up routing + firewall."""
        chain = f"TUNNEL{tunnel_id}_ROUTE_POLICY"

        # 0. Tear down per-tunnel dnsmasq first (before firewall reload)
        self._stop_proton_wg_dnsmasq(iface, mark)

        # 1. Remove mangle chain
        self._iptables.delete_chain("mangle", "ROUTE_POLICY", chain)

        # 2. Remove ip rules + routes (IPv4 + IPv6)
        self._iproute.rule_del(mark, "0xf000", table_num)
        self._iproute.route_flush_table(table_num)
        self._iproute.rule_del_v6(mark, "0xf000", table_num)
        self._iproute.route_flush_table_v6(table_num)

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

    # ── Per-tunnel dnsmasq for DNS isolation ──────────────────────────

    @staticmethod
    def _dns_port(mark: str) -> int:
        """Compute the dnsmasq port for a proton-wg tunnel from its mark.

        Port = 2000 + (mark >> 12) * 100 + 53, giving:
        0x6000→2653, 0x7000→2753, 0x9000→2953, 0xf000→3553
        """
        return 2000 + (int(mark, 16) >> 12) * 100 + 53

    @staticmethod
    def _ct_zone(mark: str) -> int:
        """Conntrack zone ID = mark value as decimal."""
        return int(mark, 16)

    @staticmethod
    def _dns_iptables_cmds(mark: str, port: int, zone: int) -> list:
        """Build the 3 check-or-append iptables commands for DNS CT zone + REDIRECT.

        Used by both _start_proton_wg_dnsmasq (live apply) and
        _rebuild_proton_wg_mangle_rules (firewall include script).
        """
        return [
            (f"iptables -t raw -C pre_dns_deal_conn_zone "
             f"-p udp ! -i lo -m mark --mark {mark}/0xf000 "
             f"-m addrtype --dst-type LOCAL -j CT --zone {zone} 2>/dev/null || "
             f"iptables -t raw -A pre_dns_deal_conn_zone "
             f"-p udp ! -i lo -m mark --mark {mark}/0xf000 "
             f"-m addrtype --dst-type LOCAL -j CT --zone {zone}"),
            (f"iptables -t raw -C out_dns_deal_conn_zone "
             f"-p udp ! -o lo -m udp --sport {port} "
             f"-j CT --zone {zone} 2>/dev/null || "
             f"iptables -t raw -A out_dns_deal_conn_zone "
             f"-p udp ! -o lo -m udp --sport {port} "
             f"-j CT --zone {zone}"),
            (f"iptables -t nat -C policy_redirect "
             f"-p udp -m mark --mark {mark}/0xf000 "
             f"-m addrtype --dst-type LOCAL "
             f"--dport 53 -j REDIRECT --to-ports {port} 2>/dev/null || "
             f"iptables -t nat -A policy_redirect "
             f"-p udp -m mark --mark {mark}/0xf000 "
             f"-m addrtype --dst-type LOCAL "
             f"--dport 53 -j REDIRECT --to-ports {port}"),
        ]

    def _start_proton_wg_dnsmasq(self, iface: str, mark: str,
                                  dns: str = "10.2.0.1") -> None:
        """Set up a per-tunnel dnsmasq instance with CT zone + DNS redirect.

        Replicates the firmware's per-tunnel DNS mechanism (used for
        wgclient1-4) so that proton-wg tunnels get isolated DNS
        resolution and adblock support via conf-dir injection.
        """
        port = self._dns_port(mark)
        zone = self._ct_zone(mark)
        conf_dir = f"/tmp/dnsmasq.d.{iface}"
        resolv_file = f"/tmp/resolv.conf.d/resolv.conf.{iface}"
        conf_path = f"/var/etc/dnsmasq.conf.{iface}"

        # 1. Create conf-dir and resolv-file
        self._ssh.exec(f"mkdir -p {conf_dir} /tmp/resolv.conf.d")
        self._ssh.write_file(resolv_file, f"# Interface {iface}\nnameserver {dns}\n")

        # 2. Write minimal dnsmasq config (matches firmware pattern)
        dnsmasq_conf = (
            f"# Auto-generated by FlintVPN — per-tunnel DNS for {iface}\n"
            f"port={port}\n"
            f"bind-dynamic\n"
            f"no-dhcp-interface=\n"
            f"no-hosts\n"
            f"cache-size=1000\n"
            f"resolv-file={resolv_file}\n"
            f"conf-dir={conf_dir}\n"
            f"log-facility=/dev/null\n"
        )
        self._ssh.write_file(conf_path, dnsmasq_conf)

        # 3. Start dnsmasq process
        self._ssh.exec(
            f"pgrep -f 'dnsmasq.*{conf_path}' >/dev/null 2>&1 || "
            f"/usr/sbin/dnsmasq -C {conf_path}"
        )

        # 4. CT zone + DNS REDIRECT rules
        for cmd in self._dns_iptables_cmds(mark, port, zone):
            self._ssh.exec(cmd)

    def _stop_proton_wg_dnsmasq(self, iface: str, mark: str) -> None:
        """Tear down the per-tunnel dnsmasq and associated iptables rules."""
        port = self._dns_port(mark)
        zone = self._ct_zone(mark)
        conf_path = f"/var/etc/dnsmasq.conf.{iface}"
        conf_dir = f"/tmp/dnsmasq.d.{iface}"
        resolv_file = f"/tmp/resolv.conf.d/resolv.conf.{iface}"

        # Single batched cleanup: kill dnsmasq, remove iptables rules, delete files
        self._ssh.exec(
            f"pgrep -f 'dnsmasq.*{conf_path}' | xargs kill 2>/dev/null; "
            f"iptables -t raw -D pre_dns_deal_conn_zone "
            f"-p udp ! -i lo -m mark --mark {mark}/0xf000 "
            f"-m addrtype --dst-type LOCAL -j CT --zone {zone} 2>/dev/null; "
            f"iptables -t raw -D out_dns_deal_conn_zone "
            f"-p udp ! -o lo -m udp --sport {port} "
            f"-j CT --zone {zone} 2>/dev/null; "
            f"iptables -t nat -D policy_redirect "
            f"-p udp -m mark --mark {mark}/0xf000 "
            f"-m addrtype --dst-type LOCAL "
            f"--dport 53 -j REDIRECT --to-ports {port} 2>/dev/null; "
            f"rm -rf {conf_dir} {resolv_file} {conf_path}; true"
        )

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

        # DNS infrastructure: CT zone + REDIRECT for each tunnel's dnsmasq
        dns_cmds = []
        for iface, mark, ipset_name, tid in tunnels:
            dns_cmds.extend(self._dns_iptables_cmds(
                mark, self._dns_port(mark), self._ct_zone(mark),
            ))

        all_cmds = cmds + dns_cmds

        if all_cmds:
            self._ssh.exec("; ".join(all_cmds))

        script = "#!/bin/sh\n# Auto-generated by FlintVPN — proton-wg mangle + DNS rules\n"
        script += "# Re-applied on every firewall reload\n\n"
        for cmd in all_cmds:
            script += cmd + "\n"
        self._ssh.write_file(f"{PROTON_WG_DIR}/mangle_rules.sh", script)
        self._ssh.exec(f"chmod +x {PROTON_WG_DIR}/mangle_rules.sh")

        self._uci.ensure_firewall_include(
            "fvpn_pwg_mangle", f"{PROTON_WG_DIR}/mangle_rules.sh"
        )

        # Rebuild IPv6 mangle rules for all tunnel types (proton-wg + vpn-client)
        self._rebuild_ipv6_mangle_rules()

    def _rebuild_ipv6_mangle_rules(self) -> None:
        """Rebuild ip6tables mangle MARK + IPv6 routing for ALL active tunnels.

        Covers both proton-wg tunnels (from .env files) and vpn-client
        tunnels (from route_policy UCI rules). Also writes the IPv6
        FORWARD rules (Phase 4 selective forwarding).

        Since vpn-client is IPv4-only, FlintVPN must manage the entire
        IPv6 routing layer for all tunnel types.
        """
        from consts import IPV6_MANGLE_SCRIPT, IPV6_FWD_SCRIPT

        tunnels = []  # (iface, mark, ipset_name, tid, ipv6_enabled)

        # 1. Proton-wg tunnels from .env files
        envs = self._ssh.exec(f"ls {PROTON_WG_DIR}/*.env 2>/dev/null || true").strip()
        for env_path in (envs.splitlines() if envs else []):
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
            ipv6_flag = vals.get("FVPN_IPV6", "0")
            if not (iface and tid and mark and ipset_name):
                continue
            tunnels.append((iface, mark, ipset_name, tid, ipv6_flag == "1"))

        # 2. vpn-client tunnels from route_policy UCI rules
        try:
            rp_raw = self._ssh.exec(
                "uci show route_policy 2>/dev/null | grep '\\.enabled=.1.' || true"
            ).strip()
            for line in rp_raw.splitlines():
                line = line.strip()
                if not line:
                    continue
                # route_policy.fvpn_rule_9001.enabled='1'
                rule_name = line.split(".")[1] if "." in line else ""
                if not rule_name.startswith("fvpn_rule"):
                    continue
                via = self._ssh.exec(
                    f"uci -q get route_policy.{rule_name}.via 2>/dev/null || echo ''"
                ).strip()
                tid = self._ssh.exec(
                    f"uci -q get route_policy.{rule_name}.tunnel_id 2>/dev/null || echo ''"
                ).strip()
                from_ipset = self._ssh.exec(
                    f"uci -q get route_policy.{rule_name}.from 2>/dev/null || echo ''"
                ).strip()
                if not (via and tid and from_ipset):
                    continue
                # Compute mark from tunnel_id (vpn-client uses 0x1000 + tunnel_id base)
                try:
                    mark_int = 0x1000 + int(tid)
                    mark = f"0x{mark_int:x}"
                except ValueError:
                    continue
                # vpn-client tunnels: IPv6 support depends on the profile's router_info
                # For now, enable IPv6 mangle for all vpn-client tunnels — the FORWARD
                # rules (Phase 4) will block actual forwarding for non-IPv6 tunnels
                tunnels.append((via, mark, from_ipset, tid, True))
        except Exception:
            pass

        # Build ip6tables mangle commands for IPv6-enabled tunnels
        cmds = []
        fwd_cmds = [
            "ip6tables -F FORWARD 2>/dev/null || true",
            "ip6tables -P FORWARD DROP",
            "ip6tables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT",
        ]

        for iface, mark, ipset_name, tid, ipv6_enabled in tunnels:
            if not ipv6_enabled:
                continue
            # Check interface is UP
            link = self._ssh.exec(f"ip link show {iface} 2>/dev/null | head -1").strip()
            if not link or "UP" not in link:
                continue

            chain = f"FVPN_V6_{tid}"
            cmds.append(f"ipset create {ipset_name} hash:mac -exist")
            cmds.append(f"ip6tables -t mangle -N {chain} 2>/dev/null || true")
            cmds.append(f"ip6tables -t mangle -F {chain}")
            cmds.append(
                f"ip6tables -t mangle -A {chain} "
                f"-m mark --mark 0x0/0xf000 "
                f"-m set --match-set {ipset_name} src "
                f"-j MARK --set-xmark {mark}/0xf000"
            )
            cmds.append(
                f"ip6tables -t mangle -C ROUTE_POLICY -j {chain} 2>/dev/null || "
                f"ip6tables -t mangle -I ROUTE_POLICY 1 -j {chain}"
            )

            # Phase 4: Allow IPv6 forwarding for marked traffic to this tunnel
            fwd_cmds.append(
                f"ip6tables -A FORWARD -m mark --mark {mark}/0xf000 -o {iface} -j ACCEPT"
            )

        # Apply mangle rules
        if cmds:
            self._ssh.exec("; ".join(cmds))

        # Write mangle firewall include script
        mangle_script = "#!/bin/sh\n# Auto-generated by FlintVPN — IPv6 mangle rules\n\n"
        for cmd in cmds:
            mangle_script += cmd + "\n"
        self._ssh.write_file(IPV6_MANGLE_SCRIPT, mangle_script)
        self._ssh.exec(f"chmod +x {IPV6_MANGLE_SCRIPT}")
        self._uci.ensure_firewall_include("fvpn_ipv6_mangle", IPV6_MANGLE_SCRIPT)

        # Write IPv6 FORWARD script (Phase 4 selective forwarding)
        fwd_script = "#!/bin/sh\n# Auto-generated by FlintVPN — IPv6 forwarding rules\n\n"
        for cmd in fwd_cmds:
            fwd_script += cmd + "\n"
        self._ssh.write_file(IPV6_FWD_SCRIPT, fwd_script)
        self._ssh.exec(f"chmod +x {IPV6_FWD_SCRIPT}")
        self._uci.ensure_firewall_include("fvpn_ipv6_fwd", IPV6_FWD_SCRIPT)

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
         ip rule add fwmark "$mark"/0xf000 lookup "$table_num" priority 6000 2>/dev/null && \
         # IPv6 routing (if enabled for this tunnel)
         if [ "$FVPN_IPV6" = "1" ]; then \
           ip -6 addr add 2a07:b944::2:2/128 dev "$iface" 2>/dev/null; \
           ip -6 route add default dev "$iface" table "$table_num" 2>/dev/null; \
           ip -6 route add blackhole default metric 254 table "$table_num" 2>/dev/null; \
           ip -6 rule add fwmark "$mark"/0xf000 lookup "$table_num" priority 6000 2>/dev/null; \
         fi && \
         # Per-tunnel dnsmasq for DNS isolation
         dns_port=$((2000 + (0x$(echo "$mark" | sed 's/0x//') / 4096) * 100 + 53)) && \
         conf_dir="/tmp/dnsmasq.d.$iface" && \
         resolv="/tmp/resolv.conf.d/resolv.conf.$iface" && \
         dnsmasq_conf="/var/etc/dnsmasq.conf.$iface" && \
         mkdir -p "$conf_dir" /tmp/resolv.conf.d && \
         echo "nameserver 10.2.0.1" > "$resolv" && \
         printf "port=%s\nbind-dynamic\nno-dhcp-interface=\nno-hosts\ncache-size=1000\nresolv-file=%s\nconf-dir=%s\nlog-facility=/dev/null\n" \
           "$dns_port" "$resolv" "$conf_dir" > "$dnsmasq_conf" && \
         /usr/sbin/dnsmasq -C "$dnsmasq_conf" \
        ) &
    done

    # Apply mangle + DNS rules (firewall include handles subsequent reloads)
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
