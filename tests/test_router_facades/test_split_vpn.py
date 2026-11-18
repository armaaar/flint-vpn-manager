"""Tests for the split VPN router facade (pure builders + facade calls)."""

import pytest

from router.facades.split_vpn import (
    RouterSplitVpn,
    build_client_config,
    build_ctl_script,
    build_dnsmasq_snippet,
    build_routing_commands,
    normalize_cidr,
    parse_status,
    slot_mark,
    slot_table,
)


class TestHelpers:
    def test_slot_mark_and_table_avoid_used_marks(self):
        # 0x1000-0x5000 vpn-client, 0x6000/7000/9000/f000 proton-wg, 0x8000 bypass
        marks = [slot_mark(i) for i in range(4)]
        assert marks == ["0xa000", "0xb000", "0xc000", "0xd000"]
        assert [slot_table(i) for i in range(4)] == [1010, 1011, 1012, 1013]

    @pytest.mark.parametrize("value,expected", [
        ("10.1.2.3", "10.1.2.3/32"),
        ("10.0.0.0/8", "10.0.0.0/8"),
        ("10.1.2.3/8", "10.0.0.0/8"),
        ("0.0.0.0/0", None),       # would hijack all of the group's traffic
        ("fd00::/8", None),        # IPv4 only
        ("nonsense", None),
        ("10.0.0.0/8; rm -rf /", None),
    ])
    def test_normalize_cidr(self, value, expected):
        assert normalize_cidr(value) == expected


class TestParseStatus:
    def test_connected(self):
        raw = (
            "Dumping connection Status:\n"
            "STATE:       CONNECTED\n"
            "IPv4:        10.20.30.40\n"
            "GWv4:        10.20.30.1\n"
            "DNSv4:       10.0.0.53 10.0.0.54\n"
            "ROUTESv4:    10.0.0.0/8 172.16.0.0/12 0.0.0.0/0\n"
        )
        st = parse_status(raw)
        assert st["state"] == "CONNECTED"
        assert st["ip"] == "10.20.30.40"
        assert st["dns"] == ["10.0.0.53", "10.0.0.54"]
        # default route dropped
        assert st["routes"] == ["10.0.0.0/8", "172.16.0.0/12"]

    def test_routes_on_continuation_lines(self):
        raw = "STATE: CONNECTED\nROUTESv4:    10.0.0.0/8\n             192.168.50.0/24\nOther: x\n"
        assert parse_status(raw)["routes"] == ["10.0.0.0/8", "192.168.50.0/24"]

    def test_disconnected_and_empty(self):
        assert parse_status("Dumping connection Status:\nSTATE:       DISCONNECTED\n")["state"] == "DISCONNECTED"
        assert parse_status("")["state"] == "DOWN"


class TestClientConfig:
    def test_renders_key_value_lines(self):
        conf = build_client_config({"server": "vpn.example.com", "port": 691, "tunnel_mode": "tcp"})
        assert "SERVER = vpn.example.com\n" in conf
        assert "SERVERPORT = 691\n" in conf
        assert "TUNNELMODE = TCP\n" in conf
        assert "DYNSSA = 2\n" in conf           # user/pass auth
        assert "WRITEDNS = NO\n" in conf        # never touch resolv.conf

    @pytest.mark.parametrize("cfg", [
        {"server": "vpn.example.com; reboot"},
        {"server": "vpn.example.com", "port": 70000},
        {"server": "vpn.example.com", "tunnel_mode": "QUIC"},
    ])
    def test_rejects_bad_values(self, cfg):
        with pytest.raises(ValueError):
            build_client_config(cfg)


class TestRoutingCommands:
    def _inst(self, **kw):
        base = {"slot": 0, "group_ipsets": ["src_mac_305"], "cidrs": ["10.0.0.0/8"],
                "dns_servers": ["10.0.0.53"]}
        base.update(kw)
        return base

    def test_marks_group_traffic_to_destinations(self):
        cmds = build_routing_commands([self._inst()])
        joined = "\n".join(cmds)
        assert ("iptables -t mangle -A FVPN_SPLITVPN -m set --match-set src_mac_305 src "
                "-m set --match-set fvpn_sv0_dst dst -j MARK --set-xmark 0xa000/0xf000") in joined
        assert "ipset add fvpn_sv0_dst 10.0.0.0/8 -exist" in joined
        assert "ip rule add fwmark 0xa000/0xf000 lookup 1010 priority 90" in joined
        assert "iptables -t mangle -I ROUTE_POLICY 1 -j FVPN_SPLITVPN" in joined

    def test_fails_closed_with_blackhole(self):
        joined = "\n".join(build_routing_commands([self._inst()]))
        assert "ip route add blackhole default metric 10000 table 1010" in joined
        assert "ip route replace default via 10.250.0.2 dev fvsv0h table 1010" in joined

    def test_dns_servers_routed_through_namespace(self):
        joined = "\n".join(build_routing_commands([self._inst()]))
        assert "ip route replace 10.0.0.53/32 via 10.250.0.2 dev fvsv0h" in joined

    def test_cleans_every_slot_and_drops_chains_when_empty(self):
        joined = "\n".join(build_routing_commands([]))
        for mark, table in (("0xa000", 1010), ("0xd000", 1013)):
            assert f"ip rule del fwmark {mark}/0xf000 lookup {table}" in joined
        assert "iptables -t mangle -X FVPN_SPLITVPN" in joined
        assert "-I ROUTE_POLICY" not in joined

    def test_skips_unsafe_ipset_names_and_bad_cidrs(self):
        joined = "\n".join(build_routing_commands([
            self._inst(group_ipsets=["src_mac_1; reboot"], cidrs=["0.0.0.0/0", "bad"])
        ]))
        assert "reboot" not in joined
        assert "ipset add fvpn_sv0_dst" not in joined

    def test_rejects_bad_slot(self):
        with pytest.raises(ValueError):
            build_routing_commands([self._inst(slot=7)])


class TestDnsmasqSnippet:
    def test_server_and_ipset_lines(self):
        snippet = build_dnsmasq_snippet([
            {"slot": 1, "domains": ["corp.example", "intra.example."], "dns_servers": ["10.0.0.53"]},
        ])
        assert "server=/corp.example/intra.example/10.0.0.53" in snippet
        assert "ipset=/corp.example/intra.example/fvpn_sv1_dst" in snippet

    def test_entry_without_domains_is_skipped(self):
        snippet = build_dnsmasq_snippet([{"slot": 0, "domains": [], "dns_servers": ["10.0.0.53"]}])
        assert "server=" not in snippet


class TestCtlScript:
    def test_has_lifecycle_actions_and_paths(self):
        script = build_ctl_script()
        for action in ("up)", "start)", "stop)", "down)", "status)"):
            assert action in script
        assert "BIN=/etc/fvpn/splitvpn/bin\n" in script
        assert "$BIN/qemu-x86_64 $BIN/barracudavpn" in script
        assert "table $((1010+$I))" in script
        # credentials only ever arrive on stdin
        assert "--serverpwd" not in script


class TestFacade:
    def test_connect_feeds_secrets_via_file_not_command_line(self, ssh, uci):
        ssh.exec.return_value = "RC: 0"
        sv = RouterSplitVpn(uci, ssh)
        sv.connect(0, "alice", "s3cret", "123456")

        written = {c.args[0]: c.args[1] for c in ssh.write_file.call_args_list}
        assert written["/tmp/fvsv0.in"] == "s3cret\n123456\n"
        for call in ssh.exec.call_args_list:
            assert "s3cret" not in call.args[0]
            assert "123456" not in call.args[0]
        assert any("/etc/fvpn/splitvpn/svctl.sh start 0 alice < /tmp/fvsv0.in" in c.args[0]
                   for c in ssh.exec.call_args_list)

    def test_connect_rejects_control_characters_in_login(self, ssh, uci):
        with pytest.raises(ValueError):
            RouterSplitVpn(uci, ssh).connect(0, "alice\nreboot", "pw", "1")

    def test_connect_quotes_domain_style_login(self, ssh, uci):
        """AD logins (DOMAIN\\user, odd chars) are allowed but shell-quoted."""
        ssh.exec.return_value = "RC: 0"
        RouterSplitVpn(uci, ssh).connect(0, "CORP\\alice; x", "pw", "1")
        assert any("start 0 'CORP\\alice; x' < /tmp/fvsv0.in" in c.args[0]
                   for c in ssh.exec.call_args_list)

    def test_dnsmasq_not_restarted_when_unchanged(self, ssh, uci):
        snippet = build_dnsmasq_snippet([{"slot": 0, "domains": ["corp.example"], "dns_servers": ["10.0.0.53"]}])

        def exec_(cmd, *a, **k):
            if cmd.startswith("for f in"):
                return "@@FILE /tmp/dnsmasq.d.wgclient2/fvpn-splitvpn.conf\n" + snippet
            return ""

        ssh.exec.side_effect = exec_
        RouterSplitVpn(uci, ssh).apply_routing([{
            "slot": 0, "group_ipsets": ["src_mac_305"], "cidrs": [], "dns_servers": ["10.0.0.53"],
            "domains": ["corp.example"], "dnsmasq_ifaces": ["wgclient2"],
        }])
        assert not any("dnsmasq restart" in c.args[0] for c in ssh.exec.call_args_list)

    def test_apply_routing_empty_removes_include(self, ssh, uci):
        RouterSplitVpn(uci, ssh).apply_routing([])
        uci.delete.assert_called_with("firewall.fvpn_splitvpn")
        uci.ensure_firewall_include.assert_not_called()
