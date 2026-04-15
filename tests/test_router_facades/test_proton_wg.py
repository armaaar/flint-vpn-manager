"""Tests for RouterProtonWG facade."""

from unittest.mock import MagicMock, patch, call

import pytest

from consts import (
    HEALTH_AMBER, HEALTH_CONNECTING, HEALTH_GREEN, HEALTH_RED,
    PROTO_WIREGUARD_TCP, PROTO_WIREGUARD_TLS,
)
from router.facades.proton_wg import RouterProtonWG, PROTON_WG_MARKS


@pytest.fixture
def pwg(uci, ipset, iptables, iproute, service_ctl, alloc_tunnel_id, ssh):
    return RouterProtonWG(uci, ipset, iptables, iproute, service_ctl, alloc_tunnel_id, ssh)


class TestNextProtonWgSlot:
    def test_first_slot_when_all_free(self, pwg, ssh):
        ssh.exec.side_effect = [
            "",  # ip link show (no existing interfaces)
            "",  # ls config files (none)
        ]
        iface, mark, table_num = pwg._next_proton_wg_slot()
        assert iface == "protonwg0"
        assert mark == "0x6000"
        assert table_num == 1006

    def test_skips_used_slot(self, pwg, ssh):
        ssh.exec.side_effect = [
            "protonwg0",  # ip link
            "/etc/fvpn/protonwg/protonwg0.conf\n/etc/fvpn/protonwg/protonwg0.env",
        ]
        iface, mark, table_num = pwg._next_proton_wg_slot()
        assert iface == "protonwg1"
        assert mark == "0x7000"

    def test_raises_when_all_slots_used(self, pwg, ssh):
        ssh.exec.side_effect = [
            "protonwg0\nprotonwg1\nprotonwg2\nprotonwg3",
            "\n".join(
                f"/etc/fvpn/protonwg/protonwg{i}.conf\n/etc/fvpn/protonwg/protonwg{i}.env"
                for i in range(4)
            ),
        ]
        with pytest.raises(RuntimeError, match="4 max"):
            pwg._next_proton_wg_slot()

    def test_reclaims_orphan_interface(self, pwg, ssh):
        """A live interface with no config and no running process gets cleaned up."""
        ssh.exec.side_effect = [
            "protonwg0",  # ip link shows live
            "",            # no config files
            "",            # pidof finds no matching process
            "",            # ip link del
        ]
        iface, mark, _ = pwg._next_proton_wg_slot()
        assert iface == "protonwg0"


class TestUploadProtonWgConfig:
    def test_creates_config_and_ipset(self, pwg, ssh, ipset, alloc_tunnel_id):
        # Use default return_value instead of side_effect to avoid StopIteration
        ssh.exec.return_value = ""
        result = pwg.upload_proton_wg_config(
            profile_name="NL TCP",
            private_key="privkey",
            public_key="pubkey",
            endpoint="1.2.3.4:443",
            socket_type="tcp",
        )
        assert result["tunnel_name"] == "protonwg0"
        assert result["vpn_protocol"] == PROTO_WIREGUARD_TCP
        assert result["mark"] == "0x6000"
        assert result["ipset_name"] == "pwg_mac_100"
        assert result["rule_name"] == "fvpn_pwg_protonwg0"
        # Config files written: .conf, .env, init.d script, .macs
        assert ssh.write_file.call_count == 4
        ipset.create.assert_called_once_with("pwg_mac_100", "hash:mac")

    def test_tls_protocol(self, pwg, ssh, ipset):
        ssh.exec.return_value = ""
        result = pwg.upload_proton_wg_config(
            "NL TLS", "privkey", "pubkey", "1.2.3.4:443",
            socket_type="tls",
        )
        assert result["vpn_protocol"] == PROTO_WIREGUARD_TLS


class TestStartProtonWgTunnel:
    def test_raises_when_binary_missing(self, pwg, ssh):
        ssh.exec.return_value = "missing"
        with pytest.raises(RuntimeError, match="proton-wg binary not found"):
            pwg.start_proton_wg_tunnel("protonwg0", "0x6000", 1006, 100)

    def test_raises_when_interface_does_not_appear(self, pwg, ssh, ipset, iproute):
        # Interface never appears in ip link output
        ssh.exec.return_value = ""
        # Override just the binary check to pass
        call_count = [0]
        orig_return = ""

        def exec_side_effect(cmd, **kw):
            call_count[0] += 1
            if "[ -x" in cmd:
                return "ok"
            return orig_return

        ssh.exec.side_effect = exec_side_effect
        with pytest.raises(RuntimeError, match="did not appear"):
            with patch("time.sleep"):
                pwg.start_proton_wg_tunnel("protonwg0", "0x6000", 1006, 100)


class TestStopProtonWgTunnel:
    def test_cleanup_order(self, pwg, ssh, iptables, iproute, uci, service_ctl):
        def exec_side_effect(cmd, **kw):
            # Return PID only for the specific pidof/grep pattern
            if "pidof proton-wg" in cmd and "PROTON_WG_INTERFACE_NAME" in cmd:
                return "12345"
            return ""

        ssh.exec.side_effect = exec_side_effect
        with patch("time.sleep"):
            pwg.stop_proton_wg_tunnel("protonwg0", "0x6000", 1006, 100)

        # 1. Remove mangle chain (first call)
        assert iptables.delete_chain.call_args_list[0] == call(
            "mangle", "ROUTE_POLICY", "TUNNEL100_ROUTE_POLICY"
        )
        # 2. Remove ip rules + routes
        iproute.rule_del.assert_called_once_with("0x6000", "0xf000", 1006)
        iproute.route_flush_table.assert_called_once_with(1006)
        # 3. Kill process
        assert any("kill 12345" in str(c) for c in ssh.exec.call_args_list)
        # 4. Delete interface
        iproute.link_delete.assert_called_once_with("protonwg0")
        # 5. Firewall cleanup
        uci.delete.assert_any_call("firewall.fvpn_zone_protonwg0")
        uci.delete.assert_any_call("firewall.fvpn_fwd_protonwg0")
        service_ctl.reload.assert_called_with("firewall")


class TestDeleteProtonWgConfig:
    def test_removes_files_ipset_and_rebuilds(self, pwg, ssh, ipset):
        ssh.exec.return_value = ""
        pwg.delete_proton_wg_config("protonwg0", 100)
        ipset.destroy.assert_called_once_with("pwg_mac_100")


class TestGetProtonWgHealth:
    def test_red_when_interface_missing(self, pwg, iproute):
        iproute.link_exists.return_value = False
        assert pwg.get_proton_wg_health("protonwg0") == HEALTH_RED

    def test_red_when_interface_down(self, pwg, iproute, ssh):
        iproute.link_exists.return_value = True
        ssh.exec.return_value = "protonwg0: <BROADCAST,MULTICAST> mtu 1420"
        assert pwg.get_proton_wg_health("protonwg0") == HEALTH_RED

    def test_green_with_recent_handshake(self, pwg, iproute, ssh):
        iproute.link_exists.return_value = True
        ssh.exec.return_value = "protonwg0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1420"
        with patch("router.tools.wg_show.parse_handshake_age", return_value=30):
            assert pwg.get_proton_wg_health("protonwg0") == HEALTH_GREEN

    def test_connecting_when_no_handshake(self, pwg, iproute, ssh):
        iproute.link_exists.return_value = True
        ssh.exec.return_value = "protonwg0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1420"
        with patch("router.tools.wg_show.parse_handshake_age", return_value=None):
            assert pwg.get_proton_wg_health("protonwg0") == HEALTH_CONNECTING

    def test_amber_with_stale_handshake(self, pwg, iproute, ssh):
        iproute.link_exists.return_value = True
        ssh.exec.return_value = "protonwg0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1420"
        with patch("router.tools.wg_show.parse_handshake_age", return_value=400):
            assert pwg.get_proton_wg_health("protonwg0") == HEALTH_AMBER


class TestEnsureProtonWgInitd:
    def test_writes_script_and_enables(self, pwg, ssh, service_ctl):
        pwg.ensure_proton_wg_initd()
        ssh.write_file.assert_called_once()
        path = ssh.write_file.call_args[0][0]
        assert path == "/etc/init.d/fvpn-protonwg"
        ssh.exec.assert_called_once_with("chmod +x /etc/init.d/fvpn-protonwg")
        service_ctl.enable.assert_called_once_with("fvpn-protonwg")


class TestUpdateConfigLive:
    def test_writes_and_applies(self, pwg, ssh):
        pwg.update_config_live("protonwg0", "[Interface]\nPrivateKey=x\n")
        ssh.write_file.assert_called_once()
        ssh.exec.assert_called_once_with(
            "wg setconf protonwg0 /etc/fvpn/protonwg/protonwg0.conf"
        )


class TestUpdateTunnelEnv:
    def test_seds_env_file(self, pwg, ssh):
        pwg.update_tunnel_env("protonwg0", 200)
        cmd = ssh.exec.call_args[0][0]
        assert "FVPN_TUNNEL_ID=200" in cmd
        assert "FVPN_IPSET=pwg_mac_200" in cmd


# ── IPv6 Tests ───────────────────────────────────────────────────────────


class TestUploadProtonWgConfigIPv6:
    def test_ipv6_config_has_dual_stack_allowed_ips(self, pwg, ssh, ipset):
        ssh.exec.return_value = ""
        result = pwg.upload_proton_wg_config(
            profile_name="IPv6 Test",
            private_key="privkey",
            public_key="pubkey",
            endpoint="1.2.3.4:443",
            socket_type="tcp",
            ipv6=True,
        )
        assert result["ipv6"] is True
        # Check .conf was written with ::/0
        conf_write = [c for c in ssh.write_file.call_args_list
                      if c[0][0].endswith(".conf")]
        assert conf_write
        conf_content = conf_write[0][0][1]
        assert "AllowedIPs = 0.0.0.0/0, ::/0" in conf_content
        # Check .env has FVPN_IPV6=1
        env_write = [c for c in ssh.write_file.call_args_list
                     if c[0][0].endswith(".env")]
        assert env_write
        env_content = env_write[0][0][1]
        assert "FVPN_IPV6=1" in env_content

    def test_ipv4_only_config(self, pwg, ssh, ipset):
        ssh.exec.return_value = ""
        result = pwg.upload_proton_wg_config(
            profile_name="IPv4 Only",
            private_key="privkey",
            public_key="pubkey",
            endpoint="1.2.3.4:443",
            ipv6=False,
        )
        assert result["ipv6"] is False
        conf_write = [c for c in ssh.write_file.call_args_list
                      if c[0][0].endswith(".conf")]
        conf_content = conf_write[0][0][1]
        assert "AllowedIPs = 0.0.0.0/0" in conf_content
        assert "::/0" not in conf_content
        env_write = [c for c in ssh.write_file.call_args_list
                     if c[0][0].endswith(".env")]
        env_content = env_write[0][0][1]
        assert "FVPN_IPV6=0" in env_content


class TestStopProtonWgTunnelIPv6:
    def test_cleanup_includes_ipv6_routing(self, pwg, ssh, iptables, iproute, uci, service_ctl):
        ssh.exec.side_effect = lambda cmd, **kw: (
            "12345" if "pidof proton-wg" in cmd else ""
        )
        with patch("time.sleep"):
            pwg.stop_proton_wg_tunnel("protonwg0", "0x6000", 1006, 100)

        # IPv6 routing cleanup should be called
        iproute.rule_del_v6.assert_called_once_with("0x6000", "0xf000", 1006)
        iproute.route_flush_table_v6.assert_called_once_with(1006)


class TestDnsPort:
    """Test _dns_port() static method — port formula: 2000 + (mark >> 12) * 100 + 53."""

    def test_mark_0x6000(self):
        assert RouterProtonWG._dns_port("0x6000") == 2653

    def test_mark_0x7000(self):
        assert RouterProtonWG._dns_port("0x7000") == 2753

    def test_mark_0x9000(self):
        assert RouterProtonWG._dns_port("0x9000") == 2953

    def test_mark_0xf000(self):
        assert RouterProtonWG._dns_port("0xf000") == 3553


class TestCtZone:
    """Test _ct_zone() static method — zone ID = mark as decimal."""

    def test_mark_0x6000(self):
        assert RouterProtonWG._ct_zone("0x6000") == 0x6000

    def test_mark_0x7000(self):
        assert RouterProtonWG._ct_zone("0x7000") == 0x7000

    def test_mark_0xf000(self):
        assert RouterProtonWG._ct_zone("0xf000") == 0xf000


class TestStartProtonWgDnsmasq:
    """Test _start_proton_wg_dnsmasq() sets up dnsmasq config, CT zone, and REDIRECT."""

    def test_creates_dnsmasq_config_and_rules(self, pwg, ssh):
        ssh.exec.return_value = ""
        pwg._start_proton_wg_dnsmasq("protonwg0", "0x6000", dns="10.2.0.1")

        # Should create conf-dir and resolv-file
        exec_calls = [str(c) for c in ssh.exec.call_args_list]
        assert any("mkdir -p /tmp/dnsmasq.d.protonwg0" in c for c in exec_calls)

        # Should write resolv file with DNS server
        resolv_writes = [c for c in ssh.write_file.call_args_list
                         if "resolv.conf.protonwg0" in str(c)]
        assert resolv_writes
        assert "10.2.0.1" in resolv_writes[0][0][1]

        # Should write dnsmasq config with correct port (2653 for 0x6000)
        conf_writes = [c for c in ssh.write_file.call_args_list
                       if "dnsmasq.conf.protonwg0" in str(c)]
        assert conf_writes
        assert "port=2653" in conf_writes[0][0][1]

        # Should set up CT zone rules (raw table)
        assert any("pre_dns_deal_conn_zone" in c for c in exec_calls)
        assert any("out_dns_deal_conn_zone" in c for c in exec_calls)

        # Should set up DNS REDIRECT rule (nat table)
        assert any("REDIRECT --to-ports 2653" in c for c in exec_calls)


class TestStopProtonWgDnsmasq:
    """Test _stop_proton_wg_dnsmasq() tears down dnsmasq and iptables rules."""

    def test_kills_dnsmasq_and_removes_rules(self, pwg, ssh):
        ssh.exec.return_value = ""
        pwg._stop_proton_wg_dnsmasq("protonwg0", "0x6000")

        exec_calls = [str(c) for c in ssh.exec.call_args_list]

        # Should kill dnsmasq process
        assert any("pgrep" in c and "kill" in c and "protonwg0" in c for c in exec_calls)

        # Should remove CT zone rules
        assert any("-D pre_dns_deal_conn_zone" in c for c in exec_calls)
        assert any("-D out_dns_deal_conn_zone" in c for c in exec_calls)

        # Should remove DNS REDIRECT
        assert any("-D policy_redirect" in c and "REDIRECT" in c for c in exec_calls)

        # Should clean up files
        assert any("rm -rf" in c and "dnsmasq.d.protonwg0" in c for c in exec_calls)


class TestEnsureProtonWgInitdIPv6:
    def test_boot_script_includes_ipv6_block(self, pwg, ssh, service_ctl):
        pwg.ensure_proton_wg_initd()
        script = ssh.write_file.call_args[0][1]
        assert "FVPN_IPV6" in script
        assert "ip -6 addr add" in script
        assert "ip -6 route add" in script
        assert "ip -6 rule add" in script
