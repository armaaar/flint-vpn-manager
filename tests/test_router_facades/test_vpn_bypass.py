"""Tests for RouterVpnBypass facade."""

from unittest.mock import MagicMock, call

import pytest

from router.facades.vpn_bypass import RouterVpnBypass


@pytest.fixture
def bypass(uci, ipset, iptables, iproute, service_ctl, ssh):
    return RouterVpnBypass(uci, ipset, iptables, iproute, service_ctl, ssh)


@pytest.fixture
def bypass_with_ip6(uci, ipset, iptables, iproute, service_ctl, ssh):
    ip6 = MagicMock()
    return RouterVpnBypass(
        uci, ipset, iptables, iproute, service_ctl, ssh, ip6tables=ip6,
    )


def _make_exception(
    exc_id="byp_test1234",
    name="Test",
    scope="global",
    scope_target=None,
    enabled=True,
    rules=None,
):
    return {
        "id": exc_id,
        "name": name,
        "preset_id": None,
        "enabled": enabled,
        "scope": scope,
        "scope_target": scope_target,
        "rules": rules or [],
    }


def _all_exec_calls(ssh) -> str:
    """Join all ssh.exec() call args into a single string for assertion."""
    return " ".join(
        c[0][0] for c in ssh.exec.call_args_list if c[0]
    )


class TestApplyAll:
    def test_empty_exceptions_calls_cleanup(self, bypass, iptables, ipset, ssh):
        bypass.apply_all([], {})
        iptables.delete_chain.assert_called_once_with(
            "mangle", "ROUTE_POLICY", "FVPN_BYPASS",
        )

    def test_all_disabled_calls_cleanup(self, bypass, iptables):
        exc = _make_exception(enabled=False)
        bypass.apply_all([exc], {})
        iptables.delete_chain.assert_called()

    def test_global_cidr_generates_ipset_and_chain(self, bypass, ssh):
        exc = _make_exception(rules=[
            {"type": "cidr", "value": "10.0.0.0/8"},
        ])
        bypass.apply_all([exc], {})

        cmd = _all_exec_calls(ssh)
        assert "ipset create fvpn_byp_test1234 hash:net -exist" in cmd
        assert "ipset add fvpn_byp_test1234 10.0.0.0/8 -exist" in cmd
        assert "FVPN_BYPASS" in cmd
        assert "-m set --match-set fvpn_byp_test1234 dst" in cmd
        assert "0x8000/0xf000" in cmd

    def test_global_port_generates_multiport_rule(self, bypass, ssh):
        exc = _make_exception(rules=[
            {"type": "port", "value": "5000:5500", "protocol": "udp"},
        ])
        bypass.apply_all([exc], {})

        cmd = _all_exec_calls(ssh)
        assert "-p udp -m multiport --dports 5000:5500" in cmd
        assert "0x8000/0xf000" in cmd

    def test_device_scope_adds_mac_match(self, bypass, ssh):
        exc = _make_exception(
            scope="device",
            scope_target="aa:bb:cc:dd:ee:ff",
            rules=[{"type": "cidr", "value": "1.2.3.0/24"}],
        )
        bypass.apply_all([exc], {})

        cmd = _all_exec_calls(ssh)
        assert "-m mac --mac-source aa:bb:cc:dd:ee:ff" in cmd
        assert "-m set --match-set fvpn_byp_test1234 dst" in cmd

    def test_group_scope_adds_ipset_src_match(self, bypass, ssh):
        exc = _make_exception(
            scope="group",
            scope_target="prof_abc",
            rules=[{"type": "cidr", "value": "1.2.3.0/24"}],
        )
        group_map = {"prof_abc": "src_mac_300"}
        bypass.apply_all([exc], group_map)

        cmd = _all_exec_calls(ssh)
        assert "-m set --match-set src_mac_300 src" in cmd

    def test_group_scope_missing_profile_skips(self, bypass, ssh):
        exc = _make_exception(
            scope="group",
            scope_target="prof_nonexistent",
            rules=[{"type": "cidr", "value": "1.2.3.0/24"}],
        )
        bypass.apply_all([exc], {})

        cmd = _all_exec_calls(ssh)
        assert "FVPN_BYPASS" in cmd
        assert "fvpn_byp_test1234 dst" not in cmd

    def test_multiple_exceptions_all_applied(self, bypass, ssh):
        exc1 = _make_exception(
            exc_id="byp_aaaa1111",
            rules=[{"type": "cidr", "value": "10.0.0.0/8"}],
        )
        exc2 = _make_exception(
            exc_id="byp_bbbb2222",
            rules=[{"type": "port", "value": "8080", "protocol": "tcp"}],
        )
        bypass.apply_all([exc1, exc2], {})

        cmd = _all_exec_calls(ssh)
        assert "fvpn_byp_aaaa1111" in cmd
        assert "-m multiport --dports 8080" in cmd

    def test_routing_table_setup(self, bypass, ssh):
        exc = _make_exception(rules=[
            {"type": "cidr", "value": "10.0.0.0/8"},
        ])
        bypass.apply_all([exc], {})

        cmd = _all_exec_calls(ssh)
        assert "ip rule add fwmark 0x8000/0xf000 lookup 1008 priority 100" in cmd
        assert "ip route flush table 1008" in cmd

    def test_firewall_include_registered(self, bypass, uci):
        exc = _make_exception(rules=[
            {"type": "cidr", "value": "10.0.0.0/8"},
        ])
        bypass.apply_all([exc], {})

        uci.ensure_firewall_include.assert_called_once_with(
            "fvpn_vpn_bypass", "/etc/fvpn/vpn_bypass.sh",
        )

    def test_firewall_include_script_written(self, bypass, ssh):
        exc = _make_exception(rules=[
            {"type": "cidr", "value": "10.0.0.0/8"},
        ])
        bypass.apply_all([exc], {})

        # Find the write_file call for the script
        write_calls = [c for c in ssh.write_file.call_args_list
                       if "/etc/fvpn/vpn_bypass.sh" in str(c)]
        assert len(write_calls) == 1
        script = write_calls[0][0][1]
        assert "#!/bin/sh" in script
        assert "FVPN_BYPASS" in script


class TestDnsmasqConfig:
    def test_domain_rules_write_dnsmasq_conf(self, bypass, ssh):
        exc = _make_exception(rules=[
            {"type": "domain", "value": "riotgames.com"},
            {"type": "domain", "value": "pvp.net"},
        ])
        bypass.apply_all([exc], {})

        write_calls = [c for c in ssh.write_file.call_args_list
                       if "fvpn_bypass.conf" in str(c)]
        assert len(write_calls) == 1
        conf = write_calls[0][0][1]
        assert "ipset=/riotgames.com/pvp.net/fvpn_byp_test1234" in conf

    def test_no_domain_rules_removes_conf(self, bypass, ssh):
        exc = _make_exception(rules=[
            {"type": "cidr", "value": "10.0.0.0/8"},
        ])
        bypass.apply_all([exc], {})

        # Should remove the dnsmasq conf
        exec_calls = " ".join(c[0][0] for c in ssh.exec.call_args_list)
        assert "rm -f /etc/dnsmasq.d/fvpn_bypass.conf" in exec_calls

    def test_dnsmasq_hup_on_domain_rules(self, bypass, ssh):
        exc = _make_exception(rules=[
            {"type": "domain", "value": "example.com"},
        ])
        bypass.apply_all([exc], {})

        exec_calls = " ".join(c[0][0] for c in ssh.exec.call_args_list)
        assert "killall -HUP dnsmasq" in exec_calls


class TestCleanup:
    def test_removes_chain_ipsets_routing(self, bypass, iptables, ipset, iproute, ssh, uci):
        ipset.list_names.return_value = ["fvpn_byp_abc", "fvpn_byp_def"]
        bypass.cleanup()

        iptables.delete_chain.assert_called_once_with(
            "mangle", "ROUTE_POLICY", "FVPN_BYPASS",
        )
        assert ipset.destroy.call_count == 2
        iproute.rule_del.assert_called_once_with("0x8000", "0xf000", 1008)
        iproute.route_flush_table.assert_called_once_with(1008)
        uci.delete.assert_called()
        uci.commit.assert_called()

    def test_cleanup_with_ip6tables(self, bypass_with_ip6):
        bypass_with_ip6.cleanup()
        # ip6tables should also clean up
        ip6 = bypass_with_ip6._ip6tables
        ip6.delete_chain.assert_called_once_with(
            "mangle", "ROUTE_POLICY", "FVPN_BYPASS",
        )


class TestCheckDnsmasqFull:
    def test_returns_true_when_installed(self, bypass, ssh):
        ssh.exec.return_value = "dnsmasq-full - 2.90-1"
        assert bypass.check_dnsmasq_full() is True

    def test_returns_false_when_not_installed(self, bypass, ssh):
        ssh.exec.return_value = ""
        assert bypass.check_dnsmasq_full() is False


class TestSourceMatch:
    def test_global_returns_empty(self, bypass):
        assert bypass._source_match("global", None, {}) == ""

    def test_device_returns_mac_match(self, bypass):
        result = bypass._source_match("device", "aa:bb:cc:dd:ee:ff", {})
        assert result == "-m mac --mac-source aa:bb:cc:dd:ee:ff"

    def test_device_invalid_mac_returns_none(self, bypass):
        assert bypass._source_match("device", "invalid", {}) is None

    def test_group_returns_ipset_match(self, bypass):
        result = bypass._source_match(
            "group", "prof_1", {"prof_1": "src_mac_300"},
        )
        assert result == "-m set --match-set src_mac_300 src"

    def test_group_missing_returns_none(self, bypass):
        assert bypass._source_match("group", "prof_missing", {}) is None

    def test_unknown_scope_returns_none(self, bypass):
        assert bypass._source_match("unknown", None, {}) is None


class TestIpsetName:
    def test_strips_byp_prefix(self):
        assert RouterVpnBypass._ipset_name("byp_abc123") == "fvpn_byp_abc123"

    def test_handles_no_prefix(self):
        assert RouterVpnBypass._ipset_name("custom_id") == "fvpn_byp_custom_id"


class TestValidation:
    def test_invalid_cidr_skipped(self, bypass, ssh):
        exc = _make_exception(rules=[
            {"type": "cidr", "value": "$(evil_cmd)"},
        ])
        bypass.apply_all([exc], {})

        cmd = _all_exec_calls(ssh)
        assert "evil_cmd" not in cmd

    def test_invalid_domain_skipped(self, bypass, ssh):
        exc = _make_exception(rules=[
            {"type": "domain", "value": "evil; rm -rf /"},
        ])
        bypass.apply_all([exc], {})

        # No dnsmasq config should be written for invalid domains
        write_calls = [c for c in ssh.write_file.call_args_list
                       if "fvpn_bypass.conf" in str(c)]
        assert len(write_calls) == 0

    def test_invalid_port_protocol_skipped(self, bypass, ssh):
        exc = _make_exception(rules=[
            {"type": "port", "value": "80", "protocol": "invalid"},
        ])
        bypass.apply_all([exc], {})

        cmd = _all_exec_calls(ssh)
        assert "multiport" not in cmd
