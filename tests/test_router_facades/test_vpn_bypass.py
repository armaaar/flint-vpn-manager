"""Tests for RouterVpnBypass facade."""

from unittest.mock import MagicMock

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
    rule_blocks=None,
):
    return {
        "id": exc_id,
        "name": name,
        "preset_id": None,
        "enabled": enabled,
        "scope": scope,
        "scope_target": scope_target,
        "rule_blocks": rule_blocks or [],
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

    def test_single_block_cidr(self, bypass, ssh):
        exc = _make_exception(rule_blocks=[
            {"rules": [{"type": "cidr", "value": "10.0.0.0/8"}]},
        ])
        bypass.apply_all([exc], {})
        cmd = _all_exec_calls(ssh)
        assert "ipset create fvpn_byp_test1234_b0 hash:net -exist" in cmd
        assert "ipset add fvpn_byp_test1234_b0 10.0.0.0/8 -exist" in cmd
        assert "-m set --match-set fvpn_byp_test1234_b0 dst" in cmd
        assert "0x8000/0xf000" in cmd

    def test_single_block_port_only(self, bypass, ssh):
        exc = _make_exception(rule_blocks=[
            {"rules": [{"type": "port", "value": "5000:5500", "protocol": "udp"}]},
        ])
        bypass.apply_all([exc], {})
        cmd = _all_exec_calls(ssh)
        assert "-p udp -m multiport --dports 5000:5500" in cmd
        # No ipset match since block has no CIDR/domain
        assert "match-set fvpn_byp_test1234_b0" not in cmd

    def test_block_with_cidr_and_port_anded(self, bypass, ssh):
        """Port + CIDR in same block should produce a single rule with BOTH matches."""
        exc = _make_exception(rule_blocks=[
            {"rules": [
                {"type": "cidr", "value": "10.0.0.0/8"},
                {"type": "port", "value": "5000:5500", "protocol": "udp"},
            ]},
        ])
        bypass.apply_all([exc], {})
        cmd = _all_exec_calls(ssh)
        # Should have ONE iptables rule with both ipset AND port match (ANDed)
        assert "-m set --match-set fvpn_byp_test1234_b0 dst" in cmd
        assert "-p udp -m multiport --dports 5000:5500" in cmd
        # Both matches should be in the same -A line
        for line in cmd.split(";"):
            if "fvpn_byp_test1234_b0 dst" in line and "multiport" in line:
                break
        else:
            pytest.fail("CIDR and port not in the same iptables rule (AND)")

    def test_two_blocks_ored(self, bypass, ssh):
        """Two blocks should produce two separate iptables rules (ORed)."""
        exc = _make_exception(rule_blocks=[
            {"rules": [{"type": "cidr", "value": "10.0.0.0/8"}]},
            {"rules": [{"type": "port", "value": "80", "protocol": "tcp"}]},
        ])
        bypass.apply_all([exc], {})
        cmd = _all_exec_calls(ssh)
        # Block 0: ipset match
        assert "fvpn_byp_test1234_b0 dst" in cmd
        # Block 1: port match (no ipset)
        assert "-p tcp -m multiport --dports 80" in cmd

    def test_mixed_block_cidr_domain_port_all_anded(self, bypass, ssh):
        """A block with CIDR + domain + port should AND all conditions."""
        exc = _make_exception(rule_blocks=[
            {"rules": [
                {"type": "cidr", "value": "10.0.0.0/8"},
                {"type": "domain", "value": "example.com"},
                {"type": "port", "value": "443", "protocol": "tcp"},
            ]},
        ])
        bypass.apply_all([exc], {})
        cmd = _all_exec_calls(ssh)
        # Ipset should be created (for CIDR + domain)
        assert "ipset create fvpn_byp_test1234_b0 hash:net -exist" in cmd
        assert "ipset add fvpn_byp_test1234_b0 10.0.0.0/8 -exist" in cmd
        # Single iptables rule with both ipset AND port match
        for line in cmd.split(";"):
            if "fvpn_byp_test1234_b0 dst" in line and "multiport" in line:
                assert "-p tcp -m multiport --dports 443" in line
                break
        else:
            pytest.fail("Mixed block did not produce a single AND rule")

    def test_device_scope_adds_mac_match(self, bypass, ssh):
        exc = _make_exception(
            scope="device",
            scope_target=["aa:bb:cc:dd:ee:ff"],
            rule_blocks=[{"rules": [{"type": "cidr", "value": "1.2.3.0/24"}]}],
        )
        bypass.apply_all([exc], {})
        cmd = _all_exec_calls(ssh)
        assert "-m mac --mac-source aa:bb:cc:dd:ee:ff" in cmd

    def test_group_scope_adds_ipset_src_match(self, bypass, ssh):
        exc = _make_exception(
            scope="group",
            scope_target=["prof_abc"],
            rule_blocks=[{"rules": [{"type": "cidr", "value": "1.2.3.0/24"}]}],
        )
        bypass.apply_all([exc], {"prof_abc": "src_mac_300"})
        cmd = _all_exec_calls(ssh)
        assert "-m set --match-set src_mac_300 src" in cmd

    def test_group_scope_missing_profile_skips(self, bypass, ssh):
        exc = _make_exception(
            scope="group",
            scope_target=["prof_nonexistent"],
            rule_blocks=[{"rules": [{"type": "cidr", "value": "1.2.3.0/24"}]}],
        )
        bypass.apply_all([exc], {})
        cmd = _all_exec_calls(ssh)
        assert "FVPN_BYPASS" in cmd
        # No iptables rule should reference the block ipset (skipped due to invalid scope)
        assert "match-set fvpn_byp_test1234_b0 dst" not in cmd

    def test_routing_table_setup(self, bypass, ssh):
        exc = _make_exception(rule_blocks=[
            {"rules": [{"type": "cidr", "value": "10.0.0.0/8"}]},
        ])
        bypass.apply_all([exc], {})
        cmd = _all_exec_calls(ssh)
        assert "ip rule add fwmark 0x8000/0xf000 lookup 1008 priority 100" in cmd

    def test_firewall_include_registered(self, bypass, uci):
        exc = _make_exception(rule_blocks=[
            {"rules": [{"type": "cidr", "value": "10.0.0.0/8"}]},
        ])
        bypass.apply_all([exc], {})
        uci.ensure_firewall_include.assert_called_once_with(
            "fvpn_vpn_bypass", "/etc/fvpn/vpn_bypass.sh",
        )

    def test_firewall_include_script_written(self, bypass, ssh):
        exc = _make_exception(rule_blocks=[
            {"rules": [{"type": "cidr", "value": "10.0.0.0/8"}]},
        ])
        bypass.apply_all([exc], {})
        write_calls = [c for c in ssh.write_file.call_args_list
                       if "/etc/fvpn/vpn_bypass.sh" in str(c)]
        assert len(write_calls) == 1
        script = write_calls[0][0][1]
        assert "#!/bin/sh" in script
        assert "FVPN_BYPASS" in script


class TestDnsmasqConfig:
    def test_domain_rules_write_dnsmasq_conf(self, bypass, ssh):
        exc = _make_exception(rule_blocks=[
            {"rules": [
                {"type": "domain", "value": "riotgames.com"},
                {"type": "domain", "value": "pvp.net"},
            ]},
        ])
        bypass.apply_all([exc], {})
        write_calls = [c for c in ssh.write_file.call_args_list
                       if "fvpn_bypass.conf" in str(c)]
        assert len(write_calls) == 1
        conf = write_calls[0][0][1]
        assert "ipset=/riotgames.com/pvp.net/fvpn_byp_test1234_b0" in conf

    def test_domain_only_block_creates_ipset(self, bypass, ssh):
        """Domain-only blocks must pre-create the ipset for dnsmasq to populate."""
        exc = _make_exception(rule_blocks=[
            {"rules": [{"type": "domain", "value": "example.com"}]},
        ])
        bypass.apply_all([exc], {})
        cmd = _all_exec_calls(ssh)
        # Ipset must be created even though there are no CIDRs
        assert "ipset create fvpn_byp_test1234_b0 hash:net -exist" in cmd
        # And the iptables rule should reference it
        assert "-m set --match-set fvpn_byp_test1234_b0 dst" in cmd

    def test_domains_in_different_blocks_get_different_ipsets(self, bypass, ssh):
        exc = _make_exception(rule_blocks=[
            {"rules": [{"type": "domain", "value": "a.com"}]},
            {"rules": [{"type": "domain", "value": "b.com"}]},
        ])
        bypass.apply_all([exc], {})
        write_calls = [c for c in ssh.write_file.call_args_list
                       if "fvpn_bypass.conf" in str(c)]
        conf = write_calls[0][0][1]
        assert "fvpn_byp_test1234_b0" in conf
        assert "fvpn_byp_test1234_b1" in conf

    def test_no_domain_rules_removes_conf(self, bypass, ssh):
        exc = _make_exception(rule_blocks=[
            {"rules": [{"type": "cidr", "value": "10.0.0.0/8"}]},
        ])
        bypass.apply_all([exc], {})
        exec_calls = " ".join(c[0][0] for c in ssh.exec.call_args_list)
        assert "rm -f /tmp/dnsmasq.d/fvpn_bypass.conf" in exec_calls


class TestCleanup:
    def test_removes_chain_ipsets_routing(self, bypass, iptables, ipset, iproute, ssh, uci):
        ipset.list_names.return_value = ["fvpn_byp_abc_b0", "fvpn_byp_abc_b1"]
        bypass.cleanup()
        iptables.delete_chain.assert_called_once_with(
            "mangle", "ROUTE_POLICY", "FVPN_BYPASS",
        )
        assert ipset.destroy.call_count == 2
        iproute.rule_del.assert_called_once()

    def test_cleanup_with_ip6tables(self, bypass_with_ip6):
        bypass_with_ip6.cleanup()
        ip6 = bypass_with_ip6._ip6tables
        ip6.delete_chain.assert_called_once_with(
            "mangle", "ROUTE_POLICY", "FVPN_BYPASS",
        )


class TestSourceMatches:
    def test_global_returns_empty_string(self, bypass):
        assert bypass._source_matches("global", None, {}) == [""]

    def test_device_single_returns_mac_match(self, bypass):
        result = bypass._source_matches("device", ["aa:bb:cc:dd:ee:ff"], {})
        assert result == ["-m mac --mac-source aa:bb:cc:dd:ee:ff"]

    def test_device_multiple_returns_multiple(self, bypass):
        result = bypass._source_matches("device", ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"], {})
        assert len(result) == 2
        assert "-m mac --mac-source aa:bb:cc:dd:ee:ff" in result
        assert "-m mac --mac-source 11:22:33:44:55:66" in result

    def test_device_invalid_mac_skipped(self, bypass):
        result = bypass._source_matches("device", ["invalid", "aa:bb:cc:dd:ee:ff"], {})
        assert len(result) == 1

    def test_group_single_returns_ipset_match(self, bypass):
        result = bypass._source_matches("group", ["prof_1"], {"prof_1": "src_mac_300"})
        assert result == ["-m set --match-set src_mac_300 src"]

    def test_group_multiple_returns_multiple(self, bypass):
        result = bypass._source_matches("group", ["prof_1", "prof_2"], {"prof_1": "src_mac_300", "prof_2": "src_mac_301"})
        assert len(result) == 2

    def test_group_missing_returns_empty(self, bypass):
        assert bypass._source_matches("group", ["prof_missing"], {}) == []

    def test_empty_target_returns_empty(self, bypass):
        assert bypass._source_matches("device", [], {}) == []
        assert bypass._source_matches("device", None, {}) == []


class TestBlockIpsetName:
    def test_basic(self):
        assert RouterVpnBypass._block_ipset_name("byp_abc123", 0) == "fvpn_byp_abc123_b0"
        assert RouterVpnBypass._block_ipset_name("byp_abc123", 2) == "fvpn_byp_abc123_b2"


class TestValidation:
    def test_invalid_cidr_skipped(self, bypass, ssh):
        exc = _make_exception(rule_blocks=[
            {"rules": [{"type": "cidr", "value": "$(evil_cmd)"}]},
        ])
        bypass.apply_all([exc], {})
        cmd = _all_exec_calls(ssh)
        assert "evil_cmd" not in cmd

    def test_invalid_port_protocol_skipped(self, bypass, ssh):
        exc = _make_exception(rule_blocks=[
            {"rules": [{"type": "port", "value": "80", "protocol": "invalid"}]},
        ])
        bypass.apply_all([exc], {})
        cmd = _all_exec_calls(ssh)
        assert "multiport" not in cmd
