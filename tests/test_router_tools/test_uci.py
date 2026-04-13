"""Tests for router_tools.uci — UCI command wrapper."""

from unittest.mock import MagicMock, call

import pytest

from router.tools.uci import Uci, _quote


# ── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture
def ssh():
    return MagicMock()


@pytest.fixture
def uci(ssh):
    return Uci(ssh)


# ── Quote helper ────────────────────────────────────────────────────────────


class TestQuote:
    def test_plain_string(self):
        assert _quote("hello") == "hello"

    def test_single_quote_escaped(self):
        assert _quote("Bob's Phone") == "Bob'\\''s Phone"

    def test_multiple_quotes(self):
        assert _quote("it's Bob's") == "it'\\''s Bob'\\''s"

    def test_empty_string(self):
        assert _quote("") == ""


# ── Get ─────────────────────────────────────────────────────────────────────


class TestGet:
    def test_get_with_default(self, uci, ssh):
        ssh.exec.return_value = "lan"
        result = uci.get("network.lan.proto", "static")
        ssh.exec.assert_called_once_with(
            "uci -q get network.lan.proto 2>/dev/null || echo 'static'"
        )
        assert result == "lan"

    def test_get_empty_default(self, uci, ssh):
        uci.get("route_policy.rule.enabled")
        ssh.exec.assert_called_once_with(
            "uci -q get route_policy.rule.enabled 2>/dev/null || echo ''"
        )

    def test_get_default_with_quote(self, uci, ssh):
        uci.get("some.path", "it's fine")
        ssh.exec.assert_called_once_with(
            "uci -q get some.path 2>/dev/null || echo 'it'\\''s fine'"
        )


# ── Set ─────────────────────────────────────────────────────────────────────


class TestSet:
    def test_set_simple(self, uci, ssh):
        uci.set("route_policy.rule.enabled", "1")
        ssh.exec.assert_called_once_with(
            "uci set route_policy.rule.enabled='1'"
        )

    def test_set_escapes_quotes(self, uci, ssh):
        uci.set("route_policy.rule.name", "Bob's Phone")
        ssh.exec.assert_called_once_with(
            "uci set route_policy.rule.name='Bob'\\''s Phone'"
        )


class TestSetType:
    def test_set_type(self, uci, ssh):
        uci.set_type("route_policy.fvpn_rule_9001", "rule")
        ssh.exec.assert_called_once_with(
            "uci set route_policy.fvpn_rule_9001=rule"
        )


# ── Delete ──────────────────────────────────────────────────────────────────


class TestDelete:
    def test_delete_idempotent(self, uci, ssh):
        uci.delete("firewall.fvpn_zone")
        ssh.exec.assert_called_once_with(
            "uci -q delete firewall.fvpn_zone 2>/dev/null; true"
        )


# ── List operations ─────────────────────────────────────────────────────────


class TestAddList:
    def test_add_list(self, uci, ssh):
        uci.add_list("route_policy.rule.from_mac", "aa:bb:cc:dd:ee:ff")
        ssh.exec.assert_called_once_with(
            "uci add_list route_policy.rule.from_mac='aa:bb:cc:dd:ee:ff'"
        )


class TestDelList:
    def test_del_list(self, uci, ssh):
        uci.del_list("route_policy.rule.from_mac", "AA:BB:CC:DD:EE:FF")
        ssh.exec.assert_called_once_with(
            "uci del_list route_policy.rule.from_mac='AA:BB:CC:DD:EE:FF'"
        )


# ── Commit ──────────────────────────────────────────────────────────────────


class TestCommit:
    def test_single_config(self, uci, ssh):
        uci.commit("route_policy")
        ssh.exec.assert_called_once_with("uci commit route_policy")

    def test_multiple_configs(self, uci, ssh):
        uci.commit("wireless", "network", "firewall")
        ssh.exec.assert_called_once_with(
            "uci commit wireless && uci commit network && uci commit firewall"
        )


# ── Add ─────────────────────────────────────────────────────────────────────


class TestAdd:
    def test_add_anonymous_section(self, uci, ssh):
        ssh.exec.return_value = "cfg123456"
        result = uci.add("firewall", "forwarding")
        ssh.exec.assert_called_once_with("uci add firewall forwarding")
        assert result == "cfg123456"


# ── Reorder / Rename ────────────────────────────────────────────────────────


class TestReorder:
    def test_reorder(self, uci, ssh):
        uci.reorder("route_policy.fvpn_rule_9001", 3)
        ssh.exec.assert_called_once_with(
            "uci reorder route_policy.fvpn_rule_9001=3"
        )


class TestRename:
    def test_rename_commits(self, uci, ssh):
        uci.rename("route_policy.@rule[4]", "fvpn_rule_9001")
        ssh.exec.assert_called_once_with(
            "uci rename route_policy.@rule[4]=fvpn_rule_9001 && "
            "uci commit route_policy"
        )


# ── Show / parse ────────────────────────────────────────────────────────────


class TestShow:
    def test_show_calls_exec_and_parses(self, uci, ssh):
        ssh.exec.return_value = (
            "route_policy.fvpn_rule_9001=rule\n"
            "route_policy.fvpn_rule_9001.name='Trusted'\n"
            "route_policy.fvpn_rule_9001.enabled='1'"
        )
        result = uci.show("route_policy")
        ssh.exec.assert_called_once_with(
            "uci show route_policy 2>/dev/null || echo ''"
        )
        assert "fvpn_rule_9001" in result
        assert result["fvpn_rule_9001"]["name"] == "Trusted"


class TestParseShow:
    def test_basic_parsing(self):
        raw = (
            "route_policy.fvpn_rule_9001=rule\n"
            "route_policy.fvpn_rule_9001.name='Streaming'\n"
            "route_policy.fvpn_rule_9001.enabled='1'"
        )
        result = Uci.parse_show(raw, "route_policy")
        assert result["fvpn_rule_9001"]["_type"] == "rule"
        assert result["fvpn_rule_9001"]["name"] == "Streaming"
        assert result["fvpn_rule_9001"]["enabled"] == "1"

    def test_multivalue_becomes_list(self):
        raw = (
            "route_policy.rule1=rule\n"
            "route_policy.rule1.from_mac='aa:bb:cc:dd:ee:ff'\n"
            "route_policy.rule1.from_mac='11:22:33:44:55:66'"
        )
        result = Uci.parse_show(raw, "route_policy")
        assert result["rule1"]["from_mac"] == [
            "aa:bb:cc:dd:ee:ff",
            "11:22:33:44:55:66",
        ]

    def test_empty_input(self):
        assert Uci.parse_show("", "route_policy") == {}

    def test_ignores_other_configs(self):
        raw = (
            "network.lan=interface\n"
            "route_policy.rule1=rule\n"
            "route_policy.rule1.name='Test'"
        )
        result = Uci.parse_show(raw, "route_policy")
        assert "lan" not in result
        assert result["rule1"]["name"] == "Test"

    def test_strips_quotes_from_values(self):
        raw = "config.section=type\nconfig.section.key='value'"
        result = Uci.parse_show(raw, "config")
        assert result["section"]["key"] == "value"


# ── Multi ───────────────────────────────────────────────────────────────────


class TestMulti:
    def test_chains_with_and(self, uci, ssh):
        uci.multi([
            "uci set route_policy.rule.enabled='1'",
            "uci commit route_policy",
        ])
        ssh.exec.assert_called_once_with(
            "uci set route_policy.rule.enabled='1' && uci commit route_policy"
        )

    def test_empty_list_no_call(self, uci, ssh):
        uci.multi([])
        ssh.exec.assert_not_called()


# ── Batch ───────────────────────────────────────────────────────────────────


class TestBatch:
    def test_writes_file_and_executes(self, uci, ssh):
        uci.batch("set firewall.zone=zone\nset firewall.zone.name='lan'", "firewall")
        ssh.write_file.assert_called_once_with(
            "/tmp/fvpn_uci_batch.txt",
            "set firewall.zone=zone\nset firewall.zone.name='lan'",
        )
        ssh.exec.assert_called_once_with(
            "uci batch < /tmp/fvpn_uci_batch.txt && "
            "uci commit firewall && "
            "rm -f /tmp/fvpn_uci_batch.txt"
        )

    def test_multiple_commits(self, uci, ssh):
        uci.batch("set x=y", "wireless", "network")
        ssh.exec.assert_called_once_with(
            "uci batch < /tmp/fvpn_uci_batch.txt && "
            "uci commit wireless && uci commit network && "
            "rm -f /tmp/fvpn_uci_batch.txt"
        )

    def test_no_commits(self, uci, ssh):
        uci.batch("set x=y")
        ssh.exec.assert_called_once_with(
            "uci batch < /tmp/fvpn_uci_batch.txt && "
            "rm -f /tmp/fvpn_uci_batch.txt"
        )


# ── Batch Set ───────────────────────────────────────────────────────────────


class TestBatchSections:
    def test_builds_and_executes_batch(self, uci, ssh):
        uci.batch_sections([
            ("wireless.fvpn_net_2g", {
                "_type": "wifi-iface",
                "ssid": "TestNet",
                "encryption": "psk2",
            }),
            ("network.fvpn_net", {
                "_type": "interface",
                "ipaddr": "192.168.9.1",
            }),
        ], "wireless", "network")
        # Should write a batch file and execute
        ssh.write_file.assert_called_once()
        content = ssh.write_file.call_args[0][1]
        assert "set wireless.fvpn_net_2g=wifi-iface" in content
        assert "set wireless.fvpn_net_2g.ssid='TestNet'" in content
        assert "set network.fvpn_net=interface" in content
        assert "set network.fvpn_net.ipaddr='192.168.9.1'" in content

    def test_quotes_values(self, uci, ssh):
        uci.batch_sections([
            ("wireless.net", {"ssid": "O'Brien's WiFi"}),
        ], "wireless")
        content = ssh.write_file.call_args[0][1]
        assert "O'\\''Brien'\\''s WiFi" in content

    def test_empty_sections_no_call(self, uci, ssh):
        uci.batch_sections([], "wireless")
        ssh.write_file.assert_not_called()


class TestBatchSet:
    def test_basic_fields(self, uci, ssh):
        uci.batch_set(
            "wireguard.peer_9001",
            {"_type": "peers", "name": "Test", "address_v4": "10.2.0.2/32"},
            "wireguard",
        )
        cmd = ssh.exec.call_args[0][0]
        assert "uci set wireguard.peer_9001=peers" in cmd
        assert "uci set wireguard.peer_9001.name='Test'" in cmd
        assert "uci set wireguard.peer_9001.address_v4='10.2.0.2/32'" in cmd
        assert "uci commit wireguard" in cmd

    def test_with_add_lists(self, uci, ssh):
        uci.batch_set(
            "route_policy.rule",
            {"_type": "rule"},
            "route_policy",
            add_lists={"from_mac": "aa:bb:cc:dd:ee:ff"},
        )
        cmd = ssh.exec.call_args[0][0]
        assert "uci add_list route_policy.rule.from_mac='aa:bb:cc:dd:ee:ff'" in cmd

    def test_escapes_quotes_in_values(self, uci, ssh):
        uci.batch_set(
            "route_policy.rule",
            {"name": "Bob's Group"},
            "route_policy",
        )
        cmd = ssh.exec.call_args[0][0]
        assert "Bob'\\''s Group" in cmd
