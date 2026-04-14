"""Tests for RouterPolicy facade."""

from unittest.mock import MagicMock, call

import pytest

from router.facades.policy import RouterPolicy


@pytest.fixture
def policy(uci, ssh):
    return RouterPolicy(uci, ssh)


class TestGetFlintVpnRules:
    def test_returns_named_fvpn_rules(self, uci, ssh):
        uci.show.return_value = {
            "fvpn_rule_9001": {
                "_type": "rule",
                "name": "USA",
                "enabled": "1",
                "tunnel_id": "1",
            },
            "fvpn_rule_9002": {
                "_type": "rule",
                "name": "UK",
                "enabled": "0",
                "tunnel_id": "2",
            },
        }
        p = RouterPolicy(uci, ssh)
        rules = p.get_flint_vpn_rules()
        assert len(rules) == 2
        assert rules[0]["rule_name"] == "fvpn_rule_9001"
        assert rules[0]["name"] == "USA"

    def test_includes_anonymous_rules_with_fvpn_group_id(self, uci, ssh):
        uci.show.return_value = {
            "@rule[4]": {
                "_type": "rule",
                "name": "Japan",
                "group_id": "1957",
            },
            "some_other_rule": {
                "_type": "rule",
                "group_id": "999",
            },
        }
        p = RouterPolicy(uci, ssh)
        rules = p.get_flint_vpn_rules()
        assert len(rules) == 1
        assert rules[0]["rule_name"] == "@rule[4]"

    def test_includes_ovpn_group_id(self, uci, ssh):
        uci.show.return_value = {
            "@rule[5]": {
                "_type": "rule",
                "name": "OVPN",
                "group_id": "28216",
            },
        }
        p = RouterPolicy(uci, ssh)
        rules = p.get_flint_vpn_rules()
        assert len(rules) == 1

    def test_excludes_non_fvpn_rules(self, uci, ssh):
        uci.show.return_value = {
            "some_rule": {
                "_type": "rule",
                "name": "Not Ours",
                "group_id": "42",
            },
        }
        p = RouterPolicy(uci, ssh)
        rules = p.get_flint_vpn_rules()
        assert len(rules) == 0

    def test_renames_type_to_section_type(self, uci, ssh):
        uci.show.return_value = {
            "fvpn_rule_9001": {"_type": "rule", "name": "X"},
        }
        p = RouterPolicy(uci, ssh)
        rules = p.get_flint_vpn_rules()
        assert "_type" not in rules[0]
        assert rules[0]["_section_type"] == "rule"

    def test_empty_route_policy(self, uci, ssh):
        uci.show.return_value = {}
        p = RouterPolicy(uci, ssh)
        assert p.get_flint_vpn_rules() == []


class TestReorderVpnRules:
    def test_reorders_and_commits(self, policy, uci):
        policy.reorder_vpn_rules(["fvpn_rule_9002", "fvpn_rule_9001"])
        assert uci.reorder.call_count == 2
        uci.reorder.assert_any_call("route_policy.fvpn_rule_9002", 0)
        uci.reorder.assert_any_call("route_policy.fvpn_rule_9001", 1)
        uci.commit.assert_called_once_with("route_policy")

    def test_empty_list_is_noop(self, policy, uci):
        policy.reorder_vpn_rules([])
        uci.reorder.assert_not_called()
        uci.commit.assert_not_called()


class TestHealAnonymousRuleSection:
    def test_renames_anonymous_section(self, policy, uci):
        policy.heal_anonymous_rule_section("@rule[4]", "fvpn_rule_9001")
        uci.rename.assert_called_once_with(
            "route_policy.@rule[4]", "fvpn_rule_9001"
        )

    def test_ignores_non_anonymous_section(self, policy, uci):
        policy.heal_anonymous_rule_section("fvpn_rule_9001", "fvpn_rule_9001")
        uci.rename.assert_not_called()

    def test_ignores_empty_target_name(self, policy, uci):
        policy.heal_anonymous_rule_section("@rule[4]", "")
        uci.rename.assert_not_called()

    def test_swallows_rename_exception(self, policy, uci):
        uci.rename.side_effect = Exception("rename failed")
        policy.heal_anonymous_rule_section("@rule[4]", "fvpn_rule_9001")
        # Should not raise


class TestGetFlintVpnPeers:
    def test_parses_peer_configs(self, policy, ssh):
        ssh.exec.return_value = (
            "wireguard.peer_9001=peers\n"
            "wireguard.peer_9001.name='US East'\n"
            "wireguard.peer_9001.public_key='abc123'\n"
        )
        peers = policy.get_flint_vpn_peers()
        assert len(peers) == 1
        assert peers[0]["peer_id"] == "peer_9001"
        assert peers[0]["name"] == "US East"

    def test_empty_output(self, policy, ssh):
        ssh.exec.return_value = ""
        assert policy.get_flint_vpn_peers() == []


class TestKillSwitch:
    def test_set_kill_switch_enabled(self, policy, uci):
        policy.set_kill_switch("fvpn_rule_9001", True)
        uci.set.assert_called_once_with(
            "route_policy.fvpn_rule_9001.killswitch", "1"
        )
        uci.commit.assert_called_once_with("route_policy")

    def test_set_kill_switch_disabled(self, policy, uci):
        policy.set_kill_switch("fvpn_rule_9001", False)
        uci.set.assert_called_once_with(
            "route_policy.fvpn_rule_9001.killswitch", "0"
        )

    def test_get_kill_switch_enabled(self, policy, uci):
        uci.get.return_value = "1"
        assert policy.get_kill_switch("fvpn_rule_9001") is True

    def test_get_kill_switch_disabled(self, policy, uci):
        uci.get.return_value = "0"
        assert policy.get_kill_switch("fvpn_rule_9001") is False

    def test_get_kill_switch_default_is_disabled(self, policy, uci):
        uci.get.return_value = "0"
        assert policy.get_kill_switch("fvpn_rule_9001") is False


class TestProfileNaming:
    def test_get_profile_name(self, policy, uci):
        uci.get.return_value = "  My VPN  "
        assert policy.get_profile_name("fvpn_rule_9001") == "My VPN"

    def test_rename_profile_wg(self, policy, uci):
        policy.rename_profile("fvpn_rule_9001", "New Name", peer_id="peer_9001")
        uci.multi.assert_called_once()
        cmds = uci.multi.call_args[0][0]
        assert any("route_policy.fvpn_rule_9001.name" in c for c in cmds)
        assert any("wireguard.peer_9001.name" in c for c in cmds)
        assert any("uci commit route_policy" in c for c in cmds)
        assert any("uci commit wireguard" in c for c in cmds)

    def test_rename_profile_ovpn(self, policy, uci):
        policy.rename_profile("fvpn_rule_9001", "New Name", client_uci_id="28216_9051")
        cmds = uci.multi.call_args[0][0]
        assert any("ovpnclient.28216_9051.name" in c for c in cmds)
        assert any("uci commit ovpnclient" in c for c in cmds)

    def test_rename_profile_both(self, policy, uci):
        policy.rename_profile("r", "N", peer_id="p", client_uci_id="c")
        cmds = uci.multi.call_args[0][0]
        assert any("wireguard" in c for c in cmds)
        assert any("ovpnclient" in c for c in cmds)


class TestFromMacTokens:
    def test_parses_mac_tokens(self, policy, uci):
        uci.get.return_value = "'AA:BB:CC:DD:EE:FF' '11:22:33:44:55:66'"
        tokens = policy.from_mac_tokens("fvpn_rule_9001")
        assert len(tokens) == 2
        assert tokens[0] == "AA:BB:CC:DD:EE:FF"
        assert tokens[1] == "11:22:33:44:55:66"

    def test_empty_mac_list(self, policy, uci):
        uci.get.return_value = ""
        assert policy.from_mac_tokens("fvpn_rule_9001") == []

    def test_filters_invalid_tokens(self, policy, uci):
        uci.get.return_value = "'AA:BB:CC:DD:EE:FF' 'not-a-mac' '11:22:33:44:55:66'"
        tokens = policy.from_mac_tokens("fvpn_rule_9001")
        assert len(tokens) == 2


class TestGetActiveInterfaces:
    def test_returns_enabled_interfaces(self, policy, ssh, uci):
        ssh.exec.return_value = "wgclient1\nwgclient2\n"
        uci.get.side_effect = lambda key, default="": {
            "network.wgclient1.disabled": "0",
            "network.wgclient2.disabled": "1",
        }.get(key, default)
        active = policy.get_active_interfaces()
        assert active == ["wgclient1"]

    def test_empty_output(self, policy, ssh):
        ssh.exec.return_value = ""
        assert policy.get_active_interfaces() == []
