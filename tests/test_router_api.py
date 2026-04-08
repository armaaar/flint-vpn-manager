"""Tests for router_api.py — GL.iNet Flint 2 router management via SSH.

Unit tests mock SSH commands.
Integration tests (marked @pytest.mark.integration) use a live router.
"""

import pytest
from unittest.mock import MagicMock

from router_api import RouterAPI


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def mock_router():
    """Create a RouterAPI with mocked SSH execution."""
    router = RouterAPI("192.168.8.1", password="test")
    router._client = MagicMock()

    router._exec_responses = {}
    router._exec_calls = []

    def mock_exec(command, timeout=30):
        router._exec_calls.append(command)
        for pattern, response in router._exec_responses.items():
            if pattern in command:
                return response
        return ""

    router.exec = mock_exec
    return router


# ── Unit Tests: DHCP Leases ──────────────────────────────────────────────────

class TestGetDhcpLeases:
    def test_parses_leases(self, mock_router):
        mock_router._exec_responses["cat /tmp/dhcp.leases"] = (
            "1775453082 42:5a:e3:13:f6:37 192.168.8.163 * 01:42:5a:e3:13:f6:37\n"
            "1775453152 a4:f9:33:1c:b6:78 192.168.8.228 Armaaar-PC 01:a4:f9:33:1c:b6:78"
        )
        leases = mock_router.get_dhcp_leases()
        assert len(leases) == 2
        assert leases[0]["mac"] == "42:5a:e3:13:f6:37"
        assert leases[0]["ip"] == "192.168.8.163"
        assert leases[0]["hostname"] == ""
        assert leases[1]["hostname"] == "Armaaar-PC"

    def test_empty_leases(self, mock_router):
        mock_router._exec_responses["cat /tmp/dhcp.leases"] = ""
        leases = mock_router.get_dhcp_leases()
        assert leases == []

    def test_mac_lowercased(self, mock_router):
        mock_router._exec_responses["cat /tmp/dhcp.leases"] = (
            "123 AA:BB:CC:DD:EE:FF 10.0.0.1 host 01:aa:bb:cc:dd:ee:ff"
        )
        leases = mock_router.get_dhcp_leases()
        assert leases[0]["mac"] == "aa:bb:cc:dd:ee:ff"


# ── Unit Tests: Tunnel Health ─────────────────────────────────────────────────

class TestGetTunnelHealth:
    def test_disabled_rule_is_red(self, mock_router):
        mock_router._exec_responses["enabled"] = "0"
        assert mock_router.get_tunnel_health("fvpn_rule_9001") == "red"

    def test_no_interface_enabled_is_connecting(self, mock_router):
        mock_router._exec_responses["enabled"] = "1"
        mock_router._exec_responses["uci get"] = ""
        assert mock_router.get_tunnel_health("fvpn_rule_9001") == "connecting"

    def test_interface_down_is_red(self, mock_router):
        mock_router._exec_responses["enabled"] = "1"
        mock_router._exec_responses["uci get"] = "wgclient1"
        mock_router._exec_responses["ifstatus"] = "false"
        mock_router._exec_responses["cat"] = ""  # no state file
        assert mock_router.get_tunnel_health("fvpn_rule_9001") == "red"

    def test_recent_handshake_is_green(self, mock_router):
        import time
        now = int(time.time())
        mock_router._exec_responses["enabled"] = "1"
        mock_router._exec_responses["uci get"] = "wgclient1"
        mock_router._exec_responses["ifstatus"] = "true"
        mock_router._exec_responses["latest-handshakes"] = f"peer1\t{now - 60}"
        mock_router._exec_responses["transfer"] = "peer1\t1000\t2000"
        assert mock_router.get_tunnel_health("fvpn_rule_9001") == "green"

    def test_old_handshake_is_amber(self, mock_router):
        import time
        now = int(time.time())
        mock_router._exec_responses["enabled"] = "1"
        mock_router._exec_responses["uci get"] = "wgclient1"
        mock_router._exec_responses["ifstatus"] = "true"
        mock_router._exec_responses["latest-handshakes"] = f"peer1\t{now - 300}"
        mock_router._exec_responses["transfer"] = ""
        assert mock_router.get_tunnel_health("fvpn_rule_9001") == "amber"

    def test_very_old_handshake_is_red(self, mock_router):
        import time
        now = int(time.time())
        mock_router._exec_responses["enabled"] = "1"
        mock_router._exec_responses["uci get"] = "wgclient1"
        mock_router._exec_responses["ifstatus"] = "true"
        mock_router._exec_responses["latest-handshakes"] = f"peer1\t{now - 700}"
        mock_router._exec_responses["transfer"] = ""
        assert mock_router.get_tunnel_health("fvpn_rule_9001") == "red"


# ── Unit Tests: Tunnel Control ─────────────────────────────────────────────────

class TestBringTunnelUp:
    def test_enables_rule_and_restarts(self, mock_router):
        mock_router._exec_responses["tunnel_id"] = "300"
        mock_router.bring_tunnel_up("fvpn_rule_test")
        assert any("enabled='1'" in c for c in mock_router._exec_calls)
        assert any("vpn-client restart" in c for c in mock_router._exec_calls)

    def test_missing_rule_raises(self, mock_router):
        mock_router._exec_responses["tunnel_id"] = "MISSING"
        with pytest.raises(RuntimeError, match="does not exist"):
            mock_router.bring_tunnel_up("nonexistent_rule")

class TestBringTunnelDown:
    def test_disables_rule_and_restarts(self, mock_router):
        mock_router.bring_tunnel_down("fvpn_rule_test")
        assert any("enabled='0'" in c for c in mock_router._exec_calls)
        assert any("vpn-client restart" in c for c in mock_router._exec_calls)


# ── Unit Tests: Device Policy ─────────────────────────────────────────────────

class TestDevicePolicy:
    def test_set_device_vpn_adds_mac(self, mock_router):
        mock_router._exec_responses["from_mac"] = ""
        mock_router._exec_responses[".from "] = "src_mac_301"
        mock_router.set_device_vpn("aa:bb:cc:dd:ee:ff", "fvpn_rule_test")
        assert any("add_list" in c and "aa:bb:cc:dd:ee:ff" in c
                    for c in mock_router._exec_calls)

    def test_set_device_vpn_skips_duplicate(self, mock_router):
        mock_router._exec_responses["from_mac"] = "aa:bb:cc:dd:ee:ff"
        mock_router.set_device_vpn("aa:bb:cc:dd:ee:ff", "fvpn_rule_test")
        assert not any("add_list" in c for c in mock_router._exec_calls)

    def test_mac_lowercased(self, mock_router):
        mock_router._exec_responses["from_mac"] = ""
        mock_router._exec_responses[".from "] = "src_mac_301"
        mock_router.set_device_vpn("AA:BB:CC:DD:EE:FF", "fvpn_rule_test")
        assert any("aa:bb:cc:dd:ee:ff" in c for c in mock_router._exec_calls)

    def test_set_device_vpn_uses_ipset_not_rtp2(self, mock_router):
        """Stage 1: must use ipset for immediate effect, never call rtp2.sh."""
        mock_router._exec_responses["from_mac"] = ""
        mock_router._exec_responses[".from "] = "src_mac_301"
        mock_router.set_device_vpn("aa:bb:cc:dd:ee:ff", "fvpn_rule_test")
        assert any("ipset add src_mac_301 aa:bb:cc:dd:ee:ff" in c
                   for c in mock_router._exec_calls)
        assert not any("rtp2.sh" in c for c in mock_router._exec_calls)

    def test_set_device_vpn_no_ipset_call_if_rule_has_no_from_field(self, mock_router):
        """Defensive: if route_policy.{rule}.from is empty, skip ipset add."""
        mock_router._exec_responses["from_mac"] = ""
        # No response for ".from " — defaults to ""
        mock_router.set_device_vpn("aa:bb:cc:dd:ee:ff", "fvpn_rule_test")
        assert not any("ipset add" in c for c in mock_router._exec_calls)
        assert not any("rtp2.sh" in c for c in mock_router._exec_calls)

    def test_remove_device_from_vpn_uses_ipset_not_rtp2(self, mock_router):
        """Stage 1: remove uses ipset del, never rtp2.sh."""
        mock_router._exec_responses["from_mac"] = "'aa:bb:cc:dd:ee:ff'"
        mock_router._exec_responses[".from "] = "src_mac_301"
        mock_router.remove_device_from_vpn("aa:bb:cc:dd:ee:ff", "fvpn_rule_test")
        assert any("del_list" in c and "aa:bb:cc:dd:ee:ff" in c
                   for c in mock_router._exec_calls)
        assert any("ipset del src_mac_301 aa:bb:cc:dd:ee:ff" in c
                   for c in mock_router._exec_calls)
        assert not any("rtp2.sh" in c for c in mock_router._exec_calls)

    def test_remove_device_from_vpn_skips_if_not_assigned(self, mock_router):
        mock_router._exec_responses["from_mac"] = ""
        mock_router.remove_device_from_vpn("aa:bb:cc:dd:ee:ff", "fvpn_rule_test")
        assert not any("del_list" in c for c in mock_router._exec_calls)
        assert not any("ipset del" in c for c in mock_router._exec_calls)

    def test_remove_device_from_all_vpn_uses_ipset_not_rtp2(self, mock_router):
        """Stage 1: remove_from_all uses ipset del per rule, never rtp2.sh.

        Reads rules via get_flint_vpn_rules and from_mac via _from_mac_tokens
        (to preserve case for UCI del_list).
        """
        mock_router._exec_responses["uci show route_policy"] = (
            "route_policy.fvpn_rule_test1=rule\n"
            "route_policy.fvpn_rule_test1.from_mac='aa:bb:cc:dd:ee:ff'\n"
            "route_policy.fvpn_rule_test1.peer_id='9001'\n"
            "route_policy.fvpn_rule_test1.via_type='wireguard'\n"
            "route_policy.fvpn_rule_test1.group_id='1957'\n"
            "route_policy.fvpn_rule_test2=rule\n"
            "route_policy.fvpn_rule_test2.from_mac='aa:bb:cc:dd:ee:ff'\n"
            "route_policy.fvpn_rule_test2.peer_id='9002'\n"
            "route_policy.fvpn_rule_test2.via_type='wireguard'\n"
            "route_policy.fvpn_rule_test2.group_id='1957'"
        )
        mock_router._exec_responses["uci -q get route_policy.fvpn_rule_test1.from_mac"] = "'aa:bb:cc:dd:ee:ff'"
        mock_router._exec_responses["uci -q get route_policy.fvpn_rule_test2.from_mac"] = "'aa:bb:cc:dd:ee:ff'"
        mock_router._exec_responses[".from "] = "src_mac_301"
        mock_router.remove_device_from_all_vpn("aa:bb:cc:dd:ee:ff")
        del_list_calls = [c for c in mock_router._exec_calls if "del_list" in c]
        ipset_del_calls = [c for c in mock_router._exec_calls if "ipset del" in c]
        assert len(del_list_calls) == 2
        assert len(ipset_del_calls) >= 2
        assert not any("rtp2.sh" in c for c in mock_router._exec_calls)

    def test_remove_device_from_vpn_preserves_uppercase_for_del_list(self, mock_router):
        """Bug fix: UCI requires exact-match for del_list. If the router stores
        the MAC in uppercase, our del_list call must also use uppercase."""
        mock_router._exec_responses["uci -q get route_policy.fvpn_rule_test.from_mac"] = (
            "'AA:BB:CC:DD:EE:FF'"
        )
        mock_router._exec_responses[".from "] = "src_mac_301"
        mock_router.remove_device_from_vpn("aa:bb:cc:dd:ee:ff", "fvpn_rule_test")
        joined = " | ".join(mock_router._exec_calls)
        # del_list must use the EXACT stored case (uppercase)
        assert "del_list route_policy.fvpn_rule_test.from_mac='AA:BB:CC:DD:EE:FF'" in joined

    def test_set_kill_switch_no_rtp2(self, mock_router):
        """Stage 1: kill switch toggle uses uci commit only, no rtp2.sh."""
        mock_router.set_kill_switch("fvpn_rule_test", True)
        assert any("killswitch='1'" in c for c in mock_router._exec_calls)
        assert any("uci commit route_policy" in c for c in mock_router._exec_calls)
        assert not any("rtp2.sh" in c for c in mock_router._exec_calls)

    def test_set_kill_switch_disable(self, mock_router):
        mock_router.set_kill_switch("fvpn_rule_test", False)
        assert any("killswitch='0'" in c for c in mock_router._exec_calls)
        assert not any("rtp2.sh" in c for c in mock_router._exec_calls)

    def test_get_kill_switch_returns_true(self, mock_router):
        """Stage 3: live kill switch read."""
        mock_router._exec_responses["killswitch"] = "1"
        assert mock_router.get_kill_switch("fvpn_rule_test") is True

    def test_get_kill_switch_returns_false(self, mock_router):
        mock_router._exec_responses["killswitch"] = "0"
        assert mock_router.get_kill_switch("fvpn_rule_test") is False

    def test_get_kill_switch_default_false_when_unset(self, mock_router):
        # No response → empty string → False
        assert mock_router.get_kill_switch("fvpn_rule_test") is False

    def test_get_profile_name_returns_router_value(self, mock_router):
        """Stage 4: profile name comes from route_policy.{rule}.name."""
        mock_router._exec_responses["route_policy.fvpn_rule_9001.name"] = "Trusted"
        assert mock_router.get_profile_name("fvpn_rule_9001") == "Trusted"

    def test_get_profile_name_empty_when_unset(self, mock_router):
        assert mock_router.get_profile_name("fvpn_rule_9001") == ""

    def test_rename_profile_wireguard_writes_route_policy_and_wireguard(self, mock_router):
        """Stage 4: WG rename writes both route_policy.name and wireguard.peer.name."""
        mock_router.rename_profile(
            rule_name="fvpn_rule_9001",
            new_name="Streaming",
            peer_id="9001",
        )
        joined = " | ".join(mock_router._exec_calls)
        assert "uci set route_policy.fvpn_rule_9001.name='Streaming'" in joined
        assert "uci set wireguard.9001.name='Streaming'" in joined
        assert "uci commit route_policy" in joined
        assert "uci commit wireguard" in joined
        # OVPN commit should NOT be issued for WG-only rename
        assert "uci commit ovpnclient" not in joined

    def test_rename_profile_openvpn_writes_route_policy_and_ovpnclient(self, mock_router):
        """Stage 4: OVPN rename writes both route_policy.name and ovpnclient.{id}.name."""
        mock_router.rename_profile(
            rule_name="fvpn_rule_ovpn_9051",
            new_name="OVPN Group",
            client_uci_id="28216_9051",
        )
        joined = " | ".join(mock_router._exec_calls)
        assert "uci set route_policy.fvpn_rule_ovpn_9051.name='OVPN Group'" in joined
        assert "uci set ovpnclient.28216_9051.name='OVPN Group'" in joined
        assert "uci commit route_policy" in joined
        assert "uci commit ovpnclient" in joined
        assert "uci commit wireguard" not in joined

    def test_rename_profile_escapes_single_quote(self, mock_router):
        """Names with single quotes should not break the uci set command."""
        mock_router.rename_profile(
            rule_name="fvpn_rule_9001",
            new_name="Bob's Phone",
            peer_id="9001",
        )
        joined = " | ".join(mock_router._exec_calls)
        # The single quote should be escaped as '\''  inside the surrounding quotes
        assert "Bob'\\''s Phone" in joined

    def test_get_device_assignments_parses_router_output(self, mock_router):
        """Stage 5: get_device_assignments returns {mac: rule_name} from router."""
        mock_router._exec_responses["uci show route_policy"] = (
            "route_policy.fvpn_rule_9001=rule\n"
            "route_policy.fvpn_rule_9001.from_mac='aa:bb:cc:dd:ee:ff' 'cc:dd:ee:ff:00:11'\n"
            "route_policy.fvpn_rule_9001.peer_id='9001'\n"
            "route_policy.fvpn_rule_9001.via_type='wireguard'\n"
            "route_policy.fvpn_rule_9001.group_id='1957'\n"
            "route_policy.fvpn_rule_9002=rule\n"
            "route_policy.fvpn_rule_9002.from_mac='11:22:33:44:55:66'\n"
            "route_policy.fvpn_rule_9002.peer_id='9002'\n"
            "route_policy.fvpn_rule_9002.via_type='wireguard'\n"
            "route_policy.fvpn_rule_9002.group_id='1957'"
        )
        out = mock_router.get_device_assignments()
        assert out["aa:bb:cc:dd:ee:ff"] == "fvpn_rule_9001"
        assert out["cc:dd:ee:ff:00:11"] == "fvpn_rule_9001"
        assert out["11:22:33:44:55:66"] == "fvpn_rule_9002"
        assert len(out) == 3

    def test_get_device_assignments_empty(self, mock_router):
        out = mock_router.get_device_assignments()
        assert out == {}

    def test_get_device_assignments_recognizes_anonymous_section(self, mock_router):
        """Stage 5 fix: GL.iNet UI may anonymize sections to @rule[N]."""
        mock_router._exec_responses["uci show route_policy"] = (
            "route_policy.@rule[4]=rule\n"
            "route_policy.@rule[4].from_mac='aa:bb:cc:dd:ee:ff'\n"
            "route_policy.@rule[4].peer_id='9001'\n"
            "route_policy.@rule[4].via_type='wireguard'\n"
            "route_policy.@rule[4].group_id='1957'"
        )
        out = mock_router.get_device_assignments()
        assert out["aa:bb:cc:dd:ee:ff"] == "@rule[4]"

    def test_get_device_assignments_ignores_non_fvpn_groups(self, mock_router):
        mock_router._exec_responses["uci show route_policy"] = (
            "route_policy.@rule[0]=rule\n"
            "route_policy.@rule[0].from_mac='aa:bb:cc:dd:ee:ff'\n"
            "route_policy.@rule[0].group_id='9999'\n"
            "route_policy.fvpn_rule_9001=rule\n"
            "route_policy.fvpn_rule_9001.from_mac='11:22:33:44:55:66'\n"
            "route_policy.fvpn_rule_9001.peer_id='9001'\n"
            "route_policy.fvpn_rule_9001.via_type='wireguard'\n"
            "route_policy.fvpn_rule_9001.group_id='1957'"
        )
        out = mock_router.get_device_assignments()
        assert "aa:bb:cc:dd:ee:ff" not in out
        assert out["11:22:33:44:55:66"] == "fvpn_rule_9001"

    def test_get_flint_vpn_rules_recognizes_anonymous_section(self, mock_router):
        """Stage 5 fix: anonymous @rule[N] sections matching FlintVPN groups are picked up."""
        mock_router._exec_responses["uci show route_policy"] = (
            "route_policy.@rule[4]=rule\n"
            "route_policy.@rule[4].name='Trusted'\n"
            "route_policy.@rule[4].peer_id='9001'\n"
            "route_policy.@rule[4].via_type='wireguard'\n"
            "route_policy.@rule[4].group_id='1957'\n"
            "route_policy.@rule[4].killswitch='0'\n"
            "route_policy.@rule[4].from_mac='aa:bb:cc:dd:ee:ff'"
        )
        rules = mock_router.get_flint_vpn_rules()
        assert len(rules) == 1
        assert rules[0]["rule_name"] == "@rule[4]"
        assert rules[0]["name"] == "Trusted"
        assert rules[0]["peer_id"] == "9001"
        assert rules[0]["killswitch"] == "0"

    def test_get_flint_vpn_rules_includes_named_and_anonymous(self, mock_router):
        mock_router._exec_responses["uci show route_policy"] = (
            "route_policy.fvpn_rule_9002=rule\n"
            "route_policy.fvpn_rule_9002.name='Streaming'\n"
            "route_policy.fvpn_rule_9002.peer_id='9002'\n"
            "route_policy.fvpn_rule_9002.via_type='wireguard'\n"
            "route_policy.fvpn_rule_9002.group_id='1957'\n"
            "route_policy.@rule[4]=rule\n"
            "route_policy.@rule[4].name='Trusted'\n"
            "route_policy.@rule[4].peer_id='9001'\n"
            "route_policy.@rule[4].via_type='wireguard'\n"
            "route_policy.@rule[4].group_id='1957'"
        )
        rules = mock_router.get_flint_vpn_rules()
        names = sorted(r["name"] for r in rules)
        assert names == ["Streaming", "Trusted"]

    def test_heal_anonymous_rule_section_renames_via_uci(self, mock_router):
        mock_router.heal_anonymous_rule_section("@rule[4]", "fvpn_rule_9001")
        joined = " | ".join(mock_router._exec_calls)
        assert "uci rename route_policy.@rule[4]=fvpn_rule_9001" in joined
        assert "uci commit route_policy" in joined

    def test_heal_anonymous_rule_section_skips_already_named(self, mock_router):
        mock_router.heal_anonymous_rule_section("fvpn_rule_9001", "fvpn_rule_9001")
        # No exec calls — already named
        assert not any("rename" in c for c in mock_router._exec_calls)


# ── Unit Tests: OpenVPN ────────────────────────────────────────────────────────

class TestGetRuleInterface:
    def test_returns_wgclient(self, mock_router):
        mock_router._exec_responses["uci get"] = "wgclient1"
        assert mock_router.get_rule_interface("fvpn_rule_9001") == "wgclient1"

    def test_returns_ovpnclient(self, mock_router):
        mock_router._exec_responses["uci get"] = "ovpnclient1"
        assert mock_router.get_rule_interface("fvpn_rule_ovpn_9001") == "ovpnclient1"

    def test_returns_none_for_novpn(self, mock_router):
        mock_router._exec_responses["uci get"] = "novpn"
        assert mock_router.get_rule_interface("some_rule") is None

    def test_returns_none_for_empty(self, mock_router):
        mock_router._exec_responses["uci get"] = ""
        assert mock_router.get_rule_interface("some_rule") is None


class TestTunnelStatusOpenVPN:
    def test_ovpn_up_shows_green(self, mock_router):
        mock_router._exec_responses["enabled"] = "1"
        mock_router._exec_responses["uci get"] = "ovpnclient1"
        mock_router._exec_responses["ifstatus"] = "true"
        health = mock_router.get_tunnel_health("fvpn_rule_ovpn_9001")
        assert health == "green"

    def test_ovpn_down_shows_red(self, mock_router):
        mock_router._exec_responses["enabled"] = "1"
        mock_router._exec_responses["uci get"] = "ovpnclient1"
        mock_router._exec_responses["ifstatus"] = "false"
        mock_router._exec_responses["grep"] = ""  # no openvpn process
        health = mock_router.get_tunnel_health("fvpn_rule_ovpn_9001")
        assert health == "red"

    def test_ovpn_connecting(self, mock_router):
        mock_router._exec_responses["enabled"] = "1"
        mock_router._exec_responses["uci get"] = "ovpnclient1"
        mock_router._exec_responses["ifstatus"] = "false"
        mock_router._exec_responses["grep"] = "10265 root openvpn"  # process running
        health = mock_router.get_tunnel_health("fvpn_rule_ovpn_9001")
        assert health == "connecting"

    def test_disabled_rule_shows_red(self, mock_router):
        mock_router._exec_responses["enabled"] = "0"
        health = mock_router.get_tunnel_health("fvpn_rule_ovpn_9001")
        assert health == "red"


# LAN access tests moved to test_lan_sync.py for the new UCI execution layer.


# ── Unit Tests: ID Range Non-Overlap ─────────────────────────────────────────

class TestIdRanges:
    """WireGuard peer IDs and OpenVPN client IDs must not overlap.

    The router's setup_instance_via.lua matches instances by peer_id without
    checking protocol. Overlapping IDs cause WG rules to bind to OVPN interfaces.
    """

    def test_wg_ids_start_at_9001(self, mock_router):
        mock_router._exec_responses["uci show wireguard"] = ""
        pid = mock_router._next_peer_id()
        assert pid == 9001

    def test_ovpn_ids_start_at_9051(self, mock_router):
        mock_router._exec_responses["uci show ovpnclient"] = ""
        cid = mock_router._next_ovpn_client_id()
        assert cid == 9051

    def test_wg_and_ovpn_ranges_do_not_overlap(self, mock_router):
        mock_router._exec_responses["uci show wireguard"] = ""
        mock_router._exec_responses["uci show ovpnclient"] = ""
        wg_ids = set()
        ovpn_ids = set()
        # Exhaust WG range
        for i in range(50):
            mock_router._exec_responses["uci show wireguard"] = "\n".join(
                f"wireguard.peer_{pid}=peers" for pid in sorted(wg_ids)
            )
            pid = mock_router._next_peer_id()
            wg_ids.add(pid)
        # Exhaust OVPN range
        for i in range(49):
            mock_router._exec_responses["uci show ovpnclient"] = "\n".join(
                f"ovpnclient.28216_{cid}=clients" for cid in sorted(ovpn_ids)
            )
            cid = mock_router._next_ovpn_client_id()
            ovpn_ids.add(cid)
        assert wg_ids.isdisjoint(ovpn_ids), f"Overlap: {wg_ids & ovpn_ids}"

    def test_wg_skips_used_ids(self, mock_router):
        # The exec command pipes through sed/grep, so mock returns processed output (just IDs)
        mock_router._exec_responses["=peers"] = "9001\n9002"
        pid = mock_router._next_peer_id()
        assert pid == 9003

    def test_ovpn_skips_used_ids(self, mock_router):
        # The exec command pipes through sed, so mock returns "groupid_clientid" lines
        mock_router._exec_responses["=clients"] = "28216_9051"
        cid = mock_router._next_ovpn_client_id()
        assert cid == 9052

    def test_wg_raises_when_exhausted(self, mock_router):
        mock_router._exec_responses["=peers"] = "\n".join(
            str(i) for i in range(9001, 9051)
        )
        with pytest.raises(RuntimeError, match="No available peer IDs"):
            mock_router._next_peer_id()

    def test_ovpn_raises_when_exhausted(self, mock_router):
        mock_router._exec_responses["=clients"] = "\n".join(
            f"28216_{i}" for i in range(9051, 9100)
        )
        with pytest.raises(RuntimeError, match="No available OpenVPN client IDs"):
            mock_router._next_ovpn_client_id()


# ── Integration Tests ─────────────────────────────────────────────────────────

@pytest.mark.integration
class TestRouterAPIIntegration:
    @pytest.fixture
    def router(self):
        r = RouterAPI("192.168.8.1", key_filename="/home/armaaar/.ssh/id_ed25519")
        try:
            r.connect()
        except Exception:
            pytest.skip("Cannot connect to router at 192.168.8.1")
        yield r
        r.disconnect()

    def test_connection(self, router):
        result = router.exec("echo ok")
        assert result == "ok"

    def test_get_dhcp_leases(self, router):
        leases = router.get_dhcp_leases()
        assert isinstance(leases, list)
        assert len(leases) >= 1
        assert all("mac" in l and "ip" in l for l in leases)

    def test_wireguard_lifecycle(self, router):
        """Create peer + rule, verify, then delete. Does NOT connect."""
        result = router.upload_wireguard_config(
            profile_name="integration_test",
            private_key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            public_key="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
            endpoint="1.2.3.4:51820",
        )
        assert "peer_id" in result
        assert "rule_name" in result

        try:
            peers = router.get_flint_vpn_peers()
            assert any(p["peer_id"] == result["peer_id"] for p in peers)

            rules = router.get_flint_vpn_rules()
            assert any(r["rule_name"] == result["rule_name"] for r in rules)

            # Verify rule has correct via_type for vpn-client compatibility
            via_type = router.exec(
                f"uci get route_policy.{result['rule_name']}.via_type 2>/dev/null"
            ).strip()
            assert via_type == "wireguard"

            peer_id_val = router.exec(
                f"uci get route_policy.{result['rule_name']}.peer_id 2>/dev/null"
            ).strip()
            assert peer_id_val == result["peer_num"]

        finally:
            router.delete_wireguard_config(result["peer_id"], result["rule_name"])

        peers = router.get_flint_vpn_peers()
        assert not any(p["peer_id"] == result["peer_id"] for p in peers)

    def test_tunnel_status_no_rule(self, router):
        status = router.get_tunnel_status("nonexistent_rule")
        assert status["up"] is False
