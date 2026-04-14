"""Tests for RouterTunnel facade."""

from unittest.mock import MagicMock, patch

import pytest

from consts import HEALTH_AMBER, HEALTH_CONNECTING, HEALTH_GREEN, HEALTH_RED
from router.facades.tunnel import RouterTunnel


@pytest.fixture
def tunnel(uci, service_ctl, ssh):
    return RouterTunnel(uci, service_ctl, ssh)


class TestBringTunnelUp:
    def test_enables_rule_and_restarts(self, tunnel, uci, service_ctl):
        uci.get.return_value = "1"  # tunnel_id exists
        tunnel.bring_tunnel_up("fvpn_rule_9001")
        uci.set.assert_called_once_with("route_policy.fvpn_rule_9001.enabled", "1")
        uci.commit.assert_called_once_with("route_policy")
        service_ctl.restart.assert_called_once_with("vpn-client")

    def test_raises_when_rule_missing(self, tunnel, uci):
        uci.get.return_value = "MISSING"
        with pytest.raises(RuntimeError, match="does not exist"):
            tunnel.bring_tunnel_up("fvpn_rule_9001")


class TestBringTunnelDown:
    def test_disables_kill_switch_then_rule_then_restores(self, tunnel, uci, service_ctl):
        tunnel.bring_tunnel_down("fvpn_rule_9001")

        # First multi call: disable kill switch + rule
        first_multi = uci.multi.call_args_list[0][0][0]
        assert any("killswitch='0'" in c for c in first_multi)
        assert any("enabled='0'" in c for c in first_multi)

        service_ctl.restart.assert_called_once_with("vpn-client")

        # Second multi call: restore kill switch
        second_multi = uci.multi.call_args_list[1][0][0]
        assert any("killswitch='1'" in c for c in second_multi)


class TestGetRuleInterface:
    def test_returns_wg_interface(self, tunnel, uci):
        uci.get.return_value = "wgclient1"
        assert tunnel.get_rule_interface("fvpn_rule_9001") == "wgclient1"

    def test_returns_ovpn_interface(self, tunnel, uci):
        uci.get.return_value = "ovpnclient1"
        assert tunnel.get_rule_interface("fvpn_rule_9001") == "ovpnclient1"

    def test_returns_none_for_empty(self, tunnel, uci):
        uci.get.return_value = ""
        assert tunnel.get_rule_interface("fvpn_rule_9001") is None

    def test_returns_none_for_non_vpn_interface(self, tunnel, uci):
        uci.get.return_value = "eth0"
        assert tunnel.get_rule_interface("fvpn_rule_9001") is None


class TestGetTunnelStatus:
    def test_disabled_rule(self, tunnel, uci):
        uci.get.return_value = "0"
        status = tunnel.get_tunnel_status("fvpn_rule_9001")
        assert not status["up"]
        assert not status["connecting"]

    def test_enabled_but_no_interface_means_connecting(self, tunnel, uci):
        uci.get.side_effect = lambda key, default="": {
            "route_policy.fvpn_rule_9001.enabled": "1",
            "route_policy.fvpn_rule_9001.via": "",
        }.get(key, default)
        status = tunnel.get_tunnel_status("fvpn_rule_9001")
        assert status["connecting"]
        assert not status["up"]

    def test_wg_interface_up_with_handshake(self, tunnel, uci, ssh):
        uci.get.side_effect = lambda key, default="": {
            "route_policy.fvpn_rule_9001.enabled": "1",
            "route_policy.fvpn_rule_9001.via": "wgclient1",
        }.get(key, default)
        ssh.exec.side_effect = lambda cmd, **kw: (
            "true" if "ifstatus" in cmd else ""
        )
        with patch("router.tools.wg_show.parse_handshake_age", return_value=60), \
             patch("router.tools.wg_show.parse_transfer", return_value=(1000, 2000)):
            status = tunnel.get_tunnel_status("fvpn_rule_9001")
        assert status["up"]
        assert status["interface"] == "wgclient1"
        assert status["handshake_seconds_ago"] == 60
        assert status["rx_bytes"] == 1000

    def test_wg_interface_down_connecting_state(self, tunnel, uci, ssh):
        uci.get.side_effect = lambda key, default="": {
            "route_policy.fvpn_rule_9001.enabled": "1",
            "route_policy.fvpn_rule_9001.via": "wgclient1",
        }.get(key, default)
        ssh.exec.side_effect = lambda cmd, **kw: (
            "false" if "ifstatus" in cmd
            else "connecting" if "wireguard" in cmd
            else ""
        )
        status = tunnel.get_tunnel_status("fvpn_rule_9001")
        assert status["connecting"]
        assert not status["up"]

    def test_ovpn_interface_up(self, tunnel, uci, ssh):
        uci.get.side_effect = lambda key, default="": {
            "route_policy.fvpn_rule_9001.enabled": "1",
            "route_policy.fvpn_rule_9001.via": "ovpnclient1",
        }.get(key, default)
        ssh.exec.return_value = "true"
        status = tunnel.get_tunnel_status("fvpn_rule_9001")
        assert status["up"]
        assert status["handshake_seconds_ago"] == 0


class TestGetTunnelHealth:
    def _make_tunnel(self, uci, service_ctl, ssh):
        return RouterTunnel(uci, service_ctl, ssh)

    def test_connecting(self, uci, service_ctl, ssh):
        t = self._make_tunnel(uci, service_ctl, ssh)
        with patch.object(t, "get_tunnel_status", return_value={"up": False, "connecting": True, "handshake_seconds_ago": None}):
            assert t.get_tunnel_health("r") == HEALTH_CONNECTING

    def test_down(self, uci, service_ctl, ssh):
        t = self._make_tunnel(uci, service_ctl, ssh)
        with patch.object(t, "get_tunnel_status", return_value={"up": False, "connecting": False, "handshake_seconds_ago": None}):
            assert t.get_tunnel_health("r") == HEALTH_RED

    def test_green_recent_handshake(self, uci, service_ctl, ssh):
        t = self._make_tunnel(uci, service_ctl, ssh)
        with patch.object(t, "get_tunnel_status", return_value={"up": True, "connecting": False, "handshake_seconds_ago": 30}):
            assert t.get_tunnel_health("r") == HEALTH_GREEN

    def test_amber_stale_handshake(self, uci, service_ctl, ssh):
        t = self._make_tunnel(uci, service_ctl, ssh)
        with patch.object(t, "get_tunnel_status", return_value={"up": True, "connecting": False, "handshake_seconds_ago": 300}):
            assert t.get_tunnel_health("r") == HEALTH_AMBER

    def test_red_very_stale_handshake(self, uci, service_ctl, ssh):
        t = self._make_tunnel(uci, service_ctl, ssh)
        with patch.object(t, "get_tunnel_status", return_value={"up": True, "connecting": False, "handshake_seconds_ago": 700}):
            assert t.get_tunnel_health("r") == HEALTH_RED

    def test_red_no_handshake(self, uci, service_ctl, ssh):
        t = self._make_tunnel(uci, service_ctl, ssh)
        with patch.object(t, "get_tunnel_status", return_value={"up": True, "connecting": False, "handshake_seconds_ago": None}):
            assert t.get_tunnel_health("r") == HEALTH_RED

    def test_green_boundary_180s(self, uci, service_ctl, ssh):
        t = self._make_tunnel(uci, service_ctl, ssh)
        with patch.object(t, "get_tunnel_status", return_value={"up": True, "connecting": False, "handshake_seconds_ago": 180}):
            assert t.get_tunnel_health("r") == HEALTH_GREEN

    def test_amber_boundary_600s(self, uci, service_ctl, ssh):
        t = self._make_tunnel(uci, service_ctl, ssh)
        with patch.object(t, "get_tunnel_status", return_value={"up": True, "connecting": False, "handshake_seconds_ago": 600}):
            assert t.get_tunnel_health("r") == HEALTH_AMBER
