"""Tests for RouterDevices facade."""

from unittest.mock import MagicMock

import pytest

from router.facades.devices import RouterDevices


@pytest.fixture
def policy_mock():
    m = MagicMock()
    m.get_flint_vpn_rules.return_value = []
    m.from_mac_tokens.return_value = []
    return m


@pytest.fixture
def devices(uci, ipset, iproute, service_ctl, policy_mock, ssh):
    return RouterDevices(uci, ipset, iproute, service_ctl, policy_mock, ssh)


class TestGetDhcpLeases:
    def test_parses_leases(self, devices, ssh):
        ssh.exec.return_value = (
            "1712345678 aa:bb:cc:dd:ee:ff 192.168.8.10 myphone\n"
            "1712345679 11:22:33:44:55:66 192.168.8.11 *\n"
        )
        leases = devices.get_dhcp_leases()
        assert len(leases) == 2
        assert leases[0]["mac"] == "aa:bb:cc:dd:ee:ff"
        assert leases[0]["ip"] == "192.168.8.10"
        assert leases[0]["hostname"] == "myphone"
        assert leases[1]["hostname"] == ""  # * becomes empty

    def test_empty_leases(self, devices, ssh):
        ssh.exec.return_value = ""
        assert devices.get_dhcp_leases() == []


class TestGetClientDetails:
    def test_combines_gl_client_and_arp(self, devices, ssh, iproute):
        ssh.exec.side_effect = [
            '{"clients": {"AA:BB:CC:DD:EE:FF": {"name": "Phone", "online": true, "iface": "2.4G", "rx": 100, "tx": 200, "total_rx": 1000, "total_tx": 2000, "ip": "192.168.8.10"}}}',
            "",  # gl-client config (empty)
            "",  # iwinfo (empty)
        ]
        iproute.neigh_show.return_value = (
            "192.168.8.10 dev br-lan lladdr 11:22:33:44:55:66 REACHABLE\n"
        )
        result = devices.get_client_details()
        assert "aa:bb:cc:dd:ee:ff" in result
        assert result["aa:bb:cc:dd:ee:ff"]["name"] == "Phone"
        assert "11:22:33:44:55:66" in result
        assert result["11:22:33:44:55:66"]["online"] is True

    def test_handles_gl_clients_error(self, devices, ssh, iproute):
        ssh.exec.side_effect = Exception("ubus failed")
        iproute.neigh_show.side_effect = Exception("neigh failed")
        result = devices.get_client_details()
        assert result == {}


class TestGetDeviceAssignments:
    def test_maps_macs_to_rules(self, devices, policy_mock):
        policy_mock.get_flint_vpn_rules.return_value = [
            {"rule_name": "fvpn_rule_9001", "from_mac": "AA:BB:CC:DD:EE:FF 11:22:33:44:55:66"},
            {"rule_name": "fvpn_rule_9002", "from_mac": "77:88:99:00:11:22"},
        ]
        assigns = devices.get_device_assignments()
        assert assigns["aa:bb:cc:dd:ee:ff"] == "fvpn_rule_9001"
        assert assigns["11:22:33:44:55:66"] == "fvpn_rule_9001"
        assert assigns["77:88:99:00:11:22"] == "fvpn_rule_9002"

    def test_handles_list_format_from_mac(self, devices, policy_mock):
        policy_mock.get_flint_vpn_rules.return_value = [
            {"rule_name": "fvpn_rule_9001", "from_mac": ["AA:BB:CC:DD:EE:FF"]},
        ]
        assigns = devices.get_device_assignments()
        assert assigns["aa:bb:cc:dd:ee:ff"] == "fvpn_rule_9001"


class TestSetDeviceVpn:
    def test_adds_mac_to_rule(self, devices, uci, ipset, policy_mock):
        policy_mock.from_mac_tokens.return_value = []
        uci.get.return_value = "src_mac_100"
        devices.set_device_vpn("AA:BB:CC:DD:EE:FF", "fvpn_rule_9001")
        uci.add_list.assert_called_once()
        ipset.add.assert_called_once_with("src_mac_100", "aa:bb:cc:dd:ee:ff")

    def test_skips_duplicate(self, devices, uci, ipset, policy_mock):
        policy_mock.from_mac_tokens.return_value = ["aa:bb:cc:dd:ee:ff"]
        devices.set_device_vpn("AA:BB:CC:DD:EE:FF", "fvpn_rule_9001")
        uci.add_list.assert_not_called()
        ipset.add.assert_not_called()


class TestRemoveDeviceFromVpn:
    def test_removes_mac_case_insensitively(self, devices, uci, ipset, policy_mock):
        policy_mock.from_mac_tokens.return_value = ["AA:BB:CC:DD:EE:FF"]
        uci.get.return_value = "src_mac_100"
        devices.remove_device_from_vpn("aa:bb:cc:dd:ee:ff", "fvpn_rule_9001")
        # Uses exact stored case for del_list
        uci.del_list.assert_called_once_with(
            "route_policy.fvpn_rule_9001.from_mac", "AA:BB:CC:DD:EE:FF"
        )
        # Removes both cases from ipset
        assert ipset.remove.call_count == 2

    def test_noop_when_mac_not_found(self, devices, uci, policy_mock):
        policy_mock.from_mac_tokens.return_value = []
        devices.remove_device_from_vpn("aa:bb:cc:dd:ee:ff", "fvpn_rule_9001")
        uci.del_list.assert_not_called()


class TestRemoveDeviceFromAllVpn:
    def test_removes_from_all_rules_and_ipsets(self, devices, uci, ipset, policy_mock, ssh):
        policy_mock.get_flint_vpn_rules.return_value = [
            {"rule_name": "fvpn_rule_9001"},
            {"rule_name": "fvpn_rule_9002"},
        ]
        policy_mock.from_mac_tokens.side_effect = [
            ["AA:BB:CC:DD:EE:FF"],
            [],
        ]
        uci.get.return_value = "src_mac_100"
        ipset.list_names.return_value = ["src_mac_200"]
        devices.remove_device_from_all_vpn("aa:bb:cc:dd:ee:ff")
        uci.del_list.assert_called_once()
        uci.commit.assert_called_once_with("route_policy")
        # Also removes from proton-wg ipsets
        assert ssh.exec.call_count >= 1


class TestStaticLeases:
    def test_set_static_lease(self, devices, uci, service_ctl):
        devices.set_static_lease("aa:bb:cc:dd:ee:ff", "192.168.8.10", "myphone")
        uci.set_type.assert_called_once()
        assert uci.set.call_count >= 2
        uci.commit.assert_called_once_with("dhcp")
        service_ctl.reload.assert_called_once_with("dnsmasq", background=True)

    def test_remove_static_lease(self, devices, uci, service_ctl):
        devices.remove_static_lease("aa:bb:cc:dd:ee:ff")
        uci.delete.assert_called_once()
        uci.commit.assert_called_once_with("dhcp")
