"""Tests for RouterLanAccess facade."""

from unittest.mock import MagicMock, patch

import pytest

from router.facades.lan_access import (
    RouterLanAccess,
    _band_from_device,
    _count_devices_per_subnet,
)


@pytest.fixture
def lan(uci, iptables, service_ctl, ssh):
    return RouterLanAccess(uci, iptables, service_ctl, ssh)


class TestGetNetworks:
    WIRELESS_OUT = (
        "wireless.mt798611=wifi-device\n"
        "wireless.mt798611.band='2g'\n"
        "wireless.default_2g=wifi-iface\n"
        "wireless.default_2g.device='mt798611'\n"
        "wireless.default_2g.network='lan'\n"
        "wireless.default_2g.mode='ap'\n"
        "wireless.default_2g.ssid='MyWiFi'\n"
        "wireless.default_2g.ifname='ra0'\n"
        "wireless.default_2g.isolate='0'\n"
        "wireless.default_2g.disabled='0'\n"
        "wireless.default_2g.encryption='psk2'\n"
        "wireless.default_2g.key='mypass'\n"
        "wireless.default_2g.hidden='0'\n"
    )
    NETWORK_OUT = (
        "network.lan=interface\n"
        "network.lan.proto='static'\n"
        "network.lan.ipaddr='192.168.8.1'\n"
        "network.lan.netmask='255.255.255.0'\n"
        "network.lan.device='br-lan'\n"
    )
    FIREWALL_OUT = (
        "firewall.zone_lan=zone\n"
        "firewall.zone_lan.name='lan'\n"
        "firewall.zone_lan.network='lan'\n"
    )

    def test_discovers_networks(self, lan, ssh):
        ssh.exec.side_effect = [
            f"{self.WIRELESS_OUT}===SPLIT==={self.NETWORK_OUT}===SPLIT==={self.FIREWALL_OUT}",
            "",  # DHCP leases
        ]
        networks = lan.get_networks()
        assert len(networks) == 1
        assert networks[0]["id"] == "lan"
        assert networks[0]["subnet"] == "192.168.8.0/24"
        assert len(networks[0]["ssids"]) == 1
        assert networks[0]["ssids"][0]["name"] == "MyWiFi"

    def test_skips_wan_and_vpn_zones(self, lan, ssh):
        firewall = (
            "firewall.zone_wan=zone\n"
            "firewall.zone_wan.name='wan'\n"
            "firewall.zone_wgclient1=zone\n"
            "firewall.zone_wgclient1.name='wgclient1'\n"
        )
        ssh.exec.side_effect = [
            f"===SPLIT===\n===SPLIT==={firewall}",
            "",
        ]
        networks = lan.get_networks()
        assert len(networks) == 0


class TestGetZoneForwardings:
    def test_returns_lan_forwardings(self, lan, ssh):
        ssh.exec.return_value = (
            "firewall.fwd_guest_lan=forwarding\n"
            "firewall.fwd_guest_lan.src='guest'\n"
            "firewall.fwd_guest_lan.dest='lan'\n"
            "firewall.fwd_wan=forwarding\n"
            "firewall.fwd_wan.src='lan'\n"
            "firewall.fwd_wan.dest='wan'\n"
        )
        fwds = lan.get_zone_forwardings()
        # Only guest→lan, wan is skipped
        assert len(fwds) == 1
        assert fwds[0]["src"] == "guest"
        assert fwds[0]["dest"] == "lan"


class TestSetZoneForwarding:
    def test_creates_forwarding(self, lan, ssh, service_ctl):
        with patch.object(lan, "get_zone_forwardings", return_value=[]):
            lan.set_zone_forwarding("guest", "lan", True)
        # Should exec uci add forwarding
        assert any("uci add firewall forwarding" in str(c) for c in ssh.exec.call_args_list)
        service_ctl.reload.assert_called_with("firewall")

    def test_removes_forwarding(self, lan, uci, service_ctl):
        with patch.object(lan, "get_zone_forwardings", return_value=[
            {"src": "guest", "dest": "lan", "section": "fwd_guest_lan"}
        ]):
            lan.set_zone_forwarding("guest", "lan", False)
        uci.delete.assert_called_once_with("firewall.fwd_guest_lan")

    def test_rejects_invalid_zone_name(self, lan):
        with pytest.raises(ValueError, match="Invalid zone name"):
            lan.set_zone_forwarding("bad;name", "lan", True)

    def test_noop_when_already_allowed(self, lan, ssh):
        with patch.object(lan, "get_zone_forwardings", return_value=[
            {"src": "guest", "dest": "lan", "section": "fwd_guest_lan"}
        ]):
            lan.set_zone_forwarding("guest", "lan", True)
        ssh.exec.assert_not_called()


class TestSetWifiIsolation:
    def test_enables_isolation(self, lan, uci, service_ctl):
        lan.set_wifi_isolation(["default_2g", "default_5g"], True)
        assert uci.set.call_count == 2
        uci.commit.assert_called_once_with("wireless")
        service_ctl.wifi_reload.assert_called_once()

    def test_empty_sections_is_noop(self, lan, uci, service_ctl):
        lan.set_wifi_isolation([], True)
        uci.set.assert_not_called()
        service_ctl.wifi_reload.assert_not_called()

    def test_rejects_invalid_section(self, lan):
        with pytest.raises(ValueError, match="Invalid wifi section"):
            lan.set_wifi_isolation(["bad;section"], True)


class TestDeviceExceptions:
    def test_apply_exceptions(self, lan, iptables):
        exceptions = [
            {"from_ip": "192.168.8.10", "to_ip": "192.168.9.20", "direction": "both"},
        ]
        with patch.object(lan, "_write_firewall_include"):
            lan.apply_device_exceptions(exceptions)
        iptables.ensure_chain.assert_called_once()
        iptables.flush_chain.assert_called_once()
        # Both directions: 2 append calls
        assert iptables.append.call_count == 2

    def test_skips_invalid_ips(self, lan, iptables):
        exceptions = [
            {"from_ip": "192.168.8.10; rm -rf /", "to_ip": "192.168.9.20"},
        ]
        with patch.object(lan, "_write_firewall_include"):
            lan.apply_device_exceptions(exceptions)
        # No rules appended for invalid IPs
        iptables.append.assert_not_called()

    def test_cleanup_exceptions(self, lan, iptables, ssh, uci):
        lan.cleanup_exceptions()
        iptables.delete_chain.assert_called_once()
        uci.delete.assert_called_once_with("firewall.fvpn_lan_access")


class TestCreateNetwork:
    def test_creates_full_infrastructure(self, lan, uci, ssh, service_ctl):
        ssh.exec.side_effect = [
            "",             # _next_ip6hint (uci show network | grep ip6hint)
            "BssidNum=2",  # _get_bssid_num
            "",             # sed (update BssidNum)
            "",             # sed (update BssidNum)
            "",             # ifup
        ]
        with patch.object(lan, "_reload_wifi_driver"):
            lan.create_network("testnet", "TestSSID", "password123", "192.168.10.1")

        uci.batch_sections.assert_called_once()
        sections = uci.batch_sections.call_args[0][0]
        # Should create: 2x wireless, 1x network, 1x zone, 2x rules (dhcp+dns), 1x forwarding, 1x dhcp
        assert len(sections) == 8

    def test_rejects_invalid_zone_id(self, lan):
        with pytest.raises(ValueError, match="Invalid zone ID"):
            lan.create_network("bad;id", "SSID", "pass", "192.168.10.1")

    def test_rejects_invalid_subnet_ip(self, lan):
        with pytest.raises(ValueError, match="Invalid subnet IP"):
            lan.create_network("testnet", "SSID", "pass", "not-an-ip")


class TestDeleteNetwork:
    def test_refuses_builtin_networks(self, lan):
        with pytest.raises(ValueError, match="Cannot delete"):
            lan.delete_network("lan")
        with pytest.raises(ValueError, match="Cannot delete"):
            lan.delete_network("guest")

    def test_deletes_matching_sections(self, lan, ssh):
        ssh.exec.side_effect = [
            "wireless.fvpn_testnet_2g=wifi-iface\n",  # wireless
            "network.fvpn_testnet=interface\n",         # network
            "firewall.fvpn_testnet_zone=zone\n",        # firewall
            "dhcp.fvpn_testnet=dhcp\n",                 # dhcp
            "BssidNum=3",                                # bssid num
            "",                                          # combined delete+sed command
        ]
        with patch.object(lan, "_reload_wifi_driver"):
            lan.delete_network("testnet")

    def test_noop_when_no_matching_sections(self, lan, ssh):
        ssh.exec.side_effect = [
            "",  # wireless (empty)
            "",  # network (empty)
            "",  # firewall (empty)
            "",  # dhcp (empty)
        ]
        with patch.object(lan, "_reload_wifi_driver") as mock_reload:
            lan.delete_network("nonexistent")
        mock_reload.assert_not_called()


class TestBandFromDevice:
    def test_2g_by_band_field(self):
        wireless = {"mt798611": {"band": "2g"}}
        assert _band_from_device("mt798611", wireless) == "2.4G"

    def test_5g_by_band_field(self):
        wireless = {"mt798612": {"band": "5g"}}
        assert _band_from_device("mt798612", wireless) == "5G"

    def test_2g_by_device_name(self):
        assert _band_from_device("mt798611", {}) == "2.4G"

    def test_5g_by_device_name(self):
        assert _band_from_device("mt798612", {}) == "5G"

    def test_unknown(self):
        assert _band_from_device("unknown", {}) == ""


class TestCountDevicesPerSubnet:
    def test_counts_correctly(self):
        leases = (
            "1712345678 aa:bb:cc:dd:ee:ff 192.168.8.10 phone\n"
            "1712345679 11:22:33:44:55:66 192.168.8.11 laptop\n"
            "1712345680 77:88:99:00:11:22 192.168.9.10 guest\n"
        )
        net_info = {
            "lan": {"subnet": "192.168.8.0/24"},
            "guest": {"subnet": "192.168.9.0/24"},
        }
        counts = _count_devices_per_subnet(leases, net_info)
        assert counts["192.168.8.0/24"] == 2
        assert counts["192.168.9.0/24"] == 1

    def test_empty_leases(self):
        counts = _count_devices_per_subnet("", {"lan": {"subnet": "192.168.8.0/24"}})
        assert counts["192.168.8.0/24"] == 0


# ── IPv6 Tests ───────────────────────────────────────────────────────────


@pytest.fixture
def ip6tables_mock():
    m = MagicMock()
    m.ensure_chain.return_value = None
    m.flush_chain.return_value = None
    m.append.return_value = None
    m.insert_if_absent.return_value = None
    m.delete_chain.return_value = None
    return m


@pytest.fixture
def lan_v6(uci, iptables, service_ctl, ssh, ip6tables_mock):
    return RouterLanAccess(uci, iptables, service_ctl, ssh, ip6tables=ip6tables_mock)


class TestApplyDeviceExceptionsIPv6:
    def test_creates_chain_in_both_stacks(self, lan_v6, iptables, ip6tables_mock):
        lan_v6.apply_device_exceptions([{
            "from_ip": "192.168.8.100",
            "to_ip": "192.168.9.50",
            "direction": "both",
        }])
        iptables.ensure_chain.assert_called_with("filter", "fvpn_lan_exc")
        ip6tables_mock.ensure_chain.assert_called_with("filter", "fvpn_lan_exc")

    def test_ipv4_rule_only_in_iptables(self, lan_v6, iptables, ip6tables_mock):
        lan_v6.apply_device_exceptions([{
            "from_ip": "192.168.8.100",
            "to_ip": "192.168.9.50",
            "direction": "outbound",
        }])
        # IPv4 address should appear in iptables
        ipt_calls = [str(c) for c in iptables.append.call_args_list]
        assert any("192.168.8.100" in c for c in ipt_calls)
        # IPv4 address should NOT appear in ip6tables
        ip6_calls = [str(c) for c in ip6tables_mock.append.call_args_list]
        assert not any("192.168.8.100" in c for c in ip6_calls)

    def test_ipv6_rule_only_in_ip6tables(self, lan_v6, iptables, ip6tables_mock):
        lan_v6.apply_device_exceptions([{
            "from_ip": "2001:db8::1",
            "to_ip": "2001:db8::2",
            "direction": "outbound",
        }])
        # IPv6 address should appear in ip6tables
        ip6_calls = [str(c) for c in ip6tables_mock.append.call_args_list]
        assert any("2001:db8::1" in c for c in ip6_calls)
        # IPv6 address should NOT appear in iptables
        ipt_calls = [str(c) for c in iptables.append.call_args_list]
        assert not any("2001:db8::1" in c for c in ipt_calls)


class TestCleanupExceptionsIPv6:
    def test_cleans_both_stacks(self, lan_v6, iptables, ip6tables_mock):
        lan_v6.cleanup_exceptions()
        iptables.delete_chain.assert_called_once()
        ip6tables_mock.delete_chain.assert_called_once()


class TestWriteFirewallIncludeIPv6:
    def test_includes_ip6tables_commands(self, lan_v6, ssh):
        lan_v6._write_firewall_include([{
            "from_ip": "192.168.8.100",
            "to_ip": "192.168.9.50",
            "direction": "both",
        }])
        script = ssh.write_file.call_args[0][1]
        assert "iptables -N fvpn_lan_exc" in script
        assert "ip6tables -N fvpn_lan_exc" in script
        assert "ip6tables -C forwarding_rule" in script


class TestSetIpv6:
    def test_enable_sets_uci_fields(self, lan, uci, ssh, service_ctl):
        ssh.exec.return_value = ""  # No existing ip6hints
        lan.set_ipv6("fvpn_iot", True)
        uci.set.assert_any_call("network.fvpn_iot.ip6assign", "64")
        uci.set.assert_any_call("network.fvpn_iot.ip6ifaceid", "::1")
        uci.set.assert_any_call("dhcp.fvpn_iot.dhcpv6", "server")
        uci.set.assert_any_call("dhcp.fvpn_iot.ra", "server")
        uci.commit.assert_called_once_with("network", "dhcp")
        service_ctl.reload.assert_any_call("dnsmasq")
        service_ctl.reload.assert_any_call("firewall")

    def test_disable_removes_uci_fields(self, lan, uci, ssh, service_ctl):
        lan.set_ipv6("fvpn_iot", False)
        uci.delete.assert_any_call("network.fvpn_iot.ip6assign")
        uci.delete.assert_any_call("network.fvpn_iot.ip6hint")
        uci.set.assert_any_call("dhcp.fvpn_iot.dhcpv6", "disabled")
        uci.set.assert_any_call("dhcp.fvpn_iot.ra", "disabled")

    def test_rejects_invalid_section_name(self, lan):
        with pytest.raises(ValueError, match="Invalid"):
            lan.set_ipv6("../etc/passwd", True)


class TestNextIp6Hint:
    def test_skips_used_hints(self, lan, ssh):
        ssh.exec.return_value = (
            "network.lan.ip6hint='0000'\n"
            "network.guest.ip6hint='0001'\n"
        )
        hint = lan._next_ip6hint()
        assert hint == "0002"

    def test_first_hint_when_none_used(self, lan, ssh):
        ssh.exec.return_value = ""
        hint = lan._next_ip6hint()
        assert hint == "0001"


class TestGetNetworksIpv6Field:
    def test_includes_ipv6_enabled(self, lan, ssh, uci):
        # Simulate UCI output with ip6assign on LAN but not IoT
        ssh.exec.return_value = (
            # Wireless
            "wireless.lan_2g=wifi-iface\n"
            "wireless.lan_2g.device='mt798611'\n"
            "wireless.lan_2g.network='lan'\n"
            "wireless.lan_2g.ssid='TestWiFi'\n"
            "wireless.lan_2g.mode='ap'\n"
            "===SPLIT===\n"
            # Network
            "network.lan=interface\n"
            "network.lan.proto='static'\n"
            "network.lan.ipaddr='192.168.8.1'\n"
            "network.lan.netmask='255.255.255.0'\n"
            "network.lan.ip6assign='64'\n"
            "===SPLIT===\n"
            # Firewall
            "firewall.lan_zone=zone\n"
            "firewall.lan_zone.name='lan'\n"
            "firewall.lan_zone.network='lan'\n"
        )
        networks = lan.get_networks()
        assert len(networks) == 1
        assert networks[0]["ipv6_enabled"] is True
