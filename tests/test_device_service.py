"""Tests for DeviceService — device assignment, listing, and caching."""

import time
from unittest.mock import MagicMock, patch

import pytest

from consts import PROFILE_TYPE_VPN, PROFILE_TYPE_NO_VPN, PROTO_WIREGUARD
from services.device_service import DeviceService


def _make_service(router=None):
    if router is None:
        router = MagicMock()
        router.policy.get_flint_vpn_rules.return_value = []
        router.devices.get_device_assignments.return_value = {}
        router.devices.get_dhcp_leases.return_value = []
        router.devices.get_client_details.return_value = {}
    ipset = MagicMock()
    ipset.list_members.return_value = []
    return DeviceService(router, ipset)


class TestResolveAssignments:
    def test_maps_vpn_devices(self):
        svc = _make_service()
        svc._router.policy.get_flint_vpn_rules.return_value = [
            {"rule_name": "fvpn_rule_9001", "via_type": "wireguard", "peer_id": "9001"},
        ]
        svc._router.devices.get_device_assignments.return_value = {
            "aa:bb:cc:dd:ee:ff": "fvpn_rule_9001",
        }
        store_data = {
            "profiles": [{
                "id": "p1", "type": PROFILE_TYPE_VPN,
                "router_info": {"rule_name": "fvpn_rule_9001", "vpn_protocol": "wireguard", "peer_id": "peer_9001"},
            }],
            "device_assignments": {},
        }
        result = svc.resolve_assignments(store_data)
        assert result["aa:bb:cc:dd:ee:ff"] == "p1"

    def test_maps_non_vpn_devices(self):
        svc = _make_service()
        store_data = {
            "profiles": [{"id": "p2", "type": PROFILE_TYPE_NO_VPN}],
            "device_assignments": {"aa:bb:cc:dd:ee:ff": "p2"},
        }
        result = svc.resolve_assignments(store_data)
        assert result["aa:bb:cc:dd:ee:ff"] == "p2"

    def test_ignores_none_assignments(self):
        svc = _make_service()
        store_data = {
            "profiles": [{"id": "p2", "type": PROFILE_TYPE_NO_VPN}],
            "device_assignments": {"aa:bb:cc:dd:ee:ff": None},
        }
        result = svc.resolve_assignments(store_data)
        assert "aa:bb:cc:dd:ee:ff" not in result

    def test_empty_data(self):
        svc = _make_service()
        result = svc.resolve_assignments({"profiles": [], "device_assignments": {}})
        assert result == {}


class TestBuildDevicesLive:
    def test_builds_from_leases(self):
        svc = _make_service()
        svc._router.devices.get_dhcp_leases.return_value = [
            {"mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.8.10", "hostname": "myphone", "expiry": 0},
        ]
        with patch("services.device_service.ps") as mock_ps, \
             patch("services.device_service.build_ip_to_network_map", return_value={}):
            mock_ps.load.return_value = {"profiles": [], "device_assignments": {}}
            devices = svc.build_devices_live()
        assert len(devices) == 1
        assert devices[0]["mac"] == "aa:bb:cc:dd:ee:ff"
        assert devices[0]["ip"] == "192.168.8.10"
        assert devices[0]["display_name"] == "myphone"

    def test_display_name_precedence(self):
        """label > hostname > MAC"""
        svc = _make_service()
        svc._router.devices.get_dhcp_leases.return_value = [
            {"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.8.10", "hostname": "dhcp-name", "expiry": 0},
        ]
        svc._router.devices.get_client_details.return_value = {
            "aa:bb:cc:dd:ee:ff": {"alias": "My Label", "online": True},
        }
        with patch("services.device_service.ps") as mock_ps, \
             patch("services.device_service.build_ip_to_network_map", return_value={}):
            mock_ps.load.return_value = {"profiles": [], "device_assignments": {}}
            devices = svc.build_devices_live()
        assert devices[0]["display_name"] == "My Label"


class TestCaching:
    def test_caches_results(self):
        svc = _make_service()
        with patch.object(svc, "build_devices_live", return_value=[{"mac": "aa:bb:cc:dd:ee:ff"}]) as mock_build:
            result1 = svc.get_devices_cached()
            result2 = svc.get_devices_cached()
        assert mock_build.call_count == 1  # Only called once
        assert result1 == result2

    def test_invalidate_cache(self):
        svc = _make_service()
        mock_build = MagicMock(return_value=[])
        with patch.object(svc, "build_devices_live", mock_build):
            svc.get_devices_cached()
            svc.invalidate_cache()
            svc.get_devices_cached()
        assert mock_build.call_count == 2


class TestAssignDevice:
    def test_assigns_to_non_vpn(self):
        svc = _make_service()
        with patch("services.device_service.ps") as mock_ps:
            mock_ps.validate_mac.return_value = "aa:bb:cc:dd:ee:ff"
            mock_ps.load.return_value = {"profiles": [], "device_assignments": {}}
            mock_ps.get_profile.return_value = {"id": "p1", "name": "Free", "type": PROFILE_TYPE_NO_VPN}
            svc.assign_device("aa:bb:cc:dd:ee:ff", "p1")
        mock_ps.assign_device.assert_called_once_with("aa:bb:cc:dd:ee:ff", "p1")

    def test_unassign_writes_sticky_none(self):
        svc = _make_service()
        with patch("services.device_service.ps") as mock_ps:
            mock_ps.validate_mac.return_value = "aa:bb:cc:dd:ee:ff"
            mock_ps.load.return_value = {"profiles": [], "device_assignments": {}}
            mock_ps.get_profile.return_value = None
            svc.assign_device("aa:bb:cc:dd:ee:ff", None)
        mock_ps.assign_device.assert_called_once_with("aa:bb:cc:dd:ee:ff", None)

    def test_invalidates_cache_after_assign(self):
        svc = _make_service()
        with patch("services.device_service.ps") as mock_ps, \
             patch.object(svc, "invalidate_cache") as mock_inv:
            mock_ps.validate_mac.return_value = "aa:bb:cc:dd:ee:ff"
            mock_ps.load.return_value = {"profiles": [], "device_assignments": {}}
            mock_ps.get_profile.return_value = None
            svc.assign_device("aa:bb:cc:dd:ee:ff", None)
        mock_inv.assert_called_once()
