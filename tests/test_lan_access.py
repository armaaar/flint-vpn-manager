"""Tests for lan_access_service.py and router_lan_access.py."""

from unittest.mock import MagicMock, patch, call
import json
import pytest

from lan_access_service import LanAccessService


def _mock_router():
    """Create a mock RouterAPI with lan_access facade."""
    r = MagicMock()
    r.lan_access = MagicMock()
    r.get_dhcp_leases.return_value = [
        {"mac": "aa:bb:cc:dd:ee:01", "ip": "192.168.8.101", "hostname": "phone"},
        {"mac": "aa:bb:cc:dd:ee:02", "ip": "192.168.8.102", "hostname": "laptop"},
        {"mac": "11:22:33:44:55:01", "ip": "192.168.9.50", "hostname": "bulb"},
    ]
    r.get_client_details.return_value = {
        "aa:bb:cc:dd:ee:01": {"name": "phone", "alias": "Phone", "online": True, "iface": "5G"},
        "aa:bb:cc:dd:ee:02": {"name": "laptop", "alias": "", "online": True, "iface": "5G"},
        "11:22:33:44:55:01": {"name": "bulb", "alias": "Smart Bulb", "online": True, "iface": "2.4G"},
    }
    return r


def _networks():
    return [
        {"id": "lan", "zone": "lan", "ssids": [{"name": "Main", "iface": "rax0", "band": "5G", "section": "wifi5g"}],
         "bridge": "br-lan", "subnet": "192.168.8.0/24", "isolation": False, "enabled": True, "device_count": 2},
        {"id": "guest", "zone": "guest", "ssids": [{"name": "Guest", "iface": "rax1", "band": "5G", "section": "guest5g"}],
         "bridge": "br-guest", "subnet": "192.168.9.0/24", "isolation": True, "enabled": True, "device_count": 1},
    ]


class TestGetLanOverview:
    def test_returns_networks_and_rules(self):
        r = _mock_router()
        r.lan_access.get_networks.return_value = _networks()
        r.lan_access.get_zone_forwardings.return_value = [
            {"src": "lan", "dest": "guest", "section": "@forwarding[1]"},
        ]

        with patch("lan_access_service.sm") as mock_sm:
            mock_sm.get_config.return_value = {"lan_access": {"exceptions": []}}
            svc = LanAccessService(r)
            result = svc.get_lan_overview()

        assert len(result["networks"]) == 2
        rules = result["access_rules"]
        lan_to_guest = next(r for r in rules if r["src_zone"] == "lan" and r["dest_zone"] == "guest")
        guest_to_lan = next(r for r in rules if r["src_zone"] == "guest" and r["dest_zone"] == "lan")
        assert lan_to_guest["allowed"] is True
        assert guest_to_lan["allowed"] is False


class TestGetNetworkDevices:
    def test_filters_by_subnet(self):
        r = _mock_router()
        r.lan_access.get_networks.return_value = _networks()

        svc = LanAccessService(r)
        devices = svc.get_network_devices("lan")
        assert len(devices) == 2
        assert all(d["ip"].startswith("192.168.8.") for d in devices)

    def test_guest_subnet(self):
        r = _mock_router()
        r.lan_access.get_networks.return_value = _networks()

        svc = LanAccessService(r)
        devices = svc.get_network_devices("guest")
        assert len(devices) == 1
        assert devices[0]["ip"] == "192.168.9.50"

    def test_unknown_zone_returns_empty(self):
        r = _mock_router()
        r.lan_access.get_networks.return_value = _networks()

        svc = LanAccessService(r)
        assert svc.get_network_devices("nonexistent") == []


class TestUpdateAccessRules:
    def test_sets_forwardings_on_router(self):
        r = _mock_router()
        rules = [
            {"src_zone": "lan", "dest_zone": "guest", "allowed": True},
            {"src_zone": "guest", "dest_zone": "lan", "allowed": False},
        ]

        with patch("lan_access_service.sm") as mock_sm:
            mock_sm.get_config.return_value = {}
            svc = LanAccessService(r)
            result = svc.update_access_rules(rules)

        assert result["success"]
        r.lan_access.set_zone_forwarding.assert_any_call("lan", "guest", True)
        r.lan_access.set_zone_forwarding.assert_any_call("guest", "lan", False)


class TestSetIsolation:
    def test_toggles_all_ssids(self):
        r = _mock_router()
        r.lan_access.get_networks.return_value = _networks()

        svc = LanAccessService(r)
        result = svc.set_isolation("guest", False)

        assert result["success"]
        r.lan_access.set_wifi_isolation.assert_called_once_with(["guest5g"], False)

    def test_unknown_zone_raises(self):
        r = _mock_router()
        r.lan_access.get_networks.return_value = _networks()

        svc = LanAccessService(r)
        with pytest.raises(ValueError, match="not found"):
            svc.set_isolation("nonexistent", True)


class TestExceptions:
    def test_add_and_remove(self):
        r = _mock_router()

        with patch("lan_access_service.sm") as mock_sm:
            mock_sm.get_config.return_value = {"lan_access": {"exceptions": []}}
            svc = LanAccessService(r)

            result = svc.add_exception({
                "from_ip": "192.168.8.101",
                "to_ip": "192.168.9.50",
                "direction": "both",
                "label": "Phone -> Bulb",
            })

        assert result["success"]
        exc = result["exception"]
        assert exc["from_ip"] == "192.168.8.101"
        assert exc["id"].startswith("exc_")
        r.lan_access.apply_device_exceptions.assert_called_once()

    def test_add_without_ip_raises(self):
        r = _mock_router()

        with patch("lan_access_service.sm") as mock_sm:
            mock_sm.get_config.return_value = {"lan_access": {"exceptions": []}}
            svc = LanAccessService(r)

            with pytest.raises(ValueError, match="required"):
                svc.add_exception({"from_ip": "", "to_ip": "", "direction": "both"})

    def test_remove(self):
        r = _mock_router()
        existing = [{"id": "exc_123", "from_ip": "1.1.1.1", "to_ip": "2.2.2.2", "direction": "both"}]

        with patch("lan_access_service.sm") as mock_sm:
            mock_sm.get_config.return_value = {"lan_access": {"exceptions": existing}}
            svc = LanAccessService(r)
            result = svc.remove_exception("exc_123")

        assert result["success"]
        r.lan_access.apply_device_exceptions.assert_called_once()


class TestReapplyAll:
    def test_reapplies_exceptions(self):
        r = _mock_router()
        existing = [{"id": "exc_1", "from_ip": "1.1.1.1", "to_ip": "2.2.2.2", "direction": "both"}]

        with patch("lan_access_service.sm") as mock_sm:
            mock_sm.get_config.return_value = {"lan_access": {"exceptions": existing}}
            svc = LanAccessService(r)
            svc.reapply_all()

        r.lan_access.apply_device_exceptions.assert_called_once()

    def test_noop_when_no_exceptions(self):
        r = _mock_router()

        with patch("lan_access_service.sm") as mock_sm:
            mock_sm.get_config.return_value = {}
            svc = LanAccessService(r)
            svc.reapply_all()

        r.lan_access.apply_device_exceptions.assert_not_called()
