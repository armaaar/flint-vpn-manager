"""Tests for lan_access_service.py and router_lan_access.py."""

from unittest.mock import MagicMock, patch, call
import json
import pytest

from services.lan_access_service import LanAccessService
from router.facades.lan_access import RouterLanAccess


def _mock_router():
    """Create a mock RouterAPI with lan_access facade."""
    r = MagicMock()
    r.lan_access = MagicMock()
    r.devices.get_dhcp_leases.return_value = [
        {"mac": "aa:bb:cc:dd:ee:01", "ip": "192.168.8.101", "hostname": "phone"},
        {"mac": "aa:bb:cc:dd:ee:02", "ip": "192.168.8.102", "hostname": "laptop"},
        {"mac": "11:22:33:44:55:01", "ip": "192.168.9.50", "hostname": "bulb"},
    ]
    r.devices.get_client_details.return_value = {
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

        with patch("services.lan_access_service.sm") as mock_sm:
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

        with patch("services.lan_access_service.sm") as mock_sm:
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

        with patch("services.lan_access_service.sm") as mock_sm:
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

        with patch("services.lan_access_service.sm") as mock_sm:
            mock_sm.get_config.return_value = {"lan_access": {"exceptions": []}}
            svc = LanAccessService(r)

            with pytest.raises(ValueError, match="required"):
                svc.add_exception({"from_ip": "", "to_ip": "", "direction": "both"})

    def test_remove(self):
        r = _mock_router()
        existing = [{"id": "exc_123", "from_ip": "1.1.1.1", "to_ip": "2.2.2.2", "direction": "both"}]

        with patch("services.lan_access_service.sm") as mock_sm:
            mock_sm.get_config.return_value = {"lan_access": {"exceptions": existing}}
            svc = LanAccessService(r)
            result = svc.remove_exception("exc_123")

        assert result["success"]
        r.lan_access.apply_device_exceptions.assert_called_once()


class TestDeleteNetwork:
    def test_delete_passes_zone_id_to_router(self):
        r = _mock_router()

        with patch("services.lan_access_service.sm") as mock_sm:
            mock_sm.get_config.return_value = {"lan_access": {"rules": [], "exceptions": []}}
            svc = LanAccessService(r)
            result = svc.delete_network("fvpn_iot")

        assert result["success"]
        r.lan_access.delete_network.assert_called_once_with("fvpn_iot")

    def test_delete_cleans_rules_referencing_zone(self):
        r = _mock_router()
        rules = [
            {"src_zone": "fvpn_iot", "dest_zone": "lan", "allowed": False},
            {"src_zone": "lan", "dest_zone": "fvpn_iot", "allowed": True},
            {"src_zone": "lan", "dest_zone": "guest", "allowed": True},
        ]

        with patch("services.lan_access_service.sm") as mock_sm:
            mock_sm.get_config.return_value = {"lan_access": {"rules": rules, "exceptions": []}}
            svc = LanAccessService(r)
            svc.delete_network("fvpn_iot")

        saved = mock_sm.update_config.call_args[1]["lan_access"]
        assert len(saved["rules"]) == 1
        assert saved["rules"][0]["src_zone"] == "lan"
        assert saved["rules"][0]["dest_zone"] == "guest"

    def test_delete_cleans_exceptions_referencing_zone(self):
        r = _mock_router()
        exceptions = [
            {"id": "exc_1", "label": "fvpn_iot -> lan"},
            {"id": "exc_2", "label": "lan -> guest"},
        ]

        with patch("services.lan_access_service.sm") as mock_sm:
            mock_sm.get_config.return_value = {"lan_access": {"rules": [], "exceptions": exceptions}}
            svc = LanAccessService(r)
            svc.delete_network("fvpn_iot")

        saved = mock_sm.update_config.call_args[1]["lan_access"]
        assert len(saved["exceptions"]) == 1
        assert saved["exceptions"][0]["id"] == "exc_2"


class TestReapplyAll:
    def test_reapplies_exceptions(self):
        r = _mock_router()
        existing = [{"id": "exc_1", "from_ip": "1.1.1.1", "to_ip": "2.2.2.2", "direction": "both"}]

        with patch("services.lan_access_service.sm") as mock_sm:
            mock_sm.get_config.return_value = {"lan_access": {"exceptions": existing}}
            svc = LanAccessService(r)
            svc.reapply_all()

        r.lan_access.apply_device_exceptions.assert_called_once()

    def test_noop_when_no_exceptions(self):
        r = _mock_router()

        with patch("services.lan_access_service.sm") as mock_sm:
            mock_sm.get_config.return_value = {}
            svc = LanAccessService(r)
            svc.reapply_all()

        r.lan_access.apply_device_exceptions.assert_not_called()


# ── Facade-level tests ───────────────────────────────────────────────


def _make_facade(uci_sections: dict[str, list[str]] = None):
    """Create a RouterLanAccess with mocked tools.

    uci_sections: mapping of config name -> list of section names returned
    by ``uci show``.  E.g. {"wireless": ["fvpn_iot_ra1"], "firewall": ["fvpn_iot_zone"]}.
    """
    uci_sections = uci_sections or {}
    ssh = MagicMock()

    def _fake_exec(cmd):
        # Handle "uci show <config>" calls
        for config, sections in uci_sections.items():
            if f"uci show {config}" in cmd:
                return "\n".join(f"{config}.{s}=section" for s in sections)
        # BssidNum check
        if "cat" in cmd and ".dat" in cmd:
            return "BssidNum=2"
        return ""

    ssh.exec.side_effect = _fake_exec
    uci = MagicMock()
    iptables = MagicMock()
    service_ctl = MagicMock()
    return RouterLanAccess(uci, iptables, service_ctl, ssh)


class TestFacadeDeleteNetwork:
    def test_prefixed_zone_id_matches_sections(self):
        """Regression: passing 'fvpn_iot' should NOT double-prefix to 'fvpn_fvpn_iot'."""
        facade = _make_facade({
            "wireless": ["fvpn_iot_ra1"],
            "network": ["fvpn_iot"],
            "firewall": ["fvpn_iot_zone"],
            "dhcp": ["fvpn_iot"],
        })
        facade.delete_network("fvpn_iot")

        # The commit+delete call is second-to-last (last is wifi driver reload)
        all_calls = [c[0][0] for c in facade._ssh.exec.call_args_list]
        delete_cmd = next(c for c in all_calls if "uci -q delete" in c)
        assert "fvpn_iot" in delete_cmd

    def test_bare_zone_id_also_works(self):
        """Passing bare 'iot' should still add the prefix."""
        facade = _make_facade({
            "wireless": ["fvpn_iot_ra1"],
            "network": [],
            "firewall": [],
            "dhcp": [],
        })
        facade.delete_network("iot")

        all_calls = [c[0][0] for c in facade._ssh.exec.call_args_list]
        delete_cmd = next(c for c in all_calls if "uci -q delete" in c)
        assert "uci -q delete wireless.fvpn_iot_ra1" in delete_cmd

    def test_rejects_builtin_zones(self):
        facade = _make_facade()
        with pytest.raises(ValueError, match="Cannot delete built-in"):
            facade.delete_network("lan")
        with pytest.raises(ValueError, match="Cannot delete built-in"):
            facade.delete_network("guest")

    def test_no_matching_sections_returns_silently(self):
        facade = _make_facade({
            "wireless": [], "network": [], "firewall": [], "dhcp": [],
        })
        facade.delete_network("fvpn_iot")
        # Should not crash; no uci delete commands issued
