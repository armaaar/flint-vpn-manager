"""Tests for lan_access blueprint — network CRUD, rules, isolation, exceptions."""

from unittest.mock import MagicMock

import pytest


class TestGetNetworks:
    def test_returns_overview(self, client, mock_registry):
        mock_registry.get_lan_service.return_value.get_lan_overview.return_value = {
            "networks": [{"id": "lan", "zone": "lan"}],
        }
        resp = client.get("/api/lan-access/networks")
        assert resp.status_code == 200


class TestCreateNetwork:
    def test_creates_network(self, client, mock_registry):
        mock_registry.get_lan_service.return_value.create_network.return_value = {
            "success": True,
        }
        resp = client.post("/api/lan-access/networks", json={
            "zone_id": "testnet", "ssid": "TestSSID",
            "password": "pass123", "subnet_ip": "192.168.10.1",
        })
        assert resp.status_code == 200

    def test_validation_error(self, client, mock_registry):
        mock_registry.get_lan_service.return_value.create_network.side_effect = (
            ValueError("Invalid zone ID")
        )
        resp = client.post("/api/lan-access/networks", json={
            "zone_id": "bad;id",
        })
        assert resp.status_code == 400


class TestUpdateNetwork:
    def test_updates_network(self, client, mock_registry):
        mock_registry.get_lan_service.return_value.update_network.return_value = {
            "success": True,
        }
        resp = client.put("/api/lan-access/networks/testnet", json={
            "ssid": "NewSSID",
        })
        assert resp.status_code == 200


class TestDeleteNetwork:
    def test_deletes_network(self, client, mock_registry):
        mock_registry.get_lan_service.return_value.delete_network.return_value = {
            "success": True,
        }
        resp = client.delete("/api/lan-access/networks/testnet")
        assert resp.status_code == 200

    def test_delete_builtin_rejected(self, client, mock_registry):
        mock_registry.get_lan_service.return_value.delete_network.side_effect = (
            ValueError("Cannot delete built-in network")
        )
        resp = client.delete("/api/lan-access/networks/lan")
        assert resp.status_code == 400


class TestNetworkDevices:
    def test_returns_devices(self, client, mock_registry):
        mock_registry.get_lan_service.return_value.get_network_devices.return_value = [
            {"mac": "aa:bb:cc:dd:ee:ff"},
        ]
        resp = client.get("/api/lan-access/networks/lan/devices")
        assert resp.status_code == 200
        assert len(resp.json["devices"]) == 1


class TestUpdateRules:
    def test_updates_rules(self, client, mock_registry):
        mock_registry.get_lan_service.return_value.update_access_rules.return_value = {
            "success": True,
        }
        resp = client.put("/api/lan-access/rules", json={
            "rules": [{"src": "guest", "dest": "lan", "allowed": True}],
        })
        assert resp.status_code == 200


class TestIsolation:
    def test_sets_isolation(self, client, mock_registry):
        mock_registry.get_lan_service.return_value.set_isolation.return_value = {
            "success": True,
        }
        resp = client.put("/api/lan-access/isolation/testnet", json={
            "enabled": True,
        })
        assert resp.status_code == 200


class TestExceptions:
    def test_get_exceptions(self, client, mock_registry):
        mock_registry.get_lan_service.return_value.get_exceptions.return_value = []
        resp = client.get("/api/lan-access/exceptions")
        assert resp.status_code == 200

    def test_add_exception(self, client, mock_registry):
        mock_registry.get_lan_service.return_value.add_exception.return_value = {
            "id": "exc1",
        }
        resp = client.post("/api/lan-access/exceptions", json={
            "from_ip": "192.168.8.10", "to_ip": "192.168.9.20",
        })
        assert resp.status_code == 200

    def test_remove_exception(self, client, mock_registry):
        mock_registry.get_lan_service.return_value.remove_exception.return_value = {
            "success": True,
        }
        resp = client.delete("/api/lan-access/exceptions/exc1")
        assert resp.status_code == 200
