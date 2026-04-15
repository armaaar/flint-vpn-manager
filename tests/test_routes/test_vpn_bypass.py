"""Tests for VPN Bypass route endpoints."""

import json


class TestGetOverview:
    def test_returns_overview(self, client, mock_registry):
        svc = mock_registry.get_bypass_service()
        svc.get_overview.return_value = {
            "exceptions": [],
            "presets": {"lol": {"name": "LoL", "builtin": True}},
            "dnsmasq_full_installed": False,
        }
        resp = client.get("/api/vpn-bypass")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "exceptions" in data
        assert "presets" in data

    def test_locked_returns_401(self, locked_client):
        resp = locked_client.get("/api/vpn-bypass")
        assert resp.status_code == 401


class TestAddException:
    def test_add_success(self, client, mock_registry):
        svc = mock_registry.get_bypass_service()
        svc.add_exception.return_value = {
            "success": True,
            "exception": {"id": "byp_abc", "name": "Test"},
        }
        resp = client.post(
            "/api/vpn-bypass/exceptions",
            json={"name": "Test", "rules": [{"type": "cidr", "value": "10.0.0.0/8"}]},
        )
        assert resp.status_code == 200
        assert resp.get_json()["success"] is True

    def test_add_validation_error(self, client, mock_registry):
        svc = mock_registry.get_bypass_service()
        svc.add_exception.side_effect = ValueError("At least one rule")
        resp = client.post(
            "/api/vpn-bypass/exceptions",
            json={"name": "Bad"},
        )
        assert resp.status_code == 400
        assert "error" in resp.get_json()


class TestUpdateException:
    def test_update_success(self, client, mock_registry):
        svc = mock_registry.get_bypass_service()
        svc.update_exception.return_value = {
            "success": True,
            "exception": {"id": "byp_1", "name": "Updated"},
        }
        resp = client.put(
            "/api/vpn-bypass/exceptions/byp_1",
            json={"name": "Updated"},
        )
        assert resp.status_code == 200

    def test_update_not_found(self, client, mock_registry):
        svc = mock_registry.get_bypass_service()
        svc.update_exception.side_effect = ValueError("not found")
        resp = client.put(
            "/api/vpn-bypass/exceptions/byp_nope",
            json={"name": "X"},
        )
        assert resp.status_code == 400


class TestDeleteException:
    def test_delete_success(self, client, mock_registry):
        svc = mock_registry.get_bypass_service()
        svc.remove_exception.return_value = {"success": True}
        resp = client.delete("/api/vpn-bypass/exceptions/byp_1")
        assert resp.status_code == 200


class TestToggleException:
    def test_toggle_success(self, client, mock_registry):
        svc = mock_registry.get_bypass_service()
        svc.toggle_exception.return_value = {
            "success": True,
            "exception": {"id": "byp_1", "enabled": False},
        }
        resp = client.put(
            "/api/vpn-bypass/exceptions/byp_1/toggle",
            json={"enabled": False},
        )
        assert resp.status_code == 200


class TestPresets:
    def test_save_preset(self, client, mock_registry):
        svc = mock_registry.get_bypass_service()
        svc.save_custom_preset.return_value = {
            "success": True,
            "preset_id": "custom_abc",
        }
        resp = client.post(
            "/api/vpn-bypass/presets",
            json={"name": "My Game", "rules": []},
        )
        assert resp.status_code == 200

    def test_delete_preset(self, client, mock_registry):
        svc = mock_registry.get_bypass_service()
        svc.delete_custom_preset.return_value = {"success": True}
        resp = client.delete("/api/vpn-bypass/presets/custom_abc")
        assert resp.status_code == 200

    def test_cannot_delete_builtin(self, client, mock_registry):
        svc = mock_registry.get_bypass_service()
        svc.delete_custom_preset.side_effect = ValueError("built-in")
        resp = client.delete("/api/vpn-bypass/presets/lol")
        assert resp.status_code == 400


class TestDnsmasqInstall:
    def test_install_success(self, client, mock_registry):
        svc = mock_registry.get_bypass_service()
        svc.install_dnsmasq_full.return_value = {"success": True}
        resp = client.post("/api/vpn-bypass/dnsmasq-install")
        assert resp.status_code == 200
