"""Tests for settings blueprint — config, server prefs, adblock, credentials."""

from unittest.mock import patch, MagicMock

import pytest


class TestGetSettings:
    def test_returns_config(self, client):
        with patch("routes.settings.sm") as mock_sm:
            mock_sm.get_config.return_value = {"router_ip": "192.168.8.1"}
            resp = client.get("/api/settings")
        assert resp.status_code == 200
        assert resp.json["router_ip"] == "192.168.8.1"


class TestUpdateSettings:
    def test_updates_config(self, client, mock_registry):
        with patch("routes.settings.sm") as mock_sm:
            mock_sm.update_config.return_value = {"router_ip": "192.168.8.2"}
            resp = client.put("/api/settings", json={"router_ip": "192.168.8.2"})
        assert resp.status_code == 200

    def test_applies_alternative_routing(self, client, mock_registry):
        with patch("routes.settings.sm") as mock_sm:
            mock_sm.update_config.return_value = {"alternative_routing": True}
            resp = client.put("/api/settings", json={"alternative_routing": True})
        assert resp.status_code == 200
        mock_registry.get_proton.return_value.set_alternative_routing.assert_called_once()

    def test_resets_router_on_ip_change(self, client, mock_registry):
        with patch("routes.settings.sm") as mock_sm:
            mock_sm.update_config.return_value = {"router_ip": "192.168.9.1"}
            resp = client.put("/api/settings", json={"router_ip": "192.168.9.1"})
        assert mock_registry.router is None  # Should have been reset


class TestServerPreferences:
    def test_get_preferences(self, client):
        with patch("routes.settings.sm") as mock_sm:
            mock_sm.get_config.return_value = {
                "server_blacklist": ["srv1"],
                "server_favourites": ["srv2"],
            }
            resp = client.get("/api/settings/server-preferences")
        assert resp.json["blacklist"] == ["srv1"]
        assert resp.json["favourites"] == ["srv2"]

    def test_update_preferences(self, client):
        with patch("routes.settings.sm") as mock_sm:
            mock_sm.get_config.return_value = {
                "server_blacklist": ["new"],
                "server_favourites": [],
            }
            resp = client.put("/api/settings/server-preferences", json={
                "blacklist": ["new"],
            })
        assert resp.status_code == 200

    def test_update_requires_data(self, client):
        with patch("routes.settings.sm"):
            resp = client.put("/api/settings/server-preferences", json={})
        assert resp.status_code == 400

    def test_add_to_blacklist(self, client):
        with patch("routes.settings.sm") as mock_sm:
            mock_sm.get_config.return_value = {
                "server_blacklist": [],
                "server_favourites": ["srv1"],
            }
            resp = client.post("/api/settings/server-preferences/blacklist/srv1")
        assert resp.status_code == 200
        # Should also remove from favourites
        call_kwargs = mock_sm.update_config.call_args[1]
        assert "srv1" in call_kwargs["server_blacklist"]
        assert "srv1" not in call_kwargs["server_favourites"]

    def test_remove_from_blacklist(self, client):
        with patch("routes.settings.sm") as mock_sm:
            mock_sm.get_config.return_value = {"server_blacklist": ["srv1"]}
            resp = client.delete("/api/settings/server-preferences/blacklist/srv1")
        assert resp.status_code == 200

    def test_add_to_favourites(self, client):
        with patch("routes.settings.sm") as mock_sm:
            mock_sm.get_config.return_value = {
                "server_blacklist": ["srv1"],
                "server_favourites": [],
            }
            resp = client.post("/api/settings/server-preferences/favourites/srv1")
        assert resp.status_code == 200
        # Should also remove from blacklist
        call_kwargs = mock_sm.update_config.call_args[1]
        assert "srv1" in call_kwargs["server_favourites"]
        assert "srv1" not in call_kwargs["server_blacklist"]


class TestCredentials:
    def test_update_credentials(self, client):
        with patch("routes.settings.sm") as mock_sm:
            resp = client.put("/api/settings/credentials", json={
                "master_password": "master",
                "proton_user": "new@proton.me",
            })
        assert resp.status_code == 200
        mock_sm.update.assert_called_once()

    def test_missing_master_password(self, client):
        with patch("routes.settings.sm"):
            resp = client.put("/api/settings/credentials", json={
                "proton_user": "new@proton.me",
            })
        assert resp.status_code == 400


class TestMasterPassword:
    def test_change_password(self, client):
        with patch("routes.settings.sm") as mock_sm:
            resp = client.put("/api/settings/master-password", json={
                "old_password": "old",
                "new_password": "newpass",
            })
        assert resp.status_code == 200

    def test_missing_fields(self, client):
        with patch("routes.settings.sm"):
            resp = client.put("/api/settings/master-password", json={
                "old_password": "old",
            })
        assert resp.status_code == 400

    def test_too_short(self, client):
        with patch("routes.settings.sm"):
            resp = client.put("/api/settings/master-password", json={
                "old_password": "old",
                "new_password": "ab",
            })
        assert resp.status_code == 400

    def test_wrong_old_password(self, client):
        with patch("routes.settings.sm") as mock_sm:
            mock_sm.change_master_password.side_effect = ValueError("Wrong password")
            resp = client.put("/api/settings/master-password", json={
                "old_password": "wrong",
                "new_password": "newpass",
            })
        assert resp.status_code == 400


class TestAdblock:
    def test_get_adblock_settings(self, client):
        with patch("routes.settings.sm") as mock_sm:
            mock_sm.get_config.return_value = {"adblock": {"blocklist_sources": []}}
            resp = client.get("/api/settings/adblock")
        assert resp.status_code == 200
        assert "presets" in resp.json

    def test_update_adblock_settings(self, client):
        with patch("routes.settings.sm") as mock_sm:
            mock_sm.get_config.return_value = {"adblock": {}}
            resp = client.put("/api/settings/adblock", json={
                "blocklist_sources": ["https://example.com/list.txt"],
            })
        assert resp.status_code == 200
