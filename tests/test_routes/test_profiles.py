"""Tests for profiles blueprint — CRUD, connect/disconnect, server switch."""

from unittest.mock import patch, MagicMock

import pytest

from services.vpn_service import NotFoundError, LimitExceededError, ConflictError


class TestGetProfiles:
    def test_returns_profile_list(self, client, mock_registry):
        mock_registry.get_service.return_value.build_profile_list.return_value = [
            {"id": "p1", "name": "US East", "type": "vpn"},
        ]
        resp = client.get("/api/profiles")
        assert resp.status_code == 200
        assert len(resp.json) == 1
        assert resp.json[0]["name"] == "US East"


class TestCreateProfile:
    def test_creates_profile(self, client, mock_registry):
        mock_registry.get_service.return_value.create_profile.return_value = {
            "id": "new-id", "name": "UK", "type": "vpn",
        }
        resp = client.post("/api/profiles", json={
            "name": "UK", "type": "vpn",
        })
        assert resp.status_code == 201
        assert resp.json["name"] == "UK"

    def test_missing_name(self, client):
        resp = client.post("/api/profiles", json={"type": "vpn"})
        assert resp.status_code == 400

    def test_missing_type(self, client):
        resp = client.post("/api/profiles", json={"name": "UK"})
        assert resp.status_code == 400

    def test_limit_exceeded(self, client, mock_registry):
        mock_registry.get_service.return_value.create_profile.side_effect = (
            LimitExceededError("Max WireGuard profiles reached")
        )
        resp = client.post("/api/profiles", json={"name": "X", "type": "vpn"})
        assert resp.status_code == 400


class TestUpdateProfile:
    def test_updates_metadata(self, client, mock_registry):
        mock_registry.get_service.return_value.update_profile.return_value = {
            "id": "p1", "name": "Updated",
        }
        resp = client.put("/api/profiles/p1", json={"name": "Updated"})
        assert resp.status_code == 200
        assert resp.json["name"] == "Updated"

    def test_not_found(self, client, mock_registry):
        mock_registry.get_service.return_value.update_profile.side_effect = NotFoundError("x")
        resp = client.put("/api/profiles/p1", json={"name": "X"})
        assert resp.status_code == 404


class TestDeleteProfile:
    def test_deletes_profile(self, client, mock_registry):
        resp = client.delete("/api/profiles/p1")
        assert resp.status_code == 200
        mock_registry.get_service.return_value.delete_profile.assert_called_once_with("p1")

    def test_not_found(self, client, mock_registry):
        mock_registry.get_service.return_value.delete_profile.side_effect = NotFoundError("x")
        resp = client.delete("/api/profiles/nonexistent")
        assert resp.status_code == 404


class TestReorderProfiles:
    def test_reorders(self, client, mock_registry):
        resp = client.put("/api/profiles/reorder", json={
            "profile_ids": ["p2", "p1"],
        })
        assert resp.status_code == 200
        mock_registry.get_service.return_value.reorder_profiles.assert_called_once()

    def test_empty_ids(self, client):
        resp = client.put("/api/profiles/reorder", json={"profile_ids": []})
        assert resp.status_code == 400


class TestChangeServer:
    def test_switches_server(self, client, mock_registry):
        mock_registry.get_service.return_value.switch_server.return_value = {"id": "p1"}
        resp = client.put("/api/profiles/p1/server", json={"server_id": "srv1"})
        assert resp.status_code == 200

    def test_missing_server_id(self, client):
        resp = client.put("/api/profiles/p1/server", json={})
        assert resp.status_code == 400

    def test_conflict(self, client, mock_registry):
        mock_registry.get_service.return_value.switch_server.side_effect = (
            ConflictError("Server switch in progress")
        )
        resp = client.put("/api/profiles/p1/server", json={"server_id": "srv1"})
        assert resp.status_code == 409


class TestChangeType:
    def test_changes_type(self, client, mock_registry):
        mock_registry.get_service.return_value.change_type.return_value = {"id": "p1"}
        resp = client.put("/api/profiles/p1/type", json={"type": "no_vpn"})
        assert resp.status_code == 200

    def test_missing_type(self, client):
        resp = client.put("/api/profiles/p1/type", json={})
        assert resp.status_code == 400


class TestChangeProtocol:
    def test_changes_protocol(self, client, mock_registry):
        mock_registry.get_service.return_value.change_protocol.return_value = {"id": "p1"}
        resp = client.put("/api/profiles/p1/protocol", json={"vpn_protocol": "openvpn"})
        assert resp.status_code == 200

    def test_missing_protocol(self, client):
        resp = client.put("/api/profiles/p1/protocol", json={})
        assert resp.status_code == 400


class TestConnect:
    def test_connects_profile(self, client, mock_registry):
        mock_registry.get_service.return_value.connect_profile.return_value = {"success": True}
        resp = client.post("/api/profiles/p1/connect")
        assert resp.status_code == 200

    def test_not_found(self, client, mock_registry):
        mock_registry.get_service.return_value.connect_profile.side_effect = NotFoundError("x")
        resp = client.post("/api/profiles/nonexistent/connect")
        assert resp.status_code == 404


class TestDisconnect:
    def test_disconnects_profile(self, client, mock_registry):
        mock_registry.get_service.return_value.disconnect_profile.return_value = {"success": True}
        resp = client.post("/api/profiles/p1/disconnect")
        assert resp.status_code == 200


class TestSetGuest:
    def test_sets_guest(self, client, mock_registry):
        resp = client.put("/api/profiles/p1/guest")
        assert resp.status_code == 200
        mock_registry.get_service.return_value.set_guest_profile.assert_called_once_with("p1")

    def test_not_found(self, client, mock_registry):
        mock_registry.get_service.return_value.set_guest_profile.side_effect = NotFoundError("x")
        resp = client.put("/api/profiles/nonexistent/guest")
        assert resp.status_code == 404


class TestRefresh:
    def test_refresh(self, client, mock_registry):
        with patch("routes.profiles.get_tracker") as mock_get_tracker:
            mock_get_tracker.return_value = MagicMock()
            mock_registry.get_service.return_value.proton.is_logged_in = True
            mock_registry.get_service.return_value.proton.server_list_expired = False
            mock_registry.get_service.return_value.proton.server_loads_expired = False
            resp = client.post("/api/refresh")
        assert resp.status_code == 200


class TestProbeLatency:
    def test_empty_server_ids(self, client):
        resp = client.post("/api/probe-latency", json={"server_ids": []})
        assert resp.status_code == 200
        assert resp.json["latencies"] == {}
