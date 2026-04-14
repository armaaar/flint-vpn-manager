"""Tests for auth blueprint — status, setup, unlock, lock."""

from unittest.mock import patch, MagicMock

import pytest


class TestStatus:
    def test_setup_needed(self, client, mock_registry):
        with patch("routes.auth.sm") as mock_sm:
            mock_sm.is_setup.return_value = False
            resp = client.get("/api/status")
        assert resp.json["status"] == "setup-needed"

    def test_locked(self, client, mock_registry):
        mock_registry.session_unlocked = False
        with patch("routes.auth.sm") as mock_sm:
            mock_sm.is_setup.return_value = True
            # Need to re-patch _helpers too since require_unlocked reads it
            with patch("routes._helpers._registry", mock_registry):
                resp = client.get("/api/status")
        assert resp.json["status"] == "locked"

    def test_unlocked(self, client, mock_registry):
        mock_registry.session_unlocked = True
        mock_registry.get_proton.return_value.is_logged_in = True
        with patch("routes.auth.sm") as mock_sm:
            mock_sm.is_setup.return_value = True
            resp = client.get("/api/status")
        assert resp.json["status"] == "unlocked"
        assert resp.json["proton_logged_in"] is True


class TestSetup:
    def test_successful_setup(self, client):
        with patch("routes.auth.sm") as mock_sm:
            resp = client.post("/api/setup", json={
                "proton_user": "user@proton.me",
                "proton_pass": "pass123",
                "router_pass": "routerpass",
                "master_password": "master123",
            })
        assert resp.status_code == 200
        assert resp.json["success"] is True
        mock_sm.setup.assert_called_once()

    def test_missing_fields(self, client):
        with patch("routes.auth.sm"):
            resp = client.post("/api/setup", json={
                "proton_user": "user@proton.me",
            })
        assert resp.status_code == 400
        assert "Missing fields" in resp.json["error"]


class TestUnlock:
    def test_missing_password(self, client):
        resp = client.post("/api/unlock", json={})
        assert resp.status_code == 400

    def test_wrong_password(self, client, mock_registry):
        with patch("routes.auth.sm") as mock_sm:
            mock_sm.unlock.side_effect = ValueError("Wrong password")
            resp = client.post("/api/unlock", json={"master_password": "wrong"})
        assert resp.status_code == 401

    def test_successful_unlock(self, client, mock_registry):
        with patch("routes.auth.sm") as mock_sm, \
             patch("routes.auth.VPNService") as mock_vpn, \
             patch("routes.auth.ps"), \
             patch("routes.auth.check_and_auto_restore"), \
             patch("routes.auth.start_tracker") as mock_tracker, \
             patch("routes.auth.start_optimizer"), \
             patch("routes.auth.backup_local_state_to_router"):
            mock_sm.get_config.return_value = {}
            mock_tracker.return_value = MagicMock()
            resp = client.post("/api/unlock", json={"master_password": "correct"})
        assert resp.status_code == 200
        assert resp.json["success"] is True


class TestLock:
    def test_lock(self, client, mock_registry):
        with patch("routes.auth.stop_tracker"), \
             patch("routes.auth.stop_optimizer"):
            resp = client.post("/api/lock")
        assert resp.status_code == 200
        mock_registry.reset.assert_called_once()


class TestRequireUnlocked:
    def test_locked_endpoints_return_401(self, locked_client):
        """Endpoints requiring unlock should return 401 when locked."""
        resp = locked_client.get("/api/profiles")
        assert resp.status_code == 401

        resp = locked_client.get("/api/devices")
        assert resp.status_code == 401

        resp = locked_client.get("/api/settings")
        assert resp.status_code == 401
