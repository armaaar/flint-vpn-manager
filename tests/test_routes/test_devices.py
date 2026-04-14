"""Tests for devices blueprint — list, assign, label."""

from unittest.mock import patch

import pytest

from services.vpn_service import NotFoundError


class TestGetDevices:
    def test_returns_devices(self, client, mock_registry):
        mock_registry.get_service.return_value.get_devices_cached.return_value = [
            {"mac": "aa:bb:cc:dd:ee:ff", "name": "Phone"},
        ]
        resp = client.get("/api/devices")
        assert resp.status_code == 200
        assert len(resp.json) == 1


class TestSetDeviceLabel:
    def test_sets_label(self, client, mock_registry):
        resp = client.put("/api/devices/aa:bb:cc:dd:ee:ff/label", json={
            "label": "Living Room TV",
            "device_class": "computer",
        })
        assert resp.status_code == 200
        assert resp.json["label"] == "Living Room TV"

    def test_error_propagation(self, client, mock_registry):
        mock_registry.get_service.return_value.set_device_label.side_effect = (
            Exception("SSH error")
        )
        resp = client.put("/api/devices/aa:bb:cc:dd:ee:ff/label", json={
            "label": "X",
        })
        assert resp.status_code == 500


class TestAssignDevice:
    def test_assigns_device(self, client, mock_registry):
        with patch("routes.devices.ps") as mock_ps:
            mock_ps.validate_mac.return_value = "aa:bb:cc:dd:ee:ff"
            resp = client.put("/api/devices/aa:bb:cc:dd:ee:ff/profile", json={
                "profile_id": "p1",
            })
        assert resp.status_code == 200

    def test_invalid_mac(self, client, mock_registry):
        with patch("routes.devices.ps") as mock_ps:
            mock_ps.validate_mac.side_effect = ValueError("bad mac")
            resp = client.put("/api/devices/invalid/profile", json={
                "profile_id": "p1",
            })
        assert resp.status_code == 400

    def test_profile_not_found(self, client, mock_registry):
        with patch("routes.devices.ps") as mock_ps:
            mock_ps.validate_mac.return_value = "aa:bb:cc:dd:ee:ff"
            mock_registry.get_service.return_value.assign_device.side_effect = (
                NotFoundError("x")
            )
            resp = client.put("/api/devices/aa:bb:cc:dd:ee:ff/profile", json={
                "profile_id": "nonexistent",
            })
        assert resp.status_code == 404

    def test_unassign_device(self, client, mock_registry):
        with patch("routes.devices.ps") as mock_ps:
            mock_ps.validate_mac.return_value = "aa:bb:cc:dd:ee:ff"
            resp = client.put("/api/devices/aa:bb:cc:dd:ee:ff/profile", json={
                "profile_id": None,
            })
        assert resp.status_code == 200
