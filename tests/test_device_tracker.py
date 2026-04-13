"""Tests for device_tracker.py — auto-assignment of new MACs to the guest group.

Focuses on the sticky-None behavior: a MAC that has been intentionally
unassigned should NOT be re-auto-assigned by the tracker on the next poll
(or after a lock/unlock that resets the in-memory _known_macs set).
"""

from unittest.mock import MagicMock

import pytest

import persistence.profile_store as ps
from background.device_tracker import DeviceTracker


@pytest.fixture
def tmp_store(tmp_path, monkeypatch):
    monkeypatch.setattr(ps, "DATA_DIR", tmp_path)
    monkeypatch.setattr(ps, "STORE_FILE", tmp_path / "profile_store.json")
    yield


def _mock_router(leases=None, vpn_assignments=None):
    router = MagicMock()
    router.devices.get_dhcp_leases.return_value = leases or []
    router.devices.get_device_assignments.return_value = vpn_assignments or {}
    return router


def _make_guest_no_vpn():
    """Create a no_vpn guest profile and return its id."""
    p = ps.create_profile("Guest", "no_vpn", is_guest=True)
    return p["id"]


class TestAutoAssignment:
    def test_new_mac_with_no_assignment_gets_auto_assigned(self, tmp_store):
        guest_id = _make_guest_no_vpn()
        router = _mock_router(leases=[
            {"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.8.10", "hostname": "x"},
        ])
        tracker = DeviceTracker(router)
        tracker.poll_once()
        data = ps.load()
        assert data["device_assignments"].get("aa:bb:cc:dd:ee:ff") == guest_id

    def test_no_guest_means_no_auto_assignment(self, tmp_store):
        # No guest profile created
        router = _mock_router(leases=[
            {"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.8.10", "hostname": "x"},
        ])
        tracker = DeviceTracker(router)
        tracker.poll_once()
        data = ps.load()
        assert "aa:bb:cc:dd:ee:ff" not in data["device_assignments"]

    def test_already_assigned_mac_is_left_alone(self, tmp_store):
        guest_id = _make_guest_no_vpn()
        # Pre-assign the MAC to a different (non-guest) group
        other = ps.create_profile("Other", "no_vpn")
        ps.assign_device("aa:bb:cc:dd:ee:ff", other["id"])

        router = _mock_router(leases=[
            {"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.8.10", "hostname": "x"},
        ])
        tracker = DeviceTracker(router)
        tracker.poll_once()
        data = ps.load()
        # Still in the original group, not moved to guest
        assert data["device_assignments"]["aa:bb:cc:dd:ee:ff"] == other["id"]

    def test_vpn_assigned_mac_is_left_alone(self, tmp_store):
        _make_guest_no_vpn()
        # Router says the MAC is in a VPN rule
        router = _mock_router(
            leases=[{"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.8.10", "hostname": "x"}],
            vpn_assignments={"aa:bb:cc:dd:ee:ff": "fvpn_rule_9001"},
        )
        tracker = DeviceTracker(router)
        tracker.poll_once()
        data = ps.load()
        # Not auto-assigned to guest because it's already in a VPN rule
        assert "aa:bb:cc:dd:ee:ff" not in data["device_assignments"]


class TestStickyNone:
    """Sticky-None: an explicit unassign survives across tracker resets."""

    def test_sticky_none_prevents_auto_reassignment(self, tmp_store):
        """A MAC with device_assignments[mac]=None must NOT be auto-assigned."""
        _make_guest_no_vpn()
        # Sticky-None marker (simulates explicit unassign that persisted to disk)
        data = ps.load()
        data["device_assignments"]["aa:bb:cc:dd:ee:ff"] = None
        ps.save(data)

        router = _mock_router(leases=[
            {"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.8.10", "hostname": "x"},
        ])
        # Fresh tracker (empty _known_macs, simulates post-restart state)
        tracker = DeviceTracker(router)
        tracker.poll_once()

        data = ps.load()
        # Still None, NOT reassigned to guest
        assert data["device_assignments"]["aa:bb:cc:dd:ee:ff"] is None

    def test_sticky_none_survives_multiple_polls(self, tmp_store):
        _make_guest_no_vpn()
        data = ps.load()
        data["device_assignments"]["aa:bb:cc:dd:ee:ff"] = None
        ps.save(data)

        router = _mock_router(leases=[
            {"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.8.10", "hostname": "x"},
        ])
        tracker = DeviceTracker(router)
        for _ in range(3):
            tracker.poll_once()

        data = ps.load()
        assert data["device_assignments"]["aa:bb:cc:dd:ee:ff"] is None

    def test_delete_profile_cascade_does_NOT_create_sticky_none(self, tmp_store):
        """Deleting a group should drop its devices' entries entirely so they
        fall back to auto-assignment, NOT leave sticky-None markers."""
        guest_id = _make_guest_no_vpn()
        other = ps.create_profile("ToDelete", "no_vpn")
        ps.assign_device("aa:bb:cc:dd:ee:ff", other["id"])

        ps.delete_profile(other["id"])

        data = ps.load()
        # Key dropped entirely
        assert "aa:bb:cc:dd:ee:ff" not in data["device_assignments"]

        # Now a fresh tracker should auto-assign it to guest
        router = _mock_router(leases=[
            {"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.8.10", "hostname": "x"},
        ])
        tracker = DeviceTracker(router)
        tracker.poll_once()
        data = ps.load()
        assert data["device_assignments"]["aa:bb:cc:dd:ee:ff"] == guest_id
