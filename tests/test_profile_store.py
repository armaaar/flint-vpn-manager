"""Tests for profile_store.py — JSON persistence and profile management."""

import json

import pytest

import persistence.profile_store as ps


@pytest.fixture
def tmp_store(tmp_path):
    """Use a temporary directory for the store file."""
    orig_dir = ps.DATA_DIR
    orig_file = ps.STORE_FILE
    ps.DATA_DIR = tmp_path
    ps.STORE_FILE = tmp_path / "profile_store.json"
    yield tmp_path
    ps.DATA_DIR = orig_dir
    ps.STORE_FILE = orig_file


class TestLoadSave:
    def test_load_empty_when_no_file(self, tmp_store):
        data = ps.load()
        assert data["profiles"] == []
        assert data["device_assignments"] == {}

    def test_save_and_load_roundtrip(self, tmp_store):
        data = ps.load()
        data["profiles"].append({"id": "test", "name": "Test"})
        ps.save(data)
        loaded = ps.load()
        assert len(loaded["profiles"]) == 1
        assert loaded["profiles"][0]["name"] == "Test"

    def test_atomic_write_creates_file(self, tmp_store):
        ps.save(ps.load())
        assert ps.STORE_FILE.exists()


class TestNormalizeServerScope:
    def test_empty_scope_returns_default(self):
        scope = ps.normalize_server_scope(None)
        assert scope["country_code"] is None
        assert scope["city"] is None
        assert scope["entry_country_code"] is None
        assert scope["server_id"] is None
        assert scope["features"] == {"streaming": False, "p2p": False, "secure_core": False, "tor": False}

    def test_new_shape_passes_through(self):
        scope = ps.normalize_server_scope({
            "country_code": "US", "city": "New York",
            "server_id": "abc123", "entry_country_code": None,
            "features": {"streaming": True, "p2p": False, "secure_core": False},
        })
        assert scope["country_code"] == "US"
        assert scope["city"] == "New York"
        assert scope["server_id"] == "abc123"
        assert scope["features"]["streaming"] is True

    def test_legacy_server_type_translates(self):
        scope = ps.normalize_server_scope({"type": "server"})
        # Old "server" type meant a specific server was pinned, but the id
        # wasn't stored in scope. Result is a fully-fastest scope.
        assert scope["country_code"] is None
        assert scope["server_id"] is None

    def test_legacy_country_type_translates(self):
        scope = ps.normalize_server_scope({"type": "country", "country_code": "DE"})
        assert scope["country_code"] == "DE"
        assert scope["city"] is None
        assert scope["server_id"] is None

    def test_legacy_city_type_translates(self):
        scope = ps.normalize_server_scope({
            "type": "city", "country_code": "DE", "city": "Berlin"
        })
        assert scope["country_code"] == "DE"
        assert scope["city"] == "Berlin"

    def test_cascade_resets_when_country_is_none(self):
        scope = ps.normalize_server_scope({
            "country_code": None, "city": "Berlin", "server_id": "abc",
            "entry_country_code": "CH",
        })
        assert scope["city"] is None
        assert scope["server_id"] is None
        assert scope["entry_country_code"] is None

    def test_cascade_resets_when_city_is_none(self):
        scope = ps.normalize_server_scope({
            "country_code": "DE", "city": None,
            "server_id": "abc", "entry_country_code": "CH",
        })
        assert scope["server_id"] is None
        assert scope["entry_country_code"] is None

    def test_entry_country_cleared_when_secure_core_off(self):
        scope = ps.normalize_server_scope({
            "country_code": "AU", "city": "Sydney",
            "entry_country_code": "CH",
            "features": {"streaming": False, "p2p": False, "secure_core": False},
        })
        assert scope["entry_country_code"] is None

    def test_load_normalizes_legacy_scopes(self, tmp_store):
        """A profile saved with the old scope shape should normalize on load."""
        ps.STORE_FILE.write_text(json.dumps({
            "profiles": [{
                "id": "p1", "type": "vpn", "name": "X",
                "server_scope": {"type": "country", "country_code": "DE"},
            }],
            "device_assignments": {},
            "device_lan_overrides": {},
        }))
        data = ps.load()
        scope = data["profiles"][0]["server_scope"]
        assert scope["country_code"] == "DE"
        assert "type" not in scope
        assert "features" in scope


class TestCreateProfile:
    def test_creates_vpn_profile(self, tmp_store):
        p = ps.create_profile("Gaming", "vpn", color="#ff0000", icon="🎮")
        assert p["name"] == "Gaming"
        assert p["type"] == "vpn"
        assert p["color"] == "#ff0000"
        assert p["id"]  # UUID generated
        # Stage 2: status is no longer cached locally — read live from router via get_tunnel_health()
        assert "status" not in p
        assert "options" in p

    def test_creates_no_vpn_profile(self, tmp_store):
        p = ps.create_profile("Direct", "no_vpn")
        assert p["type"] == "no_vpn"
        assert "status" not in p  # No tunnel status for no_vpn

    def test_creates_no_internet_profile(self, tmp_store):
        p = ps.create_profile("Printers", "no_internet", icon="🖨️")
        assert p["type"] == "no_internet"

    def test_invalid_type_raises(self, tmp_store):
        with pytest.raises(ValueError, match="Invalid profile type"):
            ps.create_profile("Bad", "invalid_type")

    def test_persists_to_disk(self, tmp_store):
        ps.create_profile("Test", "no_vpn")
        data = ps.load()
        assert len(data["profiles"]) == 1

    def test_multiple_profiles(self, tmp_store):
        ps.create_profile("A", "vpn")
        ps.create_profile("B", "no_vpn")
        ps.create_profile("C", "no_internet")
        assert len(ps.get_profiles()) == 3


class TestUpdateProfile:
    def test_updates_fields(self, tmp_store):
        p = ps.create_profile("Old Name", "no_vpn")
        updated = ps.update_profile(p["id"], name="New Name", color="#000000")
        assert updated["name"] == "New Name"
        assert updated["color"] == "#000000"

    def test_returns_none_for_missing(self, tmp_store):
        assert ps.update_profile("nonexistent", name="X") is None

    def test_cannot_change_id(self, tmp_store):
        p = ps.create_profile("Test", "no_vpn")
        ps.update_profile(p["id"], id="new-id")
        loaded = ps.get_profile(p["id"])
        assert loaded["id"] == p["id"]  # ID unchanged


class TestDeleteProfile:
    def test_deletes_profile(self, tmp_store):
        p = ps.create_profile("Deleteme", "no_vpn")
        assert ps.delete_profile(p["id"]) is True
        assert ps.get_profile(p["id"]) is None

    def test_returns_false_for_missing(self, tmp_store):
        assert ps.delete_profile("nonexistent") is False

    def test_unassigns_devices(self, tmp_store):
        p = ps.create_profile("Test", "no_vpn")
        ps.assign_device("aa:bb:cc:dd:ee:ff", p["id"])
        ps.delete_profile(p["id"])
        assert ps.get_device_assignment("aa:bb:cc:dd:ee:ff") is None


class TestGuestProfile:
    def test_no_guest_by_default(self, tmp_store):
        ps.create_profile("A", "no_vpn")
        assert ps.get_guest_profile() is None

    def test_set_guest(self, tmp_store):
        p = ps.create_profile("Guest", "no_vpn")
        ps.set_guest_profile(p["id"])
        guest = ps.get_guest_profile()
        assert guest["id"] == p["id"]

    def test_only_one_guest(self, tmp_store):
        a = ps.create_profile("A", "no_vpn")
        b = ps.create_profile("B", "no_vpn")
        ps.set_guest_profile(a["id"])
        ps.set_guest_profile(b["id"])
        data = ps.load()
        guests = [p for p in data["profiles"] if p["is_guest"]]
        assert len(guests) == 1
        assert guests[0]["id"] == b["id"]

    def test_create_with_guest_flag(self, tmp_store):
        a = ps.create_profile("A", "no_vpn", is_guest=True)
        b = ps.create_profile("B", "no_vpn", is_guest=True)
        data = ps.load()
        guests = [p for p in data["profiles"] if p["is_guest"]]
        assert len(guests) == 1
        assert guests[0]["id"] == b["id"]


class TestDeviceAssignment:
    def test_assign_device(self, tmp_store):
        p = ps.create_profile("Test", "no_vpn")
        assert ps.assign_device("aa:bb:cc:dd:ee:ff", p["id"]) is True
        assert ps.get_device_assignment("aa:bb:cc:dd:ee:ff") == p["id"]

    def test_unassign_device(self, tmp_store):
        p = ps.create_profile("Test", "no_vpn")
        ps.assign_device("aa:bb:cc:dd:ee:ff", p["id"])
        ps.assign_device("aa:bb:cc:dd:ee:ff", None)
        assert ps.get_device_assignment("aa:bb:cc:dd:ee:ff") is None

    def test_assign_to_nonexistent_profile_fails(self, tmp_store):
        assert ps.assign_device("aa:bb:cc:dd:ee:ff", "nonexistent") is False

    def test_mac_lowercased(self, tmp_store):
        p = ps.create_profile("Test", "no_vpn")
        ps.assign_device("AA:BB:CC:DD:EE:FF", p["id"])
        assert ps.get_device_assignment("aa:bb:cc:dd:ee:ff") == p["id"]

    def test_get_devices_for_profile(self, tmp_store):
        p = ps.create_profile("Test", "no_vpn")
        ps.assign_device("aa:bb:cc:dd:ee:ff", p["id"])
        ps.assign_device("11:22:33:44:55:66", p["id"])
        ps.assign_device("77:88:99:aa:bb:cc", None)
        devices = ps.get_devices_for_profile(p["id"])
        assert len(devices) == 2

    def test_get_unassigned_devices(self, tmp_store):
        p = ps.create_profile("Test", "no_vpn")
        ps.assign_device("aa:bb:cc:dd:ee:ff", p["id"])
        ps.assign_device("11:22:33:44:55:66", None)
        unassigned = ps.get_unassigned_devices()
        assert unassigned == ["11:22:33:44:55:66"]


class TestReorderProfiles:
    def test_reorder(self, tmp_store):
        a = ps.create_profile("A", "no_vpn")
        b = ps.create_profile("B", "no_vpn")
        c = ps.create_profile("C", "no_vpn")
        # Default order: A, B, C
        assert [p["name"] for p in ps.get_profiles()] == ["A", "B", "C"]
        # Reorder to C, A, B
        ps.reorder_profiles([c["id"], a["id"], b["id"]])
        assert [p["name"] for p in ps.get_profiles()] == ["C", "A", "B"]

    def test_reorder_with_missing_ids(self, tmp_store):
        a = ps.create_profile("A", "no_vpn")
        b = ps.create_profile("B", "no_vpn")
        # Only pass one ID — the other should be appended
        ps.reorder_profiles([b["id"]])
        names = [p["name"] for p in ps.get_profiles()]
        assert names[0] == "B"
        assert "A" in names

    def test_reorder_no_change(self, tmp_store):
        a = ps.create_profile("A", "no_vpn")
        b = ps.create_profile("B", "no_vpn")
        result = ps.reorder_profiles([a["id"], b["id"]])
        assert result is False  # No change

    def test_reorder_returns_true_on_change(self, tmp_store):
        a = ps.create_profile("A", "no_vpn")
        b = ps.create_profile("B", "no_vpn")
        result = ps.reorder_profiles([b["id"], a["id"]])
        assert result is True


class TestSanitizesLegacyDeviceFields:
    """Stage 8: legacy device-tracking fields are dropped on save."""

    def test_save_strips_legacy_fields(self, tmp_store):
        # Inject legacy fields directly, then save and reload
        data = ps.load()
        data["device_last_seen"] = {"aa:bb:cc:dd:ee:ff": "2026-01-01T00:00:00"}
        data["device_hostnames"] = {"aa:bb:cc:dd:ee:ff": "Old"}
        data["device_ips"] = {"aa:bb:cc:dd:ee:ff": "1.2.3.4"}
        data["device_client_info"] = {"aa:bb:cc:dd:ee:ff": {"online": True}}
        data["device_labels"] = {"aa:bb:cc:dd:ee:ff": "Old Label"}
        ps.save(data)

        reloaded = ps.load()
        assert "device_last_seen" not in reloaded
        assert "device_hostnames" not in reloaded
        assert "device_ips" not in reloaded
        assert "device_client_info" not in reloaded
        assert "device_labels" not in reloaded
