"""Tests for profile_store.py — JSON persistence and profile management."""

import json

import pytest

import profile_store as ps


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


# ── LAN Access Control ──────────────────────────────────────────────────────

class TestProfileLanAccess:
    def test_set_and_get(self, tmp_store):
        p = ps.create_profile("VPN1", "vpn")
        ps.set_profile_lan_access(p["id"], "group_only", "blocked")
        result = ps.get_profile_lan_access(p["id"])
        assert result["outbound"] == "group_only"
        assert result["inbound"] == "blocked"
        assert result["outbound_allow"] == []
        assert result["inbound_allow"] == []

    def test_default_is_allowed(self, tmp_store):
        p = ps.create_profile("VPN1", "vpn")
        result = ps.get_profile_lan_access(p["id"])
        assert result["outbound"] == "allowed"
        assert result["inbound"] == "allowed"
        assert result["outbound_allow"] == []
        assert result["inbound_allow"] == []

    def test_invalid_value_raises(self, tmp_store):
        p = ps.create_profile("VPN1", "vpn")
        with pytest.raises(ValueError):
            ps.set_profile_lan_access(p["id"], "invalid", "allowed")

    def test_nonexistent_profile_returns_none(self, tmp_store):
        result = ps.set_profile_lan_access("nonexistent", "allowed", "allowed")
        assert result is None

    def test_set_with_allow_lists(self, tmp_store):
        p = ps.create_profile("G1", "vpn")
        other = ps.create_profile("G2", "vpn")
        ps.set_profile_lan_access(
            p["id"], "group_only", "group_only",
            outbound_allow=["AA:BB:CC:DD:EE:FF"],  # MAC, gets lowercased
            inbound_allow=[other["id"], "11:22:33:44:55:66"],
        )
        result = ps.get_profile_lan_access(p["id"])
        assert result["outbound_allow"] == ["aa:bb:cc:dd:ee:ff"]
        assert other["id"] in result["inbound_allow"]
        assert "11:22:33:44:55:66" in result["inbound_allow"]


class TestAllowListValidation:
    def test_invalid_mac_rejected(self, tmp_store):
        p = ps.create_profile("G1", "vpn")
        with pytest.raises(ValueError):
            ps.set_profile_lan_access(
                p["id"], "group_only", "allowed",
                outbound_allow=["not-a-mac"],
            )

    def test_unknown_profile_id_rejected(self, tmp_store):
        p = ps.create_profile("G1", "vpn")
        with pytest.raises(ValueError):
            ps.set_profile_lan_access(
                p["id"], "group_only", "allowed",
                outbound_allow=["nonexistent-profile-id"],
            )

    def test_self_reference_rejected(self, tmp_store):
        # A group cannot reference itself in its own allow list (it's already
        # the source of "group_only" semantics).
        p = ps.create_profile("G1", "vpn")
        with pytest.raises(ValueError):
            ps.set_profile_lan_access(
                p["id"], "group_only", "allowed",
                outbound_allow=[p["id"]],
            )

    def test_dedups_entries(self, tmp_store):
        p = ps.create_profile("G1", "vpn")
        ps.set_profile_lan_access(
            p["id"], "group_only", "allowed",
            outbound_allow=["aa:bb:cc:dd:ee:ff", "AA:BB:CC:DD:EE:FF"],
        )
        result = ps.get_profile_lan_access(p["id"])
        assert result["outbound_allow"] == ["aa:bb:cc:dd:ee:ff"]


class TestDeviceLanOverride:
    def test_set_and_get(self, tmp_store):
        ps.set_device_lan_override("aa:bb:cc:dd:ee:ff", "blocked", "allowed")
        result = ps.get_device_lan_override("aa:bb:cc:dd:ee:ff")
        assert result["outbound"] == "blocked"
        assert result["inbound"] == "allowed"
        assert result["outbound_allow"] == []
        assert result["inbound_allow"] == []

    def test_none_clears_override(self, tmp_store):
        ps.set_device_lan_override("aa:bb:cc:dd:ee:ff", "blocked", None)
        ps.set_device_lan_override("aa:bb:cc:dd:ee:ff", None, None)
        assert ps.get_device_lan_override("aa:bb:cc:dd:ee:ff") is None

    def test_invalid_value_raises(self, tmp_store):
        with pytest.raises(ValueError):
            ps.set_device_lan_override("aa:bb:cc:dd:ee:ff", "bad", None)

    def test_only_allow_list_persisted(self, tmp_store):
        # Partial override with no state change but with allow lists must
        # persist (not be auto-cleared as if empty).
        p = ps.create_profile("G1", "vpn")
        ps.set_device_lan_override(
            "aa:bb:cc:dd:ee:ff", None, None,
            inbound_allow=[p["id"]],
        )
        ovr = ps.get_device_lan_override("aa:bb:cc:dd:ee:ff")
        assert ovr is not None
        assert ovr["outbound"] is None
        assert ovr["inbound"] is None
        assert ovr["inbound_allow"] == [p["id"]]

    def test_fully_empty_clears(self, tmp_store):
        ps.set_device_lan_override("aa:bb:cc:dd:ee:ff", "blocked", None)
        ps.set_device_lan_override(
            "aa:bb:cc:dd:ee:ff", None, None,
            outbound_allow=[], inbound_allow=[],
        )
        assert ps.get_device_lan_override("aa:bb:cc:dd:ee:ff") is None


class TestEffectiveLanAccess:
    def test_inherits_from_group(self, tmp_store):
        p = ps.create_profile("VPN1", "vpn")
        ps.set_profile_lan_access(p["id"], "group_only", "blocked")
        ps.assign_device("aa:bb:cc:dd:ee:ff", p["id"])
        result = ps.get_effective_lan_access("aa:bb:cc:dd:ee:ff")
        assert result["outbound"] == "group_only"
        assert result["inbound"] == "blocked"
        assert result["inherited"] is True

    def test_device_overrides_group(self, tmp_store):
        p = ps.create_profile("VPN1", "vpn")
        ps.set_profile_lan_access(p["id"], "group_only", "group_only")
        ps.assign_device("aa:bb:cc:dd:ee:ff", p["id"])
        ps.set_device_lan_override("aa:bb:cc:dd:ee:ff", "blocked", None)
        result = ps.get_effective_lan_access("aa:bb:cc:dd:ee:ff")
        assert result["outbound"] == "blocked"  # overridden
        assert result["inbound"] == "group_only"  # inherited
        assert result["inherited"] is False

    def test_default_when_no_group(self, tmp_store):
        # No assignment, no override → default allowed/allowed
        result = ps.get_effective_lan_access("aa:bb:cc:dd:ee:ff")
        assert result["outbound"] == "allowed"
        assert result["inbound"] == "allowed"

    def test_allow_lists_merge_additively(self, tmp_store):
        # Group has one entry, device override adds another → effective union.
        p = ps.create_profile("Trusted", "vpn")
        ps.set_profile_lan_access(
            p["id"], "group_only", "group_only",
            inbound_allow=["aa:aa:aa:aa:aa:aa"],
        )
        ps.assign_device("11:22:33:44:55:66", p["id"])
        ps.set_device_lan_override(
            "11:22:33:44:55:66", None, None,
            inbound_allow=["bb:bb:bb:bb:bb:bb"],
        )
        result = ps.get_effective_lan_access("11:22:33:44:55:66")
        values = {e["value"]: e["source"] for e in result["inbound_allow"]}
        assert values == {
            "aa:aa:aa:aa:aa:aa": "group",
            "bb:bb:bb:bb:bb:bb": "device",
        }

    def test_allow_lists_dedup_across_layers(self, tmp_store):
        p = ps.create_profile("G1", "vpn")
        ps.set_profile_lan_access(
            p["id"], "group_only", "group_only",
            inbound_allow=["aa:aa:aa:aa:aa:aa"],
        )
        ps.assign_device("11:22:33:44:55:66", p["id"])
        ps.set_device_lan_override(
            "11:22:33:44:55:66", None, None,
            inbound_allow=["aa:aa:aa:aa:aa:aa"],
        )
        result = ps.get_effective_lan_access("11:22:33:44:55:66")
        # Same MAC → dedup; group source wins (it was added first).
        assert len(result["inbound_allow"]) == 1
        assert result["inbound_allow"][0]["source"] == "group"


class TestDeleteProfileCleansLanOverrides:
    def test_overrides_removed_on_delete(self, tmp_store):
        p = ps.create_profile("VPN1", "vpn")
        ps.assign_device("aa:bb:cc:dd:ee:ff", p["id"])
        ps.set_device_lan_override("aa:bb:cc:dd:ee:ff", "blocked", "blocked")
        ps.delete_profile(p["id"])
        assert ps.get_device_lan_override("aa:bb:cc:dd:ee:ff") is None

    def test_profile_id_stripped_from_other_groups_allow_lists(self, tmp_store):
        a = ps.create_profile("A", "vpn")
        b = ps.create_profile("B", "vpn")
        ps.set_profile_lan_access(
            a["id"], "group_only", "group_only",
            inbound_allow=[b["id"]],
        )
        ps.delete_profile(b["id"])
        result = ps.get_profile_lan_access(a["id"])
        assert b["id"] not in result["inbound_allow"]

    def test_profile_id_stripped_from_device_override_allow_lists(self, tmp_store):
        a = ps.create_profile("A", "vpn")
        b = ps.create_profile("B", "vpn")
        ps.assign_device("11:22:33:44:55:66", a["id"])
        ps.set_device_lan_override(
            "11:22:33:44:55:66", None, None,
            inbound_allow=[b["id"]],
        )
        ps.delete_profile(b["id"])
        ovr = ps.get_device_lan_override("11:22:33:44:55:66")
        assert ovr is not None
        assert b["id"] not in ovr["inbound_allow"]
