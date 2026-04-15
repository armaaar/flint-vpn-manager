"""Tests for VpnBypassService."""

from unittest.mock import MagicMock, patch

import pytest

from services.vpn_bypass_service import VpnBypassService


def _mock_router():
    r = MagicMock()
    r.vpn_bypass = MagicMock()
    r.vpn_bypass.check_dnsmasq_full.return_value = False
    r.vpn_bypass.apply_all.return_value = None
    r.vpn_bypass.cleanup.return_value = None
    r.exec.return_value = ""
    return r


def _base_config(**overrides):
    config = {"router_ip": "192.168.8.1"}
    config.update(overrides)
    return config


def _simple_blocks():
    return [{"label": "IPs", "rules": [{"type": "cidr", "value": "10.0.0.0/8"}]}]


class TestGetOverview:
    def test_returns_exceptions_and_presets(self):
        r = _mock_router()
        with patch("services.vpn_bypass_service.sm") as mock_sm:
            mock_sm.get_config.return_value = _base_config(
                vpn_bypass={
                    "exceptions": [
                        {"id": "byp_1", "name": "Test", "enabled": True,
                         "scope": "global", "scope_target": None,
                         "rule_blocks": _simple_blocks()},
                    ],
                    "dnsmasq_full_installed": True,
                }
            )
            svc = VpnBypassService(r)
            result = svc.get_overview()

        assert len(result["exceptions"]) == 1
        assert "lol" in result["presets"]
        assert result["presets"]["lol"]["builtin"] is True
        # Presets now have rule_blocks
        assert "rule_blocks" in result["presets"]["lol"]

    def test_migrates_old_flat_rules(self):
        r = _mock_router()
        with patch("services.vpn_bypass_service.sm") as mock_sm:
            mock_sm.get_config.return_value = _base_config(
                vpn_bypass={
                    "exceptions": [
                        {"id": "byp_old", "name": "Old", "enabled": True,
                         "scope": "global", "scope_target": None,
                         "rules": [
                             {"type": "cidr", "value": "10.0.0.0/8"},
                             {"type": "port", "value": "80", "protocol": "tcp"},
                         ]},
                    ],
                }
            )
            svc = VpnBypassService(r)
            result = svc.get_overview()

        exc = result["exceptions"][0]
        assert "rule_blocks" in exc
        assert len(exc["rule_blocks"]) == 2  # each old rule becomes its own block
        assert exc["rule_blocks"][0]["rules"][0]["value"] == "10.0.0.0/8"


class TestAddException:
    def test_add_with_rule_blocks(self):
        r = _mock_router()
        with patch("services.vpn_bypass_service.sm") as mock_sm:
            mock_sm.get_config.return_value = _base_config()
            svc = VpnBypassService(r)
            result = svc.add_exception({
                "name": "My Rule",
                "scope": "global",
                "rule_blocks": _simple_blocks(),
            })

        assert result["success"] is True
        assert result["exception"]["id"].startswith("byp_")
        assert len(result["exception"]["rule_blocks"]) == 1

    def test_add_from_preset_copies_blocks(self):
        r = _mock_router()
        with patch("services.vpn_bypass_service.sm") as mock_sm:
            mock_sm.get_config.return_value = _base_config()
            svc = VpnBypassService(r)
            result = svc.add_exception({
                "name": "LoL",
                "preset_id": "lol",
                "scope": "global",
            })

        exc = result["exception"]
        assert exc["preset_id"] == "lol"
        assert len(exc["rule_blocks"]) == 2  # LoL has 2 blocks (IPs + domains)

    def test_add_raises_on_empty_blocks(self):
        r = _mock_router()
        with patch("services.vpn_bypass_service.sm") as mock_sm:
            mock_sm.get_config.return_value = _base_config()
            svc = VpnBypassService(r)
            with pytest.raises(ValueError, match="At least one rule block"):
                svc.add_exception({"name": "Empty"})

    def test_add_validates_group_scope(self):
        r = _mock_router()
        with patch("services.vpn_bypass_service.sm") as mock_sm:
            mock_sm.get_config.return_value = _base_config()
            svc = VpnBypassService(r)
            with pytest.raises(ValueError, match="scope_target.*required"):
                svc.add_exception({
                    "name": "Bad",
                    "scope": "group",
                    "rule_blocks": _simple_blocks(),
                })


class TestUpdateException:
    def test_update_name(self):
        r = _mock_router()
        with patch("services.vpn_bypass_service.sm") as mock_sm:
            mock_sm.get_config.return_value = _base_config(
                vpn_bypass={
                    "exceptions": [
                        {"id": "byp_1", "name": "Old", "enabled": True,
                         "scope": "global", "scope_target": None,
                         "rule_blocks": _simple_blocks()},
                    ],
                }
            )
            svc = VpnBypassService(r)
            result = svc.update_exception("byp_1", {"name": "New"})

        assert result["exception"]["name"] == "New"

    def test_update_nonexistent_raises(self):
        r = _mock_router()
        with patch("services.vpn_bypass_service.sm") as mock_sm:
            mock_sm.get_config.return_value = _base_config(vpn_bypass={"exceptions": []})
            svc = VpnBypassService(r)
            with pytest.raises(ValueError, match="not found"):
                svc.update_exception("byp_nope", {"name": "X"})


class TestRemoveException:
    def test_remove_persists_and_reapplies(self):
        r = _mock_router()
        with patch("services.vpn_bypass_service.sm") as mock_sm:
            mock_sm.get_config.return_value = _base_config(
                vpn_bypass={
                    "exceptions": [
                        {"id": "byp_1", "name": "X", "enabled": True,
                         "scope": "global", "scope_target": None,
                         "rule_blocks": _simple_blocks()},
                    ],
                }
            )
            svc = VpnBypassService(r)
            result = svc.remove_exception("byp_1")

        assert result["success"] is True
        r.vpn_bypass.apply_all.assert_called_once()


class TestToggleException:
    def test_toggle_disable(self):
        r = _mock_router()
        with patch("services.vpn_bypass_service.sm") as mock_sm:
            mock_sm.get_config.return_value = _base_config(
                vpn_bypass={
                    "exceptions": [
                        {"id": "byp_1", "name": "X", "enabled": True,
                         "scope": "global", "scope_target": None,
                         "rule_blocks": _simple_blocks()},
                    ],
                }
            )
            svc = VpnBypassService(r)
            result = svc.toggle_exception("byp_1", False)

        assert result["exception"]["enabled"] is False


class TestPresets:
    def test_save_custom_preset_with_blocks(self):
        r = _mock_router()
        with patch("services.vpn_bypass_service.sm") as mock_sm:
            mock_sm.get_config.return_value = _base_config()
            svc = VpnBypassService(r)
            result = svc.save_custom_preset({
                "name": "My Game",
                "rule_blocks": [
                    {"label": "Ports", "rules": [{"type": "port", "value": "9000", "protocol": "udp"}]},
                ],
            })

        assert result["success"] is True
        assert "rule_blocks" in result["preset"]

    def test_cannot_overwrite_builtin(self):
        r = _mock_router()
        with patch("services.vpn_bypass_service.sm") as mock_sm:
            mock_sm.get_config.return_value = _base_config()
            svc = VpnBypassService(r)
            with pytest.raises(ValueError, match="built-in"):
                svc.save_custom_preset({"id": "lol", "name": "Fake"})


class TestOnGroupDeleted:
    def test_disables_affected_exceptions(self):
        r = _mock_router()
        with patch("services.vpn_bypass_service.sm") as mock_sm:
            mock_sm.get_config.return_value = _base_config(
                vpn_bypass={
                    "exceptions": [
                        {"id": "byp_1", "name": "Group rule", "enabled": True,
                         "scope": "group", "scope_target": "prof_123",
                         "rule_blocks": _simple_blocks()},
                        {"id": "byp_2", "name": "Global rule", "enabled": True,
                         "scope": "global", "scope_target": None,
                         "rule_blocks": _simple_blocks()},
                    ],
                }
            )
            svc = VpnBypassService(r)
            svc.on_group_deleted("prof_123")

        call_args = mock_sm.update_config.call_args
        vb = call_args[1]["vpn_bypass"]
        exc1 = next(e for e in vb["exceptions"] if e["id"] == "byp_1")
        exc2 = next(e for e in vb["exceptions"] if e["id"] == "byp_2")
        assert exc1["enabled"] is False
        assert exc2["enabled"] is True


class TestMigrate:
    def test_old_flat_rules_migrated_to_blocks(self):
        old = {"id": "byp_1", "rules": [
            {"type": "cidr", "value": "10.0.0.0/8"},
            {"type": "port", "value": "80", "protocol": "tcp"},
        ]}
        result = VpnBypassService._migrate(old)
        assert "rule_blocks" in result
        assert "rules" not in result
        assert len(result["rule_blocks"]) == 2

    def test_new_format_unchanged(self):
        new = {"id": "byp_1", "rule_blocks": [{"rules": []}]}
        result = VpnBypassService._migrate(new)
        assert result is new


class TestReapplyAll:
    def test_reads_config_and_applies(self):
        r = _mock_router()
        with patch("services.vpn_bypass_service.sm") as mock_sm, \
             patch("persistence.profile_store.load") as mock_load:
            mock_sm.get_config.return_value = _base_config(
                vpn_bypass={
                    "exceptions": [
                        {"id": "byp_1", "name": "X", "enabled": True,
                         "scope": "global", "scope_target": None,
                         "rule_blocks": _simple_blocks()},
                    ],
                }
            )
            mock_load.return_value = {"profiles": []}
            svc = VpnBypassService(r)
            svc.reapply_all()

        r.vpn_bypass.apply_all.assert_called_once()
