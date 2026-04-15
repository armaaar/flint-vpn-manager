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


class TestGetOverview:
    def test_returns_exceptions_and_presets(self):
        r = _mock_router()
        with patch("services.vpn_bypass_service.sm") as mock_sm:
            mock_sm.get_config.return_value = _base_config(
                vpn_bypass={
                    "exceptions": [
                        {"id": "byp_1", "name": "Test", "enabled": True,
                         "scope": "global", "scope_target": None,
                         "rules": [{"type": "cidr", "value": "10.0.0.0/8"}]},
                    ],
                    "custom_presets": {
                        "my_game": {"name": "My Game", "rules": []},
                    },
                    "dnsmasq_full_installed": True,
                }
            )
            svc = VpnBypassService(r)
            result = svc.get_overview()

        assert len(result["exceptions"]) == 1
        assert "lol" in result["presets"]
        assert "valorant" in result["presets"]
        assert "my_game" in result["presets"]
        assert result["presets"]["lol"]["builtin"] is True
        assert result["presets"]["my_game"]["builtin"] is False
        assert result["dnsmasq_full_installed"] is True

    def test_checks_dnsmasq_live_when_cached_false(self):
        r = _mock_router()
        r.vpn_bypass.check_dnsmasq_full.return_value = True
        with patch("services.vpn_bypass_service.sm") as mock_sm:
            mock_sm.get_config.return_value = _base_config(
                vpn_bypass={"dnsmasq_full_installed": False}
            )
            svc = VpnBypassService(r)
            result = svc.get_overview()

        assert result["dnsmasq_full_installed"] is True
        r.vpn_bypass.check_dnsmasq_full.assert_called_once()


class TestAddException:
    def test_add_custom_exception(self):
        r = _mock_router()
        with patch("services.vpn_bypass_service.sm") as mock_sm:
            mock_sm.get_config.return_value = _base_config()
            svc = VpnBypassService(r)
            result = svc.add_exception({
                "name": "My Rule",
                "scope": "global",
                "rules": [{"type": "cidr", "value": "10.0.0.0/8"}],
            })

        assert result["success"] is True
        assert result["exception"]["name"] == "My Rule"
        assert result["exception"]["id"].startswith("byp_")
        mock_sm.update_config.assert_called_once()
        r.vpn_bypass.apply_all.assert_called_once()

    def test_add_from_preset(self):
        r = _mock_router()
        with patch("services.vpn_bypass_service.sm") as mock_sm:
            mock_sm.get_config.return_value = _base_config()
            svc = VpnBypassService(r)
            result = svc.add_exception({
                "name": "LoL",
                "preset_id": "lol",
                "scope": "device",
                "scope_target": "aa:bb:cc:dd:ee:ff",
            })

        exc = result["exception"]
        assert exc["preset_id"] == "lol"
        assert len(exc["rules"]) > 0
        assert exc["scope"] == "device"

    def test_add_raises_on_empty_rules(self):
        r = _mock_router()
        with patch("services.vpn_bypass_service.sm") as mock_sm:
            mock_sm.get_config.return_value = _base_config()
            svc = VpnBypassService(r)
            with pytest.raises(ValueError, match="At least one rule"):
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
                    "rules": [{"type": "cidr", "value": "10.0.0.0/8"}],
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
                         "rules": [{"type": "cidr", "value": "10.0.0.0/8"}]},
                    ],
                }
            )
            svc = VpnBypassService(r)
            result = svc.update_exception("byp_1", {"name": "New Name"})

        assert result["exception"]["name"] == "New Name"

    def test_update_nonexistent_raises(self):
        r = _mock_router()
        with patch("services.vpn_bypass_service.sm") as mock_sm:
            mock_sm.get_config.return_value = _base_config(
                vpn_bypass={"exceptions": []}
            )
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
                         "scope": "global", "scope_target": None, "rules": []},
                    ],
                }
            )
            svc = VpnBypassService(r)
            result = svc.remove_exception("byp_1")

        assert result["success"] is True
        mock_sm.update_config.assert_called_once()
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
                         "rules": [{"type": "cidr", "value": "10.0.0.0/8"}]},
                    ],
                }
            )
            svc = VpnBypassService(r)
            result = svc.toggle_exception("byp_1", False)

        assert result["exception"]["enabled"] is False


class TestPresets:
    def test_save_custom_preset(self):
        r = _mock_router()
        with patch("services.vpn_bypass_service.sm") as mock_sm:
            mock_sm.get_config.return_value = _base_config()
            svc = VpnBypassService(r)
            result = svc.save_custom_preset({
                "name": "My Game",
                "rules": [{"type": "port", "value": "9000", "protocol": "udp"}],
            })

        assert result["success"] is True
        assert result["preset_id"].startswith("custom_")
        mock_sm.update_config.assert_called_once()

    def test_cannot_overwrite_builtin(self):
        r = _mock_router()
        with patch("services.vpn_bypass_service.sm") as mock_sm:
            mock_sm.get_config.return_value = _base_config()
            svc = VpnBypassService(r)
            with pytest.raises(ValueError, match="built-in"):
                svc.save_custom_preset({"id": "lol", "name": "Fake"})

    def test_delete_custom_preset(self):
        r = _mock_router()
        with patch("services.vpn_bypass_service.sm") as mock_sm:
            mock_sm.get_config.return_value = _base_config(
                vpn_bypass={"custom_presets": {"my_game": {"name": "X", "rules": []}}}
            )
            svc = VpnBypassService(r)
            result = svc.delete_custom_preset("my_game")

        assert result["success"] is True

    def test_cannot_delete_builtin(self):
        r = _mock_router()
        with patch("services.vpn_bypass_service.sm") as mock_sm:
            mock_sm.get_config.return_value = _base_config()
            svc = VpnBypassService(r)
            with pytest.raises(ValueError, match="built-in"):
                svc.delete_custom_preset("lol")


class TestOnGroupDeleted:
    def test_disables_affected_exceptions(self):
        r = _mock_router()
        with patch("services.vpn_bypass_service.sm") as mock_sm:
            mock_sm.get_config.return_value = _base_config(
                vpn_bypass={
                    "exceptions": [
                        {"id": "byp_1", "name": "LoL for group", "enabled": True,
                         "scope": "group", "scope_target": "prof_123",
                         "rules": [{"type": "cidr", "value": "10.0.0.0/8"}]},
                        {"id": "byp_2", "name": "Global rule", "enabled": True,
                         "scope": "global", "scope_target": None,
                         "rules": [{"type": "cidr", "value": "10.0.0.0/8"}]},
                    ],
                }
            )
            svc = VpnBypassService(r)
            svc.on_group_deleted("prof_123")

        # Should have persisted with byp_1 disabled
        call_args = mock_sm.update_config.call_args
        vb = call_args[1]["vpn_bypass"]
        exc1 = next(e for e in vb["exceptions"] if e["id"] == "byp_1")
        exc2 = next(e for e in vb["exceptions"] if e["id"] == "byp_2")
        assert exc1["enabled"] is False
        assert exc2["enabled"] is True

    def test_no_change_when_no_match(self):
        r = _mock_router()
        with patch("services.vpn_bypass_service.sm") as mock_sm:
            mock_sm.get_config.return_value = _base_config(
                vpn_bypass={
                    "exceptions": [
                        {"id": "byp_1", "name": "X", "enabled": True,
                         "scope": "global", "scope_target": None, "rules": []},
                    ],
                }
            )
            svc = VpnBypassService(r)
            svc.on_group_deleted("prof_other")

        mock_sm.update_config.assert_not_called()


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
                         "rules": [{"type": "cidr", "value": "10.0.0.0/8"}]},
                    ],
                }
            )
            mock_load.return_value = {"profiles": []}
            svc = VpnBypassService(r)
            svc.reapply_all()

        r.vpn_bypass.apply_all.assert_called_once()


class TestValidateScope:
    def test_global_clears_target(self):
        exc = {"scope": "global", "scope_target": "leftover"}
        VpnBypassService._validate_scope(exc)
        assert exc["scope_target"] is None

    def test_invalid_scope_raises(self):
        with pytest.raises(ValueError, match="Invalid scope"):
            VpnBypassService._validate_scope({"scope": "bad"})
