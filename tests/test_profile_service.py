"""Tests for ProfileService — profile CRUD and mutation operations."""

import threading
from unittest.mock import MagicMock, patch, call

import pytest

from consts import (
    PROFILE_TYPE_VPN, PROFILE_TYPE_NO_VPN, PROFILE_TYPE_NO_INTERNET,
    PROTO_WIREGUARD, PROTO_OPENVPN, PROTO_WIREGUARD_TCP,
)
from services.profile_service import (
    ProfileService, NotFoundError, ConflictError,
    LimitExceededError, NotLoggedInError, require_vpn_profile,
)


def _make_service(router=None, proton=None):
    if router is None:
        router = MagicMock()
    if proton is None:
        proton = MagicMock()
        proton.is_logged_in = True
    return ProfileService(
        router=router,
        proton=proton,
        ipset=MagicMock(),
        switch_locks={},
        cancel_smart_fn=MagicMock(),
        sync_noint_fn=MagicMock(),
        sync_adblock_fn=MagicMock(),
        reconcile_ipset_fn=MagicMock(),
    )


SAMPLE_ROUTER_INFO = {
    "peer_id": "peer_9001", "peer_num": "9001", "group_id": "1957",
    "tunnel_id": 100, "rule_name": "fvpn_rule_9001", "vpn_protocol": PROTO_WIREGUARD,
}
SAMPLE_SERVER_INFO = {"id": "srv1", "endpoint": "1.2.3.4:51820"}
SAMPLE_PROFILE = {
    "id": "p1", "name": "US East", "type": PROFILE_TYPE_VPN,
    "router_info": SAMPLE_ROUTER_INFO, "server_id": "srv1",
    "options": {}, "server_scope": None,
}


class TestRequireVpnProfile:
    def test_returns_vpn_profile(self):
        with patch("services.profile_service.ps") as mock_ps:
            mock_ps.get_profile.return_value = {"type": PROFILE_TYPE_VPN}
            result = require_vpn_profile("p1")
        assert result["type"] == PROFILE_TYPE_VPN

    def test_raises_not_found(self):
        with patch("services.profile_service.ps") as mock_ps:
            mock_ps.get_profile.return_value = None
            with pytest.raises(NotFoundError):
                require_vpn_profile("p1")

    def test_raises_for_non_vpn(self):
        with patch("services.profile_service.ps") as mock_ps:
            mock_ps.get_profile.return_value = {"type": PROFILE_TYPE_NO_VPN}
            with pytest.raises(ValueError, match="Not a VPN"):
                require_vpn_profile("p1")


class TestCreateProfile:
    def test_creates_no_vpn_profile(self):
        svc = _make_service()
        with patch("services.profile_service.ps") as mock_ps:
            mock_ps.create_profile.return_value = {"id": "p1", "name": "Free", "type": PROFILE_TYPE_NO_VPN}
            mock_ps.normalize_server_scope.return_value = None
            result = svc.create_profile("Free", PROFILE_TYPE_NO_VPN)
        assert result["type"] == PROFILE_TYPE_NO_VPN

    def test_creates_vpn_profile(self):
        svc = _make_service()
        with patch("services.profile_service.ps") as mock_ps, \
             patch("services.profile_service.get_strategy") as mock_gs, \
             patch("services.profile_service.require_protocol_slot"):
            mock_gs.return_value.create.return_value = (
                SAMPLE_ROUTER_INFO, SAMPLE_SERVER_INFO, "wg_key", "2026-01-01",
            )
            mock_ps.create_profile.return_value = {
                "id": "p1", "name": "US", "type": PROFILE_TYPE_VPN,
                "router_info": SAMPLE_ROUTER_INFO,
            }
            mock_ps.normalize_server_scope.return_value = None
            svc.proton.get_server_by_id.return_value = {"id": "srv1"}
            result = svc.create_profile("US", PROFILE_TYPE_VPN, server_id="srv1")
        assert result["type"] == PROFILE_TYPE_VPN

    def test_requires_server_id_for_vpn(self):
        svc = _make_service()
        with patch("services.profile_service.require_protocol_slot"):
            with pytest.raises(ValueError, match="server_id required"):
                svc.create_profile("US", PROFILE_TYPE_VPN)

    def test_requires_proton_login(self):
        svc = _make_service()
        svc.proton.is_logged_in = False
        with patch("services.profile_service.require_protocol_slot"):
            with pytest.raises(NotLoggedInError):
                svc.create_profile("US", PROFILE_TYPE_VPN, server_id="srv1")

    def test_enforces_protocol_limits(self):
        svc = _make_service()
        with patch("services.profile_service.require_protocol_slot") as mock_req:
            mock_req.side_effect = LimitExceededError("Max reached")
            with pytest.raises(LimitExceededError):
                svc.create_profile("US", PROFILE_TYPE_VPN, server_id="srv1")


class TestUpdateProfile:
    def test_updates_metadata(self):
        svc = _make_service()
        with patch("services.profile_service.ps") as mock_ps:
            mock_ps.update_profile.return_value = {
                "id": "p1", "name": "New Name", "type": PROFILE_TYPE_NO_VPN,
                "router_info": {},
            }
            result = svc.update_profile("p1", name="New Name")
        assert result["name"] == "New Name"

    def test_not_found(self):
        svc = _make_service()
        with patch("services.profile_service.ps") as mock_ps:
            mock_ps.update_profile.return_value = None
            with pytest.raises(NotFoundError):
                svc.update_profile("nonexistent", name="X")

    def test_sets_kill_switch_on_router(self):
        svc = _make_service()
        with patch("services.profile_service.ps") as mock_ps:
            mock_ps.update_profile.return_value = {
                "id": "p1", "name": "US", "type": PROFILE_TYPE_VPN,
                "router_info": {"rule_name": "fvpn_rule_9001", "vpn_protocol": PROTO_WIREGUARD},
            }
            svc.update_profile("p1", kill_switch=False)
        svc.router.policy.set_kill_switch.assert_called_once_with("fvpn_rule_9001", False)

    def test_renames_on_router(self):
        svc = _make_service()
        with patch("services.profile_service.ps") as mock_ps:
            mock_ps.update_profile.return_value = {
                "id": "p1", "name": "New", "type": PROFILE_TYPE_VPN,
                "router_info": {
                    "rule_name": "fvpn_rule_9001", "vpn_protocol": PROTO_WIREGUARD,
                    "peer_id": "peer_9001",
                },
            }
            svc.update_profile("p1", name="New")
        svc.router.policy.rename_profile.assert_called_once()


class TestDeleteProfile:
    def test_deletes_vpn_profile(self):
        svc = _make_service()
        with patch("services.profile_service.ps") as mock_ps, \
             patch("services.profile_service.get_strategy") as mock_gs:
            mock_ps.get_profile.return_value = dict(SAMPLE_PROFILE)
            svc.delete_profile("p1")
        mock_ps.delete_profile.assert_called_once_with("p1")
        mock_gs.return_value.delete.assert_called_once()

    def test_deletes_non_vpn_profile(self):
        svc = _make_service()
        with patch("services.profile_service.ps") as mock_ps:
            mock_ps.get_profile.return_value = {"id": "p1", "name": "X", "type": PROFILE_TYPE_NO_VPN}
            svc.delete_profile("p1")
        mock_ps.delete_profile.assert_called_once_with("p1")

    def test_not_found(self):
        svc = _make_service()
        with patch("services.profile_service.ps") as mock_ps:
            mock_ps.get_profile.return_value = None
            with pytest.raises(NotFoundError):
                svc.delete_profile("p1")

    def test_cancels_smart_protocol(self):
        svc = _make_service()
        with patch("services.profile_service.ps") as mock_ps:
            mock_ps.get_profile.return_value = {"id": "p1", "name": "X", "type": PROFILE_TYPE_NO_VPN}
            svc.delete_profile("p1")
        svc._cancel_smart.assert_called_once_with("p1")


class TestChangeType:
    def test_no_vpn_to_no_internet(self):
        svc = _make_service()
        with patch("services.profile_service.ps") as mock_ps:
            mock_ps.get_profile.side_effect = [
                {"id": "p1", "name": "X", "type": PROFILE_TYPE_NO_VPN},
                {"id": "p1", "name": "X", "type": PROFILE_TYPE_NO_INTERNET},
            ]
            result = svc.change_type("p1", PROFILE_TYPE_NO_INTERNET)
        mock_ps.update_profile.assert_called_once_with("p1", type=PROFILE_TYPE_NO_INTERNET)

    def test_same_type_raises(self):
        svc = _make_service()
        with patch("services.profile_service.ps") as mock_ps:
            mock_ps.get_profile.return_value = {"id": "p1", "type": PROFILE_TYPE_VPN}
            with pytest.raises(ValueError, match="already type"):
                svc.change_type("p1", PROFILE_TYPE_VPN)

    def test_invalid_type_raises(self):
        svc = _make_service()
        with patch("services.profile_service.ps") as mock_ps:
            mock_ps.get_profile.return_value = {"id": "p1", "type": PROFILE_TYPE_NO_VPN}
            with pytest.raises(ValueError, match="Invalid type"):
                svc.change_type("p1", "invalid")

    def test_vpn_to_no_vpn_tears_down(self):
        svc = _make_service()
        with patch("services.profile_service.ps") as mock_ps, \
             patch("services.profile_service.get_strategy") as mock_gs:
            mock_ps.get_profile.side_effect = [
                dict(SAMPLE_PROFILE),
                dict(SAMPLE_PROFILE),  # re-read under lock
                {"id": "p1", "type": PROFILE_TYPE_NO_VPN},  # after update
            ]
            svc.change_type("p1", PROFILE_TYPE_NO_VPN)
        mock_gs.return_value.delete.assert_called_once()

    def test_not_found(self):
        svc = _make_service()
        with patch("services.profile_service.ps") as mock_ps:
            mock_ps.get_profile.return_value = None
            with pytest.raises(NotFoundError):
                svc.change_type("p1", PROFILE_TYPE_VPN)


class TestReorderProfiles:
    def test_reorders_and_syncs(self):
        svc = _make_service()
        with patch("services.profile_service.ps") as mock_ps:
            mock_ps.load.return_value = {
                "profiles": [
                    {"id": "p2", "type": PROFILE_TYPE_VPN, "router_info": {"rule_name": "fvpn_rule_9002"}},
                    {"id": "p1", "type": PROFILE_TYPE_VPN, "router_info": {"rule_name": "fvpn_rule_9001"}},
                    {"id": "p3", "type": PROFILE_TYPE_NO_VPN},
                ],
            }
            svc.reorder_profiles(["p1", "p2", "p3"])
        svc.router.policy.reorder_vpn_rules.assert_called_once_with(
            ["fvpn_rule_9001", "fvpn_rule_9002"]
        )

    def test_empty_raises(self):
        svc = _make_service()
        with pytest.raises(ValueError, match="profile_ids required"):
            svc.reorder_profiles([])


class TestSetGuestProfile:
    def test_sets_guest(self):
        svc = _make_service()
        with patch("services.profile_service.ps") as mock_ps:
            mock_ps.set_guest_profile.return_value = True
            svc.set_guest_profile("p1")

    def test_not_found(self):
        svc = _make_service()
        with patch("services.profile_service.ps") as mock_ps:
            mock_ps.set_guest_profile.return_value = False
            with pytest.raises(NotFoundError):
                svc.set_guest_profile("nonexistent")
