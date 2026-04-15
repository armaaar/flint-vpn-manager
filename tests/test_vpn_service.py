"""Tests for vpn_service.py — VPNService business logic.

Uses unittest.mock for router and proton APIs. Tests verify that the
service calls the right methods on its dependencies without testing
router_api or proton_api internals.
"""

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from consts import (
    HEALTH_GREEN,
    HEALTH_RED,
    PROFILE_TYPE_NO_INTERNET,
    PROFILE_TYPE_NO_VPN,
    PROFILE_TYPE_VPN,
    PROTO_OPENVPN,
    PROTO_WIREGUARD,
)
from services.vpn_service import (
    VPNService,
    ConflictError,
    LimitExceededError,
    NotFoundError,
    NotLoggedInError,
    backup_local_state_to_router,
    check_and_auto_restore,
    ROUTER_BACKUP_PATH,
    _local_router_key,
    _router_rule_key,
)


# ── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture
def mock_router():
    router = MagicMock()
    router.policy.get_flint_vpn_rules.return_value = []
    router.devices.get_device_assignments.return_value = {}
    router.devices.get_dhcp_leases.return_value = []
    router.devices.get_client_details.return_value = {}
    router.tunnel.get_tunnel_health.return_value = HEALTH_GREEN
    router.policy.get_kill_switch.return_value = True
    router.policy.get_profile_name.return_value = None
    router.get_router_fingerprint.return_value = "aa:bb:cc:dd:ee:ff"
    router.read_file.return_value = ""
    router.exec.return_value = ""
    return router


@pytest.fixture
def mock_proton():
    proton = MagicMock()
    proton.is_logged_in = True
    proton.get_server_by_id.return_value = MagicMock()
    proton.server_to_dict.return_value = {
        "id": "server-1",
        "name": "US#1",
        "country": "US",
        "city": "New York",
        "load": 42,
    }
    return proton


@pytest.fixture
def service(mock_router, mock_proton):
    return VPNService(mock_router, mock_proton)


# ── Helpers ─────────────────────────────────────────────────────────────────

def _make_local_vpn_profile(peer_id="9001", profile_id="vpn-1", name="TestVPN",
                            protocol=PROTO_WIREGUARD):
    """Build a minimal local VPN profile dict."""
    return {
        "id": profile_id,
        "type": PROFILE_TYPE_VPN,
        "name": name,
        "color": "#3498db",
        "icon": "\U0001f512",
        "is_guest": False,
        "router_info": {
            "rule_name": f"fvpn_rule_{peer_id}",
            "peer_id": peer_id,
            "vpn_protocol": protocol,
        },
        "server_id": "server-1",
        "server": {"id": "server-1", "endpoint": "1.2.3.4"},
        "server_scope": {},
        "options": {},
    }


def _make_router_rule(peer_id="9001", rule_name=None, via_type=PROTO_WIREGUARD,
                      name="TestVPN", killswitch="1"):
    """Build a minimal router rule dict as returned by get_flint_vpn_rules."""
    return {
        "rule_name": rule_name or f"fvpn_rule_{peer_id}",
        "peer_id": peer_id,
        "via_type": via_type,
        "name": name,
        "killswitch": killswitch,
        "enabled": "1",
    }


def _make_non_vpn_profile(profile_id="novpn-1", name="Direct",
                          profile_type=PROFILE_TYPE_NO_VPN, display_order=1):
    """Build a minimal non-VPN profile dict."""
    return {
        "id": profile_id,
        "type": profile_type,
        "name": name,
        "color": "#888",
        "icon": "\U0001f30d",
        "is_guest": False,
        "display_order": display_order,
    }


def _store_data(profiles=None, device_assignments=None):
    """Build a minimal profile_store data dict."""
    return {
        "profiles": profiles or [],
        "device_assignments": device_assignments or {},
    }


# ── TestBuildProfileList ────────────────────────────────────────────────────


class TestBuildProfileList:
    """Tests for VPNService.build_profile_list."""

    @patch("services.profile_list_builder.ps.load")
    def test_empty_no_rules_no_profiles(self, mock_load, service):
        """No router rules + no local profiles -> empty list."""
        mock_load.return_value = _store_data()
        result = service.build_profile_list()
        assert result == []

    @patch("services.profile_list_builder.ps.load")
    def test_merge_router_rule_with_local_vpn(self, mock_load, service, mock_router):
        """Router rule matched to local VPN profile by (protocol, peer_id)."""
        local = _make_local_vpn_profile(peer_id="9001", profile_id="vpn-1")
        mock_load.return_value = _store_data(profiles=[local])
        mock_router.policy.get_flint_vpn_rules.return_value = [
            _make_router_rule(peer_id="9001", name="MyVPN"),
        ]

        result = service.build_profile_list()

        assert len(result) == 1
        p = result[0]
        assert p["id"] == "vpn-1"
        assert p["type"] == PROFILE_TYPE_VPN
        assert p["name"] == "MyVPN"  # from router rule
        assert p["health"] == HEALTH_GREEN
        assert p["kill_switch"] is True
        assert "_orphan" not in p
        assert "_ghost" not in p

    @patch("services.profile_list_builder.ps.load")
    def test_unified_display_order_sorts_all_profiles(self, mock_load, service, mock_router):
        """All profiles are sorted by display_order regardless of type."""
        vpn = _make_local_vpn_profile(peer_id="9001", profile_id="vpn-1")
        vpn["display_order"] = 1
        novpn_b = _make_non_vpn_profile(profile_id="novpn-b", name="B", display_order=2)
        novpn_a = _make_non_vpn_profile(profile_id="novpn-a", name="A", display_order=0)

        mock_load.return_value = _store_data(profiles=[vpn, novpn_b, novpn_a])
        mock_router.policy.get_flint_vpn_rules.return_value = [
            _make_router_rule(peer_id="9001"),
        ]

        result = service.build_profile_list()

        assert len(result) == 3
        assert result[0]["id"] == "novpn-a"  # display_order=0
        assert result[1]["type"] == PROFILE_TYPE_VPN  # display_order=1
        assert result[2]["id"] == "novpn-b"  # display_order=2

    @patch("services.profile_list_builder.ps.load")
    def test_ghost_profile(self, mock_load, service, mock_router):
        """Local VPN profile with no matching router rule -> _ghost=True, health=red."""
        local = _make_local_vpn_profile(peer_id="9001", profile_id="vpn-1")
        mock_load.return_value = _store_data(profiles=[local])
        mock_router.policy.get_flint_vpn_rules.return_value = []  # no matching rule

        result = service.build_profile_list()

        assert len(result) == 1
        p = result[0]
        assert p["_ghost"] is True
        assert p["health"] == HEALTH_RED
        assert p["kill_switch"] is False

    @patch("services.profile_list_builder.ps.load")
    def test_orphan_profile(self, mock_load, service, mock_router):
        """Router rule with no matching local profile -> _orphan=True."""
        mock_load.return_value = _store_data()  # no local profiles
        mock_router.policy.get_flint_vpn_rules.return_value = [
            _make_router_rule(peer_id="9002", name="OrphanVPN"),
        ]

        result = service.build_profile_list()

        assert len(result) == 1
        p = result[0]
        assert p["_orphan"] is True
        assert p["name"] == "OrphanVPN"

    @patch("services.profile_list_builder.ps.load")
    def test_device_count_from_router_assignments(self, mock_load, service, mock_router):
        """device_count reflects router's from_mac assignments."""
        local = _make_local_vpn_profile(peer_id="9001", profile_id="vpn-1")
        mock_load.return_value = _store_data(profiles=[local])
        mock_router.policy.get_flint_vpn_rules.return_value = [
            _make_router_rule(peer_id="9001"),
        ]
        mock_router.devices.get_device_assignments.return_value = {
            "aa:bb:cc:dd:ee:01": "fvpn_rule_9001",
            "aa:bb:cc:dd:ee:02": "fvpn_rule_9001",
        }

        result = service.build_profile_list()

        assert result[0]["device_count"] == 2


# ── TestCreateProfile ───────────────────────────────────────────────────────


class TestCreateProfile:
    """Tests for VPNService.create_profile."""

    @patch("services.profile_service.ps.create_profile")
    def test_create_non_vpn(self, mock_create, service, mock_router):
        """Creating a non-VPN profile doesn't touch the router."""
        mock_create.return_value = {
            "id": "novpn-1", "type": PROFILE_TYPE_NO_VPN, "name": "Direct",
        }

        result = service.create_profile(
            name="Direct", profile_type=PROFILE_TYPE_NO_VPN,
        )

        assert result["type"] == PROFILE_TYPE_NO_VPN
        mock_create.assert_called_once()
        mock_router.policy.set_kill_switch.assert_not_called()

    @patch("services.profile_service.ps.create_profile")
    @patch("services.profile_service.get_strategy")
    @patch("services.vpn_service.ps.get_profiles")
    def test_create_vpn_profile(self, mock_get_profiles, mock_get_strategy,
                                mock_create, service, mock_proton):
        """Creating a VPN profile calls strategy.create and ps.create_profile."""
        mock_get_profiles.return_value = []  # no existing profiles

        mock_strategy = MagicMock()
        mock_strategy.create.return_value = (
            {"rule_name": "fvpn_rule_9001", "peer_id": "9001", "vpn_protocol": PROTO_WIREGUARD},
            {"id": "server-1", "endpoint": "1.2.3.4"},
            "base64_wg_key",
            1807264162,
        )
        mock_get_strategy.return_value = mock_strategy

        mock_create.return_value = {
            "id": "vpn-1", "type": PROFILE_TYPE_VPN, "name": "US VPN",
            "router_info": {"rule_name": "fvpn_rule_9001", "peer_id": "9001",
                            "vpn_protocol": PROTO_WIREGUARD},
        }

        result = service.create_profile(
            name="US VPN",
            profile_type=PROFILE_TYPE_VPN,
            vpn_protocol=PROTO_WIREGUARD,
            server_id="server-1",
        )

        mock_strategy.create.assert_called_once()
        mock_create.assert_called_once()
        assert result["type"] == PROFILE_TYPE_VPN

    @patch("services.vpn_service.ps.get_profiles")
    def test_create_vpn_limit_exceeded(self, mock_get_profiles, service):
        """Too many WG profiles -> LimitExceededError."""
        existing = [
            _make_local_vpn_profile(peer_id=str(9001 + i), profile_id=f"vpn-{i}")
            for i in range(VPNService.MAX_WG_GROUPS)
        ]
        mock_get_profiles.return_value = existing

        with pytest.raises(LimitExceededError, match="WireGuard UDP"):
            service.create_profile(
                name="OneMore", profile_type=PROFILE_TYPE_VPN,
                vpn_protocol=PROTO_WIREGUARD, server_id="server-1",
            )

    def test_create_vpn_no_server_id(self, service):
        """VPN profile without server_id -> ValueError."""
        with pytest.raises(ValueError, match="server_id required"):
            service.create_profile(
                name="NoServer", profile_type=PROFILE_TYPE_VPN,
                vpn_protocol=PROTO_WIREGUARD, server_id=None,
            )

    @patch("services.vpn_service.ps.get_profiles")
    def test_create_vpn_not_logged_in(self, mock_get_profiles, service, mock_proton):
        """VPN profile when Proton not logged in -> NotLoggedInError."""
        mock_get_profiles.return_value = []
        mock_proton.is_logged_in = False

        with pytest.raises(NotLoggedInError):
            service.create_profile(
                name="Offline", profile_type=PROFILE_TYPE_VPN,
                vpn_protocol=PROTO_WIREGUARD, server_id="server-1",
            )


# ── TestDeleteProfile ───────────────────────────────────────────────────────


class TestDeleteProfile:
    """Tests for VPNService.delete_profile."""

    @patch("services.vpn_service.noint_sync.sync_noint_to_router")
    @patch("services.profile_service.ps.delete_profile")
    @patch("services.profile_service.ps.get_profile")
    def test_delete_non_vpn(self, mock_get, mock_delete, mock_noint_sync, service):
        """Deleting a non-VPN profile doesn't call strategy.delete."""
        mock_get.return_value = _make_non_vpn_profile(profile_id="novpn-1")

        service.delete_profile("novpn-1")

        mock_delete.assert_called_once_with("novpn-1")
        mock_noint_sync.assert_called_once()

    @patch("services.vpn_service.noint_sync.sync_noint_to_router")
    @patch("services.profile_service.ps.delete_profile")
    @patch("services.profile_service.ps.get_profile")
    @patch("services.profile_service.get_strategy")
    def test_delete_vpn(self, mock_get_strategy, mock_get, mock_delete,
                        mock_noint_sync, service):
        """Deleting a VPN profile calls strategy.delete."""
        mock_get.return_value = _make_local_vpn_profile(profile_id="vpn-1")
        mock_strategy = MagicMock()
        mock_get_strategy.return_value = mock_strategy

        service.delete_profile("vpn-1")

        mock_strategy.delete.assert_called_once()
        mock_delete.assert_called_once_with("vpn-1")
        mock_noint_sync.assert_called_once()

    @patch("services.profile_service.ps.get_profile")
    def test_delete_nonexistent(self, mock_get, service):
        """Deleting a non-existent profile -> NotFoundError."""
        mock_get.return_value = None

        with pytest.raises(NotFoundError):
            service.delete_profile("doesnt-exist")


# ── TestSwitchServer ────────────────────────────────────────────────────────


class TestSwitchServer:
    """Tests for VPNService.switch_server."""

    @patch("services.profile_service.ps.get_profile")
    @patch("services.profile_service.ps.update_profile")
    @patch("services.profile_service.get_strategy")
    def test_successful_switch(self, mock_get_strategy, mock_update, mock_get,
                               service, mock_proton):
        """Successful switch calls strategy.switch_server and updates profile_store."""
        profile = _make_local_vpn_profile(profile_id="vpn-1")
        # get_profile is called twice: once at the start, once to return the result
        mock_get.return_value = profile

        mock_strategy = MagicMock()
        mock_strategy.switch_server.return_value = (
            None,  # new_ri (None for WG = keep old)
            {"id": "server-2", "endpoint": "5.6.7.8"},
            None,  # wg_key
            None,  # cert_expiry
        )
        mock_get_strategy.return_value = mock_strategy

        result = service.switch_server("vpn-1", "server-2")

        mock_strategy.switch_server.assert_called_once()
        mock_update.assert_called_once()
        update_kwargs = mock_update.call_args[1]
        assert update_kwargs["server_id"] == "server-2"

    @patch("services.profile_service.ps.get_profile")
    @patch("services.profile_service.ps.update_profile")
    @patch("services.profile_service.get_strategy")
    def test_concurrent_switch_raises(self, mock_get_strategy, mock_update,
                                      mock_get, service, mock_proton):
        """Second concurrent switch on same profile raises RuntimeError."""
        import threading

        profile = _make_local_vpn_profile(profile_id="vpn-1")
        mock_get.return_value = profile

        # Use an Event so the first thread holds the lock while the second
        # thread attempts to acquire it.
        hold = threading.Event()

        def slow_switch(*args, **kwargs):
            hold.wait(timeout=5)  # hold the lock until released
            return (None, {"id": "server-2"}, None, None)

        mock_strategy = MagicMock()
        mock_strategy.switch_server.side_effect = slow_switch
        mock_get_strategy.return_value = mock_strategy

        # Start thread 1 which will hold the lock
        t1 = threading.Thread(target=service.switch_server, args=("vpn-1", "server-2"))
        t1.start()
        time.sleep(0.1)  # let t1 acquire the lock

        # Thread 2 should fail immediately
        with pytest.raises(RuntimeError, match="in progress"):
            service.switch_server("vpn-1", "server-2")

        hold.set()  # release t1
        t1.join(timeout=5)

    @patch("services.profile_service.ps.get_profile")
    def test_switch_nonexistent_profile(self, mock_get, service):
        """Switching a non-existent profile -> NotFoundError."""
        mock_get.return_value = None

        with pytest.raises(NotFoundError):
            service.switch_server("doesnt-exist", "server-2")

    @patch("services.profile_service.ps.get_profile")
    def test_switch_non_vpn_profile(self, mock_get, service):
        """Switching a non-VPN profile -> ValueError."""
        mock_get.return_value = _make_non_vpn_profile(profile_id="novpn-1")

        with pytest.raises(ValueError, match="Not a VPN"):
            service.switch_server("novpn-1", "server-2")


# ── TestDevices ─────────────────────────────────────────────────────────────


class TestDevices:
    """Tests for device list building and caching."""

    @patch("services.vpn_service.ps.load")
    def test_build_devices_live_merges_sources(self, mock_load,
                                               service, mock_router):
        """build_devices_live merges DHCP leases with gl-clients data."""
        mock_load.return_value = _store_data()
        mock_router.devices.get_dhcp_leases.return_value = [
            {"mac": "AA:BB:CC:DD:EE:01", "ip": "192.168.8.100", "hostname": "phone"},
        ]
        mock_router.devices.get_client_details.return_value = {
            "AA:BB:CC:DD:EE:01": {
                "online": True,
                "device_class": "phone",
                "alias": "My Phone",
                "rx_speed": 100,
                "tx_speed": 50,
            },
        }

        devices = service.build_devices_live()

        assert len(devices) == 1
        d = devices[0]
        assert d["mac"] == "aa:bb:cc:dd:ee:01"
        assert d["ip"] == "192.168.8.100"
        assert d["hostname"] == "phone"
        assert d["label"] == "My Phone"
        assert d["router_online"] is True
        assert d["display_name"] == "My Phone"  # label takes precedence

    @patch("services.vpn_service.ps.load")
    def test_device_cache_ttl(self, mock_load, service, mock_router):
        """Second call within TTL returns cached data without rebuilding."""
        mock_load.return_value = _store_data()
        mock_router.devices.get_dhcp_leases.return_value = [
            {"mac": "AA:BB:CC:DD:EE:01", "ip": "192.168.8.100", "hostname": "phone"},
        ]
        mock_router.devices.get_client_details.return_value = {}

        first = service.get_devices_cached()
        second = service.get_devices_cached()

        # router.get_dhcp_leases should only be called once (cached on second call)
        assert mock_router.devices.get_dhcp_leases.call_count == 1
        assert first is second

    @patch("services.vpn_service.ps.load")
    def test_invalidate_device_cache(self, mock_load, service, mock_router):
        """invalidate_device_cache forces a rebuild on next call."""
        mock_load.return_value = _store_data()
        mock_router.devices.get_dhcp_leases.return_value = [
            {"mac": "AA:BB:CC:DD:EE:01", "ip": "192.168.8.100", "hostname": "phone"},
        ]
        mock_router.devices.get_client_details.return_value = {}

        service.get_devices_cached()
        service.invalidate_device_cache()
        service.get_devices_cached()

        # After invalidation, router is queried again
        assert mock_router.devices.get_dhcp_leases.call_count == 2


# ── TestAssignDevice ────────────────────────────────────────────────────────


class TestAssignDevice:
    """Tests for VPNService.assign_device."""

    @patch("services.vpn_service.noint_sync.sync_noint_to_router")
    @patch("services.vpn_service.ps.get_profile")
    @patch("services.vpn_service.ps.load")
    @patch("services.vpn_service.ps.validate_mac")
    def test_assign_to_vpn(self, mock_validate, mock_load, mock_get_profile,
                           mock_noint_sync, service, mock_router):
        """Assigning to VPN profile calls router.remove_device_from_all_vpn + set_device_vpn."""
        mock_validate.return_value = "aa:bb:cc:dd:ee:01"
        mock_load.return_value = _store_data()
        mock_get_profile.return_value = _make_local_vpn_profile(profile_id="vpn-1")

        service.assign_device("aa:bb:cc:dd:ee:01", "vpn-1")

        mock_router.devices.remove_device_from_all_vpn.assert_called_once_with("aa:bb:cc:dd:ee:01")
        mock_router.devices.set_device_vpn.assert_called_once_with(
            "aa:bb:cc:dd:ee:01", "fvpn_rule_9001",
        )
        mock_noint_sync.assert_called_once()

    @patch("services.vpn_service.noint_sync.sync_noint_to_router")
    @patch("services.vpn_service.ps.assign_device")
    @patch("services.vpn_service.ps.get_profile")
    @patch("services.vpn_service.ps.load")
    @patch("services.vpn_service.ps.validate_mac")
    def test_assign_to_non_vpn(self, mock_validate, mock_load, mock_get_profile,
                               mock_assign, mock_noint_sync, service, mock_router):
        """Assigning to non-VPN profile calls ps.assign_device."""
        mock_validate.return_value = "aa:bb:cc:dd:ee:01"
        mock_load.return_value = _store_data()
        mock_get_profile.return_value = _make_non_vpn_profile(profile_id="novpn-1")

        service.assign_device("aa:bb:cc:dd:ee:01", "novpn-1")

        mock_assign.assert_called_once_with("aa:bb:cc:dd:ee:01", "novpn-1")
        mock_router.devices.set_device_vpn.assert_not_called()

    @patch("services.vpn_service.noint_sync.sync_noint_to_router")
    @patch("services.vpn_service.ps.assign_device")
    @patch("services.vpn_service.ps.get_profile")
    @patch("services.vpn_service.ps.load")
    @patch("services.vpn_service.ps.validate_mac")
    def test_unassign_sticky_none(self, mock_validate, mock_load, mock_get_profile,
                                  mock_assign, mock_noint_sync, service, mock_router):
        """Unassigning (profile_id=None) writes sticky-None via ps.assign_device."""
        mock_validate.return_value = "aa:bb:cc:dd:ee:01"
        mock_load.return_value = _store_data()
        # get_profile is called for logging but returns None since profile_id is None
        mock_get_profile.return_value = None

        service.assign_device("aa:bb:cc:dd:ee:01", None)

        mock_assign.assert_called_once_with("aa:bb:cc:dd:ee:01", None)
        mock_router.devices.remove_device_from_all_vpn.assert_called_once()

    @patch("services.vpn_service.ps.get_profile")
    @patch("services.vpn_service.ps.load")
    @patch("services.vpn_service.ps.validate_mac")
    def test_assign_to_nonexistent_profile(self, mock_validate, mock_load,
                                           mock_get_profile, service):
        """Assigning to a non-existent profile -> NotFoundError."""
        mock_validate.return_value = "aa:bb:cc:dd:ee:01"
        mock_load.return_value = _store_data()
        mock_get_profile.return_value = None

        with pytest.raises(NotFoundError, match="Profile not found"):
            service.assign_device("aa:bb:cc:dd:ee:01", "doesnt-exist")


# ── TestSyncLanToRouter ────────────────────────────────────────────────────


class TestSyncNointToRouter:
    """Tests for VPNService.sync_noint_to_router."""

    @patch("services.vpn_service.noint_sync.sync_noint_to_router")
    @patch("services.vpn_service.ps.load")
    def test_delegates_to_noint_sync(self, mock_load, mock_sync, service, mock_router):
        """sync_noint_to_router delegates to noint_sync.sync_noint_to_router."""
        mock_load.return_value = _store_data()
        mock_sync.return_value = {"applied": True, "uci_lines": 5, "membership_ops": 2, "reload": False}

        service.sync_noint_to_router()

        mock_sync.assert_called_once_with(mock_router, store=mock_load.return_value)

    @patch("services.vpn_service.noint_sync.sync_noint_to_router")
    @patch("services.vpn_service.ps.load")
    def test_sync_failure_does_not_propagate(self, mock_load, mock_sync, service):
        """Noint sync failures are logged but don't raise."""
        mock_load.return_value = _store_data()
        mock_sync.side_effect = Exception("SSH down")

        # Should not raise
        service.sync_noint_to_router()


# ── TestBackupRestore ──────────────────────────────────────────────────────


class TestBackupRestore:
    """Tests for backup_local_state_to_router and check_and_auto_restore."""

    def test_backup_writes_to_router(self, tmp_path, mock_router):
        """backup_local_state_to_router writes wrapped JSON to the router."""
        store_file = tmp_path / "profile_store.json"
        store_file.write_text(json.dumps({"profiles": [], "device_assignments": {}}))

        backup_local_state_to_router(mock_router, store_file)

        mock_router.write_file.assert_called_once()
        call_args = mock_router.write_file.call_args
        assert call_args[0][0] == ROUTER_BACKUP_PATH
        written = json.loads(call_args[0][1])
        assert "_meta" in written
        assert "saved_at" in written["_meta"]
        assert "data" in written
        assert written["data"]["profiles"] == []

    def test_backup_skips_missing_file(self, tmp_path, mock_router):
        """backup_local_state_to_router silently skips if file doesn't exist."""
        missing = tmp_path / "doesnt_exist.json"

        backup_local_state_to_router(mock_router, missing)

        mock_router.write_file.assert_not_called()

    @patch("services.backup_service.ps.save")
    def test_auto_restore_always_restores_from_router(self, mock_save, mock_router):
        """check_and_auto_restore always overwrites local with router backup."""
        backup_data = {"profiles": [{"id": "restored"}], "device_assignments": {}}
        wrapped = {
            "_meta": {
                "saved_at": datetime.now(timezone.utc).isoformat(),
                "router_fingerprint": "aa:bb:cc:dd:ee:ff",
            },
            "data": backup_data,
        }
        mock_router.read_file.return_value = json.dumps(wrapped)

        check_and_auto_restore(mock_router)

        mock_save.assert_called_once_with(backup_data)

    @patch("services.backup_service.ps.save")
    def test_auto_restore_resets_on_new_router(self, mock_save, mock_router):
        """check_and_auto_restore resets to empty store when no backup exists."""
        mock_router.read_file.return_value = ""

        check_and_auto_restore(mock_router)

        mock_save.assert_called_once()
        saved_data = mock_save.call_args[0][0]
        assert saved_data["profiles"] == []
        assert saved_data["device_assignments"] == {}

    @patch("services.backup_service.ps.save")
    def test_auto_restore_leaves_local_on_unparseable(self, mock_save, mock_router):
        """check_and_auto_restore leaves local alone if backup is corrupt."""
        mock_router.read_file.return_value = "not valid json{{"

        check_and_auto_restore(mock_router)

        mock_save.assert_not_called()

    @patch("services.backup_service.ps.save")
    def test_auto_restore_leaves_local_on_ssh_failure(self, mock_save, mock_router):
        """check_and_auto_restore leaves local alone if SSH read fails."""
        mock_router.read_file.side_effect = Exception("SSH connection refused")

        check_and_auto_restore(mock_router)

        mock_save.assert_not_called()


# ── TestConnectDisconnect ──────────────────────────────────────────────────


class TestConnectDisconnect:
    """Tests for connect_profile and disconnect_profile."""

    @patch("services.vpn_service.get_strategy")
    @patch("services.profile_service.ps.get_profile")
    def test_connect(self, mock_get, mock_get_strategy, service):
        """connect_profile calls strategy.connect."""
        mock_get.return_value = _make_local_vpn_profile(profile_id="vpn-1")
        mock_strategy = MagicMock()
        mock_strategy.connect.return_value = HEALTH_GREEN
        mock_get_strategy.return_value = mock_strategy

        result = service.connect_profile("vpn-1")

        mock_strategy.connect.assert_called_once()
        assert result["success"] is True
        assert result["health"] == HEALTH_GREEN

    @patch("services.vpn_service.get_strategy")
    @patch("services.profile_service.ps.get_profile")
    def test_disconnect(self, mock_get, mock_get_strategy, service):
        """disconnect_profile calls strategy.disconnect."""
        mock_get.return_value = _make_local_vpn_profile(profile_id="vpn-1")
        mock_strategy = MagicMock()
        mock_get_strategy.return_value = mock_strategy

        result = service.disconnect_profile("vpn-1")

        mock_strategy.disconnect.assert_called_once()
        assert result["success"] is True
        assert result["health"] == HEALTH_RED

    @patch("services.profile_service.ps.get_profile")
    def test_connect_not_found(self, mock_get, service):
        """connect_profile with unknown profile -> NotFoundError."""
        mock_get.return_value = None

        with pytest.raises(NotFoundError):
            service.connect_profile("doesnt-exist")

    @patch("services.profile_service.ps.get_profile")
    def test_disconnect_not_found(self, mock_get, service):
        """disconnect_profile with unknown profile -> NotFoundError."""
        mock_get.return_value = None

        with pytest.raises(NotFoundError):
            service.disconnect_profile("doesnt-exist")
