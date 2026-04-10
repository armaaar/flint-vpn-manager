"""Tests for app.py — Flask REST API endpoints.

Uses Flask's test client. Router and ProtonVPN APIs are mocked.
"""

import json

import pytest
from unittest.mock import MagicMock, patch

import profile_store as ps
import secrets_manager as sm
from vpn_service import (
    check_and_auto_restore, ROUTER_BACKUP_PATH,
)


@pytest.fixture
def tmp_data(tmp_path):
    """Redirect all file-based stores to tmp dir."""
    # Profile store
    orig_ps_dir = ps.DATA_DIR
    orig_ps_file = ps.STORE_FILE
    ps.DATA_DIR = tmp_path
    ps.STORE_FILE = tmp_path / "profile_store.json"

    # Secrets manager
    orig_sm_dir = sm.DATA_DIR
    orig_sm_secrets = sm.SECRETS_FILE
    orig_sm_config = sm.CONFIG_FILE
    sm.DATA_DIR = tmp_path
    sm.SECRETS_FILE = tmp_path / "secrets.enc"
    sm.CONFIG_FILE = tmp_path / "config.json"

    yield tmp_path

    ps.DATA_DIR = orig_ps_dir
    ps.STORE_FILE = orig_ps_file
    sm.DATA_DIR = orig_sm_dir
    sm.SECRETS_FILE = orig_sm_secrets
    sm.CONFIG_FILE = orig_sm_config


@pytest.fixture
def client(tmp_data):
    """Flask test client with mocked router/proton APIs."""
    import app as flask_app

    flask_app.app.config["TESTING"] = True
    flask_app._session_unlocked = False
    flask_app._router_api = MagicMock()
    flask_app._proton_api = MagicMock()

    with flask_app.app.test_client() as c:
        yield c, flask_app


@pytest.fixture
def unlocked_client(client):
    """Test client with session pre-unlocked."""
    from vpn_service import VPNService
    c, app_mod = client
    # Setup secrets first
    sm.setup("user", "pass", "rpass", "master")
    app_mod._session_unlocked = True
    # Create the service wrapping the same mock objects the tests configure
    app_mod._service = VPNService(app_mod._router_api, app_mod._proton_api)
    return c, app_mod


class TestStatusEndpoint:
    def test_setup_needed(self, client):
        c, _ = client
        resp = c.get("/api/status")
        assert resp.json["status"] == "setup-needed"

    def test_locked(self, client):
        c, _ = client
        sm.setup("u", "p", "r", "m")
        resp = c.get("/api/status")
        assert resp.json["status"] == "locked"

    def test_unlocked(self, unlocked_client):
        c, app_mod = unlocked_client
        mock_proton = MagicMock()
        mock_proton.is_logged_in = True
        app_mod._proton_api = mock_proton
        resp = c.get("/api/status")
        assert resp.json["status"] == "unlocked"


class TestSetupEndpoint:
    def test_setup_success(self, client):
        c, _ = client
        resp = c.post("/api/setup", json={
            "proton_user": "user",
            "proton_pass": "pass",
            "router_pass": "rpass",
            "master_password": "master",
        })
        assert resp.json["success"] is True
        assert sm.is_setup()

    def test_setup_missing_fields(self, client):
        c, _ = client
        resp = c.post("/api/setup", json={"proton_user": "user"})
        assert resp.status_code == 400


class TestUnlockEndpoint:
    def test_unlock_success(self, client):
        c, app_mod = client
        sm.setup("u", "p", "r", "master")
        # Mock start_tracker to avoid actual router connection
        with patch("app.start_tracker"):
            resp = c.post("/api/unlock", json={"master_password": "master"})
        assert resp.json["success"] is True

    def test_unlock_wrong_password(self, client):
        c, _ = client
        sm.setup("u", "p", "r", "master")
        resp = c.post("/api/unlock", json={"master_password": "wrong"})
        assert resp.status_code == 401


class TestProfileEndpoints:
    def test_get_profiles_empty(self, unlocked_client):
        c, _ = unlocked_client
        resp = c.get("/api/profiles")
        assert resp.json == []

    def test_create_no_vpn_profile(self, unlocked_client):
        c, _ = unlocked_client
        resp = c.post("/api/profiles", json={
            "name": "Direct", "type": "no_vpn", "color": "#ff0000"
        })
        assert resp.status_code == 201
        assert resp.json["name"] == "Direct"
        assert resp.json["type"] == "no_vpn"

    def test_create_no_internet_profile(self, unlocked_client):
        c, _ = unlocked_client
        resp = c.post("/api/profiles", json={
            "name": "Printers", "type": "no_internet", "icon": "🖨️"
        })
        assert resp.status_code == 201
        assert resp.json["type"] == "no_internet"

    def test_create_missing_fields(self, unlocked_client):
        c, _ = unlocked_client
        resp = c.post("/api/profiles", json={"name": "Test"})
        assert resp.status_code == 400

    def test_update_profile(self, unlocked_client):
        c, _ = unlocked_client
        create = c.post("/api/profiles", json={"name": "Old", "type": "no_vpn"})
        pid = create.json["id"]
        resp = c.put(f"/api/profiles/{pid}", json={"name": "New"})
        assert resp.json["name"] == "New"

    def test_delete_profile(self, unlocked_client):
        c, _ = unlocked_client
        create = c.post("/api/profiles", json={"name": "Del", "type": "no_vpn"})
        pid = create.json["id"]
        resp = c.delete(f"/api/profiles/{pid}")
        assert resp.json["success"] is True
        # Verify deleted
        profiles = c.get("/api/profiles").json
        assert len(profiles) == 0

    def test_delete_nonexistent(self, unlocked_client):
        c, _ = unlocked_client
        resp = c.delete("/api/profiles/nonexistent")
        assert resp.status_code == 404

    def test_profiles_require_unlock(self, client):
        c, _ = client
        sm.setup("u", "p", "r", "m")
        resp = c.get("/api/profiles")
        assert resp.status_code == 401


class TestConnectDisconnect:
    """Stage 2: tunnel status is live from router. No local cache writes."""

    def _make_vpn_profile(self, app_mod):
        """Create a fake VPN profile in the local store with router_info."""
        ps.save({
            **ps._EMPTY_STORE,
            "profiles": [{
                "id": "test-vpn-1",
                "type": "vpn",
                "name": "Test VPN",
                "color": "#3498db",
                "icon": "🔒",
                "is_guest": False,
                "router_info": {
                    "rule_name": "fvpn_rule_9001",
                    "peer_id": "9001",
                    "vpn_protocol": "wireguard",
                },
            }],
        })

    def test_connect_returns_health_from_router(self, unlocked_client):
        c, app_mod = unlocked_client
        self._make_vpn_profile(app_mod)
        app_mod._router_api.bring_tunnel_up.return_value = None
        app_mod._router_api.get_tunnel_health.return_value = "connecting"

        resp = c.post("/api/profiles/test-vpn-1/connect")
        assert resp.status_code == 200
        assert resp.json["success"] is True
        assert resp.json["health"] == "connecting"

    def test_connect_does_not_write_status_to_store(self, unlocked_client):
        c, app_mod = unlocked_client
        self._make_vpn_profile(app_mod)
        app_mod._router_api.bring_tunnel_up.return_value = None
        app_mod._router_api.get_tunnel_health.return_value = "green"

        c.post("/api/profiles/test-vpn-1/connect")
        stored = ps.get_profile("test-vpn-1")
        assert "status" not in stored

    def test_connect_returns_error_when_health_query_fails(self, unlocked_client):
        """Strategy.connect() treats bring_up + health as atomic; health failure propagates."""
        c, app_mod = unlocked_client
        self._make_vpn_profile(app_mod)
        app_mod._router_api.bring_tunnel_up.return_value = None
        app_mod._router_api.get_tunnel_health.side_effect = Exception("ssh fail")

        resp = c.post("/api/profiles/test-vpn-1/connect")
        assert resp.status_code == 500
        assert "error" in resp.json

    def test_connect_returns_error_when_bring_up_fails(self, unlocked_client):
        c, app_mod = unlocked_client
        self._make_vpn_profile(app_mod)
        app_mod._router_api.bring_tunnel_up.side_effect = Exception("up failed")

        resp = c.post("/api/profiles/test-vpn-1/connect")
        assert resp.status_code == 500
        # No status field cached in store
        stored = ps.get_profile("test-vpn-1")
        assert "status" not in stored

    def test_disconnect_returns_red_health(self, unlocked_client):
        c, app_mod = unlocked_client
        self._make_vpn_profile(app_mod)
        app_mod._router_api.bring_tunnel_down.return_value = None

        resp = c.post("/api/profiles/test-vpn-1/disconnect")
        assert resp.status_code == 200
        assert resp.json["success"] is True
        assert resp.json["health"] == "red"

    def test_disconnect_does_not_write_status_to_store(self, unlocked_client):
        c, app_mod = unlocked_client
        self._make_vpn_profile(app_mod)
        app_mod._router_api.bring_tunnel_down.return_value = None

        c.post("/api/profiles/test-vpn-1/disconnect")
        stored = ps.get_profile("test-vpn-1")
        assert "status" not in stored

    def test_disconnect_handles_router_error_gracefully(self, unlocked_client):
        """Stage 2: api_disconnect must not crash when bring_tunnel_down throws."""
        c, app_mod = unlocked_client
        self._make_vpn_profile(app_mod)
        app_mod._router_api.bring_tunnel_down.side_effect = Exception("down failed")

        resp = c.post("/api/profiles/test-vpn-1/disconnect")
        assert resp.status_code == 500
        assert "error" in resp.json

    def test_get_profiles_strips_legacy_status_field(self, unlocked_client):
        """Old data with 'status' should be cleaned out at read time."""
        c, app_mod = unlocked_client
        ps.save({
            **ps._EMPTY_STORE,
            "profiles": [{
                "id": "legacy-vpn",
                "type": "vpn",
                "name": "Legacy",
                "color": "#000",
                "icon": "🔒",
                "is_guest": False,
                "status": "connected",  # legacy field
                "router_info": {
                    "rule_name": "fvpn_rule_9001",
                    "peer_id": "9001",
                    "vpn_protocol": "wireguard",
                },
            }],
        })
        app_mod._router_api.get_flint_vpn_rules.return_value = [{
            "rule_name": "fvpn_rule_9001",
            "name": "Legacy",
            "killswitch": "1",
            "via_type": "wireguard",
            "peer_id": "9001",
        }]
        app_mod._router_api.get_device_assignments.return_value = {}
        app_mod._router_api.get_tunnel_health.return_value = "red"

        resp = c.get("/api/profiles")
        assert resp.status_code == 200
        for p in resp.json:
            assert "status" not in p
            if p["type"] == "vpn":
                assert p["health"] == "red"

    def test_get_profiles_loading_health_on_router_error(self, unlocked_client):
        c, app_mod = unlocked_client
        self._make_vpn_profile(app_mod)
        app_mod._router_api.get_flint_vpn_rules.return_value = [{
            "rule_name": "fvpn_rule_9001",
            "name": "Test VPN",
            "killswitch": "1",
            "via_type": "wireguard",
            "peer_id": "9001",
        }]
        app_mod._router_api.get_device_assignments.return_value = {}
        app_mod._router_api.get_tunnel_health.side_effect = Exception("ssh fail")

        resp = c.get("/api/profiles")
        for p in resp.json:
            if p["type"] == "vpn":
                assert p["health"] == "loading"

    def test_create_vpn_profile_no_status_field_in_store(self, unlocked_client):
        """Stage 2: create_profile no longer initializes status='disconnected'."""
        from profile_store import create_profile
        p = create_profile(
            name="Fresh",
            profile_type="vpn",
            router_info={"rule_name": "fvpn_rule_9001", "peer_id": "9001"},
        )
        assert "status" not in p


class TestKillSwitchLive:
    """Stage 3: kill switch is live from router. No local cache writes."""

    def _make_vpn_profile(self):
        ps.save({
            **ps._EMPTY_STORE,
            "profiles": [{
                "id": "ks-vpn-1",
                "type": "vpn",
                "name": "KS Test",
                "color": "#3498db",
                "icon": "🔒",
                "is_guest": False,
                "router_info": {
                    "rule_name": "fvpn_rule_9001",
                    "peer_id": "9001",
                    "vpn_protocol": "wireguard",
                },
            }],
        })

    def test_create_vpn_profile_no_kill_switch_field_in_store(self, unlocked_client):
        """create_profile no longer stores kill_switch in profile_store."""
        from profile_store import create_profile
        p = create_profile(
            name="Fresh",
            profile_type="vpn",
            router_info={"rule_name": "fvpn_rule_9001", "peer_id": "9001"},
        )
        assert "kill_switch" not in p

    def test_get_profiles_returns_live_kill_switch_from_router(self, unlocked_client):
        c, app_mod = unlocked_client
        self._make_vpn_profile()
        app_mod._router_api.get_flint_vpn_rules.return_value = [{
            "rule_name": "fvpn_rule_9001",
            "name": "KS Test",
            "killswitch": "1",
            "via_type": "wireguard",
            "peer_id": "9001",
        }]
        app_mod._router_api.get_device_assignments.return_value = {}
        app_mod._router_api.get_tunnel_health.return_value = "green"

        resp = c.get("/api/profiles")
        assert resp.status_code == 200
        vpn = [p for p in resp.json if p["type"] == "vpn"][0]
        assert vpn["kill_switch"] is True

    def test_get_profiles_kill_switch_false_when_disabled_on_router(self, unlocked_client):
        c, app_mod = unlocked_client
        self._make_vpn_profile()
        app_mod._router_api.get_flint_vpn_rules.return_value = [{
            "rule_name": "fvpn_rule_9001",
            "name": "KS Test",
            "killswitch": "0",
            "via_type": "wireguard",
            "peer_id": "9001",
        }]
        app_mod._router_api.get_device_assignments.return_value = {}
        app_mod._router_api.get_tunnel_health.return_value = "green"

        resp = c.get("/api/profiles")
        vpn = [p for p in resp.json if p["type"] == "vpn"][0]
        assert vpn["kill_switch"] is False

    def test_update_kill_switch_writes_to_router(self, unlocked_client):
        c, app_mod = unlocked_client
        self._make_vpn_profile()
        app_mod._router_api.get_kill_switch.return_value = False

        resp = c.put("/api/profiles/ks-vpn-1", json={"kill_switch": False})
        assert resp.status_code == 200
        app_mod._router_api.set_kill_switch.assert_called_with("fvpn_rule_9001", False)
        # Response reflects the live router value
        assert resp.json["kill_switch"] is False
        # Local store was not polluted with kill_switch
        stored = ps.get_profile("ks-vpn-1")
        assert "kill_switch" not in stored

    def test_update_kill_switch_to_true(self, unlocked_client):
        c, app_mod = unlocked_client
        self._make_vpn_profile()
        app_mod._router_api.get_kill_switch.return_value = True

        c.put("/api/profiles/ks-vpn-1", json={"kill_switch": True})
        app_mod._router_api.set_kill_switch.assert_called_with("fvpn_rule_9001", True)


class TestProfileNameLive:
    """Stage 4: profile name is router-canonical (route_policy.{rule}.name)."""

    def _make_vpn_profile(self, vpn_protocol="wireguard"):
        ri = {
            "rule_name": "fvpn_rule_9001",
            "vpn_protocol": vpn_protocol,
        }
        if vpn_protocol == "wireguard":
            ri["peer_id"] = "9001"
        else:
            ri["client_uci_id"] = "28216_9051"
            ri["rule_name"] = "fvpn_rule_ovpn_9051"
        ps.save({
            **ps._EMPTY_STORE,
            "profiles": [{
                "id": "name-vpn-1",
                "type": "vpn",
                "name": "Local Cached Name",
                "color": "#3498db",
                "icon": "🔒",
                "is_guest": False,
                "router_info": ri,
            }],
        })

    def test_get_profiles_overrides_name_with_router_value(self, unlocked_client):
        c, app_mod = unlocked_client
        self._make_vpn_profile()
        app_mod._router_api.get_flint_vpn_rules.return_value = [{
            "rule_name": "fvpn_rule_9001",
            "name": "Live Router Name",
            "killswitch": "1",
            "via_type": "wireguard",
            "peer_id": "9001",
        }]
        app_mod._router_api.get_device_assignments.return_value = {}
        app_mod._router_api.get_tunnel_health.return_value = "green"

        resp = c.get("/api/profiles")
        vpn = [p for p in resp.json if p["type"] == "vpn"][0]
        assert vpn["name"] == "Live Router Name"

    def test_get_profiles_falls_back_to_local_name_when_router_empty(self, unlocked_client):
        c, app_mod = unlocked_client
        self._make_vpn_profile()
        # Router rule exists but has no name set
        app_mod._router_api.get_flint_vpn_rules.return_value = [{
            "rule_name": "fvpn_rule_9001",
            "killswitch": "1",
            "via_type": "wireguard",
            "peer_id": "9001",
        }]
        app_mod._router_api.get_device_assignments.return_value = {}
        app_mod._router_api.get_tunnel_health.return_value = "green"

        resp = c.get("/api/profiles")
        vpn = [p for p in resp.json if p["type"] == "vpn"][0]
        # Falls back to local stored name
        assert vpn["name"] == "Local Cached Name"

    def test_update_profile_name_calls_router_rename_for_wg(self, unlocked_client):
        c, app_mod = unlocked_client
        self._make_vpn_profile(vpn_protocol="wireguard")
        app_mod._router_api.get_kill_switch.return_value = True
        app_mod._router_api.get_profile_name.return_value = "Renamed"

        resp = c.put("/api/profiles/name-vpn-1", json={"name": "Renamed"})
        assert resp.status_code == 200
        app_mod._router_api.rename_profile.assert_called_once()
        call_kwargs = app_mod._router_api.rename_profile.call_args.kwargs
        assert call_kwargs["rule_name"] == "fvpn_rule_9001"
        assert call_kwargs["new_name"] == "Renamed"
        assert call_kwargs["peer_id"] == "9001"
        assert call_kwargs["client_uci_id"] == ""
        assert resp.json["name"] == "Renamed"

    def test_update_profile_name_calls_router_rename_for_ovpn(self, unlocked_client):
        c, app_mod = unlocked_client
        self._make_vpn_profile(vpn_protocol="openvpn")
        app_mod._router_api.get_kill_switch.return_value = True
        app_mod._router_api.get_profile_name.return_value = "OVPN New"

        resp = c.put("/api/profiles/name-vpn-1", json={"name": "OVPN New"})
        assert resp.status_code == 200
        app_mod._router_api.rename_profile.assert_called_once()
        call_kwargs = app_mod._router_api.rename_profile.call_args.kwargs
        assert call_kwargs["rule_name"] == "fvpn_rule_ovpn_9051"
        assert call_kwargs["client_uci_id"] == "28216_9051"
        assert call_kwargs["peer_id"] == ""

    def test_update_non_vpn_profile_name_does_not_call_router(self, unlocked_client):
        c, app_mod = unlocked_client
        ps.save({
            **ps._EMPTY_STORE,
            "profiles": [{
                "id": "novpn-1",
                "type": "no_vpn",
                "name": "Direct",
                "color": "#888",
                "icon": "🌐",
                "is_guest": False,
            }],
        })
        c.put("/api/profiles/novpn-1", json={"name": "Renamed Direct"})
        app_mod._router_api.rename_profile.assert_not_called()
        # Local store should be updated for non-VPN
        assert ps.get_profile("novpn-1")["name"] == "Renamed Direct"


class TestBuildProfileList:
    """Stage 5: profile list is built from router rules + local metadata."""

    def _setup_router(self, app_mod, rules=None, assignments=None,
                      health_map=None):
        rules = rules or []
        assignments = assignments or {}
        health_map = health_map or {}
        app_mod._router_api.get_flint_vpn_rules.return_value = rules
        app_mod._router_api.get_device_assignments.return_value = assignments
        app_mod._router_api.get_tunnel_health.side_effect = lambda r: health_map.get(r, "loading")

    def test_get_profiles_uses_router_rules_as_source(self, unlocked_client):
        c, app_mod = unlocked_client
        ps.save({
            **ps._EMPTY_STORE,
            "profiles": [{
                "id": "vpn-uuid-1",
                "type": "vpn",
                "name": "Old Local Name",
                "color": "#3498db",
                "icon": "🔒",
                "is_guest": False,
                "router_info": {"rule_name": "fvpn_rule_9001",
                                "peer_id": "9001",
                                "vpn_protocol": "wireguard"},
            }],
        })
        self._setup_router(app_mod,
            rules=[{"rule_name": "fvpn_rule_9001",
                    "name": "Live Router Name",
                    "killswitch": "1",
                    "via_type": "wireguard",
                    "peer_id": "9001"}],
            health_map={"fvpn_rule_9001": "green"},
        )
        resp = c.get("/api/profiles")
        assert resp.status_code == 200
        vpn = [p for p in resp.json if p["type"] == "vpn"][0]
        assert vpn["id"] == "vpn-uuid-1"  # local UUID preserved
        assert vpn["name"] == "Live Router Name"
        assert vpn["color"] == "#3498db"  # local metadata preserved
        assert vpn["health"] == "green"
        assert vpn["kill_switch"] is True

    def test_get_profiles_kill_switch_off_from_router(self, unlocked_client):
        c, app_mod = unlocked_client
        ps.save({
            **ps._EMPTY_STORE,
            "profiles": [{
                "id": "vpn-uuid-1", "type": "vpn", "name": "X",
                "color": "#000", "icon": "🔒", "is_guest": False,
                "router_info": {"rule_name": "fvpn_rule_9001",
                                "peer_id": "9001", "vpn_protocol": "wireguard"},
            }],
        })
        self._setup_router(app_mod,
            rules=[{"rule_name": "fvpn_rule_9001", "name": "X",
                    "killswitch": "0", "via_type": "wireguard", "peer_id": "9001"}],
        )
        resp = c.get("/api/profiles")
        vpn = [p for p in resp.json if p["type"] == "vpn"][0]
        assert vpn["kill_switch"] is False

    def test_get_profiles_marks_ghost_for_deleted_router_rule(self, unlocked_client):
        """Local profile exists but router rule is gone — surface as ghost."""
        c, app_mod = unlocked_client
        ps.save({
            **ps._EMPTY_STORE,
            "profiles": [{
                "id": "ghost-uuid", "type": "vpn", "name": "Was Here",
                "color": "#000", "icon": "🔒", "is_guest": False,
                "router_info": {"rule_name": "fvpn_rule_9999",
                                "peer_id": "9999", "vpn_protocol": "wireguard"},
            }],
        })
        self._setup_router(app_mod, rules=[])
        resp = c.get("/api/profiles")
        ghosts = [p for p in resp.json if p.get("_ghost")]
        assert len(ghosts) == 1
        assert ghosts[0]["id"] == "ghost-uuid"
        assert ghosts[0]["health"] == "red"

    def test_get_profiles_marks_orphan_for_unknown_router_rule(self, unlocked_client):
        """Router has a rule we don't know about — surface as orphan."""
        c, app_mod = unlocked_client
        ps.save(ps._EMPTY_STORE)
        self._setup_router(app_mod,
            rules=[{"rule_name": "fvpn_rule_9050", "name": "Unknown",
                    "killswitch": "1", "via_type": "wireguard", "peer_id": "9050"}],
            health_map={"fvpn_rule_9050": "green"},
        )
        resp = c.get("/api/profiles")
        orphans = [p for p in resp.json if p.get("_orphan")]
        assert len(orphans) == 1
        assert orphans[0]["name"] == "Unknown"
        assert orphans[0]["id"] == "fvpn_rule_9050"  # rule_name as fallback id

    def test_get_profiles_respects_display_order(self, unlocked_client):
        c, app_mod = unlocked_client
        ps.save({
            **ps._EMPTY_STORE,
            "profiles": [
                {"id": "novpn-1", "type": "no_vpn", "name": "Direct",
                 "color": "#888", "icon": "🌐", "is_guest": False, "display_order": 0},
                {"id": "vpn-1", "type": "vpn", "name": "VPN-A",
                 "color": "#000", "icon": "🔒", "is_guest": False, "display_order": 1,
                 "router_info": {"rule_name": "fvpn_rule_9001",
                                 "peer_id": "9001", "vpn_protocol": "wireguard"}},
            ],
        })
        self._setup_router(app_mod,
            rules=[{"rule_name": "fvpn_rule_9001", "name": "VPN-A",
                    "killswitch": "1", "via_type": "wireguard", "peer_id": "9001"}],
            health_map={"fvpn_rule_9001": "green"},
        )
        resp = c.get("/api/profiles")
        types = [p["type"] for p in resp.json]
        # With unified ordering, display_order determines the order
        assert types == ["no_vpn", "vpn"]

    def test_get_profiles_device_count_from_router(self, unlocked_client):
        c, app_mod = unlocked_client
        ps.save({
            **ps._EMPTY_STORE,
            "profiles": [{
                "id": "vpn-1", "type": "vpn", "name": "X", "color": "#000",
                "icon": "🔒", "is_guest": False,
                "router_info": {"rule_name": "fvpn_rule_9001",
                                "peer_id": "9001", "vpn_protocol": "wireguard"},
            }],
        })
        self._setup_router(app_mod,
            rules=[{"rule_name": "fvpn_rule_9001", "name": "X",
                    "killswitch": "1", "via_type": "wireguard", "peer_id": "9001"}],
            assignments={"aa:bb:cc:dd:ee:ff": "fvpn_rule_9001",
                         "11:22:33:44:55:66": "fvpn_rule_9001"},
            health_map={"fvpn_rule_9001": "green"},
        )
        resp = c.get("/api/profiles")
        vpn = [p for p in resp.json if p["type"] == "vpn"][0]
        assert vpn["device_count"] == 2


class TestServerResolutionLive:
    """Stage 7: server info comes from Proton API by id, not local cache."""

    def _make_vpn_profile(self, server_id="srv-abc", server_cache=None):
        cache = server_cache if server_cache is not None else {"id": server_id, "endpoint": "1.2.3.4:51820"}
        ps.save({
            **ps._EMPTY_STORE,
            "profiles": [{
                "id": "vpn-uuid", "type": "vpn", "name": "X",
                "color": "#000", "icon": "🔒", "is_guest": False,
                "router_info": {"rule_name": "fvpn_rule_9001",
                                "peer_id": "9001", "vpn_protocol": "wireguard"},
                "server_id": server_id,
                "server": cache,
            }],
        })

    def _setup_router(self, app_mod):
        app_mod._router_api.get_flint_vpn_rules.return_value = [{
            "rule_name": "fvpn_rule_9001",
            "name": "X",
            "killswitch": "1",
            "via_type": "wireguard",
            "peer_id": "9001",
        }]
        app_mod._router_api.get_device_assignments.return_value = {}
        app_mod._router_api.get_tunnel_health.return_value = "green"

    def test_get_profiles_resolves_server_from_proton(self, unlocked_client):
        c, app_mod = unlocked_client
        self._make_vpn_profile()
        self._setup_router(app_mod)

        app_mod._proton_api.is_logged_in = True
        live_server = {
            "id": "srv-abc",
            "name": "DE#999",
            "country": "Germany",
            "country_code": "DE",
            "city": "Berlin",
            "load": 42,
        }
        app_mod._proton_api.server_to_dict.return_value = live_server
        app_mod._proton_api.get_server_by_id.return_value = MagicMock()  # truthy

        resp = c.get("/api/profiles")
        vpn = [p for p in resp.json if p["type"] == "vpn"][0]
        assert vpn["server"]["name"] == "DE#999"
        assert vpn["server"]["city"] == "Berlin"
        assert vpn["server"]["load"] == 42
        # Endpoint preserved from cache (not in Proton logical server)
        assert vpn["server"]["endpoint"] == "1.2.3.4:51820"
        app_mod._proton_api.get_server_by_id.assert_called_with("srv-abc")

    def test_get_profiles_falls_back_to_cache_when_proton_logged_out(self, unlocked_client):
        c, app_mod = unlocked_client
        self._make_vpn_profile(server_cache={
            "id": "srv-abc",
            "name": "Cached Name",
            "load": 99,
            "endpoint": "1.2.3.4:51820",
        })
        self._setup_router(app_mod)

        app_mod._proton_api.is_logged_in = False

        resp = c.get("/api/profiles")
        vpn = [p for p in resp.json if p["type"] == "vpn"][0]
        assert vpn["server"]["name"] == "Cached Name"
        assert vpn["server"]["load"] == 99

    def test_get_profiles_falls_back_when_proton_returns_none(self, unlocked_client):
        c, app_mod = unlocked_client
        self._make_vpn_profile(server_cache={
            "id": "srv-abc",
            "name": "Stale",
            "load": 50,
            "endpoint": "1.2.3.4:51820",
        })
        self._setup_router(app_mod)

        app_mod._proton_api.is_logged_in = True
        app_mod._proton_api.get_server_by_id.return_value = None

        resp = c.get("/api/profiles")
        vpn = [p for p in resp.json if p["type"] == "vpn"][0]
        assert vpn["server"]["name"] == "Stale"
        assert vpn["server"]["load"] == 50

    def test_create_vpn_profile_stores_server_id_and_minimal_cache(self, tmp_data):
        from profile_store import create_profile
        full_server = {
            "id": "srv-xyz",
            "name": "DE#123",
            "country": "Germany",
            "country_code": "DE",
            "city": "Frankfurt",
            "load": 25,
            "endpoint": "5.6.7.8:51820",
            "physical_server_domain": "node-de-1.protonvpn.net",
        }
        p = create_profile(
            name="X",
            profile_type="vpn",
            server=full_server,
            router_info={"rule_name": "fvpn_rule_9001", "peer_id": "9001"},
        )
        assert p["server_id"] == "srv-xyz"
        cache = p["server"]
        assert cache["id"] == "srv-xyz"
        assert cache["endpoint"] == "5.6.7.8:51820"
        assert cache["physical_server_domain"] == "node-de-1.protonvpn.net"
        # Name / country / city / load are NOT cached locally
        assert "name" not in cache
        assert "country" not in cache
        assert "city" not in cache
        assert "load" not in cache


class TestDeviceAssignmentsLive:
    """Stage 5: VPN device assignments are router-canonical."""

    def test_get_devices_uses_router_assignments_for_vpn(self, unlocked_client):
        c, app_mod = unlocked_client
        ps.save({
            **ps._EMPTY_STORE,
            "profiles": [{
                "id": "vpn-1", "type": "vpn", "name": "X", "color": "#000",
                "icon": "🔒", "is_guest": False,
                "router_info": {"rule_name": "fvpn_rule_9001",
                                "peer_id": "9001", "vpn_protocol": "wireguard"},
            }],
            "device_assignments": {},
        })
        app_mod._router_api.get_flint_vpn_rules.return_value = [{
            "rule_name": "fvpn_rule_9001",
            "name": "X",
            "peer_id": "9001",
            "via_type": "wireguard",
            "group_id": "1957",
        }]
        app_mod._router_api.get_device_assignments.return_value = {
            "aa:bb:cc:dd:ee:ff": "fvpn_rule_9001"
        }
        resp = c.get("/api/devices")
        macs_with_pid = {d["mac"]: d.get("profile_id") for d in resp.json}
        assert macs_with_pid.get("aa:bb:cc:dd:ee:ff") == "vpn-1"

    def test_get_devices_uses_local_assignments_for_non_vpn(self, unlocked_client):
        c, app_mod = unlocked_client
        ps.save({
            **ps._EMPTY_STORE,
            "profiles": [{
                "id": "novpn-1", "type": "no_vpn", "name": "Direct",
                "color": "#888", "icon": "🌐", "is_guest": False,
            }],
            "device_assignments": {"aa:bb:cc:dd:ee:ff": "novpn-1"},
        })
        app_mod._router_api.get_dhcp_leases.return_value = [
            {"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.8.10", "hostname": "test"}
        ]
        app_mod._router_api.get_client_details.return_value = {}
        app_mod._router_api.get_flint_vpn_rules.return_value = []
        app_mod._router_api.get_device_assignments.return_value = {}
        app_mod._service.invalidate_device_cache()
        resp = c.get("/api/devices")
        macs = {d["mac"]: d.get("profile_id") for d in resp.json}
        assert macs.get("aa:bb:cc:dd:ee:ff") == "novpn-1"

    def test_assign_device_to_vpn_calls_router_only(self, unlocked_client):
        c, app_mod = unlocked_client
        ps.save({
            **ps._EMPTY_STORE,
            "profiles": [{
                "id": "vpn-1", "type": "vpn", "name": "X", "color": "#000",
                "icon": "🔒", "is_guest": False,
                "router_info": {"rule_name": "fvpn_rule_9001",
                                "peer_id": "9001", "vpn_protocol": "wireguard"},
            }],
        })
        app_mod._router_api.get_device_assignments.return_value = {}
        resp = c.put("/api/devices/aa:bb:cc:dd:ee:ff/profile",
                     json={"profile_id": "vpn-1"})
        assert resp.status_code == 200
        app_mod._router_api.set_device_vpn.assert_called_with(
            "aa:bb:cc:dd:ee:ff", "fvpn_rule_9001"
        )
        # Local store should NOT have a VPN assignment
        stored = ps.load()
        assert stored["device_assignments"].get("aa:bb:cc:dd:ee:ff") in (None,)

    def test_assign_device_to_no_vpn_writes_locally(self, unlocked_client):
        c, app_mod = unlocked_client
        ps.save({
            **ps._EMPTY_STORE,
            "profiles": [{
                "id": "novpn-1", "type": "no_vpn", "name": "Direct",
                "color": "#888", "icon": "🌐", "is_guest": False,
            }],
        })
        app_mod._router_api.get_device_assignments.return_value = {}
        c.put("/api/devices/aa:bb:cc:dd:ee:ff/profile",
              json={"profile_id": "novpn-1"})
        # Local store should have the assignment
        stored = ps.load()
        assert stored["device_assignments"].get("aa:bb:cc:dd:ee:ff") == "novpn-1"
        # Router VPN setter should NOT be called
        app_mod._router_api.set_device_vpn.assert_not_called()

    def test_unassign_device_clears_router_and_local(self, unlocked_client):
        c, app_mod = unlocked_client
        ps.save({
            **ps._EMPTY_STORE,
            "device_assignments": {"aa:bb:cc:dd:ee:ff": "novpn-1"},
        })
        app_mod._router_api.get_device_assignments.return_value = {
            "aa:bb:cc:dd:ee:ff": "fvpn_rule_9001"
        }
        c.put("/api/devices/aa:bb:cc:dd:ee:ff/profile",
              json={"profile_id": None})
        app_mod._router_api.remove_device_from_all_vpn.assert_called_with("aa:bb:cc:dd:ee:ff")
        stored = ps.load()
        # Sticky-None: KEY exists with value None so the device tracker
        # won't auto-reassign on the next unlock/restart.
        assert "aa:bb:cc:dd:ee:ff" in stored["device_assignments"]
        assert stored["device_assignments"]["aa:bb:cc:dd:ee:ff"] is None

    def test_unassign_vpn_only_device_writes_sticky_marker(self, unlocked_client):
        """A device that was VPN-assigned (no local entry) should still get a
        sticky-None marker on explicit unassign so the tracker won't auto-
        reassign it on the next unlock/restart."""
        c, app_mod = unlocked_client
        ps.save(ps._EMPTY_STORE)  # No local entry for the MAC
        # Router says the device is in a VPN rule
        app_mod._router_api.get_device_assignments.return_value = {
            "aa:bb:cc:dd:ee:ff": "fvpn_rule_9001"
        }
        c.put("/api/devices/aa:bb:cc:dd:ee:ff/profile",
              json={"profile_id": None})
        stored = ps.load()
        assert "aa:bb:cc:dd:ee:ff" in stored["device_assignments"]
        assert stored["device_assignments"]["aa:bb:cc:dd:ee:ff"] is None

    def test_assign_vpn_drops_local_entry(self, unlocked_client):
        """Assigning a previously-unassigned (sticky-None) device to a VPN
        group should clear the local entry so a future unassign can re-write
        a fresh sticky-None marker."""
        c, app_mod = unlocked_client
        # Pre-existing sticky-None
        ps.save({
            **ps._EMPTY_STORE,
            "profiles": [{
                "id": "vpn-1", "type": "vpn", "name": "X",
                "color": "#000", "icon": "🔒", "is_guest": False,
                "router_info": {"rule_name": "fvpn_rule_9001",
                                "peer_id": "9001", "vpn_protocol": "wireguard"},
            }],
            "device_assignments": {"aa:bb:cc:dd:ee:ff": None},
        })
        app_mod._router_api.get_device_assignments.return_value = {}
        c.put("/api/devices/aa:bb:cc:dd:ee:ff/profile",
              json={"profile_id": "vpn-1"})
        stored = ps.load()
        # Local entry dropped (router is the source for VPN assignments)
        assert "aa:bb:cc:dd:ee:ff" not in stored["device_assignments"]
        app_mod._router_api.set_device_vpn.assert_called_with(
            "aa:bb:cc:dd:ee:ff", "fvpn_rule_9001"
        )


class TestGuestEndpoint:
    def test_set_guest(self, unlocked_client):
        c, _ = unlocked_client
        create = c.post("/api/profiles", json={"name": "Guest", "type": "no_vpn"})
        pid = create.json["id"]
        resp = c.put(f"/api/profiles/{pid}/guest")
        assert resp.json["success"] is True
        assert ps.get_guest_profile()["id"] == pid


class TestDeviceEndpoints:
    def test_get_devices_empty(self, unlocked_client):
        c, app_mod = unlocked_client
        # Stage 8: device list comes live from router. With empty router state,
        # the list is empty.
        app_mod._router_api.get_dhcp_leases.return_value = []
        app_mod._router_api.get_client_details.return_value = {}
        app_mod._router_api.get_flint_vpn_rules.return_value = []
        app_mod._router_api.get_device_assignments.return_value = {}
        # Make sure cache is fresh
        app_mod._service.invalidate_device_cache()
        resp = c.get("/api/devices")
        assert resp.json == []

    def test_assign_device(self, unlocked_client):
        c, app_mod = unlocked_client
        # Create a non-VPN profile (no router calls needed)
        create = c.post("/api/profiles", json={"name": "Test", "type": "no_vpn"})
        pid = create.json["id"]

        # Mock router as empty so the device shows up via local-assignment surfacing
        app_mod._router_api.get_dhcp_leases.return_value = [
            {"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.8.100", "hostname": "TestDev"}
        ]
        app_mod._router_api.get_client_details.return_value = {}
        app_mod._router_api.get_flint_vpn_rules.return_value = []
        app_mod._router_api.get_device_assignments.return_value = {}
        app_mod._service.invalidate_device_cache()

        resp = c.put("/api/devices/aa:bb:cc:dd:ee:ff/profile", json={"profile_id": pid})
        assert resp.json["success"] is True

        app_mod._service.invalidate_device_cache()
        devices = c.get("/api/devices").json
        dev = next(d for d in devices if d["mac"] == "aa:bb:cc:dd:ee:ff")
        assert dev["profile_id"] == pid

    def test_unassign_device(self, unlocked_client):
        c, _ = unlocked_client
        create = c.post("/api/profiles", json={"name": "Test", "type": "no_vpn"})
        pid = create.json["id"]
        ps.assign_device("aa:bb:cc:dd:ee:ff", pid)

        resp = c.put("/api/devices/aa:bb:cc:dd:ee:ff/profile", json={"profile_id": None})
        assert resp.json["success"] is True


class TestSettingsEndpoints:
    def test_get_settings(self, unlocked_client):
        c, _ = unlocked_client
        resp = c.get("/api/settings")
        assert "router_ip" in resp.json

    def test_update_settings(self, unlocked_client):
        c, _ = unlocked_client
        resp = c.put("/api/settings", json={"router_ip": "10.0.0.1"})
        assert resp.json["router_ip"] == "10.0.0.1"


class TestOpenVPNProfileEndpoints:
    def test_create_ovpn_requires_server_id(self, unlocked_client):
        c, _ = unlocked_client
        resp = c.post("/api/profiles", json={
            "name": "OVPN Test", "type": "vpn", "vpn_protocol": "openvpn"
        })
        assert resp.status_code == 400
        assert "server_id" in resp.json["error"]

    def test_delete_ovpn_profile(self, unlocked_client):
        c, app_mod = unlocked_client
        # Create a no_vpn profile (we can't create real OVPN without ProtonVPN)
        # Just test that delete handles router_info with vpn_protocol=openvpn
        import profile_store as pstore
        p = pstore.create_profile("OVPN Test", "vpn", router_info={
            "vpn_protocol": "openvpn",
            "client_uci_id": "28216_9999",
            "rule_name": "fvpn_rule_ovpn_9999",
        })
        resp = c.delete(f"/api/profiles/{p['id']}")
        assert resp.json["success"] is True


class TestReorderEndpoint:
    def test_reorder_profiles(self, unlocked_client):
        c, _ = unlocked_client
        a = c.post("/api/profiles", json={"name": "A", "type": "no_vpn"}).json
        b = c.post("/api/profiles", json={"name": "B", "type": "no_vpn"}).json
        c_prof = c.post("/api/profiles", json={"name": "C", "type": "no_vpn"}).json

        resp = c.put("/api/profiles/reorder", json={
            "profile_ids": [c_prof["id"], a["id"], b["id"]]
        })
        assert resp.json["success"] is True

        profiles = c.get("/api/profiles").json
        assert profiles[0]["name"] == "C"
        assert profiles[1]["name"] == "A"
        assert profiles[2]["name"] == "B"

    def test_reorder_missing_ids(self, unlocked_client):
        c, _ = unlocked_client
        resp = c.put("/api/profiles/reorder", json={"profile_ids": []})
        assert resp.status_code == 400


class TestDeviceLabelEndpoint:
    """Stage 8: device label = gl-client.alias on the router (canonical).
    No local cache write."""

    def test_set_label_writes_to_router(self, unlocked_client):
        c, app_mod = unlocked_client
        # Mock the gl-client lookup
        app_mod._router_api.exec.return_value = "client_42"
        resp = c.put("/api/devices/aa:bb:cc:dd:ee:ff/label", json={
            "label": "My TV", "device_class": "television"
        })
        assert resp.json["success"] is True
        assert resp.json["label"] == "My TV"
        # Verify the router was called with the alias write
        all_calls = " | ".join(
            str(call) for call in app_mod._router_api.exec.call_args_list
        )
        assert "alias='My TV'" in all_calls
        assert "class='television'" in all_calls
        # Local store should NOT have any device_labels key (Stage 8: removed)
        stored = ps.load()
        assert "device_labels" not in stored

    def test_clear_label_writes_empty_alias_to_router(self, unlocked_client):
        c, app_mod = unlocked_client
        app_mod._router_api.exec.return_value = "client_42"
        resp = c.put("/api/devices/aa:bb:cc:dd:ee:ff/label", json={"label": ""})
        assert resp.json["success"] is True
        assert resp.json["label"] == ""
        all_calls = " | ".join(
            str(call) for call in app_mod._router_api.exec.call_args_list
        )
        assert "alias=''" in all_calls


class TestLogsEndpoint:
    def test_get_logs(self, unlocked_client):
        c, _ = unlocked_client
        resp = c.get("/api/logs")
        assert isinstance(resp.json, list)

    def test_get_log_content(self, unlocked_client):
        c, app_mod = unlocked_client
        # Create a test log file
        import app as flask_app
        log_file = flask_app.LOG_DIR / "test.log"
        log_file.write_text("line1\nline2\nline3\n")
        try:
            resp = c.get("/api/logs/test.log")
            assert resp.json["total_lines"] == 3
            assert len(resp.json["lines"]) == 3
        finally:
            log_file.unlink()

    def test_invalid_log_name(self, unlocked_client):
        c, _ = unlocked_client
        resp = c.get("/api/logs/notafile.txt")
        assert resp.status_code == 400  # doesn't end in .log


class TestVPNLimits:
    def test_wg_limit_message(self, unlocked_client):
        c, _ = unlocked_client
        # Create 5 non-vpn profiles shouldn't hit any limit
        for i in range(5):
            resp = c.post("/api/profiles", json={"name": f"NV{i}", "type": "no_vpn"})
            assert resp.status_code == 201

    def test_create_profile_requires_server_for_vpn(self, unlocked_client):
        c, _ = unlocked_client
        resp = c.post("/api/profiles", json={"name": "VPN", "type": "vpn"})
        assert resp.status_code == 400
        assert "server_id" in resp.json["error"]


class TestLanAccessEndpoints:
    def test_set_profile_lan_access(self, unlocked_client):
        c, _ = unlocked_client
        create = c.post("/api/profiles", json={"name": "LAN", "type": "no_vpn"})
        pid = create.json["id"]
        resp = c.put(f"/api/profiles/{pid}/lan-access", json={
            "outbound": "group_only", "inbound": "blocked"
        })
        assert resp.json["success"] is True
        assert resp.json["lan_access"]["outbound"] == "group_only"

    def test_set_profile_lan_access_with_allow_lists(self, unlocked_client):
        c, _ = unlocked_client
        a = c.post("/api/profiles", json={"name": "A", "type": "no_vpn"}).json
        b = c.post("/api/profiles", json={"name": "B", "type": "no_vpn"}).json
        resp = c.put(f"/api/profiles/{a['id']}/lan-access", json={
            "outbound": "group_only",
            "inbound": "group_only",
            "outbound_allow": [],
            "inbound_allow": [b["id"], "aa:bb:cc:dd:ee:ff"],
        })
        assert resp.status_code == 200
        # Round-trip via /api/profiles
        plist = c.get("/api/profiles").json
        a_out = next(p for p in plist if p["id"] == a["id"])
        assert b["id"] in a_out["lan_access"]["inbound_allow"]
        assert "aa:bb:cc:dd:ee:ff" in a_out["lan_access"]["inbound_allow"]
        assert a_out["lan_access"]["outbound_allow"] == []

    def test_set_device_lan_access(self, unlocked_client):
        c, _ = unlocked_client
        create = c.post("/api/profiles", json={"name": "LAN", "type": "no_vpn"})
        pid = create.json["id"]
        ps.assign_device("aa:bb:cc:dd:ee:ff", pid)
        resp = c.put("/api/devices/aa:bb:cc:dd:ee:ff/lan-access", json={
            "outbound": "blocked", "inbound": None
        })
        assert resp.json["success"] is True

    def test_set_device_lan_access_with_allow_lists(self, unlocked_client):
        c, _ = unlocked_client
        pid = c.post("/api/profiles", json={"name": "A", "type": "no_vpn"}).json["id"]
        other = c.post("/api/profiles", json={"name": "B", "type": "no_vpn"}).json["id"]
        ps.assign_device("aa:bb:cc:dd:ee:ff", pid)
        resp = c.put("/api/devices/aa:bb:cc:dd:ee:ff/lan-access", json={
            "outbound": None, "inbound": None,
            "outbound_allow": [], "inbound_allow": [other],
        })
        assert resp.status_code == 200
        ovr = ps.get_device_lan_override("aa:bb:cc:dd:ee:ff")
        assert ovr is not None
        assert ovr["inbound_allow"] == [other]

    def test_profiles_include_lan_access(self, unlocked_client):
        c, _ = unlocked_client
        c.post("/api/profiles", json={"name": "LAN", "type": "no_vpn"})
        profiles = c.get("/api/profiles").json
        assert "lan_access" in profiles[0]
        assert profiles[0]["lan_access"]["outbound"] == "allowed"
        # Allow lists must always be present in the API shape (even when empty)
        assert profiles[0]["lan_access"]["outbound_allow"] == []
        assert profiles[0]["lan_access"]["inbound_allow"] == []

    def test_devices_include_lan_fields(self, unlocked_client):
        c, app_mod = unlocked_client
        create = c.post("/api/profiles", json={"name": "LAN", "type": "no_vpn"})
        pid = create.json["id"]
        ps.assign_device("aa:bb:cc:dd:ee:ff", pid)

        # Stage 8: device data is live from router. Mock the live sources.
        app_mod._router_api.get_dhcp_leases.return_value = [
            {"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.8.100", "hostname": "test"}
        ]
        app_mod._router_api.get_client_details.return_value = {}
        app_mod._router_api.get_flint_vpn_rules.return_value = []
        app_mod._router_api.get_device_assignments.return_value = {}
        app_mod._service.invalidate_device_cache()

        devices = c.get("/api/devices").json
        d = next(x for x in devices if x["mac"] == "aa:bb:cc:dd:ee:ff")
        assert "lan_outbound" in d
        assert "lan_inbound" in d
        assert "lan_inherited" in d
        assert "lan_outbound_allow" in d
        assert "lan_inbound_allow" in d

    def test_invalid_lan_value(self, unlocked_client):
        c, _ = unlocked_client
        create = c.post("/api/profiles", json={"name": "LAN", "type": "no_vpn"})
        pid = create.json["id"]
        resp = c.put(f"/api/profiles/{pid}/lan-access", json={
            "outbound": "invalid", "inbound": "allowed"
        })
        assert resp.status_code == 400


class TestRefreshEndpoint:
    def test_refresh(self, unlocked_client):
        c, _ = unlocked_client
        with patch("app.get_tracker") as mock_tracker:
            mock_tracker.return_value = MagicMock()
            resp = c.post("/api/refresh")
        assert resp.json["success"] is True


class TestBackupAndRestore:
    """Backup-to-router on save() + auto-restore-on-unlock from router."""

    def test_backup_callback_pushes_to_router_after_save(self, unlocked_client):
        c, app_mod = unlocked_client
        # Configure mocks: router fingerprint is a string (not MagicMock) so
        # the backup wrapper can JSON-serialize it.
        app_mod._router_api.get_router_fingerprint.return_value = "aa:bb:cc:11:22:33"
        app_mod._router_api.write_file.reset_mock()
        # Backup wrapper writes via router.write_file
        ps.save({**ps._EMPTY_STORE, "profiles": [
            {"id": "p1", "type": "no_vpn", "name": "Test",
             "color": "#000", "icon": "🔒", "is_guest": False},
        ]})
        # write_file should have been called with the backup path
        write_calls = app_mod._router_api.write_file.call_args_list
        assert any(
            call.args[0] == ROUTER_BACKUP_PATH for call in write_calls
        )
        # The wrapped JSON should contain the profile data + _meta
        last_call = next(
            call for call in write_calls
            if call.args[0] == ROUTER_BACKUP_PATH
        )
        wrapped = json.loads(last_call.args[1])
        assert wrapped["_meta"]["version"] == 1
        assert "saved_at" in wrapped["_meta"]
        assert wrapped["data"]["profiles"][0]["id"] == "p1"

    def test_backup_failure_does_not_break_save(self, unlocked_client):
        c, app_mod = unlocked_client
        app_mod._router_api.write_file.side_effect = RuntimeError("ssh down")
        # Save should still succeed even though backup fails
        ps.save({**ps._EMPTY_STORE, "profiles": [
            {"id": "p2", "type": "no_vpn", "name": "Test2",
             "color": "#000", "icon": "🔒", "is_guest": False},
        ]})
        # Local file is intact
        loaded = ps.load()
        assert loaded["profiles"][0]["id"] == "p2"

    def test_auto_restore_when_local_missing(self, unlocked_client):
        c, app_mod = unlocked_client
        # Make sure local store is missing
        if ps.STORE_FILE.exists():
            ps.STORE_FILE.unlink()

        # Mock router's read_file to return a backup with newer timestamp
        from datetime import datetime, timezone, timedelta
        backup = {
            "_meta": {
                "version": 1,
                "saved_at": (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat(),
                "router_fingerprint": "aa:bb:cc:11:22:33",
            },
            "data": {
                "profiles": [{"id": "restored-id", "type": "no_vpn", "name": "Restored",
                              "color": "#000", "icon": "🔒", "is_guest": False}],
                "device_assignments": {},
                "device_lan_overrides": {},
            },
        }
        app_mod._router_api.read_file.return_value = json.dumps(backup)
        app_mod._router_api.get_router_fingerprint.return_value = "aa:bb:cc:11:22:33"

        check_and_auto_restore(app_mod._router_api)

        loaded = ps.load()
        assert any(p["id"] == "restored-id" for p in loaded["profiles"])

    def test_auto_restore_skipped_on_fingerprint_mismatch(self, unlocked_client):
        c, app_mod = unlocked_client
        if ps.STORE_FILE.exists():
            ps.STORE_FILE.unlink()
        from datetime import datetime, timezone
        backup = {
            "_meta": {
                "version": 1,
                "saved_at": datetime.now(timezone.utc).isoformat(),
                "router_fingerprint": "aa:bb:cc:11:22:33",
            },
            "data": {"profiles": [{"id": "wrong-router", "type": "no_vpn",
                                   "name": "X", "color": "#000", "icon": "🔒",
                                   "is_guest": False}],
                     "device_assignments": {}, "device_lan_overrides": {}},
        }
        app_mod._router_api.read_file.return_value = json.dumps(backup)
        # Different fingerprint
        app_mod._router_api.get_router_fingerprint.return_value = "ff:ee:dd:cc:bb:aa"

        check_and_auto_restore(app_mod._router_api)

        # Local store should still be missing (no restore)
        assert not ps.STORE_FILE.exists()

    def test_auto_restore_self_heal_when_local_newer(self, unlocked_client):
        c, app_mod = unlocked_client
        # Local store with current mtime
        ps.save({
            **ps._EMPTY_STORE,
            "profiles": [{"id": "local-newer", "type": "no_vpn",
                          "name": "X", "color": "#000", "icon": "🔒",
                          "is_guest": False}],
        })
        # Backup timestamp from 1 hour ago (older than local)
        from datetime import datetime, timezone, timedelta
        backup = {
            "_meta": {
                "version": 1,
                "saved_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
                "router_fingerprint": "aa:bb:cc:11:22:33",
            },
            "data": {"profiles": [{"id": "old-backup", "type": "no_vpn",
                                   "name": "Old", "color": "#000", "icon": "🔒",
                                   "is_guest": False}],
                     "device_assignments": {}, "device_lan_overrides": {}},
        }
        app_mod._router_api.read_file.return_value = json.dumps(backup)
        app_mod._router_api.get_router_fingerprint.return_value = "aa:bb:cc:11:22:33"
        app_mod._router_api.write_file.reset_mock()

        check_and_auto_restore(app_mod._router_api)

        # Local should still be the local-newer version
        loaded = ps.load()
        assert any(p["id"] == "local-newer" for p in loaded["profiles"])
        # Self-heal should have called write_file with backup path
        write_calls = app_mod._router_api.write_file.call_args_list
        assert any(
            call.args[0] == ROUTER_BACKUP_PATH for call in write_calls
        )

    def test_auto_restore_no_op_when_no_backup(self, unlocked_client):
        c, app_mod = unlocked_client
        if ps.STORE_FILE.exists():
            ps.STORE_FILE.unlink()
        app_mod._router_api.read_file.return_value = None
        # Should not raise, should not restore
        check_and_auto_restore(app_mod._router_api)
        assert not ps.STORE_FILE.exists()


class TestProtonWgConnectDisconnect:
    """Tests for WireGuard TCP/TLS (proton-wg) tunnel lifecycle."""

    def _make_proton_wg_profile(self, app_mod, proto="wireguard-tcp"):
        ps.save({
            **ps._EMPTY_STORE,
            "profiles": [{
                "id": "test-pwg-1",
                "type": "vpn",
                "name": "WG TCP Test",
                "color": "#00aaff",
                "icon": "🔒",
                "is_guest": False,
                "wg_key": "dGVzdGtleQ==",
                "cert_expiry": 1807264162,
                "router_info": {
                    "tunnel_name": "protonwg0",
                    "tunnel_id": 303,
                    "mark": "0x6000",
                    "table_num": 1006,
                    "ipset_name": "src_mac_303",
                    "socket_type": "tcp",
                    "vpn_protocol": proto,
                    "rule_name": "fvpn_pwg_protonwg0",
                },
            }],
        })

    def test_connect_calls_start_proton_wg_tunnel(self, unlocked_client):
        c, app_mod = unlocked_client
        self._make_proton_wg_profile(app_mod)
        app_mod._router_api.start_proton_wg_tunnel.return_value = None
        app_mod._router_api.get_proton_wg_health.return_value = "green"

        resp = c.post("/api/profiles/test-pwg-1/connect")
        assert resp.status_code == 200
        assert resp.json["health"] == "green"
        app_mod._router_api.start_proton_wg_tunnel.assert_called_once_with(
            iface="protonwg0", mark="0x6000", table_num=1006, tunnel_id=303,
        )
        # Should NOT call bring_tunnel_up (that's for kernel WG / OVPN)
        app_mod._router_api.bring_tunnel_up.assert_not_called()

    def test_disconnect_calls_stop_proton_wg_tunnel(self, unlocked_client):
        c, app_mod = unlocked_client
        self._make_proton_wg_profile(app_mod)
        app_mod._router_api.stop_proton_wg_tunnel.return_value = None

        resp = c.post("/api/profiles/test-pwg-1/disconnect")
        assert resp.status_code == 200
        app_mod._router_api.stop_proton_wg_tunnel.assert_called_once_with(
            iface="protonwg0", mark="0x6000", table_num=1006, tunnel_id=303,
        )
        app_mod._router_api.bring_tunnel_down.assert_not_called()

    def test_kernel_wg_still_uses_bring_tunnel_up(self, unlocked_client):
        """Kernel WG (UDP) profiles must NOT go through proton-wg path."""
        c, app_mod = unlocked_client
        ps.save({
            **ps._EMPTY_STORE,
            "profiles": [{
                "id": "test-udp-1", "type": "vpn", "name": "WG UDP",
                "color": "#fff", "icon": "🔒", "is_guest": False,
                "router_info": {
                    "rule_name": "fvpn_rule_9001",
                    "peer_id": "9001",
                    "vpn_protocol": "wireguard",
                },
            }],
        })
        app_mod._router_api.bring_tunnel_up.return_value = None
        app_mod._router_api.get_tunnel_health.return_value = "green"

        resp = c.post("/api/profiles/test-udp-1/connect")
        assert resp.status_code == 200
        app_mod._router_api.bring_tunnel_up.assert_called_once()
        app_mod._router_api.start_proton_wg_tunnel.assert_not_called()

    def test_openvpn_still_uses_bring_tunnel_up(self, unlocked_client):
        """OpenVPN profiles must NOT go through proton-wg path."""
        c, app_mod = unlocked_client
        ps.save({
            **ps._EMPTY_STORE,
            "profiles": [{
                "id": "test-ovpn-1", "type": "vpn", "name": "OVPN Test",
                "color": "#fff", "icon": "🔒", "is_guest": False,
                "router_info": {
                    "rule_name": "fvpn_rule_ovpn_9051",
                    "client_uci_id": "28216_9051",
                    "vpn_protocol": "openvpn",
                },
            }],
        })
        app_mod._router_api.bring_tunnel_up.return_value = None
        app_mod._router_api.get_tunnel_health.return_value = "green"

        resp = c.post("/api/profiles/test-ovpn-1/connect")
        assert resp.status_code == 200
        app_mod._router_api.bring_tunnel_up.assert_called_once()
        app_mod._router_api.start_proton_wg_tunnel.assert_not_called()

    def test_delete_proton_wg_calls_stop_and_delete(self, unlocked_client):
        """Deleting a proton-wg profile must call stop + delete, not delete_wireguard_config."""
        c, app_mod = unlocked_client
        self._make_proton_wg_profile(app_mod)
        app_mod._router_api.stop_proton_wg_tunnel.return_value = None
        app_mod._router_api.delete_proton_wg_config.return_value = None

        resp = c.delete("/api/profiles/test-pwg-1")
        assert resp.status_code == 200
        app_mod._router_api.stop_proton_wg_tunnel.assert_called_once()
        app_mod._router_api.delete_proton_wg_config.assert_called_once()
        # Should NOT call kernel WG delete
        app_mod._router_api.delete_wireguard_config.assert_not_called()

    def test_delete_kernel_wg_still_uses_delete_wireguard_config(self, unlocked_client):
        c, app_mod = unlocked_client
        ps.save({
            **ps._EMPTY_STORE,
            "profiles": [{
                "id": "test-udp-1", "type": "vpn", "name": "WG UDP",
                "color": "#fff", "icon": "🔒", "is_guest": False,
                "router_info": {
                    "rule_name": "fvpn_rule_9001",
                    "peer_id": "9001",
                    "vpn_protocol": "wireguard",
                },
            }],
        })
        app_mod._router_api.delete_wireguard_config.return_value = None

        resp = c.delete("/api/profiles/test-udp-1")
        assert resp.status_code == 200
        app_mod._router_api.delete_wireguard_config.assert_called_once()
        app_mod._router_api.stop_proton_wg_tunnel.assert_not_called()

    def test_update_proton_wg_skips_kill_switch_and_rename(self, unlocked_client):
        """proton-wg profiles: kill_switch is always on, rename is local-only."""
        c, app_mod = unlocked_client
        self._make_proton_wg_profile(app_mod)

        resp = c.put("/api/profiles/test-pwg-1", json={
            "name": "Renamed",
            "kill_switch": False,
        })
        assert resp.status_code == 200
        assert resp.json["kill_switch"] is True  # Always on for proton-wg
        # Should NOT call router for rename or kill switch
        app_mod._router_api.rename_profile.assert_not_called()
        app_mod._router_api.set_kill_switch.assert_not_called()

    def test_wg_key_stored_for_proton_wg_profiles(self, unlocked_client):
        """wg_key and cert_expiry must be stored for all WG types including TCP/TLS."""
        c, app_mod = unlocked_client
        self._make_proton_wg_profile(app_mod)
        profile = ps.get_profile("test-pwg-1")
        assert profile["wg_key"] == "dGVzdGtleQ=="
        assert profile["cert_expiry"] == 1807264162

    def test_device_assignment_uses_ipset_for_proton_wg(self, unlocked_client):
        """Device assignment for proton-wg must use ipset add, not set_device_vpn."""
        c, app_mod = unlocked_client
        self._make_proton_wg_profile(app_mod)
        app_mod._router_api.remove_device_from_all_vpn.return_value = None
        app_mod._router_api.exec.return_value = ""

        resp = c.put("/api/devices/aa:bb:cc:dd:ee:ff/profile", json={
            "profile_id": "test-pwg-1",
        })
        assert resp.status_code == 200
        # Should call exec for ipset, not set_device_vpn
        app_mod._router_api.set_device_vpn.assert_not_called()
        # Verify ipset commands were called
        exec_calls = [str(c) for c in app_mod._router_api.exec.call_args_list]
        assert any("ipset create src_mac_303" in s for s in exec_calls)
        assert any("ipset add src_mac_303" in s for s in exec_calls)
