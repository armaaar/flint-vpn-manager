"""Tests for SplitVpnService."""

import hashlib
import io
import tarfile
from unittest.mock import MagicMock, patch

import pytest

import services.split_vpn_service as svc_mod
from services.split_vpn_service import SplitVpnService, _extract_from_deb, _is_connected

PROFILES = {"profiles": [
    {"id": "g_work", "type": "vpn", "name": "Work",
     "router_info": {"rule_name": "fvpn_rule_9012", "vpn_protocol": "wireguard"}},
    {"id": "g_off", "type": "no_internet", "name": "Offline"},
]}


@pytest.fixture
def env():
    config = {"router_ip": "192.168.8.1"}
    router = MagicMock()
    hashes = {n: h for n, (_, h) in svc_mod.SPLITVPN_BARRACUDA["files"].items()}
    router.split_vpn.runtime_status.return_value = {**hashes, "qemu-x86_64": "localbuild"}
    router.uci.show.return_value = {"fvpn_rule_9012": {"via": "wgclient5"}}
    router.exec.return_value = "305"

    def update_config(**kw):
        config.update(kw)
        return config

    with patch.object(svc_mod, "sm") as sm, \
         patch.object(svc_mod, "_expected_runtime_hashes",
                      return_value={**hashes, "qemu-x86_64": "localbuild"}), \
         patch("persistence.profile_store.load", return_value=PROFILES):
        sm.get_config.side_effect = lambda: config
        sm.update_config.side_effect = update_config
        sm.unlock.return_value = {"proton_user": "x"}
        yield {"router": router, "config": config, "sm": sm, "svc": SplitVpnService(router)}


def _create(env, **kw):
    data = {"name": "Work VPN", "server": "vpn.example.com", "username": "alice",
            "password": "pw", "master_password": "mp", "group_ids": ["g_work"],
            "totp_secret": "JBSWY3DPEHPK3PXP",
            "domains": ["corp.example"], "cidrs": ["10.50.0.0/16"]}
    data.update(kw)
    return env["svc"].create(data)


class TestCreate:
    def test_creates_and_stores_credentials_encrypted(self, env):
        vpn = _create(env)
        assert vpn["slot"] == 0 and vpn["has_password"] is True and vpn["has_totp"] is True
        (mp,), kwargs = env["sm"].update.call_args
        assert mp == "mp"
        entry = kwargs["split_vpn_credentials"][vpn["id"]]
        assert entry["password"] == "pw"
        assert entry["totp"]["secret"] == "JBSWY3DPEHPK3PXP"
        stored = env["config"]["split_vpns"]["vpns"][0]
        assert "password" not in stored and "totp_secret" not in stored
        env["router"].split_vpn.write_client_config.assert_called_once()

    def test_rejects_invalid_totp_secret(self, env):
        with pytest.raises(ValueError, match="base32"):
            _create(env, totp_secret="not base32 !!")
        env["router"].split_vpn.write_client_config.assert_not_called()
        env["sm"].update.assert_not_called()

    def test_requires_master_password(self, env):
        with pytest.raises(ValueError, match="Master password"):
            _create(env, master_password="")

    def test_wrong_master_password(self, env):
        env["sm"].unlock.side_effect = ValueError("bad")
        with pytest.raises(ValueError, match="Wrong master password"):
            _create(env)

    def test_rejects_group_without_internet(self, env):
        with pytest.raises(ValueError, match="no internet"):
            _create(env, group_ids=["g_off"])

    def test_rejects_default_route_cidr(self, env):
        with pytest.raises(ValueError, match="default routes"):
            _create(env, cidrs=["0.0.0.0/0"])

    def test_allocates_next_free_slot_and_caps(self, env):
        slots = [_create(env, name=f"v{i}")["slot"] for i in range(4)]
        assert slots == [0, 1, 2, 3]
        with pytest.raises(ValueError, match="At most"):
            _create(env, name="v5")


class TestReapply:
    def test_builds_instances_for_router(self, env):
        vpn = _create(env)
        env["svc"]._record_pushed(vpn["id"], {"routes": ["10.0.0.0/8"], "dns": ["10.0.0.53"]})
        env["router"].split_vpn.apply_routing.reset_mock()
        env["svc"].reapply_all()
        (instances,), _ = env["router"].split_vpn.apply_routing.call_args
        inst = instances[0]
        assert inst["group_ipsets"] == ["src_mac_305"]
        assert set(inst["cidrs"]) == {"10.50.0.0/16", "10.0.0.0/8"}
        assert inst["dns_servers"] == ["10.0.0.53"]
        assert inst["dnsmasq_ifaces"] == ["wgclient5"]

    def test_pushed_routes_can_be_ignored(self, env):
        vpn = _create(env, use_pushed_routes=False)
        env["svc"]._record_pushed(vpn["id"], {"routes": ["10.0.0.0/8"], "dns": []})
        env["svc"].reapply_all()
        (instances,), _ = env["router"].split_vpn.apply_routing.call_args
        assert instances[0]["cidrs"] == ["10.50.0.0/16"]

    def test_disabled_vpn_clears_routing(self, env):
        _create(env, enabled=False)
        env["svc"].reapply_all()
        env["router"].split_vpn.apply_routing.assert_called_with([])


class TestConnect:
    def test_connect_records_pushed_routes(self, env):
        vpn = _create(env)
        env["router"].split_vpn.connect.return_value = {
            "state": "CONNECTED", "ip": "10.9.9.9", "dns": ["10.0.0.53"], "routes": ["10.0.0.0/8"],
        }
        res = env["svc"].connect(vpn["id"], " 123456 ")
        assert res["connected"] is True
        env["router"].split_vpn.connect.assert_called_with(0, "alice", "pw", "123456")
        stored = env["config"]["split_vpns"]["vpns"][0]
        assert stored["pushed_routes"] == ["10.0.0.0/8"]
        assert stored["pushed_dns"] == ["10.0.0.53"]

    def test_connect_generates_code_from_totp_secret(self, env):
        vpn = _create(env)
        env["router"].split_vpn.connect.return_value = {"state": "CONNECTED", "ip": "10.9.9.9"}
        with patch.object(svc_mod, "seconds_left", return_value=25), \
             patch.object(svc_mod, "totp_code", return_value="654321") as code:
            env["svc"].connect(vpn["id"])
        assert code.call_args.args[0]["secret"] == "JBSWY3DPEHPK3PXP"
        env["router"].split_vpn.connect.assert_called_with(0, "alice", "pw", "654321")

    def test_waits_for_fresh_window_when_code_about_to_expire(self, env):
        vpn = _create(env)
        env["router"].split_vpn.connect.return_value = {"state": "CONNECTED"}
        with patch.object(svc_mod, "seconds_left", return_value=3), \
             patch.object(svc_mod.time, "sleep") as sleep:
            env["svc"].connect(vpn["id"])
        sleep.assert_called_once_with(3.5)

    def test_connect_requires_secret_or_otp_and_password(self, env):
        vpn = _create(env, totp_secret=None)
        with pytest.raises(ValueError, match="No TOTP secret"):
            env["svc"].connect(vpn["id"])
        env["svc"]._creds.clear()
        with pytest.raises(ValueError, match="No stored password"):
            env["svc"].connect(vpn["id"], "123456")

    def test_connect_requires_runtime(self, env):
        vpn = _create(env)
        env["router"].split_vpn.runtime_status.return_value = {}
        with pytest.raises(ValueError, match="runtime"):
            env["svc"].connect(vpn["id"], "123456")


class TestMonitor:
    def test_reconnects_down_vpn_and_backs_off_on_failure(self, env):
        vpn = _create(env)
        env["router"].split_vpn.status.return_value = {"state": "DOWN"}
        env["router"].split_vpn.connect.return_value = {"state": "DISCONNECTED"}
        svc = env["svc"]
        assert svc.check_and_reconnect(now=1000) == [vpn["id"]]
        # failed -> backoff: an immediate second pass doesn't retry
        assert svc.check_and_reconnect(now=1001) == []

    def test_skips_connected_disabled_and_manual_disconnect(self, env):
        vpn = _create(env)
        svc = env["svc"]
        env["router"].split_vpn.status.return_value = {"state": "CONNECTED"}
        assert svc.check_and_reconnect(now=1000) == []
        env["router"].split_vpn.status.return_value = {"state": "DOWN"}
        svc.disconnect(vpn["id"])                      # manual → paused
        assert svc.check_and_reconnect(now=10**9) == []
        svc.update(vpn["id"], {"auto_connect": False})
        svc._backoff.clear()
        assert svc.check_and_reconnect(now=10**9) == []


class TestGroupDeleted:
    def test_removes_group_from_vpns(self, env):
        _create(env)
        env["svc"].on_group_deleted("g_work")
        assert env["config"]["split_vpns"]["vpns"][0]["group_ids"] == []


@pytest.mark.parametrize("status,expected", [
    ({"state": "CONNECTED"}, True),
    ({"state": "SOMETHING", "ip": "10.0.0.2"}, True),
    ({"state": "DISCONNECTED", "ip": "10.0.0.2"}, False),
    ({"state": "DOWN"}, False),
])
def test_is_connected(status, expected):
    assert _is_connected(status) is expected


def test_extract_from_deb():
    payload = b"binary!"
    tbuf = io.BytesIO()
    with tarfile.open(fileobj=tbuf, mode="w:xz") as tf:
        info = tarfile.TarInfo("./usr/bin/qemu-x86_64")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    body = tbuf.getvalue()

    def member(name, data):
        hdr = f"{name:<16}{0:<12}{0:<6}{0:<6}{100644:<8}{len(data):<10}`\n".encode()
        return hdr + data + (b"\n" if len(data) % 2 else b"")

    deb = b"!<arch>\n" + member("debian-binary", b"2.0\n") + member("data.tar.xz", body)
    assert _extract_from_deb(deb, "./usr/bin/qemu-x86_64") == payload


class TestSopsCredentials:
    def test_create_with_secret_ref_needs_no_password(self, env):
        with patch.object(svc_mod.sops, "split_vpn_credentials",
                          return_value={"username": "bob", "password": "sops-pw",
                                        "totp_secret": "JBSWY3DPEHPK3PXP"}):
            vpn = env["svc"].create({"name": "Work", "server": "vpn.example.com",
                                     "secret_ref": "work", "group_ids": ["g_work"]})
            assert vpn["credentials_source"] == "sops"
            assert vpn["has_password"] and vpn["has_totp"]
        env["sm"].update.assert_not_called()          # nothing copied into secrets.enc

    def test_connect_uses_sops_values(self, env):
        creds = {"username": "bob", "password": "sops-pw", "totp_secret": "JBSWY3DPEHPK3PXP"}
        with patch.object(svc_mod.sops, "split_vpn_credentials", return_value=creds):
            vpn = env["svc"].create({"name": "Work", "server": "vpn.example.com",
                                     "secret_ref": "work", "group_ids": ["g_work"]})
            env["router"].split_vpn.connect.return_value = {"state": "CONNECTED"}
            with patch.object(svc_mod, "seconds_left", return_value=25), \
                 patch.object(svc_mod, "totp_code", return_value="111222"):
                env["svc"].connect(vpn["id"])
        env["router"].split_vpn.connect.assert_called_with(0, "bob", "sops-pw", "111222")

    def test_sops_error_surfaces_as_value_error(self, env):
        with patch.object(svc_mod.sops, "split_vpn_credentials",
                          side_effect=svc_mod.sops.SopsError("No 'split_vpns.x' entry")):
            with pytest.raises(ValueError, match="split_vpns.x"):
                env["svc"].create({"name": "Work", "server": "vpn.example.com",
                                   "secret_ref": "x", "group_ids": ["g_work"]})

    def test_rejects_bad_secret_ref(self, env):
        with pytest.raises(ValueError, match="SOPS secret reference"):
            env["svc"].create({"name": "W", "server": "vpn.example.com",
                               "secret_ref": "../etc", "group_ids": ["g_work"]})


class TestRuntime:
    def test_install_needs_vendor_archive(self, env, tmp_path):
        with patch.object(svc_mod, "_find_barracuda_archive", return_value=None):
            with pytest.raises(ValueError, match="dlportal"):
                env["svc"].install_runtime()

    def test_install_rejects_wrong_archive_hash(self, env, tmp_path):
        bad = tmp_path / "VPNClient_5.3.10_Linux.tar.gz"
        bad.write_bytes(b"not the real thing")
        with patch.object(svc_mod, "_find_barracuda_archive", return_value=bad):
            with pytest.raises(ValueError, match="Checksum mismatch"):
                env["svc"].install_runtime()
        env["router"].split_vpn.install_runtime_file.assert_not_called()

    def test_status_requires_every_runtime_file(self, env):
        env["router"].split_vpn.runtime_status.return_value = {"qemu-x86_64": "localbuild"}
        st = env["svc"].runtime_status()
        assert st["installed"] is False
        assert st["files"]["barracudavpn-daemon"] is False
