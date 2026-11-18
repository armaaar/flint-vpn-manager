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
    router.split_vpn.runtime_status.return_value = {
        name: spec["binary_sha256"] for name, spec in svc_mod.SPLITVPN_RUNTIME.items()
    }
    router.uci.show.return_value = {"fvpn_rule_9012": {"via": "wgclient5"}}
    router.exec.return_value = "305"

    def update_config(**kw):
        config.update(kw)
        return config

    with patch.object(svc_mod, "sm") as sm, \
         patch("persistence.profile_store.load", return_value=PROFILES):
        sm.get_config.side_effect = lambda: config
        sm.update_config.side_effect = update_config
        sm.unlock.return_value = {"proton_user": "x"}
        yield {"router": router, "config": config, "sm": sm, "svc": SplitVpnService(router)}


def _create(env, **kw):
    data = {"name": "Work VPN", "server": "vpn.example.com", "username": "alice",
            "password": "pw", "master_password": "mp", "group_ids": ["g_work"],
            "domains": ["corp.example"], "cidrs": ["10.50.0.0/16"]}
    data.update(kw)
    return env["svc"].create(data)


class TestCreate:
    def test_creates_and_stores_password_encrypted(self, env):
        vpn = _create(env)
        assert vpn["slot"] == 0 and vpn["has_password"] is True
        env["sm"].update.assert_called_once_with("mp", split_vpn_passwords={vpn["id"]: "pw"})
        assert "password" not in env["config"]["split_vpns"]["vpns"][0]
        env["router"].split_vpn.write_client_config.assert_called_once()

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

    def test_connect_requires_otp_and_password(self, env):
        vpn = _create(env)
        with pytest.raises(ValueError, match="one-time"):
            env["svc"].connect(vpn["id"], "")
        env["svc"]._passwords.clear()
        with pytest.raises(ValueError, match="No stored password"):
            env["svc"].connect(vpn["id"], "123456")

    def test_connect_requires_runtime(self, env):
        vpn = _create(env)
        env["router"].split_vpn.runtime_status.return_value = {}
        with pytest.raises(ValueError, match="runtime"):
            env["svc"].connect(vpn["id"], "123456")


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
