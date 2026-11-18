"""Tests for the Split VPN MCP tools and the MCP API client timeout override."""

import asyncio
import json
from unittest.mock import MagicMock

import httpx
import pytest
from mcp.server.fastmcp import FastMCP

from mcp_server.api_client import FlintAPI
from mcp_server.tools import split_vpn


@pytest.fixture
def setup():
    mcp = FastMCP("test")
    api = MagicMock()
    api.get.return_value = {"ok": True}
    api.post.return_value = {"ok": True}
    api.put.return_value = {"ok": True}
    api.delete.return_value = {"success": True}
    split_vpn.register(mcp, api)
    return mcp, api


def _call(mcp, tool, **args):
    _content, structured = asyncio.run(mcp.call_tool(tool, args))
    return json.loads(structured["result"])


def test_all_tools_registered(setup):
    mcp, _ = setup
    names = {t.name for t in asyncio.run(mcp.list_tools())}
    assert names == {
        "flint_list_split_vpns",
        "flint_create_split_vpn",
        "flint_update_split_vpn",
        "flint_delete_split_vpn",
        "flint_connect_split_vpn",
        "flint_disconnect_split_vpn",
        "flint_get_split_vpn_log",
        "flint_install_split_vpn_runtime",
    }


def test_list_live_default(setup):
    mcp, api = setup
    assert _call(mcp, "flint_list_split_vpns") == {"ok": True}
    api.get.assert_called_once_with("/api/split-vpns", live="1")


def test_list_not_live(setup):
    mcp, api = setup
    _call(mcp, "flint_list_split_vpns", live=False)
    api.get.assert_called_once_with("/api/split-vpns", live="0")


def test_create_sends_full_body(setup):
    mcp, api = setup
    _call(
        mcp, "flint_create_split_vpn",
        name="Work", server="vpn.example.com", username="alice",
        password="pw", master_password="mp", group_ids=["p1"],
        domains=["corp.example.com"],
    )
    api.post.assert_called_once_with("/api/split-vpns", json={
        "name": "Work",
        "server": "vpn.example.com",
        "port": 691,
        "tunnel_mode": "TCP",
        "username": "alice",
        "password": "pw",
        "master_password": "mp",
        "group_ids": ["p1"],
        "domains": ["corp.example.com"],
        "cidrs": [],
        "use_pushed_routes": True,
        "enabled": True,
        "auto_connect": True,
        "connect_mode": "always",
        "presence_macs": [],
        "presence_grace_min": 5,
        "yield_to_device_tunnel": True,
    })


def test_update_sends_only_given_fields(setup):
    mcp, api = setup
    _call(mcp, "flint_update_split_vpn", vpn_id="sv_1", enabled=False, cidrs=[])
    api.put.assert_called_once_with(
        "/api/split-vpns/sv_1", json={"enabled": False, "cidrs": []}
    )


def test_update_password_includes_master(setup):
    mcp, api = setup
    _call(mcp, "flint_update_split_vpn", vpn_id="sv_1",
          password="new", master_password="mp")
    api.put.assert_called_once_with(
        "/api/split-vpns/sv_1", json={"password": "new", "master_password": "mp"}
    )


def test_update_master_without_password_ignored(setup):
    mcp, api = setup
    _call(mcp, "flint_update_split_vpn", vpn_id="sv_1", master_password="mp")
    api.put.assert_called_once_with("/api/split-vpns/sv_1", json={})


def test_delete(setup):
    mcp, api = setup
    _call(mcp, "flint_delete_split_vpn", vpn_id="sv_1")
    api.delete.assert_called_once_with("/api/split-vpns/sv_1")


def test_connect_uses_long_timeout(setup):
    mcp, api = setup
    _call(mcp, "flint_connect_split_vpn", vpn_id="sv_1", otp="123456")
    args, kwargs = api.post.call_args
    assert args == ("/api/split-vpns/sv_1/connect",)
    assert kwargs["json"] == {"otp": "123456"}
    assert kwargs["timeout"] >= 200


def test_connect_without_otp_uses_stored_totp(setup):
    mcp, api = setup
    _call(mcp, "flint_connect_split_vpn", vpn_id="sv_1")
    _, kwargs = api.post.call_args
    assert kwargs["json"] == {}


def test_update_totp_secret_sends_master_password(setup):
    mcp, api = setup
    _call(mcp, "flint_update_split_vpn", vpn_id="sv_1", totp_secret="JBSWY3DPEHPK3PXP", master_password="mp")
    api.put.assert_called_once_with(
        "/api/split-vpns/sv_1", json={"totp_secret": "JBSWY3DPEHPK3PXP", "master_password": "mp"}
    )


def test_disconnect(setup):
    mcp, api = setup
    _call(mcp, "flint_disconnect_split_vpn", vpn_id="sv_1")
    api.post.assert_called_once_with("/api/split-vpns/sv_1/disconnect")


def test_get_log(setup):
    mcp, api = setup
    _call(mcp, "flint_get_split_vpn_log", vpn_id="sv_1")
    api.get.assert_called_once_with("/api/split-vpns/sv_1/log")


def test_install_runtime_uses_long_timeout(setup):
    mcp, api = setup
    _call(mcp, "flint_install_split_vpn_runtime")
    args, kwargs = api.post.call_args
    assert args == ("/api/split-vpns/runtime/install",)
    assert kwargs["timeout"] >= 600


# ── FlintAPI timeout override ────────────────────────────────────────────


def _api_with_transport(seen):
    def handler(request):
        seen.append(request.extensions["timeout"])
        return httpx.Response(200, json={"ok": True})

    api = FlintAPI("http://test")
    api._client = httpx.Client(
        base_url="http://test", transport=httpx.MockTransport(handler), timeout=30.0
    )
    return api


def test_post_default_timeout():
    seen = []
    _api_with_transport(seen).post("/x", json={})
    assert seen[0]["read"] == 30.0


def test_post_timeout_override():
    seen = []
    assert _api_with_transport(seen).post("/x", json={}, timeout=210.0) == {"ok": True}
    assert seen[0]["read"] == 210.0
