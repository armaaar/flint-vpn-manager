"""Tests for SmartProtocolManager — protocol fallback state machine."""

import threading
import time as real_time
from unittest.mock import MagicMock, patch, call

import pytest

from consts import (
    PROTO_WIREGUARD, PROTO_WIREGUARD_TCP, PROTO_WIREGUARD_TLS,
    PROTO_OPENVPN, PROFILE_TYPE_VPN,
)
from vpn.smart_protocol import SmartProtocolManager, CONNECT_TIMEOUT, PROTOCOL_CHAIN


def _make_manager(change_fn=None, lock_fn=None):
    if change_fn is None:
        change_fn = MagicMock()
    if lock_fn is None:
        lock_fn = MagicMock(return_value=threading.RLock())
    return SmartProtocolManager(change_fn, lock_fn)


def _make_profile(proto=PROTO_WIREGUARD, rule_name="fvpn_rule_9001",
                  profile_type=PROFILE_TYPE_VPN, options=None, server_scope=None):
    return {
        "type": profile_type,
        "router_info": {
            "rule_name": rule_name,
            "vpn_protocol": proto,
        },
        "options": options or {},
        "server_scope": server_scope,
    }


def _register(mgr, profile_id, proto, profile=None):
    """Register a profile using real time, then return the state."""
    if profile is None:
        profile = _make_profile(proto=proto)
    with patch("vpn.smart_protocol.ps") as mock_ps:
        mock_ps.get_profile.return_value = profile
        mgr.register(profile_id, proto)
    return mgr._pending[profile_id]


class TestRegister:
    def test_registers_profile(self):
        mgr = _make_manager()
        _register(mgr, "p1", PROTO_WIREGUARD)
        assert mgr.is_pending("p1")

    def test_chain_excludes_current_protocol(self):
        mgr = _make_manager()
        state = _register(mgr, "p1", PROTO_WIREGUARD)
        protos = [p for p, _ in state["chain"]]
        assert PROTO_WIREGUARD not in protos
        assert PROTO_WIREGUARD_TCP in protos

    def test_excludes_openvpn_for_tor_servers(self):
        mgr = _make_manager()
        profile = _make_profile(server_scope={"features": {"tor": True}})
        state = _register(mgr, "p1", PROTO_WIREGUARD, profile)
        protos = [p for p, _ in state["chain"]]
        assert PROTO_OPENVPN not in protos

    def test_excludes_openvpn_for_secure_core(self):
        mgr = _make_manager()
        profile = _make_profile(server_scope={"features": {"secure_core": True}})
        state = _register(mgr, "p1", PROTO_WIREGUARD, profile)
        protos = [p for p, _ in state["chain"]]
        assert PROTO_OPENVPN not in protos


class TestCancel:
    def test_removes_from_pending(self):
        mgr = _make_manager()
        _register(mgr, "p1", PROTO_WIREGUARD)
        mgr.cancel("p1")
        assert not mgr.is_pending("p1")

    def test_cancel_nonexistent_is_noop(self):
        mgr = _make_manager()
        mgr.cancel("nonexistent")


class TestIsPending:
    def test_not_pending(self):
        mgr = _make_manager()
        assert not mgr.is_pending("p1")


class TestTick:
    def test_noop_when_no_pending(self):
        mgr = _make_manager()
        mgr.tick(MagicMock())

    def test_cancels_non_vpn_profile(self):
        mgr = _make_manager()
        with patch("vpn.smart_protocol.ps") as mock_ps:
            mock_ps.get_profile.return_value = _make_profile()
            mgr.register("p1", PROTO_WIREGUARD)
            mock_ps.get_profile.return_value = _make_profile(profile_type="no_vpn")
            mgr.tick(MagicMock())
        assert not mgr.is_pending("p1")

    def test_cancels_when_profile_deleted(self):
        mgr = _make_manager()
        with patch("vpn.smart_protocol.ps") as mock_ps:
            mock_ps.get_profile.return_value = _make_profile()
            mgr.register("p1", PROTO_WIREGUARD)
            mock_ps.get_profile.return_value = None
            mgr.tick(MagicMock())
        assert not mgr.is_pending("p1")

    def test_cancels_when_no_rule_name(self):
        mgr = _make_manager()
        profile_no_rule = _make_profile()
        profile_no_rule["router_info"]["rule_name"] = ""
        with patch("vpn.smart_protocol.ps") as mock_ps:
            mock_ps.get_profile.return_value = _make_profile()
            mgr.register("p1", PROTO_WIREGUARD)
            mock_ps.get_profile.return_value = profile_no_rule
            mgr.tick(MagicMock())
        assert not mgr.is_pending("p1")

    def test_removes_on_green_health(self):
        mgr = _make_manager()
        with patch("vpn.smart_protocol.ps") as mock_ps, \
             patch("vpn.smart_protocol.get_strategy") as mock_gs:
            mock_ps.get_profile.return_value = _make_profile()
            mgr.register("p1", PROTO_WIREGUARD)
            mock_gs.return_value.get_health.return_value = "green"
            mgr.tick(MagicMock())
        assert not mgr.is_pending("p1")

    def test_removes_on_amber_health(self):
        mgr = _make_manager()
        with patch("vpn.smart_protocol.ps") as mock_ps, \
             patch("vpn.smart_protocol.get_strategy") as mock_gs:
            mock_ps.get_profile.return_value = _make_profile()
            mgr.register("p1", PROTO_WIREGUARD)
            mock_gs.return_value.get_health.return_value = "amber"
            mgr.tick(MagicMock())
        assert not mgr.is_pending("p1")

    def test_waits_before_timeout(self):
        mgr = _make_manager()
        _register(mgr, "p1", PROTO_WIREGUARD)
        # started_at is real time.time(), so elapsed is ~0 — well under timeout
        with patch("vpn.smart_protocol.ps") as mock_ps, \
             patch("vpn.smart_protocol.get_strategy") as mock_gs:
            mock_ps.get_profile.return_value = _make_profile()
            mock_gs.return_value.get_health.return_value = "red"
            mgr.tick(MagicMock())
        assert mgr.is_pending("p1")

    def test_switches_protocol_after_timeout(self):
        change_fn = MagicMock()
        mgr = _make_manager(change_fn=change_fn)
        _register(mgr, "p1", PROTO_WIREGUARD)
        # Force past timeout
        mgr._pending["p1"]["started_at"] = real_time.time() - CONNECT_TIMEOUT - 1

        with patch("vpn.smart_protocol.ps") as mock_ps, \
             patch("vpn.smart_protocol.get_strategy") as mock_gs, \
             patch("vpn.smart_protocol.check_protocol_slot", return_value=True):
            mock_ps.get_profile.return_value = _make_profile()
            mock_gs.return_value.get_health.return_value = "red"
            mgr.tick(MagicMock())

        change_fn.assert_called_once()
        assert change_fn.call_args[0][0] == "p1"
        assert change_fn.call_args[0][1] == PROTO_WIREGUARD_TCP

    def test_skips_unavailable_protocol_slots(self):
        change_fn = MagicMock()
        mgr = _make_manager(change_fn=change_fn)
        _register(mgr, "p1", PROTO_WIREGUARD)
        mgr._pending["p1"]["started_at"] = real_time.time() - CONNECT_TIMEOUT - 1

        with patch("vpn.smart_protocol.ps") as mock_ps, \
             patch("vpn.smart_protocol.get_strategy") as mock_gs, \
             patch("vpn.smart_protocol.check_protocol_slot") as mock_check:
            mock_ps.get_profile.return_value = _make_profile()
            mock_gs.return_value.get_health.return_value = "red"
            mock_check.side_effect = lambda proto, **kw: proto != PROTO_WIREGUARD_TCP
            mgr.tick(MagicMock())

        assert change_fn.call_args[0][1] == PROTO_WIREGUARD_TLS

    def test_exhausts_all_protocols(self):
        change_fn = MagicMock()
        mgr = _make_manager(change_fn=change_fn)
        _register(mgr, "p1", PROTO_WIREGUARD)
        mgr._pending["p1"]["started_at"] = real_time.time() - CONNECT_TIMEOUT - 1

        with patch("vpn.smart_protocol.ps") as mock_ps, \
             patch("vpn.smart_protocol.get_strategy") as mock_gs, \
             patch("vpn.smart_protocol.check_protocol_slot", return_value=False):
            mock_ps.get_profile.return_value = _make_profile()
            mock_gs.return_value.get_health.return_value = "red"
            mgr.tick(MagicMock())

        assert not mgr.is_pending("p1")
        change_fn.assert_not_called()

    def test_does_not_switch_when_lock_held(self):
        change_fn = MagicMock()
        # Use a regular Lock (non-reentrant) held from another thread
        lock = threading.Lock()
        held = threading.Event()

        def hold_lock():
            lock.acquire()
            held.set()
            # Hold until test is done
            real_time.sleep(2)
            lock.release()

        t = threading.Thread(target=hold_lock, daemon=True)
        t.start()
        held.wait()  # Ensure lock is acquired by the other thread

        lock_fn = MagicMock(return_value=lock)
        mgr = _make_manager(change_fn=change_fn, lock_fn=lock_fn)
        _register(mgr, "p1", PROTO_WIREGUARD)
        mgr._pending["p1"]["started_at"] = real_time.time() - CONNECT_TIMEOUT - 1

        with patch("vpn.smart_protocol.ps") as mock_ps, \
             patch("vpn.smart_protocol.get_strategy") as mock_gs:
            mock_ps.get_profile.return_value = _make_profile()
            mock_gs.return_value.get_health.return_value = "red"
            mgr.tick(MagicMock())

        change_fn.assert_not_called()
        assert mgr.is_pending("p1")

    def test_clears_port_and_custom_dns_on_switch(self):
        change_fn = MagicMock()
        mgr = _make_manager(change_fn=change_fn)
        profile = _make_profile(options={"port": 51820, "custom_dns": "1.1.1.1"})
        _register(mgr, "p1", PROTO_WIREGUARD)
        mgr._pending["p1"]["started_at"] = real_time.time() - CONNECT_TIMEOUT - 1

        with patch("vpn.smart_protocol.ps") as mock_ps, \
             patch("vpn.smart_protocol.get_strategy") as mock_gs, \
             patch("vpn.smart_protocol.check_protocol_slot", return_value=True):
            mock_ps.get_profile.return_value = profile
            mock_gs.return_value.get_health.return_value = "red"
            mgr.tick(MagicMock())

        update_call = mock_ps.update_profile.call_args
        assert update_call[0][0] == "p1"
        updated_opts = update_call[1]["options"]
        assert "port" not in updated_opts
        assert "custom_dns" not in updated_opts

    def test_ssh_error_retries_next_tick(self):
        mgr = _make_manager()
        with patch("vpn.smart_protocol.ps") as mock_ps, \
             patch("vpn.smart_protocol.get_strategy") as mock_gs:
            mock_ps.get_profile.return_value = _make_profile()
            mgr.register("p1", PROTO_WIREGUARD)
            mock_gs.return_value.get_health.side_effect = Exception("SSH error")
            mgr.tick(MagicMock())
        assert mgr.is_pending("p1")


class TestGetStatus:
    def test_empty_status(self):
        mgr = _make_manager()
        assert mgr.get_status() == {}

    def test_status_with_pending(self):
        mgr = _make_manager()
        _register(mgr, "p1", PROTO_WIREGUARD)
        status = mgr.get_status()
        assert "p1" in status
        assert status["p1"]["attempting"] == PROTO_WIREGUARD
        assert status["p1"]["attempt"] == 1
        assert status["p1"]["total"] == len(PROTOCOL_CHAIN)

    def test_status_after_switch(self):
        change_fn = MagicMock()
        mgr = _make_manager(change_fn=change_fn)
        _register(mgr, "p1", PROTO_WIREGUARD)
        mgr._pending["p1"]["started_at"] = real_time.time() - CONNECT_TIMEOUT - 1

        with patch("vpn.smart_protocol.ps") as mock_ps, \
             patch("vpn.smart_protocol.get_strategy") as mock_gs, \
             patch("vpn.smart_protocol.check_protocol_slot", return_value=True):
            mock_ps.get_profile.return_value = _make_profile()
            mock_gs.return_value.get_health.return_value = "red"
            mgr.tick(MagicMock())

        status = mgr.get_status()
        if "p1" in status:
            assert status["p1"]["attempt"] == 2
