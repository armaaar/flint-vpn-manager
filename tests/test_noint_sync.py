"""Tests for noint_sync — NoInternet ipset enforcement."""

from unittest.mock import MagicMock, patch, call
import pytest

import noint_sync


def _make_store(profiles=None, assignments=None):
    return {
        "profiles": profiles or [],
        "device_assignments": assignments or {},
    }


def _noint_profile(pid="noint-1"):
    return {"id": pid, "type": "no_internet"}


def _novpn_profile(pid="novpn-1"):
    return {"id": pid, "type": "no_vpn"}


class TestSyncNointToRouter:
    """sync_noint_to_router — happy paths."""

    def _router(self, ipset_members="", rule_exists=True):
        r = MagicMock()
        r.exec.side_effect = lambda cmd, **kw: (
            ipset_members if "ipset list" in cmd
            else ("rule" if rule_exists else "MISSING")
        )
        return r

    def test_no_noint_groups_no_op(self):
        store = _make_store(profiles=[_novpn_profile()])
        r = self._router(rule_exists=False)
        result = noint_sync.sync_noint_to_router(r, store=store, device_ips={})
        assert not result["applied"]
        r.fvpn_ipset_membership.assert_not_called()
        r.fvpn_uci_apply.assert_not_called()

    def test_noint_group_creates_sections_on_first_run(self):
        store = _make_store(
            profiles=[_noint_profile("noint-1")],
            assignments={"aa:bb:cc:dd:ee:ff": "noint-1"},
        )
        r = self._router(rule_exists=False)
        result = noint_sync.sync_noint_to_router(
            r, store=store, device_ips={"aa:bb:cc:dd:ee:ff": "192.168.8.100"}
        )
        assert result["applied"]
        assert result["reload"]
        r.fvpn_uci_apply.assert_called_once()
        batch = r.fvpn_uci_apply.call_args[0][0]
        assert "fvpn_noint_ips" in batch
        assert "fvpn_noint_block" in batch
        assert "192.168.8.100" in batch

    def test_membership_add(self):
        store = _make_store(
            profiles=[_noint_profile("ni")],
            assignments={"aa:bb:cc:dd:ee:01": "ni", "aa:bb:cc:dd:ee:02": "ni"},
        )
        r = self._router(ipset_members="192.168.8.1\n", rule_exists=True)
        result = noint_sync.sync_noint_to_router(
            r, store=store,
            device_ips={
                "aa:bb:cc:dd:ee:01": "192.168.8.1",
                "aa:bb:cc:dd:ee:02": "192.168.8.2",
            },
        )
        assert result["applied"]
        assert result["adds"] == 1
        assert result["removes"] == 0
        r.fvpn_ipset_membership.assert_called_once_with(
            "fvpn_noint_ips", add=["192.168.8.2"], remove=[]
        )

    def test_membership_remove(self):
        store = _make_store(
            profiles=[_noint_profile("ni")],
            assignments={},  # no devices assigned
        )
        r = self._router(ipset_members="192.168.8.50\n192.168.8.51\n", rule_exists=True)
        result = noint_sync.sync_noint_to_router(r, store=store, device_ips={})
        assert result["removes"] == 2
        r.fvpn_ipset_membership.assert_called_once_with(
            "fvpn_noint_ips", add=[], remove=["192.168.8.50", "192.168.8.51"]
        )

    def test_device_without_ip_skipped(self):
        store = _make_store(
            profiles=[_noint_profile("ni")],
            assignments={"aa:bb:cc:dd:ee:ff": "ni"},
        )
        r = self._router(rule_exists=True)
        result = noint_sync.sync_noint_to_router(r, store=store, device_ips={})
        assert not result["applied"]

    def test_removes_sections_when_no_noint_groups_left(self):
        store = _make_store(profiles=[_novpn_profile()])
        r = self._router(ipset_members="192.168.8.1\n", rule_exists=True)
        result = noint_sync.sync_noint_to_router(r, store=store, device_ips={})
        assert result["applied"]
        assert result["reload"]
        batch = r.fvpn_uci_apply.call_args[0][0]
        assert "delete" in batch


class TestWipeNoint:
    def test_wipe_calls_cleanup(self):
        r = MagicMock()
        noint_sync.wipe_noint(r)
        assert r.exec.call_count == 2  # delete + reload
