"""Tests for ipset_ops.py — Centralized ipset operations."""

from unittest.mock import MagicMock, patch, call

import pytest

from ipset_ops import IpsetOps


@pytest.fixture
def router():
    return MagicMock()


@pytest.fixture
def ipset(router):
    return IpsetOps(router)


class TestEnsureMacSet:
    def test_creates_ipset(self, ipset, router):
        ipset.ensure_mac_set("src_mac_42")
        router.exec.assert_called_once_with("ipset create src_mac_42 hash:mac -exist")


class TestAddMac:
    def test_adds_mac(self, ipset, router):
        ipset.add_mac("src_mac_42", "aa:bb:cc:dd:ee:ff")
        router.exec.assert_called_once_with("ipset add src_mac_42 aa:bb:cc:dd:ee:ff -exist")


class TestListMembers:
    def test_parses_members(self, ipset, router):
        router.exec.return_value = "AA:BB:CC:DD:EE:FF\n11:22:33:44:55:66\n"
        result = ipset.list_members("src_mac_42")
        assert result == ["AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"]

    def test_empty_ipset(self, ipset, router):
        router.exec.return_value = ""
        result = ipset.list_members("src_mac_42")
        assert result == []

    def test_returns_empty_on_error(self, ipset, router):
        router.exec.side_effect = RuntimeError("SSH failed")
        result = ipset.list_members("src_mac_42")
        assert result == []


class TestEnsureAndAdd:
    def test_calls_both(self, ipset, router):
        ipset.ensure_and_add("src_mac_42", "aa:bb:cc:dd:ee:ff")
        assert router.exec.call_count == 2
        router.exec.assert_any_call("ipset create src_mac_42 hash:mac -exist")
        router.exec.assert_any_call("ipset add src_mac_42 aa:bb:cc:dd:ee:ff -exist")


class TestReconcileProtonWgMembers:
    @patch("ipset_ops.ps.load")
    def test_readds_members_from_store(self, mock_load, ipset, router):
        mock_load.return_value = {
            "profiles": [{
                "id": "p1",
                "router_info": {
                    "vpn_protocol": "wireguard-tcp",
                    "tunnel_id": 42,
                    "ipset_name": "src_mac_42",
                },
            }],
            "device_assignments": {
                "aa:bb:cc:dd:ee:ff": "p1",
                "11:22:33:44:55:66": "p1",
                "99:99:99:99:99:99": "other_profile",
            },
        }
        ipset.reconcile_proton_wg_members()
        # Should add only the two MACs assigned to p1
        assert router.exec.call_count == 2
        router.exec.assert_any_call("ipset add src_mac_42 aa:bb:cc:dd:ee:ff -exist")
        router.exec.assert_any_call("ipset add src_mac_42 11:22:33:44:55:66 -exist")

    @patch("ipset_ops.ps.load")
    def test_skips_non_proton_wg(self, mock_load, ipset, router):
        mock_load.return_value = {
            "profiles": [{
                "id": "p1",
                "router_info": {"vpn_protocol": "wireguard", "tunnel_id": 1},
            }],
            "device_assignments": {"aa:bb:cc:dd:ee:ff": "p1"},
        }
        ipset.reconcile_proton_wg_members()
        router.exec.assert_not_called()

    def test_accepts_store_data_arg(self, ipset, router):
        store = {
            "profiles": [{
                "id": "p1",
                "router_info": {
                    "vpn_protocol": "wireguard-tls",
                    "tunnel_id": 7,
                    "ipset_name": "src_mac_7",
                },
            }],
            "device_assignments": {"aa:bb:cc:dd:ee:ff": "p1"},
        }
        ipset.reconcile_proton_wg_members(store)
        router.exec.assert_called_once_with("ipset add src_mac_7 aa:bb:cc:dd:ee:ff -exist")


class TestReconcileProtonWgFull:
    @patch("ipset_ops.ps.load")
    def test_creates_ipsets_adds_members_rebuilds_mangle(self, mock_load, ipset, router):
        mock_load.return_value = {
            "profiles": [{
                "id": "p1",
                "router_info": {
                    "vpn_protocol": "wireguard-tcp",
                    "tunnel_id": 42,
                    "ipset_name": "src_mac_42",
                },
            }],
            "device_assignments": {"aa:bb:cc:dd:ee:ff": "p1"},
        }
        ipset.reconcile_proton_wg_full()
        # Should: create ipset, add MAC, then rebuild mangle
        router.exec.assert_any_call("ipset create src_mac_42 hash:mac -exist")
        router.exec.assert_any_call("ipset add src_mac_42 aa:bb:cc:dd:ee:ff -exist")
        router._rebuild_proton_wg_mangle_rules.assert_called_once()

    @patch("ipset_ops.ps.load")
    def test_empty_profiles(self, mock_load, ipset, router):
        mock_load.return_value = {"profiles": [], "device_assignments": {}}
        ipset.reconcile_proton_wg_full()
        # Only mangle rebuild should happen
        router._rebuild_proton_wg_mangle_rules.assert_called_once()
