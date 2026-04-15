"""Tests for ipset_ops.py — Centralized ipset operations.

IpsetOps now delegates to router.ipset_tool (Ipset tool layer).
Reconciliation writes .macs files on the router and runs the mangle script.
"""

from unittest.mock import MagicMock, patch, call

import pytest

from router.ipset_ops import IpsetOps


@pytest.fixture
def router():
    r = MagicMock()
    # ipset_tool is already a MagicMock auto-attribute on MagicMock
    return r


@pytest.fixture
def ipset(router):
    return IpsetOps(router)


class TestEnsureMacSet:
    def test_creates_ipset(self, ipset, router):
        ipset.ensure_mac_set("src_mac_42")
        router.ipset_tool.create.assert_called_once_with("src_mac_42", "hash:mac")


class TestAddMac:
    def test_adds_mac(self, ipset, router):
        ipset.add_mac("src_mac_42", "aa:bb:cc:dd:ee:ff")
        router.ipset_tool.add.assert_called_once_with("src_mac_42", "aa:bb:cc:dd:ee:ff")


class TestListMembers:
    def test_parses_members(self, ipset, router):
        router.ipset_tool.members.return_value = ["AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"]
        result = ipset.list_members("src_mac_42")
        assert result == ["AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"]

    def test_empty_ipset(self, ipset, router):
        router.ipset_tool.members.return_value = []
        result = ipset.list_members("src_mac_42")
        assert result == []

    def test_returns_empty_on_error(self, ipset, router):
        router.ipset_tool.members.side_effect = RuntimeError("SSH failed")
        result = ipset.list_members("src_mac_42")
        assert result == []


class TestEnsureAndAdd:
    def test_calls_both(self, ipset, router):
        ipset.ensure_and_add("src_mac_42", "aa:bb:cc:dd:ee:ff")
        router.ipset_tool.create.assert_called_once_with("src_mac_42", "hash:mac")
        router.ipset_tool.add.assert_called_once_with("src_mac_42", "aa:bb:cc:dd:ee:ff")


class TestReconcileProtonWgMembers:
    @patch("router.ipset_ops.ps.load")
    def test_syncs_macs_and_runs_script(self, mock_load, ipset, router):
        mock_load.return_value = {
            "profiles": [{
                "id": "p1",
                "router_info": {
                    "vpn_protocol": "wireguard-tcp",
                    "tunnel_id": 42,
                    "tunnel_name": "protonwg0",
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
        # Should write .macs file with the two MACs assigned to p1
        router.proton_wg.write_tunnel_macs.assert_called_once()
        args = router.proton_wg.write_tunnel_macs.call_args[0]
        assert args[0] == "protonwg0"
        assert set(args[1]) == {"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"}
        # Should run the mangle script
        router.exec.assert_called()

    @patch("router.ipset_ops.ps.load")
    def test_skips_non_proton_wg(self, mock_load, ipset, router):
        mock_load.return_value = {
            "profiles": [{
                "id": "p1",
                "router_info": {"vpn_protocol": "wireguard", "tunnel_id": 1},
            }],
            "device_assignments": {"aa:bb:cc:dd:ee:ff": "p1"},
        }
        ipset.reconcile_proton_wg_members()
        router.proton_wg.write_tunnel_macs.assert_not_called()

    def test_accepts_store_data_arg(self, ipset, router):
        store = {
            "profiles": [{
                "id": "p1",
                "router_info": {
                    "vpn_protocol": "wireguard-tls",
                    "tunnel_id": 7,
                    "tunnel_name": "protonwg0",
                    "ipset_name": "src_mac_7",
                },
            }],
            "device_assignments": {"aa:bb:cc:dd:ee:ff": "p1"},
        }
        ipset.reconcile_proton_wg_members(store)
        router.proton_wg.write_tunnel_macs.assert_called_once_with(
            "protonwg0", ["aa:bb:cc:dd:ee:ff"]
        )


class TestReconcileProtonWgFull:
    @patch("router.ipset_ops.ps.load")
    def test_syncs_macs_and_rebuilds_mangle(self, mock_load, ipset, router):
        mock_load.return_value = {
            "profiles": [{
                "id": "p1",
                "router_info": {
                    "vpn_protocol": "wireguard-tcp",
                    "tunnel_id": 42,
                    "tunnel_name": "protonwg0",
                    "ipset_name": "src_mac_42",
                },
            }],
            "device_assignments": {"aa:bb:cc:dd:ee:ff": "p1"},
        }
        ipset.reconcile_proton_wg_full()
        # Should write .macs file
        router.proton_wg.write_tunnel_macs.assert_called_once()
        # Should rebuild mangle rules (which includes ipset creation + population)
        router.proton_wg._rebuild_proton_wg_mangle_rules.assert_called_once()

    @patch("router.ipset_ops.ps.load")
    def test_empty_profiles(self, mock_load, ipset, router):
        mock_load.return_value = {"profiles": [], "device_assignments": {}}
        ipset.reconcile_proton_wg_full()
        # Only mangle rebuild should happen
        router.proton_wg._rebuild_proton_wg_mangle_rules.assert_called_once()
