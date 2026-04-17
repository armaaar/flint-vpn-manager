"""Tests for noint_sync — NoInternet ipset enforcement (firewall include).

noint_sync uses a firewall include script that creates a hash:mac ipset
and a REJECT rule in the FORWARD chain for WAN-bound traffic.
"""

from unittest.mock import MagicMock, call
import pytest

import router.noint_sync as noint_sync


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

    def _router(self, ipset_members=None, include_exists=True,
                legacy_ipset=False, legacy_rule=False,
                legacy_uci_ipset=False, legacy_per_zone=None):
        r = MagicMock()
        r.ipset_tool.members.return_value = ipset_members or []

        def _uci_get(path, default=""):
            if path == f"firewall.{noint_sync._UCI_INCLUDE}":
                return "include" if include_exists else "MISSING"
            if path == f"firewall.{noint_sync._LEGACY_IPSET}":
                return "ipset" if legacy_ipset else "MISSING"
            if path == f"firewall.{noint_sync._LEGACY_RULE}":
                return "rule" if legacy_rule else "MISSING"
            if path == f"firewall.{noint_sync._LEGACY_UCI_IPSET}":
                return "ipset" if legacy_uci_ipset else "MISSING"
            return default
        r.uci.get.side_effect = _uci_get

        # For legacy migration — mock uci.show
        fw_sections = {}
        if legacy_per_zone:
            for zone in legacy_per_zone:
                fw_sections[f"fvpn_noint_{zone}"] = {"_type": "rule"}
        r.uci.show.return_value = fw_sections

        return r

    def test_no_noint_groups_no_op(self):
        store = _make_store(profiles=[_novpn_profile()])
        r = self._router(include_exists=False)
        result = noint_sync.sync_noint_to_router(r, store=store)
        assert not result["applied"]
        r.ipset_tool.membership_batch.assert_not_called()
        r.write_file.assert_not_called()

    def test_deploys_include_on_first_run(self):
        store = _make_store(
            profiles=[_noint_profile("noint-1")],
            assignments={"aa:bb:cc:dd:ee:ff": "noint-1"},
        )
        r = self._router(include_exists=False)
        result = noint_sync.sync_noint_to_router(r, store=store)
        assert result["applied"]
        assert result["reload"]
        # Include script deployed
        r.write_file.assert_any_call(
            noint_sync._SCRIPT_PATH, noint_sync._SCRIPT_CONTENT)
        r.uci.ensure_firewall_include.assert_called_once_with(
            noint_sync._UCI_INCLUDE, noint_sync._SCRIPT_PATH)
        # Kernel ipset created and populated
        r.ipset_tool.create.assert_called_with("fvpn_noint_macs", "hash:mac")
        r.ipset_tool.membership_batch.assert_called_once_with(
            "fvpn_noint_macs", add=["AA:BB:CC:DD:EE:FF"])
        # .macs file written
        r.write_file.assert_any_call(
            noint_sync._MACS_FILE, "AA:BB:CC:DD:EE:FF\n")

    def test_membership_add(self):
        store = _make_store(
            profiles=[_noint_profile("ni")],
            assignments={
                "aa:bb:cc:dd:ee:01": "ni",
                "aa:bb:cc:dd:ee:02": "ni",
            },
        )
        r = self._router(
            ipset_members=["AA:BB:CC:DD:EE:01"],
            include_exists=True,
        )
        result = noint_sync.sync_noint_to_router(r, store=store)
        assert result["applied"]
        assert result["adds"] == 1
        assert result["removes"] == 0
        r.ipset_tool.membership_batch.assert_called_once_with(
            "fvpn_noint_macs", add=["AA:BB:CC:DD:EE:02"], remove=[]
        )
        # .macs file updated
        r.write_file.assert_called_once()

    def test_membership_remove(self):
        store = _make_store(
            profiles=[_noint_profile("ni")],
            assignments={},
        )
        r = self._router(
            ipset_members=["AA:BB:CC:DD:EE:50", "AA:BB:CC:DD:EE:51"],
            include_exists=True,
        )
        result = noint_sync.sync_noint_to_router(r, store=store)
        assert result["removes"] == 2
        r.ipset_tool.membership_batch.assert_called_once_with(
            "fvpn_noint_macs",
            add=[],
            remove=["AA:BB:CC:DD:EE:50", "AA:BB:CC:DD:EE:51"],
        )

    def test_tears_down_when_no_noint_groups_left(self):
        store = _make_store(profiles=[_novpn_profile()])
        r = self._router(
            ipset_members=["AA:BB:CC:DD:EE:01"],
            include_exists=True,
        )
        result = noint_sync.sync_noint_to_router(r, store=store)
        assert result["applied"]
        assert result["reload"]
        # Include removed
        r.uci.delete.assert_any_call(f"firewall.{noint_sync._UCI_INCLUDE}")
        r.exec.assert_any_call(
            f"rm -f {noint_sync._SCRIPT_PATH} {noint_sync._MACS_FILE}")
        r.ipset_tool.destroy.assert_called_with("fvpn_noint_macs")

    def test_no_change_no_op(self):
        """When MACs match and include exists, nothing happens."""
        store = _make_store(
            profiles=[_noint_profile("ni")],
            assignments={"aa:bb:cc:dd:ee:01": "ni"},
        )
        r = self._router(
            ipset_members=["AA:BB:CC:DD:EE:01"],
            include_exists=True,
        )
        result = noint_sync.sync_noint_to_router(r, store=store)
        assert not result["applied"] or result["adds"] == 0
        assert not result["reload"]

    def test_legacy_ipset_migrated(self):
        store = _make_store(
            profiles=[_noint_profile("ni")],
            assignments={"aa:bb:cc:dd:ee:ff": "ni"},
        )
        r = self._router(include_exists=False, legacy_ipset=True)
        noint_sync.sync_noint_to_router(r, store=store)
        r.uci.delete.assert_any_call("firewall.fvpn_noint_ips")
        r.ipset_tool.destroy.assert_any_call("fvpn_noint_ips")

    def test_legacy_single_rule_migrated(self):
        store = _make_store(
            profiles=[_noint_profile("ni")],
            assignments={"aa:bb:cc:dd:ee:ff": "ni"},
        )
        r = self._router(include_exists=False, legacy_rule=True)
        noint_sync.sync_noint_to_router(r, store=store)
        r.uci.delete.assert_any_call("firewall.fvpn_noint_block")

    def test_legacy_uci_ipset_migrated(self):
        store = _make_store(
            profiles=[_noint_profile("ni")],
            assignments={"aa:bb:cc:dd:ee:ff": "ni"},
        )
        r = self._router(include_exists=False, legacy_uci_ipset=True)
        noint_sync.sync_noint_to_router(r, store=store)
        r.uci.delete.assert_any_call("firewall.fvpn_noint_macs")

    def test_legacy_per_zone_rules_migrated(self):
        store = _make_store(
            profiles=[_noint_profile("ni")],
            assignments={"aa:bb:cc:dd:ee:ff": "ni"},
        )
        r = self._router(
            include_exists=False,
            legacy_per_zone=["lan", "guest", "fvpn_iot"],
        )
        noint_sync.sync_noint_to_router(r, store=store)
        r.uci.delete.assert_any_call("firewall.fvpn_noint_lan")
        r.uci.delete.assert_any_call("firewall.fvpn_noint_guest")
        r.uci.delete.assert_any_call("firewall.fvpn_noint_fvpn_iot")


class TestWipeNoint:
    def test_wipe_removes_include_and_legacy(self):
        r = MagicMock()
        r.uci.show.return_value = {}
        noint_sync.wipe_noint(r)
        # Include removed
        r.uci.delete.assert_any_call(f"firewall.{noint_sync._UCI_INCLUDE}")
        r.exec.assert_any_call(
            f"rm -f {noint_sync._SCRIPT_PATH} {noint_sync._MACS_FILE}")
        r.ipset_tool.destroy.assert_any_call("fvpn_noint_macs")
        r.service_ctl.reload.assert_called_with("firewall")

    def test_wipe_cleans_legacy_ipset(self):
        r = MagicMock()
        r.uci.show.return_value = {}
        noint_sync.wipe_noint(r)
        r.ipset_tool.destroy.assert_any_call("fvpn_noint_ips")


class TestScriptContent:
    def test_script_creates_ipset_and_reject_rule(self):
        script = noint_sync._SCRIPT_CONTENT
        assert "ipset create" in script
        assert "fvpn_noint_macs" in script
        assert "hash:mac" in script
        assert "REJECT" in script
        assert "FORWARD" in script
        assert "noint.macs" in script

    def test_script_discovers_wan_device(self):
        script = noint_sync._SCRIPT_CONTENT
        assert "uci get network.wan.device" in script
