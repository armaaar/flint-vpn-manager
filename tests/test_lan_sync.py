"""Tests for lan_sync.py — UCI-native LAN access execution layer.

Replaces the old TestGenerateLanRules / TestLanAllowLists / TestLanRouterMethods
tests in test_router_api.py. Covers:
  - serialize_lan_state (pure function): all the rule shapes
  - diff_state: structural and membership diffs
  - sync_lan_to_router orchestration with a mock router
"""

import json
from unittest.mock import MagicMock

import pytest

import lan_sync
import profile_store as ps


@pytest.fixture
def tmp_store(tmp_path, monkeypatch):
    monkeypatch.setattr(ps, "DATA_DIR", tmp_path)
    monkeypatch.setattr(ps, "STORE_FILE", tmp_path / "profile_store.json")
    yield


# ── serialize_lan_state ──────────────────────────────────────────────────


class TestSerializeLanStateAllAllowed:
    def test_all_allowed_no_sections(self, tmp_store):
        store = {
            "profiles": [{
                "id": "p1234567-aaaa", "type": "vpn",
                "lan_access": {"outbound": "allowed", "inbound": "allowed",
                               "outbound_allow": [], "inbound_allow": []},
            }],
            "device_assignments": {},
            "device_lan_overrides": {},
        }
        ips = {"aa:bb:cc:dd:ee:ff": "192.168.8.100"}
        assignment_map = {"aa:bb:cc:dd:ee:ff": "p1234567-aaaa"}
        state = lan_sync.serialize_lan_state(store, ips, assignment_map)
        assert state["ipsets"] == {}
        assert state["rules"] == {}
        assert state["rule_order"] == []


class TestSerializeLanStateGroupRules:
    def test_blocked_outbound_group_rule(self, tmp_store):
        store = {
            "profiles": [{
                "id": "p1234567-aaaa", "type": "vpn",
                "lan_access": {"outbound": "blocked", "inbound": "allowed",
                               "outbound_allow": [], "inbound_allow": []},
            }],
            "device_assignments": {},
            "device_lan_overrides": {},
        }
        ips = {"aa:bb:cc:dd:ee:ff": "192.168.8.100"}
        assignment_map = {"aa:bb:cc:dd:ee:ff": "p1234567-aaaa"}
        state = lan_sync.serialize_lan_state(store, ips, assignment_map)

        # One ipset for the group
        assert "fvpn_lan_p1234567_ips" in state["ipsets"]
        assert state["ipsets"]["fvpn_lan_p1234567_ips"]["entry"] == ["192.168.8.100"]
        # One DROP rule referencing the ipset src
        assert "fvpn_lan_p1234567_outdrop" in state["rules"]
        rule = state["rules"]["fvpn_lan_p1234567_outdrop"]
        assert rule["target"] == "DROP"
        assert rule["ipset"] == "fvpn_lan_p1234567_ips src"
        assert "extra" not in rule

    def test_blocked_inbound_group_rule(self, tmp_store):
        store = {
            "profiles": [{
                "id": "p1234567-aaaa", "type": "vpn",
                "lan_access": {"outbound": "allowed", "inbound": "blocked",
                               "outbound_allow": [], "inbound_allow": []},
            }],
            "device_assignments": {},
            "device_lan_overrides": {},
        }
        ips = {"aa:bb:cc:dd:ee:ff": "192.168.8.100"}
        assignment_map = {"aa:bb:cc:dd:ee:ff": "p1234567-aaaa"}
        state = lan_sync.serialize_lan_state(store, ips, assignment_map)

        assert "fvpn_lan_p1234567_indrop" in state["rules"]
        rule = state["rules"]["fvpn_lan_p1234567_indrop"]
        assert rule["ipset"] == "fvpn_lan_p1234567_ips dst"
        assert rule["target"] == "DROP"

    def test_group_only_outbound_uses_negation(self, tmp_store):
        store = {
            "profiles": [{
                "id": "p1234567-aaaa", "type": "vpn",
                "lan_access": {"outbound": "group_only", "inbound": "allowed",
                               "outbound_allow": [], "inbound_allow": []},
            }],
            "device_assignments": {},
            "device_lan_overrides": {},
        }
        assignment_map = {"aa:bb:cc:dd:ee:ff": "p1234567-aaaa"}
        ips = {"aa:bb:cc:dd:ee:ff": "192.168.8.100"}
        state = lan_sync.serialize_lan_state(store, ips, assignment_map)

        rule = state["rules"]["fvpn_lan_p1234567_outdrop"]
        assert rule["ipset"] == "fvpn_lan_p1234567_ips src"
        assert "! --match-set fvpn_lan_p1234567_ips dst" in rule["extra"]
        assert rule["target"] == "DROP"

    def test_group_only_inbound_uses_negation(self, tmp_store):
        store = {
            "profiles": [{
                "id": "p1234567-aaaa", "type": "vpn",
                "lan_access": {"outbound": "allowed", "inbound": "group_only",
                               "outbound_allow": [], "inbound_allow": []},
            }],
            "device_assignments": {},
            "device_lan_overrides": {},
        }
        assignment_map = {"aa:bb:cc:dd:ee:ff": "p1234567-aaaa"}
        ips = {"aa:bb:cc:dd:ee:ff": "192.168.8.100"}
        state = lan_sync.serialize_lan_state(store, ips, assignment_map)

        rule = state["rules"]["fvpn_lan_p1234567_indrop"]
        assert rule["ipset"] == "fvpn_lan_p1234567_ips dst"
        assert "! --match-set fvpn_lan_p1234567_ips src" in rule["extra"]


class TestSerializeLanStateExceptions:
    def test_outbound_allow_mac_uses_extras_ipset(self, tmp_store):
        store = {
            "profiles": [{
                "id": "p1234567-aaaa", "type": "vpn",
                "lan_access": {
                    "outbound": "blocked", "inbound": "allowed",
                    "outbound_allow": ["aa:aa:aa:aa:aa:aa"],
                    "inbound_allow": [],
                },
            }],
            "device_assignments": {},
            "device_lan_overrides": {},
        }
        ips = {
            "11:22:33:44:55:66": "192.168.8.50",
            "aa:aa:aa:aa:aa:aa": "192.168.8.99",
        }
        assignment_map = {"11:22:33:44:55:66": "p1234567-aaaa"}
        state = lan_sync.serialize_lan_state(store, ips, assignment_map)

        # Extras ipset created with the peer's IP
        assert "fvpn_extra_p1234567_out_ips" in state["ipsets"]
        assert state["ipsets"]["fvpn_extra_p1234567_out_ips"]["entry"] == ["192.168.8.99"]
        # ACCEPT rule references the extras ipset
        accept = state["rules"]["fvpn_lan_p1234567_outacc_extra"]
        assert accept["target"] == "ACCEPT"
        assert "--match-set fvpn_extra_p1234567_out_ips dst" in accept["extra"]
        # ACCEPT comes BEFORE the DROP in rule_order
        assert state["rule_order"].index("fvpn_lan_p1234567_outacc_extra") < \
               state["rule_order"].index("fvpn_lan_p1234567_outdrop")

    def test_inbound_allow_profile_uuid_references_target_group_ipset(self, tmp_store):
        store = {
            "profiles": [
                {"id": "trusted1-aaaa", "type": "vpn",
                 "lan_access": {
                     "outbound": "allowed", "inbound": "group_only",
                     "outbound_allow": [], "inbound_allow": ["us-only1-bbbb"],
                 }},
                {"id": "us-only1-bbbb", "type": "vpn",
                 "lan_access": {
                     "outbound": "allowed", "inbound": "allowed",
                     "outbound_allow": [], "inbound_allow": [],
                 }},
            ],
            "device_assignments": {},
            "device_lan_overrides": {},
        }
        ips = {
            "11:22:33:44:55:66": "192.168.8.50",
            "aa:aa:aa:aa:aa:aa": "192.168.8.91",
            "bb:bb:bb:bb:bb:bb": "192.168.8.92",
        }
        assignment_map = {
            "11:22:33:44:55:66": "trusted1-aaaa",
            "aa:aa:aa:aa:aa:aa": "us-only1-bbbb",
            "bb:bb:bb:bb:bb:bb": "us-only1-bbbb",
        }
        state = lan_sync.serialize_lan_state(store, ips, assignment_map)

        # Trusted group has ACCEPT rule referencing us-only group's ipset
        accept_key = "fvpn_lan_trusted1_inacc_us-only1"
        assert accept_key in state["rules"]
        accept = state["rules"][accept_key]
        assert accept["target"] == "ACCEPT"
        assert accept["ipset"] == "fvpn_lan_trusted1_ips dst"
        assert "--match-set fvpn_lan_us-only1_ips src" in accept["extra"]

        # Both groups' ipsets exist
        assert "fvpn_lan_trusted1_ips" in state["ipsets"]
        assert "fvpn_lan_us-only1_ips" in state["ipsets"]
        # us-only1 ipset contains both members
        us_entries = set(state["ipsets"]["fvpn_lan_us-only1_ips"]["entry"])
        assert us_entries == {"192.168.8.91", "192.168.8.92"}

    def test_allow_list_no_op_when_state_allowed(self, tmp_store):
        store = {
            "profiles": [{
                "id": "p1234567-aaaa", "type": "vpn",
                "lan_access": {
                    "outbound": "allowed", "inbound": "allowed",
                    "outbound_allow": ["aa:aa:aa:aa:aa:aa"],
                    "inbound_allow": ["aa:aa:aa:aa:aa:aa"],
                },
            }],
            "device_assignments": {},
            "device_lan_overrides": {},
        }
        assignment_map = {"11:22:33:44:55:66": "p1234567-aaaa"}
        ips = {"11:22:33:44:55:66": "192.168.8.50",
               "aa:aa:aa:aa:aa:aa": "192.168.8.99"}
        state = lan_sync.serialize_lan_state(store, ips, assignment_map)

        # No rules at all when state is allowed
        assert all("ACCEPT" not in r.get("target", "") for r in state["rules"].values())
        assert all("DROP" not in r.get("target", "") for r in state["rules"].values())

    def test_allow_list_skips_peer_with_no_ip(self, tmp_store):
        store = {
            "profiles": [{
                "id": "p1234567-aaaa", "type": "vpn",
                "lan_access": {
                    "outbound": "allowed", "inbound": "group_only",
                    "outbound_allow": [], "inbound_allow": ["aa:aa:aa:aa:aa:aa"],
                },
            }],
            "device_assignments": {},
            "device_lan_overrides": {},
        }
        assignment_map = {"11:22:33:44:55:66": "p1234567-aaaa"}
        ips = {"11:22:33:44:55:66": "192.168.8.50"}  # peer offline
        state = lan_sync.serialize_lan_state(store, ips, assignment_map)

        # No extras ipset / ACCEPT rule for the missing-IP peer
        assert "fvpn_extra_p1234567_in_ips" not in state["ipsets"]
        assert "fvpn_lan_p1234567_inacc_extra" not in state["rules"]
        # The DROP for the group is still emitted
        assert "fvpn_lan_p1234567_indrop" in state["rules"]


class TestSerializeLanStateDeviceOverrides:
    def test_device_override_emitted_before_group(self, tmp_store):
        store = {
            "profiles": [{
                "id": "p1234567-aaaa", "type": "vpn",
                "lan_access": {
                    "outbound": "allowed", "inbound": "allowed",
                    "outbound_allow": [], "inbound_allow": [],
                },
            }],
            "device_assignments": {},
            "device_lan_overrides": {
                "aa:bb:cc:dd:ee:ff": {
                    "outbound": "blocked", "inbound": None,
                    "outbound_allow": [], "inbound_allow": [],
                },
            },
        }
        assignment_map = {
            "aa:bb:cc:dd:ee:ff": "p1234567-aaaa",
            "11:22:33:44:55:66": "p1234567-aaaa",
        }
        ips = {
            "aa:bb:cc:dd:ee:ff": "192.168.8.100",
            "11:22:33:44:55:66": "192.168.8.101",
        }
        state = lan_sync.serialize_lan_state(store, ips, assignment_map)

        # Per-device DROP rule with src_mac
        sec = "fvpn_devovr_aabbccddeeff_outdrop"
        assert sec in state["rules"]
        assert state["rules"][sec]["src_mac"] == "aa:bb:cc:dd:ee:ff"
        assert state["rules"][sec]["target"] == "DROP"
        # No group rule (group is allowed)
        assert "fvpn_lan_p1234567_outdrop" not in state["rules"]


class TestSerializeLanStateNoInternet:
    def test_single_no_internet_group_creates_global_ipset(self, tmp_store):
        store = {
            "profiles": [{
                "id": "noint1-aaaaa", "type": "no_internet",
            }],
            "device_assignments": {"aa:bb:cc:dd:ee:ff": "noint1-aaaaa"},
            "device_lan_overrides": {},
        }
        ips = {"aa:bb:cc:dd:ee:ff": "192.168.8.50"}
        assignment_map = {"aa:bb:cc:dd:ee:ff": "noint1-aaaaa"}
        state = lan_sync.serialize_lan_state(store, ips, assignment_map)

        assert lan_sync.NOINT_IPSET in state["ipsets"]
        assert state["ipsets"][lan_sync.NOINT_IPSET]["entry"] == ["192.168.8.50"]
        assert lan_sync.NOINT_RULE in state["rules"]
        rule = state["rules"][lan_sync.NOINT_RULE]
        assert rule["src"] == "lan"
        assert rule["dest"] == "wan"
        assert rule["target"] == "REJECT"
        assert rule["ipset"] == f"{lan_sync.NOINT_IPSET} src"

    def test_multiple_no_internet_groups_share_one_ipset(self, tmp_store):
        """Regression test: multiple no-internet groups must NOT create
        per-group ipsets. The router can't distinguish them, only the local
        store can. All members go in the single global ipset."""
        store = {
            "profiles": [
                {"id": "noint1-aaaaa", "type": "no_internet"},
                {"id": "noint2-bbbbb", "type": "no_internet"},
            ],
            "device_assignments": {
                "aa:bb:cc:dd:ee:ff": "noint1-aaaaa",
                "11:22:33:44:55:66": "noint2-bbbbb",
            },
            "device_lan_overrides": {},
        }
        ips = {
            "aa:bb:cc:dd:ee:ff": "192.168.8.50",
            "11:22:33:44:55:66": "192.168.8.51",
        }
        assignment_map = dict(store["device_assignments"])
        state = lan_sync.serialize_lan_state(store, ips, assignment_map)

        # Single ipset, both members
        assert list(state["ipsets"].keys()) == [lan_sync.NOINT_IPSET]
        entries = set(state["ipsets"][lan_sync.NOINT_IPSET]["entry"])
        assert entries == {"192.168.8.50", "192.168.8.51"}
        # Single rule
        rule_keys = list(state["rules"].keys())
        assert rule_keys == [lan_sync.NOINT_RULE]


class TestDiffState:
    def test_empty_to_desired_emits_full_create(self, tmp_store):
        live = {"ipsets": {}, "rules": {}, "ipset_uci": {}, "ipset_uci_entries": {}}
        desired = {
            "ipsets": {
                "fvpn_lan_aaa_ips": lan_sync._make_ipset(
                    "fvpn_lan_aaa_ips", ["192.168.8.10"]
                ),
            },
            "rules": {
                "fvpn_lan_aaa_outdrop": lan_sync._make_rule(
                    name="x", ipset="fvpn_lan_aaa_ips src", target="DROP"
                ),
            },
            "rule_order": ["fvpn_lan_aaa_outdrop"],
        }
        diff = lan_sync.diff_state(live, desired)
        assert diff["needs_reload"] is True
        # The batch should set both the ipset and the rule
        assert "fvpn_lan_aaa_ips" in diff["uci_batch"]
        assert "fvpn_lan_aaa_outdrop" in diff["uci_batch"]
        assert "192.168.8.10" in diff["uci_batch"]

    def test_no_change_returns_empty_batch(self, tmp_store):
        rule = lan_sync._make_rule(
            name="x", src="lan", dest="lan", proto="all",
            ipset="fvpn_lan_aaa_ips src", target="DROP",
        )
        live = {
            "ipsets": {"fvpn_lan_aaa_ips": ["192.168.8.10"]},
            "rules": {"fvpn_lan_aaa_outdrop": {
                "src": "lan", "dest": "lan", "proto": "all",
                "ipset": "fvpn_lan_aaa_ips src", "target": "DROP",
            }},
            "ipset_uci": {"fvpn_lan_aaa_ips": "fvpn_lan_aaa_ips"},
            "ipset_uci_entries": {"fvpn_lan_aaa_ips": ["192.168.8.10"]},
        }
        desired = {
            "ipsets": {
                "fvpn_lan_aaa_ips": lan_sync._make_ipset(
                    "fvpn_lan_aaa_ips", ["192.168.8.10"]
                ),
            },
            "rules": {"fvpn_lan_aaa_outdrop": rule},
            "rule_order": ["fvpn_lan_aaa_outdrop"],
        }
        diff = lan_sync.diff_state(live, desired)
        assert diff["needs_reload"] is False
        assert diff["uci_batch"] == ""
        assert diff["membership_ops"] == {}

    def test_membership_only_diff_no_reload(self, tmp_store):
        rule = lan_sync._make_rule(
            name="x", ipset="fvpn_lan_aaa_ips src", target="DROP",
        )
        live = {
            "ipsets": {"fvpn_lan_aaa_ips": ["192.168.8.10"]},
            "rules": {"fvpn_lan_aaa_outdrop": {
                "src": "lan", "dest": "lan", "proto": "all",
                "ipset": "fvpn_lan_aaa_ips src", "target": "DROP",
            }},
            "ipset_uci": {"fvpn_lan_aaa_ips": "fvpn_lan_aaa_ips"},
            "ipset_uci_entries": {"fvpn_lan_aaa_ips": ["192.168.8.10"]},
        }
        # New device joined the group: ip 192.168.8.20 added
        desired = {
            "ipsets": {
                "fvpn_lan_aaa_ips": lan_sync._make_ipset(
                    "fvpn_lan_aaa_ips", ["192.168.8.10", "192.168.8.20"]
                ),
            },
            "rules": {"fvpn_lan_aaa_outdrop": rule},
            "rule_order": ["fvpn_lan_aaa_outdrop"],
        }
        diff = lan_sync.diff_state(live, desired)
        # Membership op without structural change → no reload
        assert diff["needs_reload"] is False
        assert "fvpn_lan_aaa_ips" in diff["membership_ops"]
        add, remove = diff["membership_ops"]["fvpn_lan_aaa_ips"]
        assert add == ["192.168.8.20"]
        assert remove == []
        # UCI dual-write present in batch (for reboot persistence)
        assert "add_list firewall.fvpn_lan_aaa_ips.entry='192.168.8.20'" in diff["uci_batch"]

    def test_obsolete_section_emits_delete(self, tmp_store):
        live = {
            "ipsets": {"fvpn_lan_old_ips": ["192.168.8.10"]},
            "rules": {"fvpn_lan_old_outdrop": {
                "src": "lan", "dest": "lan", "proto": "all",
                "ipset": "fvpn_lan_old_ips src", "target": "DROP",
            }},
            "ipset_uci": {"fvpn_lan_old_ips": "fvpn_lan_old_ips"},
            "ipset_uci_entries": {"fvpn_lan_old_ips": ["192.168.8.10"]},
        }
        desired = {"ipsets": {}, "rules": {}, "rule_order": []}
        diff = lan_sync.diff_state(live, desired)
        assert diff["needs_reload"] is True
        assert "delete firewall.fvpn_lan_old_ips" in diff["uci_batch"]
        assert "delete firewall.fvpn_lan_old_outdrop" in diff["uci_batch"]


class TestSyncLanToRouter:
    """sync_lan_to_router orchestration with a mock router."""

    def _make_router(self, live_state=None, fingerprint="aa:bb:cc:dd:ee:ff"):
        router = MagicMock()
        router.get_dhcp_leases.return_value = []
        router.get_flint_vpn_rules.return_value = []
        router.get_device_assignments.return_value = {}
        router.get_router_fingerprint.return_value = fingerprint
        router.fvpn_lan_full_state.return_value = live_state or {
            "ipsets": {}, "rules": {}, "ipset_uci": {}, "ipset_uci_entries": {},
        }
        return router

    def test_sync_with_empty_state_is_noop(self, tmp_store):
        router = self._make_router()
        store = {"profiles": [], "device_assignments": {}, "device_lan_overrides": {}}
        result = lan_sync.sync_lan_to_router(router, store=store, device_ips={})
        assert result["applied"] is False
        assert result["reload"] is False
        # No UCI batch was applied
        router.fvpn_uci_apply.assert_not_called()

    def test_sync_creates_blocked_group(self, tmp_store):
        router = self._make_router()
        store = {
            "profiles": [{
                "id": "p1234567-aaaa", "type": "vpn",
                "lan_access": {"outbound": "blocked", "inbound": "allowed",
                               "outbound_allow": [], "inbound_allow": []},
            }],
            "device_assignments": {},
            "device_lan_overrides": {},
        }
        device_ips = {"aa:bb:cc:dd:ee:ff": "192.168.8.100"}
        assignment_map = {"aa:bb:cc:dd:ee:ff": "p1234567-aaaa"}
        result = lan_sync.sync_lan_to_router(
            router, store=store, device_ips=device_ips,
            assignment_map=assignment_map,
        )
        assert result["applied"] is True
        assert result["reload"] is True
        router.fvpn_uci_apply.assert_called_once()
        batch_arg, kwargs = router.fvpn_uci_apply.call_args
        assert "fvpn_lan_p1234567_ips" in batch_arg[0]
        assert "fvpn_lan_p1234567_outdrop" in batch_arg[0]
        assert kwargs.get("reload") is True
