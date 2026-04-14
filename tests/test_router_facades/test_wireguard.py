"""Tests for RouterWireguard facade."""

from unittest.mock import MagicMock

import pytest

from consts import PROTO_WIREGUARD
from router.facades.wireguard import RouterWireguard


@pytest.fixture
def wg(uci, service_ctl, alloc_tunnel_id, ssh):
    return RouterWireguard(uci, service_ctl, alloc_tunnel_id, ssh)


class TestNextPeerId:
    def test_first_available(self, wg, ssh):
        ssh.exec.return_value = ""
        assert wg._next_peer_id() == 9001

    def test_skips_used_ids(self, wg, ssh):
        ssh.exec.return_value = "9001\n9002\n9003\n"
        assert wg._next_peer_id() == 9004

    def test_raises_when_all_used(self, wg, ssh):
        ssh.exec.return_value = "\n".join(str(i) for i in range(9001, 9051))
        with pytest.raises(RuntimeError, match="No available peer IDs"):
            wg._next_peer_id()

    def test_handles_non_numeric_lines(self, wg, ssh):
        ssh.exec.return_value = "9001\nnot_a_number\n9002\n"
        assert wg._next_peer_id() == 9003


class TestUploadWireguardConfig:
    def test_creates_peer_and_rule(self, wg, uci, ssh, alloc_tunnel_id):
        ssh.exec.return_value = ""  # no existing peers
        result = wg.upload_wireguard_config(
            profile_name="US East",
            private_key="privkey",
            public_key="pubkey",
            endpoint="1.2.3.4:51820",
        )
        assert result["peer_id"] == "peer_9001"
        assert result["peer_num"] == "9001"
        assert result["group_id"] == "1957"
        assert result["rule_name"] == "fvpn_rule_9001"
        assert result["vpn_protocol"] == PROTO_WIREGUARD
        assert result["tunnel_id"] == 100  # from alloc_tunnel_id

        # Verify UCI batch_set was called for peer and rule
        assert uci.batch_set.call_count == 2
        peer_call = uci.batch_set.call_args_list[0]
        assert "wireguard.peer_9001" in peer_call[0][0]
        rule_call = uci.batch_set.call_args_list[1]
        assert "route_policy.fvpn_rule_9001" in rule_call[0][0]


class TestUpdateWireguardPeerLive:
    def test_updates_uci_and_applies_wg_set(self, wg, ssh):
        ssh.exec.side_effect = [
            "old_pubkey",       # old public key
            "",                  # uci set + commit
            "wgclient1",        # get interface from route_policy
            "interface: wgclient1",  # wg show check
            "",                  # wg set command
        ]
        wg.update_wireguard_peer_live(
            "peer_9001", "fvpn_rule_9001",
            "new_privkey", "new_pubkey", "5.6.7.8:51820",
        )
        # Should have run wg set with peer remove for old key
        last_cmd = ssh.exec.call_args_list[-1][0][0]
        assert "wg set wgclient1" in last_cmd
        assert "new_pubkey" in last_cmd
        assert "old_pubkey" in last_cmd
        assert "remove" in last_cmd

    def test_skips_wg_set_when_no_interface(self, wg, ssh):
        ssh.exec.side_effect = [
            "old_pubkey",  # old key
            "",             # uci set
            "",             # empty interface
        ]
        wg.update_wireguard_peer_live(
            "peer_9001", "fvpn_rule_9001",
            "new_privkey", "new_pubkey", "5.6.7.8:51820",
        )
        assert ssh.exec.call_count == 3  # no wg set

    def test_does_not_remove_peer_when_same_key(self, wg, ssh):
        ssh.exec.side_effect = [
            "same_pubkey",         # old == new
            "",                     # uci set
            "wgclient1",           # interface
            "interface: wgclient1", # wg show
            "",                     # wg set
        ]
        wg.update_wireguard_peer_live(
            "peer_9001", "fvpn_rule_9001",
            "privkey", "same_pubkey", "5.6.7.8:51820",
        )
        last_cmd = ssh.exec.call_args_list[-1][0][0]
        assert "remove" not in last_cmd


class TestDeleteWireguardConfig:
    def test_disables_deletes_and_restarts(self, wg, uci, service_ctl):
        wg.delete_wireguard_config("peer_9001", "fvpn_rule_9001")
        # Disable rule, commit, restart, delete rule, commit, delete peer, commit, restart
        assert uci.set.call_count == 1
        assert uci.delete.call_count == 2
        assert uci.commit.call_count == 3
        assert service_ctl.restart.call_count == 2
