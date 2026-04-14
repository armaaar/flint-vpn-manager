"""Tests for RouterOpenvpn facade."""

import pytest

from consts import PROTO_OPENVPN
from router.facades.openvpn import RouterOpenvpn


@pytest.fixture
def ovpn(uci, service_ctl, alloc_tunnel_id, ssh):
    return RouterOpenvpn(uci, service_ctl, alloc_tunnel_id, ssh)


class TestNextOvpnClientId:
    def test_first_available(self, ovpn, ssh):
        ssh.exec.return_value = ""
        assert ovpn._next_ovpn_client_id() == 9051

    def test_skips_used_ids(self, ovpn, ssh):
        # The sed output produces "28216_9051" lines, split("_")[1] extracts the number
        ssh.exec.return_value = "28216_9051\n28216_9052\n"
        assert ovpn._next_ovpn_client_id() == 9053

    def test_raises_when_all_used(self, ovpn, ssh):
        lines = "\n".join(f"28216_{i}" for i in range(9051, 9100))
        ssh.exec.return_value = lines
        with pytest.raises(RuntimeError, match="No available OpenVPN client IDs"):
            ovpn._next_ovpn_client_id()


class TestUploadOpenvpnConfig:
    def test_creates_client_and_rule(self, ovpn, uci, ssh, alloc_tunnel_id):
        ssh.exec.side_effect = [
            "",  # no existing clients
            "",  # mkdir
            "",  # chmod
        ]
        result = ovpn.upload_openvpn_config(
            profile_name="NL OVPN",
            ovpn_config="remote 1.2.3.4\n{CLIENT_ID}\n",
            username="user",
            password="pass",
        )
        assert result["client_id"] == "9051"
        assert result["client_uci_id"] == "28216_9051"
        assert result["rule_name"] == "fvpn_rule_ovpn_9051"
        assert result["vpn_protocol"] == PROTO_OPENVPN
        assert result["tunnel_id"] == 100

        # Verify config was written with CLIENT_ID replaced
        config_write = ssh.write_file.call_args_list[0]
        assert "28216_9051" in config_write[0][1]  # CLIENT_ID replaced

        # Verify auth file was written
        auth_write = ssh.write_file.call_args_list[1]
        assert "user\npass\n" in auth_write[0][1]


class TestUpdateOpenvpnClient:
    def test_writes_config_and_auth(self, ovpn, ssh):
        ovpn.update_openvpn_client(
            "28216_9051", "remote 5.6.7.8\n{CLIENT_ID}\n", "newuser", "newpass"
        )
        assert ssh.write_file.call_count == 2
        config_write = ssh.write_file.call_args_list[0]
        assert "28216_9051" in config_write[0][1]
        auth_write = ssh.write_file.call_args_list[1]
        assert "newuser\nnewpass\n" in auth_write[0][1]


class TestDeleteOpenvpnConfig:
    def test_disables_deletes_cleanup(self, ovpn, uci, service_ctl, ssh):
        ovpn.delete_openvpn_config("28216_9051", "fvpn_rule_ovpn_9051")
        # Disable rule, commit, restart, delete rule, commit, delete client, commit, rm, restart
        assert uci.set.call_count == 1
        assert uci.delete.call_count == 2
        assert uci.commit.call_count == 3
        assert service_ctl.restart.call_count == 2
        # Verify profile directory cleanup
        rm_call = [c for c in ssh.exec.call_args_list if "rm -rf" in str(c)]
        assert len(rm_call) == 1
