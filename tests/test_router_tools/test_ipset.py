"""Tests for router_tools.ipset — ipset command wrapper."""

from unittest.mock import MagicMock

import pytest

from router.tools.ipset import Ipset


@pytest.fixture
def ssh():
    return MagicMock()


@pytest.fixture
def ipset(ssh):
    return Ipset(ssh)


class TestCreate:
    def test_default_hash_mac(self, ipset, ssh):
        ipset.create("src_mac_300")
        ssh.exec.assert_called_once_with(
            "ipset create src_mac_300 hash:mac -exist"
        )

    def test_custom_type(self, ipset, ssh):
        ipset.create("fvpn_noint_ips", "hash:ip")
        ssh.exec.assert_called_once_with(
            "ipset create fvpn_noint_ips hash:ip -exist"
        )


class TestAdd:
    def test_add_entry(self, ipset, ssh):
        ipset.add("src_mac_300", "aa:bb:cc:dd:ee:ff")
        ssh.exec.assert_called_once_with(
            "ipset add src_mac_300 aa:bb:cc:dd:ee:ff -exist"
        )


class TestRemove:
    def test_remove_idempotent(self, ipset, ssh):
        ipset.remove("src_mac_300", "aa:bb:cc:dd:ee:ff")
        ssh.exec.assert_called_once_with(
            "ipset del src_mac_300 aa:bb:cc:dd:ee:ff 2>/dev/null || true"
        )


class TestMembers:
    def test_parses_members(self, ipset, ssh):
        ssh.exec.return_value = "AA:BB:CC:DD:EE:FF\n11:22:33:44:55:66\n"
        result = ipset.members("src_mac_300")
        assert result == ["AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"]

    def test_empty_set(self, ipset, ssh):
        ssh.exec.return_value = ""
        assert ipset.members("src_mac_300") == []

    def test_returns_empty_on_error(self, ipset, ssh):
        ssh.exec.side_effect = RuntimeError("SSH fail")
        assert ipset.members("src_mac_300") == []


class TestFlush:
    def test_flush(self, ipset, ssh):
        ipset.flush("src_mac_300")
        ssh.exec.assert_called_once_with(
            "ipset flush src_mac_300 2>/dev/null || true"
        )


class TestDestroy:
    def test_destroy(self, ipset, ssh):
        ipset.destroy("src_mac_300")
        ssh.exec.assert_called_once_with(
            "ipset destroy src_mac_300 2>/dev/null || true"
        )


class TestListNames:
    def test_with_prefix(self, ipset, ssh):
        ssh.exec.return_value = "src_mac_300\nsrc_mac_301\n"
        result = ipset.list_names("src_mac_")
        ssh.exec.assert_called_once_with(
            "ipset list -n 2>/dev/null | grep '^src_mac_'"
        )
        assert result == ["src_mac_300", "src_mac_301"]

    def test_no_prefix(self, ipset, ssh):
        ssh.exec.return_value = "src_mac_300\nfvpn_adblock\n"
        result = ipset.list_names()
        ssh.exec.assert_called_once_with("ipset list -n 2>/dev/null")
        assert result == ["src_mac_300", "fvpn_adblock"]

    def test_returns_empty_on_error(self, ipset, ssh):
        ssh.exec.side_effect = RuntimeError("fail")
        assert ipset.list_names() == []


class TestMembershipBatch:
    def test_add_and_remove(self, ipset, ssh):
        ipset.membership_batch(
            "src_mac_300",
            add=["aa:bb:cc:dd:ee:ff"],
            remove=["11:22:33:44:55:66"],
        )
        cmd = ssh.exec.call_args[0][0]
        # Removes come before adds
        assert "ipset del src_mac_300 11:22:33:44:55:66 2>/dev/null || true" in cmd
        assert "ipset add src_mac_300 aa:bb:cc:dd:ee:ff -exist" in cmd
        assert cmd.index("del") < cmd.index("add")

    def test_empty_no_call(self, ipset, ssh):
        ipset.membership_batch("src_mac_300")
        ssh.exec.assert_not_called()
