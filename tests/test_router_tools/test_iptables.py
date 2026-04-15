"""Tests for router_tools.iptables — iptables and ip6tables command wrappers."""

from unittest.mock import MagicMock

import pytest

from router.tools.iptables import Iptables, Ip6tables


@pytest.fixture
def ssh():
    return MagicMock()


@pytest.fixture
def ipt(ssh):
    return Iptables(ssh)


class TestEnsureChain:
    def test_creates_chain(self, ipt, ssh):
        ipt.ensure_chain("mangle", "TUNNEL300_ROUTE_POLICY")
        ssh.exec.assert_called_once_with(
            "iptables -t mangle -N TUNNEL300_ROUTE_POLICY 2>/dev/null || true"
        )


class TestFlushChain:
    def test_flushes(self, ipt, ssh):
        ipt.flush_chain("mangle", "TUNNEL300_ROUTE_POLICY")
        ssh.exec.assert_called_once_with(
            "iptables -t mangle -F TUNNEL300_ROUTE_POLICY 2>/dev/null || true"
        )


class TestDeleteChain:
    def test_removes_jump_flushes_deletes(self, ipt, ssh):
        ipt.delete_chain("mangle", "ROUTE_POLICY", "TUNNEL300_ROUTE_POLICY")
        cmd = ssh.exec.call_args[0][0]
        assert "-D ROUTE_POLICY -j TUNNEL300_ROUTE_POLICY" in cmd
        assert "-F TUNNEL300_ROUTE_POLICY" in cmd
        assert "-X TUNNEL300_ROUTE_POLICY" in cmd
        assert cmd.endswith("true")


class TestAppend:
    def test_append_rule(self, ipt, ssh):
        ipt.append(
            "nat", "fvpn_adblock",
            "-m set --match-set fvpn_adblock_macs src",
            "-p udp --dport 53",
            "-j REDIRECT --to-ports 5354",
        )
        ssh.exec.assert_called_once_with(
            "iptables -t nat -A fvpn_adblock "
            "-m set --match-set fvpn_adblock_macs src "
            "-p udp --dport 53 "
            "-j REDIRECT --to-ports 5354"
        )


class TestInsertIfAbsent:
    def test_check_or_insert(self, ipt, ssh):
        ipt.insert_if_absent(
            "filter", "forwarding_rule", "-j fvpn_lan_exc"
        )
        cmd = ssh.exec.call_args[0][0]
        assert "-C forwarding_rule -j fvpn_lan_exc 2>/dev/null" in cmd
        assert "-I forwarding_rule 1 -j fvpn_lan_exc" in cmd
        assert "||" in cmd


class TestRemoveRule:
    def test_remove_idempotent(self, ipt, ssh):
        ipt.remove_rule("nat", "policy_redirect", "-j fvpn_adblock")
        ssh.exec.assert_called_once_with(
            "iptables -t nat -D policy_redirect -j fvpn_adblock 2>/dev/null; true"
        )


class TestListRules:
    def test_parses_rules(self, ipt, ssh):
        ssh.exec.return_value = (
            "-N TUNNEL300_ROUTE_POLICY\n"
            "-A TUNNEL300_ROUTE_POLICY -m mark ...\n"
        )
        result = ipt.list_rules("mangle", "TUNNEL300_ROUTE_POLICY")
        assert len(result) == 2

    def test_returns_empty_on_error(self, ipt, ssh):
        ssh.exec.side_effect = RuntimeError("fail")
        assert ipt.list_rules("mangle", "NONEXIST") == []


# ── Ip6tables ────────────────────────────────────────────────────────


@pytest.fixture
def ip6t(ssh):
    return Ip6tables(ssh)


class TestIp6tablesEnsureChain:
    def test_uses_ip6tables_binary(self, ip6t, ssh):
        ip6t.ensure_chain("nat", "fvpn_adblock")
        ssh.exec.assert_called_once_with(
            "ip6tables -t nat -N fvpn_adblock 2>/dev/null || true"
        )


class TestIp6tablesDeleteChain:
    def test_uses_ip6tables_binary(self, ip6t, ssh):
        ip6t.delete_chain("mangle", "ROUTE_POLICY", "FVPN_V6_300")
        cmd = ssh.exec.call_args[0][0]
        assert cmd.startswith("ip6tables")
        assert "-D ROUTE_POLICY -j FVPN_V6_300" in cmd
        assert "-F FVPN_V6_300" in cmd
        assert "-X FVPN_V6_300" in cmd


class TestIp6tablesAppend:
    def test_uses_ip6tables_binary(self, ip6t, ssh):
        ip6t.append(
            "nat", "fvpn_adblock",
            "-p udp --dport 53 -j REDIRECT --to-ports 5354",
        )
        ssh.exec.assert_called_once_with(
            "ip6tables -t nat -A fvpn_adblock "
            "-p udp --dport 53 -j REDIRECT --to-ports 5354"
        )


class TestIp6tablesInsertIfAbsent:
    def test_uses_ip6tables_binary(self, ip6t, ssh):
        ip6t.insert_if_absent("nat", "policy_redirect", "-j fvpn_adblock")
        cmd = ssh.exec.call_args[0][0]
        assert "ip6tables -t nat -C" in cmd
        assert "ip6tables -t nat -I" in cmd
