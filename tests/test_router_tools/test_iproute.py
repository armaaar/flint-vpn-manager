"""Tests for router_tools.iproute — iproute2 command wrapper."""

from unittest.mock import MagicMock

import pytest

from router.tools.iproute import Iproute


@pytest.fixture
def ssh():
    return MagicMock()


@pytest.fixture
def ip(ssh):
    return Iproute(ssh)


class TestLinkExists:
    def test_exists(self, ip, ssh):
        ssh.exec.return_value = "3: protonwg0: <POINTOPOINT,NOARP,UP>"
        assert ip.link_exists("protonwg0") is True

    def test_not_exists(self, ip, ssh):
        ssh.exec.return_value = ""
        assert ip.link_exists("protonwg0") is False

    def test_error_returns_false(self, ip, ssh):
        ssh.exec.side_effect = RuntimeError("fail")
        assert ip.link_exists("protonwg0") is False


class TestLinkDelete:
    def test_delete_idempotent(self, ip, ssh):
        ip.link_delete("protonwg0")
        ssh.exec.assert_called_once_with(
            "ip link del protonwg0 2>/dev/null; true"
        )


class TestLinkSetUp:
    def test_set_up(self, ip, ssh):
        ip.link_set_up("protonwg0")
        ssh.exec.assert_called_once_with("ip link set protonwg0 up")


class TestAddrAdd:
    def test_add_address(self, ip, ssh):
        ip.addr_add("10.2.0.2/32", "protonwg0")
        ssh.exec.assert_called_once_with(
            "ip addr add 10.2.0.2/32 dev protonwg0 2>/dev/null; true"
        )


class TestRouteAdd:
    def test_default_route(self, ip, ssh):
        ip.route_add("default", "protonwg0", 100)
        ssh.exec.assert_called_once_with(
            "ip route add default dev protonwg0 table 100 2>/dev/null; true"
        )

    def test_with_metric(self, ip, ssh):
        ip.route_add("default", "protonwg0", 100, metric=254)
        ssh.exec.assert_called_once_with(
            "ip route add default dev protonwg0 table 100 metric 254 2>/dev/null; true"
        )


class TestRouteAddBlackhole:
    def test_blackhole(self, ip, ssh):
        ip.route_add_blackhole("default", 100, metric=254)
        ssh.exec.assert_called_once_with(
            "ip route add blackhole default table 100 metric 254 2>/dev/null; true"
        )

    def test_no_metric(self, ip, ssh):
        ip.route_add_blackhole("default", 100)
        ssh.exec.assert_called_once_with(
            "ip route add blackhole default table 100 2>/dev/null; true"
        )


class TestRouteFlushTable:
    def test_flush(self, ip, ssh):
        ip.route_flush_table(100)
        ssh.exec.assert_called_once_with(
            "ip route flush table 100 2>/dev/null; true"
        )


class TestRuleAdd:
    def test_add_rule(self, ip, ssh):
        ip.rule_add("0x6000", "0xf000", 100, 6000)
        ssh.exec.assert_called_once_with(
            "ip rule add fwmark 0x6000/0xf000 lookup 100 "
            "priority 6000 2>/dev/null; true"
        )


class TestRuleDel:
    def test_del_rule(self, ip, ssh):
        ip.rule_del("0x6000", "0xf000", 100)
        ssh.exec.assert_called_once_with(
            "ip rule del fwmark 0x6000/0xf000 lookup 100 "
            "2>/dev/null; true"
        )


class TestNeighShow:
    def test_returns_output(self, ip, ssh):
        ssh.exec.return_value = "192.168.8.1 dev br-lan lladdr aa:bb:cc:dd:ee:ff REACHABLE"
        result = ip.neigh_show()
        assert "REACHABLE" in result
