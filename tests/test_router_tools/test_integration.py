"""Integration tests for router_tools — run against a live router.

These tests verify that tool-layer commands produce correct results on the
actual GL.iNet Flint 2 hardware. They catch BusyBox quirks, quoting edge
cases, and ipset/iptables version differences that mocks can't.

Run with: pytest -m integration tests/test_router_tools/test_integration.py
"""

import pytest

from router.api import RouterAPI
from router.tools import Uci, Ipset, Iptables, Iproute, ServiceCtl


@pytest.fixture
def router():
    r = RouterAPI("192.168.8.1", key_filename="/home/armaaar/.ssh/id_ed25519")
    try:
        r.connect()
    except Exception:
        pytest.skip("Cannot connect to router at 192.168.8.1")
    yield r
    r.disconnect()


@pytest.mark.integration
class TestUciIntegration:
    def test_show_parses_route_policy(self, router):
        result = router.uci.show("route_policy")
        assert isinstance(result, dict)

    def test_get_returns_value(self, router):
        ip = router.uci.get("network.lan.ipaddr", "MISSING")
        assert ip != "MISSING"
        assert "." in ip  # Should be an IP address

    def test_get_missing_returns_default(self, router):
        result = router.uci.get("nonexistent.section.field", "FALLBACK")
        assert result == "FALLBACK"


@pytest.mark.integration
class TestIpsetIntegration:
    TEMP_SET = "fvpn_test_set"

    def test_lifecycle(self, router):
        """Create, add, list, remove, destroy — full lifecycle."""
        ipset = router.ipset_tool
        try:
            ipset.create(self.TEMP_SET, "hash:mac")
            ipset.add(self.TEMP_SET, "AA:BB:CC:DD:EE:FF")
            members = ipset.members(self.TEMP_SET)
            assert "AA:BB:CC:DD:EE:FF" in members
            ipset.remove(self.TEMP_SET, "AA:BB:CC:DD:EE:FF")
            members = ipset.members(self.TEMP_SET)
            assert "AA:BB:CC:DD:EE:FF" not in members
        finally:
            ipset.destroy(self.TEMP_SET)

    def test_members_nonexistent_returns_empty(self, router):
        result = router.ipset_tool.members("nonexistent_fvpn_test")
        assert result == []


@pytest.mark.integration
class TestIprouteIntegration:
    def test_neigh_show_returns_data(self, router):
        result = router.iproute.neigh_show()
        assert len(result) > 0

    def test_link_exists_br_lan(self, router):
        assert router.iproute.link_exists("br-lan") is True

    def test_link_exists_nonexistent(self, router):
        assert router.iproute.link_exists("fvpn_test_nonexistent") is False
