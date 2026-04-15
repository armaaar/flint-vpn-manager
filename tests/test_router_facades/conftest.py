"""Shared fixtures for router facade tests."""

from unittest.mock import MagicMock

import pytest


@pytest.fixture
def ssh():
    """Mock SSH client with exec and write_file."""
    m = MagicMock()
    m.exec.return_value = ""
    m.write_file.return_value = None
    return m


@pytest.fixture
def uci():
    """Mock UCI tool with common methods."""
    m = MagicMock()
    m.show.return_value = {}
    m.get.return_value = ""
    m.set.return_value = None
    m.commit.return_value = None
    m.multi.return_value = None
    m.delete.return_value = None
    m.add_list.return_value = None
    m.del_list.return_value = None
    m.rename.return_value = None
    m.reorder.return_value = None
    m.batch.return_value = None
    m.batch_set.return_value = None
    m.batch_sections.return_value = None
    m.ensure_firewall_include.return_value = None
    m.set_type.return_value = None
    return m


@pytest.fixture
def ipset():
    """Mock ipset tool."""
    m = MagicMock()
    m.create.return_value = None
    m.destroy.return_value = None
    m.add.return_value = None
    m.remove.return_value = None
    m.flush.return_value = None
    m.membership_batch.return_value = None
    m.list_names.return_value = []
    return m


@pytest.fixture
def iptables():
    """Mock iptables tool."""
    m = MagicMock()
    m.ensure_chain.return_value = None
    m.flush_chain.return_value = None
    m.append.return_value = None
    m.insert_if_absent.return_value = None
    m.delete_chain.return_value = None
    return m


@pytest.fixture
def iproute():
    """Mock iproute2 tool."""
    m = MagicMock()
    m.neigh_show.return_value = ""
    m.addr_add.return_value = None
    m.link_set_up.return_value = None
    m.link_delete.return_value = None
    m.link_exists.return_value = False
    m.route_add.return_value = None
    m.route_add_blackhole.return_value = None
    m.route_flush_table.return_value = None
    m.rule_add.return_value = None
    m.rule_del.return_value = None
    # IPv6 variants
    m.addr_add_v6.return_value = None
    m.route_add_v6.return_value = None
    m.route_add_blackhole_v6.return_value = None
    m.route_flush_table_v6.return_value = None
    m.rule_add_v6.return_value = None
    m.rule_del_v6.return_value = None
    m.neigh_show_v6.return_value = ""
    return m


@pytest.fixture
def service_ctl():
    """Mock service control tool."""
    m = MagicMock()
    m.restart.return_value = None
    m.reload.return_value = None
    m.start.return_value = None
    m.stop.return_value = None
    m.enable.return_value = None
    m.disable.return_value = None
    m.wifi_reload.return_value = None
    return m


@pytest.fixture
def alloc_tunnel_id():
    """Mock tunnel ID allocator that returns incrementing IDs."""
    counter = [100]

    def _alloc(ssh):
        tid = counter[0]
        counter[0] += 1
        return tid

    return MagicMock(side_effect=_alloc)
