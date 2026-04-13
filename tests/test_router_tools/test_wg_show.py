"""Tests for router_tools.wg_show — WireGuard stats parsing."""

import time
from unittest.mock import MagicMock

import pytest

from router.tools.wg_show import parse_handshake_age, parse_transfer


@pytest.fixture
def ssh():
    return MagicMock()


class TestParseHandshakeAge:
    def test_recent_handshake(self, ssh):
        now = int(time.time())
        ssh.exec.return_value = f"pubkey123\t{now - 30}"
        age = parse_handshake_age(ssh, "wgclient1")
        assert age is not None
        assert 28 <= age <= 32  # allow for test execution time

    def test_zero_handshake_returns_none(self, ssh):
        ssh.exec.return_value = "pubkey123\t0"
        assert parse_handshake_age(ssh, "wgclient1") is None

    def test_empty_output_returns_none(self, ssh):
        ssh.exec.return_value = ""
        assert parse_handshake_age(ssh, "wgclient1") is None

    def test_error_returns_none(self, ssh):
        ssh.exec.side_effect = RuntimeError("SSH fail")
        assert parse_handshake_age(ssh, "wgclient1") is None


class TestParseTransfer:
    def test_normal_output(self, ssh):
        ssh.exec.return_value = "pubkey123\t1000\t2000"
        rx, tx = parse_transfer(ssh, "wgclient1")
        assert rx == 1000
        assert tx == 2000

    def test_empty_returns_zeros(self, ssh):
        ssh.exec.return_value = ""
        assert parse_transfer(ssh, "wgclient1") == (0, 0)

    def test_error_returns_zeros(self, ssh):
        ssh.exec.side_effect = RuntimeError("SSH fail")
        assert parse_transfer(ssh, "wgclient1") == (0, 0)
