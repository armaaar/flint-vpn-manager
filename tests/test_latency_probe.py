"""Tests for latency_probe.py — TCP latency measurement."""

import pytest
from unittest.mock import MagicMock, patch

from proton_vpn.latency_probe import (
    _parse_probe_output,
    _tcp_connect_ms,
    probe_servers_via_router,
    probe_servers_local,
)


class TestParseProbeOutput:
    def test_parses_success_lines(self):
        output = "1.2.3.4 45\n5.6.7.8 120\n"
        ip_to_ids = {"1.2.3.4": ["s1"], "5.6.7.8": ["s2"]}
        result = _parse_probe_output(output, ip_to_ids)
        assert result == {"s1": 45.0, "s2": 120.0}

    def test_parses_fail_lines(self):
        output = "1.2.3.4 FAIL\n"
        ip_to_ids = {"1.2.3.4": ["s1"]}
        result = _parse_probe_output(output, ip_to_ids)
        assert result == {"s1": None}

    def test_parses_mixed(self):
        output = "1.2.3.4 32\n5.6.7.8 FAIL\n9.0.1.2 88\n"
        ip_to_ids = {
            "1.2.3.4": ["s1"],
            "5.6.7.8": ["s2"],
            "9.0.1.2": ["s3"],
        }
        result = _parse_probe_output(output, ip_to_ids)
        assert result == {"s1": 32.0, "s2": None, "s3": 88.0}

    def test_empty_output(self):
        assert _parse_probe_output("", {}) == {}
        assert _parse_probe_output("", {"1.2.3.4": ["s1"]}) == {}

    def test_multiple_servers_same_ip(self):
        """Multiple logical servers can share the same physical IP."""
        output = "1.2.3.4 50\n"
        ip_to_ids = {"1.2.3.4": ["s1", "s2"]}
        result = _parse_probe_output(output, ip_to_ids)
        assert result == {"s1": 50.0, "s2": 50.0}

    def test_unknown_ip_ignored(self):
        output = "99.99.99.99 50\n"
        ip_to_ids = {"1.2.3.4": ["s1"]}
        result = _parse_probe_output(output, ip_to_ids)
        assert result == {}

    def test_invalid_latency_value(self):
        output = "1.2.3.4 garbage\n"
        ip_to_ids = {"1.2.3.4": ["s1"]}
        result = _parse_probe_output(output, ip_to_ids)
        assert result == {"s1": None}


class TestProbeServersViaRouter:
    def test_empty_servers(self):
        router = MagicMock()
        assert probe_servers_via_router(router, []) == {}

    def test_no_entry_ips(self):
        router = MagicMock()
        assert probe_servers_via_router(router, [{"id": "s1"}]) == {}

    def test_calls_router_exec(self):
        router = MagicMock()
        router.exec.return_value = "1.2.3.4 42\n"
        servers = [{"id": "s1", "entry_ip": "1.2.3.4"}]
        result = probe_servers_via_router(router, servers)
        assert result == {"s1": 42.0}
        router.exec.assert_called_once()
        # Verify the command contains the IP and uses curl
        cmd = router.exec.call_args[0][0]
        assert "1.2.3.4" in cmd
        assert "curl" in cmd

    def test_router_exec_failure_returns_empty(self):
        router = MagicMock()
        router.exec.side_effect = RuntimeError("SSH failed")
        servers = [{"id": "s1", "entry_ip": "1.2.3.4"}]
        result = probe_servers_via_router(router, servers)
        assert result == {}

    def test_multiple_servers(self):
        router = MagicMock()
        router.exec.return_value = "1.2.3.4 30\n5.6.7.8 FAIL\n"
        servers = [
            {"id": "s1", "entry_ip": "1.2.3.4"},
            {"id": "s2", "entry_ip": "5.6.7.8"},
        ]
        result = probe_servers_via_router(router, servers)
        assert result == {"s1": 30.0, "s2": None}


class TestProbeServersLocal:
    def test_empty_servers(self):
        assert probe_servers_local([]) == {}

    @patch("proton_vpn.latency_probe._tcp_connect_ms")
    def test_parallel_probing(self, mock_tcp):
        mock_tcp.side_effect = [25.0, None, 80.0]
        servers = [
            {"id": "s1", "entry_ip": "1.1.1.1"},
            {"id": "s2", "entry_ip": "2.2.2.2"},
            {"id": "s3", "entry_ip": "3.3.3.3"},
        ]
        result = probe_servers_local(servers)
        assert len(result) == 3
        assert mock_tcp.call_count == 3

    def test_no_entry_ip_skipped(self):
        result = probe_servers_local([{"id": "s1"}])
        assert result == {}


class TestTcpConnectMs:
    @patch("proton_vpn.latency_probe.socket.socket")
    def test_successful_connect(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        result = _tcp_connect_ms("1.2.3.4", 443, 2.0)
        assert result is not None
        assert isinstance(result, float)
        mock_sock.connect.assert_called_once_with(("1.2.3.4", 443))
        mock_sock.close.assert_called_once()

    @patch("proton_vpn.latency_probe.socket.socket")
    def test_timeout(self, mock_socket_cls):
        import socket
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = socket.timeout("timed out")
        mock_socket_cls.return_value = mock_sock
        result = _tcp_connect_ms("1.2.3.4", 443, 2.0)
        assert result is None

    @patch("proton_vpn.latency_probe.socket.socket")
    def test_connection_refused(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError("Connection refused")
        mock_socket_cls.return_value = mock_sock
        result = _tcp_connect_ms("1.2.3.4", 443, 2.0)
        assert result is None
