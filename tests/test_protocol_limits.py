"""Tests for protocol_limits.py — Protocol slot counting and enforcement."""

from unittest.mock import patch

import pytest

from consts import (
    PROFILE_TYPE_VPN,
    PROFILE_TYPE_NO_VPN,
    PROTO_OPENVPN,
    PROTO_WIREGUARD,
    PROTO_WIREGUARD_TCP,
    PROTO_WIREGUARD_TLS,
)
from vpn.protocol_limits import (
    MAX_WG_GROUPS,
    MAX_OVPN_GROUPS,
    MAX_PWG_GROUPS,
    check_protocol_slot,
    require_protocol_slot,
)
from services.vpn_service import LimitExceededError


def _make_vpn_profile(vpn_protocol, profile_id="p1"):
    return {
        "id": profile_id,
        "type": PROFILE_TYPE_VPN,
        "router_info": {"vpn_protocol": vpn_protocol},
    }


class TestCheckProtocolSlot:
    @patch("vpn.protocol_limits.ps.get_profiles")
    def test_wg_slot_available(self, mock_get):
        mock_get.return_value = [
            _make_vpn_profile(PROTO_WIREGUARD, f"p{i}") for i in range(MAX_WG_GROUPS - 1)
        ]
        assert check_protocol_slot(PROTO_WIREGUARD) is True

    @patch("vpn.protocol_limits.ps.get_profiles")
    def test_wg_slot_full(self, mock_get):
        mock_get.return_value = [
            _make_vpn_profile(PROTO_WIREGUARD, f"p{i}") for i in range(MAX_WG_GROUPS)
        ]
        assert check_protocol_slot(PROTO_WIREGUARD) is False

    @patch("vpn.protocol_limits.ps.get_profiles")
    def test_wg_slot_with_exclude(self, mock_get):
        """Excluding the profile itself frees a slot."""
        mock_get.return_value = [
            _make_vpn_profile(PROTO_WIREGUARD, f"p{i}") for i in range(MAX_WG_GROUPS)
        ]
        assert check_protocol_slot(PROTO_WIREGUARD, exclude_profile_id="p0") is True

    @patch("vpn.protocol_limits.ps.get_profiles")
    def test_ovpn_slot_available(self, mock_get):
        mock_get.return_value = []
        assert check_protocol_slot(PROTO_OPENVPN) is True

    @patch("vpn.protocol_limits.ps.get_profiles")
    def test_ovpn_slot_full(self, mock_get):
        mock_get.return_value = [
            _make_vpn_profile(PROTO_OPENVPN, f"p{i}") for i in range(MAX_OVPN_GROUPS)
        ]
        assert check_protocol_slot(PROTO_OPENVPN) is False

    @patch("vpn.protocol_limits.ps.get_profiles")
    def test_pwg_tcp_slot_counts_both_tcp_and_tls(self, mock_get):
        """proton-wg TCP and TLS share the same pool."""
        mock_get.return_value = [
            _make_vpn_profile("wireguard-tcp", "p0"),
            _make_vpn_profile("wireguard-tls", "p1"),
            _make_vpn_profile("wireguard-tls", "p2"),
        ]
        assert check_protocol_slot(PROTO_WIREGUARD_TCP) is True  # 3 < 4

    @patch("vpn.protocol_limits.ps.get_profiles")
    def test_pwg_slot_full(self, mock_get):
        mock_get.return_value = [
            _make_vpn_profile("wireguard-tcp", f"p{i}") for i in range(MAX_PWG_GROUPS)
        ]
        assert check_protocol_slot(PROTO_WIREGUARD_TLS) is False

    @patch("vpn.protocol_limits.ps.get_profiles")
    def test_non_vpn_profiles_not_counted(self, mock_get):
        """NoVPN profiles should not count toward limits."""
        mock_get.return_value = [
            {"id": "nv1", "type": PROFILE_TYPE_NO_VPN, "router_info": {}},
        ] + [
            _make_vpn_profile(PROTO_WIREGUARD, f"p{i}") for i in range(MAX_WG_GROUPS)
        ]
        assert check_protocol_slot(PROTO_WIREGUARD) is False


class TestRequireProtocolSlot:
    @patch("vpn.protocol_limits.ps.get_profiles")
    def test_raises_when_full(self, mock_get):
        mock_get.return_value = [
            _make_vpn_profile(PROTO_WIREGUARD, f"p{i}") for i in range(MAX_WG_GROUPS)
        ]
        with pytest.raises(LimitExceededError, match="WireGuard UDP"):
            require_protocol_slot(PROTO_WIREGUARD)

    @patch("vpn.protocol_limits.ps.get_profiles")
    def test_no_raise_when_available(self, mock_get):
        mock_get.return_value = []
        require_protocol_slot(PROTO_WIREGUARD)  # should not raise

    @patch("vpn.protocol_limits.ps.get_profiles")
    def test_ovpn_error_message(self, mock_get):
        mock_get.return_value = [
            _make_vpn_profile(PROTO_OPENVPN, f"p{i}") for i in range(MAX_OVPN_GROUPS)
        ]
        with pytest.raises(LimitExceededError, match="OpenVPN"):
            require_protocol_slot(PROTO_OPENVPN)

    @patch("vpn.protocol_limits.ps.get_profiles")
    def test_pwg_error_message(self, mock_get):
        mock_get.return_value = [
            _make_vpn_profile("wireguard-tcp", f"p{i}") for i in range(MAX_PWG_GROUPS)
        ]
        with pytest.raises(LimitExceededError, match="WireGuard TCP/TLS"):
            require_protocol_slot(PROTO_WIREGUARD_TCP)

    @patch("vpn.protocol_limits.ps.get_profiles")
    def test_exclude_profile_id(self, mock_get):
        mock_get.return_value = [
            _make_vpn_profile(PROTO_WIREGUARD, f"p{i}") for i in range(MAX_WG_GROUPS)
        ]
        # Without exclude -> raises
        with pytest.raises(LimitExceededError):
            require_protocol_slot(PROTO_WIREGUARD)
        # With exclude -> passes
        require_protocol_slot(PROTO_WIREGUARD, exclude_profile_id="p0")
