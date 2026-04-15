"""Tests for tunnel_strategy.py — Strategy Pattern for VPN protocol handling.

Covers the get_strategy factory and all three concrete strategies:
WireGuardStrategy, OpenVPNStrategy, ProtonWGStrategy.
"""

from unittest.mock import MagicMock, call, patch

import pytest

from vpn.tunnel_strategy import (
    OpenVPNStrategy,
    ProtonWGStrategy,
    WireGuardStrategy,
    _parse_wg_config,
    get_strategy,
)


# ── Shared fixtures / helpers ────────────────────────────────────────────────

SAMPLE_WG_CONFIG = (
    "[Interface]\n"
    "PrivateKey = test_private_key\n"
    "Address = 10.2.0.2/32\n"
    "DNS = 10.2.0.1\n"
    "\n"
    "[Peer]\n"
    "PublicKey = test_public_key\n"
    "AllowedIPs = 0.0.0.0/0\n"
    "Endpoint = 1.2.3.4:51820\n"
)

SAMPLE_SERVER_INFO = {
    "id": "server-1",
    "endpoint": "1.2.3.4:51820",
    "physical_server_domain": "node-de-01.protonvpn.net",
    "protocol": "wireguard",
}

SAMPLE_WG_KEY = "base64_ed25519_key_here"
SAMPLE_CERT_EXPIRY = 1807264162


def _mock_proton():
    """Create a MagicMock proton API with sensible return values."""
    proton = MagicMock()
    proton.generate_wireguard_config.return_value = (
        SAMPLE_WG_CONFIG,
        SAMPLE_SERVER_INFO,
        SAMPLE_WG_KEY,
        SAMPLE_CERT_EXPIRY,
    )
    proton.generate_openvpn_config.return_value = (
        "client\nremote 1.2.3.4 443 tcp\n",
        {**SAMPLE_SERVER_INFO, "protocol": "openvpn-tcp"},
        "ovpn_user",
        "ovpn_pass",
    )
    return proton


def _mock_router():
    """Create a MagicMock router API with sensible return values."""
    router = MagicMock()
    router.wireguard.upload_wireguard_config.return_value = {
        "rule_name": "fvpn_rule_9001",
        "peer_id": "9001",
        "vpn_protocol": "wireguard",
    }
    router.openvpn.upload_openvpn_config.return_value = {
        "rule_name": "fvpn_rule_ovpn_9051",
        "client_uci_id": "28216_9051",
        "vpn_protocol": "openvpn",
    }
    router.proton_wg.upload_proton_wg_config.return_value = {
        "rule_name": "fvpn_rule_protonwg_1",
        "tunnel_name": "protonwg0",
        "tunnel_id": 1,
        "mark": "0x10000",
        "table_num": 100,
        "vpn_protocol": "wireguard-tcp",
    }
    router.tunnel.get_tunnel_health.return_value = "green"
    router.proton_wg.get_proton_wg_health.return_value = "green"
    router.PROTON_WG_DIR = "/etc/protonwg"
    return router


DEFAULT_OPTIONS = {
    "netshield": 2,
    "moderate_nat": False,
    "nat_pmp": False,
    "vpn_accelerator": True,
}


# ── get_strategy factory ────────────────────────────────────────────────────


class TestGetStrategy:
    def test_returns_wireguard_strategy_for_wireguard(self):
        strategy = get_strategy("wireguard")
        assert isinstance(strategy, WireGuardStrategy)

    def test_returns_openvpn_strategy_for_openvpn(self):
        strategy = get_strategy("openvpn")
        assert isinstance(strategy, OpenVPNStrategy)

    def test_returns_protonwg_strategy_for_wireguard_tcp(self):
        strategy = get_strategy("wireguard-tcp")
        assert isinstance(strategy, ProtonWGStrategy)
        assert strategy.transport == "tcp"

    def test_returns_protonwg_strategy_for_wireguard_tls(self):
        strategy = get_strategy("wireguard-tls")
        assert isinstance(strategy, ProtonWGStrategy)
        assert strategy.transport == "tls"

    def test_raises_valueerror_for_unknown_protocol(self):
        with pytest.raises(ValueError, match="Unknown VPN protocol"):
            get_strategy("ipsec")

    def test_raises_valueerror_for_empty_string(self):
        with pytest.raises(ValueError, match="Unknown VPN protocol"):
            get_strategy("")


# ── _parse_wg_config helper ─────────────────────────────────────────────────


class TestParseWgConfig:
    def test_parses_all_fields(self):
        result = _parse_wg_config(SAMPLE_WG_CONFIG)
        assert result["private_key"] == "test_private_key"
        assert result["public_key"] == "test_public_key"
        assert result["endpoint"] == "1.2.3.4:51820"
        assert result["dns"] == "10.2.0.1"

    def test_default_dns_when_missing(self):
        config = (
            "[Interface]\n"
            "PrivateKey = pk\n"
            "\n"
            "[Peer]\n"
            "PublicKey = pub\n"
            "Endpoint = 5.6.7.8:51820\n"
        )
        result = _parse_wg_config(config)
        assert result["dns"] == "10.2.0.1"

    def test_handles_empty_string(self):
        result = _parse_wg_config("")
        assert result["private_key"] == ""
        assert result["public_key"] == ""
        assert result["endpoint"] == ""
        assert result["dns"] == "10.2.0.1"


# ── WireGuardStrategy ───────────────────────────────────────────────────────


class TestWireGuardStrategy:
    def setup_method(self):
        self.strategy = WireGuardStrategy()
        self.router = _mock_router()
        self.proton = _mock_proton()
        self.server = MagicMock(name="LogicalServer")

    def test_create(self):
        router_info, server_info, wg_key, cert_expiry = self.strategy.create(
            self.router, self.proton, "TestProfile", self.server, DEFAULT_OPTIONS
        )

        # Proton called with correct args
        self.proton.generate_wireguard_config.assert_called_once_with(
            self.server,
            profile_name="TestProfile",
            netshield=2,
            moderate_nat=False,
            nat_pmp=False,
            vpn_accelerator=True,
            transport="udp",
            port=None,
            custom_dns=None,
            ipv6=False,
        )

        # Router upload called with parsed WG fields
        self.router.wireguard.upload_wireguard_config.assert_called_once_with(
            profile_name="TestProfile",
            private_key="test_private_key",
            public_key="test_public_key",
            endpoint="1.2.3.4:51820",
            dns="10.2.0.1",
            ipv6=False,
        )

        # Return values
        assert router_info["rule_name"] == "fvpn_rule_9001"
        assert router_info["peer_id"] == "9001"
        assert server_info == SAMPLE_SERVER_INFO
        assert wg_key == SAMPLE_WG_KEY
        assert cert_expiry == SAMPLE_CERT_EXPIRY

    def test_delete(self):
        router_info = {"rule_name": "fvpn_rule_9001", "peer_id": "9001"}
        self.strategy.delete(self.router, router_info)

        self.router.wireguard.delete_wireguard_config.assert_called_once_with(
            "9001", "fvpn_rule_9001"
        )

    def test_connect(self):
        router_info = {"rule_name": "fvpn_rule_9001"}
        health = self.strategy.connect(self.router, router_info)

        self.router.tunnel.bring_tunnel_up.assert_called_once_with("fvpn_rule_9001")
        self.router.tunnel.get_tunnel_health.assert_called_once_with("fvpn_rule_9001")
        assert health == "green"

    def test_disconnect(self):
        router_info = {"rule_name": "fvpn_rule_9001"}
        self.strategy.disconnect(self.router, router_info)

        self.router.tunnel.bring_tunnel_down.assert_called_once_with("fvpn_rule_9001")

    def test_switch_server(self):
        profile = {
            "name": "TestProfile",
            "wg_key": "existing_ed25519_key",
        }
        old_router_info = {"rule_name": "fvpn_rule_9001", "peer_id": "9001"}

        new_ri, server_info, wg_key, cert_expiry = self.strategy.switch_server(
            self.router, self.proton, profile, self.server,
            DEFAULT_OPTIONS, old_router_info,
        )

        # Should reuse existing wg_key
        self.proton.generate_wireguard_config.assert_called_once_with(
            self.server,
            profile_name="TestProfile",
            netshield=2,
            moderate_nat=False,
            nat_pmp=False,
            vpn_accelerator=True,
            existing_wg_key="existing_ed25519_key",
            transport="udp",
            port=None,
            custom_dns=None,
            ipv6=False,
        )

        # In-place update, not delete-recreate
        self.router.wireguard.update_wireguard_peer_live.assert_called_once_with(
            peer_id="9001",
            rule_name="fvpn_rule_9001",
            private_key="test_private_key",
            public_key="test_public_key",
            endpoint="1.2.3.4:51820",
            dns="10.2.0.1",
        )

        # router_info is None (unchanged)
        assert new_ri is None
        assert server_info == SAMPLE_SERVER_INFO
        assert wg_key == SAMPLE_WG_KEY
        assert cert_expiry == SAMPLE_CERT_EXPIRY

    def test_switch_server_raises_without_peer_id(self):
        profile = {"name": "Test", "wg_key": "key"}
        old_router_info = {"rule_name": "fvpn_rule_9001", "peer_id": ""}

        with pytest.raises(ValueError, match="missing peer_id"):
            self.strategy.switch_server(
                self.router, self.proton, profile, self.server,
                DEFAULT_OPTIONS, old_router_info,
            )

    def test_get_health(self):
        router_info = {"rule_name": "fvpn_rule_9001"}
        health = self.strategy.get_health(self.router, router_info)

        self.router.tunnel.get_tunnel_health.assert_called_once_with("fvpn_rule_9001")
        assert health == "green"


# ── OpenVPNStrategy ─────────────────────────────────────────────────────────


class TestOpenVPNStrategy:
    def setup_method(self):
        self.strategy = OpenVPNStrategy()
        self.router = _mock_router()
        self.proton = _mock_proton()
        self.server = MagicMock(name="LogicalServer")

    def test_create(self):
        router_info, server_info, wg_key, cert_expiry = self.strategy.create(
            self.router, self.proton, "OVPNProfile", self.server,
            {**DEFAULT_OPTIONS, "ovpn_protocol": "tcp"},
        )

        self.proton.generate_openvpn_config.assert_called_once_with(
            self.server,
            protocol="tcp",
            netshield=2,
            moderate_nat=False,
            nat_pmp=False,
            vpn_accelerator=True,
            port=None,
        )

        self.router.openvpn.upload_openvpn_config.assert_called_once_with(
            profile_name="OVPNProfile",
            ovpn_config="client\nremote 1.2.3.4 443 tcp\n",
            username="ovpn_user",
            password="ovpn_pass",
        )

        assert router_info["rule_name"] == "fvpn_rule_ovpn_9051"
        assert router_info["client_uci_id"] == "28216_9051"
        assert wg_key is None
        assert cert_expiry is None

    def test_create_uses_transport_fallback_for_protocol(self):
        """When ovpn_protocol is not in options, falls back to transport arg."""
        self.strategy.create(
            self.router, self.proton, "FallbackProto", self.server,
            {"netshield": 0}, transport="udp",
        )
        self.proton.generate_openvpn_config.assert_called_once_with(
            self.server,
            protocol="udp",
            netshield=0,
            moderate_nat=False,
            nat_pmp=False,
            vpn_accelerator=True,
            port=None,
        )

    def test_delete(self):
        router_info = {
            "rule_name": "fvpn_rule_ovpn_9051",
            "client_uci_id": "28216_9051",
        }
        self.strategy.delete(self.router, router_info)

        self.router.openvpn.delete_openvpn_config.assert_called_once_with(
            "28216_9051", "fvpn_rule_ovpn_9051"
        )

    def test_connect(self):
        router_info = {"rule_name": "fvpn_rule_ovpn_9051"}
        health = self.strategy.connect(self.router, router_info)

        self.router.tunnel.bring_tunnel_up.assert_called_once_with("fvpn_rule_ovpn_9051")
        self.router.tunnel.get_tunnel_health.assert_called_once_with("fvpn_rule_ovpn_9051")
        assert health == "green"

    def test_disconnect(self):
        router_info = {"rule_name": "fvpn_rule_ovpn_9051"}
        self.strategy.disconnect(self.router, router_info)

        self.router.tunnel.bring_tunnel_down.assert_called_once_with("fvpn_rule_ovpn_9051")

    def test_switch_server(self):
        """Full delete-recreate flow: capture MACs, delete, upload, reorder, reassign, bring up."""
        old_ri = {
            "rule_name": "fvpn_rule_ovpn_9051",
            "client_uci_id": "28216_9051",
        }
        profile = {
            "name": "OVPNProfile",
            "server": {"protocol": "openvpn-tcp"},
        }

        # Mock from_mac_tokens returning devices assigned to the old rule
        self.router.policy.from_mac_tokens.return_value = [
            "AA:BB:CC:DD:EE:01",
            "AA:BB:CC:DD:EE:02",
        ]

        # Mock existing rules for section-order capture
        self.router.policy.get_flint_vpn_rules.return_value = [
            {"rule_name": "fvpn_rule_9001", "enabled": "1"},
            {"rule_name": "fvpn_rule_ovpn_9051", "enabled": "1"},
            {"rule_name": "fvpn_rule_9002", "enabled": "0"},
        ]

        new_ri, server_info, wg_key, cert_expiry = self.strategy.switch_server(
            self.router, self.proton, profile, self.server,
            DEFAULT_OPTIONS, old_ri,
        )

        # 1. Captured MACs from old rule
        self.router.policy.from_mac_tokens.assert_called_once_with("fvpn_rule_ovpn_9051")

        # 2. Deleted old config
        self.router.openvpn.delete_openvpn_config.assert_called_once_with(
            "28216_9051", "fvpn_rule_ovpn_9051"
        )

        # 3. Generated new OVPN config (protocol=tcp because server.protocol ends with "tcp")
        self.proton.generate_openvpn_config.assert_called_once_with(
            self.server,
            protocol="tcp",
            netshield=2,
            moderate_nat=False,
            nat_pmp=False,
            vpn_accelerator=True,
            port=None,
        )

        # 4. Uploaded new config
        self.router.openvpn.upload_openvpn_config.assert_called_once()

        # 5. Reordered rules to preserve original position
        self.router.policy.reorder_vpn_rules.assert_called_once()
        reorder_arg = self.router.policy.reorder_vpn_rules.call_args[0][0]
        # New rule should be at index 1 (where old one was)
        assert reorder_arg[1] == "fvpn_rule_ovpn_9051"

        # 6. Re-attached devices
        assert self.router.devices.set_device_vpn.call_count == 2
        assigned_macs = [c[0][0] for c in self.router.devices.set_device_vpn.call_args_list]
        assert "aa:bb:cc:dd:ee:01" in assigned_macs
        assert "aa:bb:cc:dd:ee:02" in assigned_macs

        # 7. Tunnel was enabled, so bring_tunnel_up should be called
        self.router.tunnel.bring_tunnel_up.assert_called_once()

        # Returns new router_info (not None, unlike WG in-place)
        assert new_ri is not None
        assert new_ri["rule_name"] == "fvpn_rule_ovpn_9051"
        assert wg_key is None
        assert cert_expiry is None

    def test_switch_server_skips_bring_up_when_disabled(self):
        """If the old tunnel was disabled, don't bring the new one up."""
        old_ri = {
            "rule_name": "fvpn_rule_ovpn_9051",
            "client_uci_id": "28216_9051",
        }
        profile = {
            "name": "OVPNProfile",
            "server": {"protocol": "openvpn-udp"},
        }
        self.router.policy.from_mac_tokens.return_value = []
        self.router.policy.get_flint_vpn_rules.return_value = [
            {"rule_name": "fvpn_rule_ovpn_9051", "enabled": "0"},
        ]

        self.strategy.switch_server(
            self.router, self.proton, profile, self.server,
            DEFAULT_OPTIONS, old_ri,
        )

        self.router.tunnel.bring_tunnel_up.assert_not_called()

    def test_switch_server_raises_without_client_uci_id(self):
        profile = {"name": "Test", "server": {}}
        old_ri = {"rule_name": "fvpn_rule_ovpn_9051", "client_uci_id": ""}

        with pytest.raises(ValueError, match="missing client_uci_id"):
            self.strategy.switch_server(
                self.router, self.proton, profile, self.server,
                DEFAULT_OPTIONS, old_ri,
            )

    def test_switch_server_tolerates_from_mac_failure(self):
        """If from_mac_tokens fails, switch proceeds without re-assigning."""
        old_ri = {
            "rule_name": "fvpn_rule_ovpn_9051",
            "client_uci_id": "28216_9051",
        }
        profile = {
            "name": "OVPNProfile",
            "server": {"protocol": "openvpn-udp"},
        }
        self.router.policy.from_mac_tokens.side_effect = Exception("SSH error")
        self.router.policy.get_flint_vpn_rules.return_value = [
            {"rule_name": "fvpn_rule_ovpn_9051", "enabled": "0"},
        ]

        # Should not raise
        new_ri, _, _, _ = self.strategy.switch_server(
            self.router, self.proton, profile, self.server,
            DEFAULT_OPTIONS, old_ri,
        )
        assert new_ri is not None
        self.router.devices.set_device_vpn.assert_not_called()

    def test_get_health(self):
        router_info = {"rule_name": "fvpn_rule_ovpn_9051"}
        health = self.strategy.get_health(self.router, router_info)

        self.router.tunnel.get_tunnel_health.assert_called_once_with("fvpn_rule_ovpn_9051")
        assert health == "green"


# ── ProtonWGStrategy ────────────────────────────────────────────────────────


class TestProtonWGStrategy:
    def setup_method(self):
        self.strategy_tcp = ProtonWGStrategy("tcp")
        self.strategy_tls = ProtonWGStrategy("tls")
        self.router = _mock_router()
        self.proton = _mock_proton()
        self.server = MagicMock(name="LogicalServer")

    def _sample_router_info(self):
        return {
            "rule_name": "fvpn_rule_protonwg_1",
            "tunnel_name": "protonwg0",
            "tunnel_id": 1,
            "mark": "0x10000",
            "table_num": 100,
        }

    def test_create_tcp(self):
        router_info, server_info, wg_key, cert_expiry = self.strategy_tcp.create(
            self.router, self.proton, "TCPProfile", self.server, DEFAULT_OPTIONS
        )

        # Should pass transport="tcp" to proton
        self.proton.generate_wireguard_config.assert_called_once_with(
            self.server,
            profile_name="TCPProfile",
            netshield=2,
            moderate_nat=False,
            nat_pmp=False,
            vpn_accelerator=True,
            transport="tcp",
            port=None,
            custom_dns=None,
            ipv6=False,
        )

        # Should upload via proton_wg path with socket_type
        self.router.proton_wg.upload_proton_wg_config.assert_called_once_with(
            profile_name="TCPProfile",
            private_key="test_private_key",
            public_key="test_public_key",
            endpoint="1.2.3.4:51820",
            socket_type="tcp",
            dns="10.2.0.1",
            ipv6=False,
        )

        assert wg_key == SAMPLE_WG_KEY
        assert cert_expiry == SAMPLE_CERT_EXPIRY

    def test_create_tls(self):
        self.strategy_tls.create(
            self.router, self.proton, "TLSProfile", self.server, DEFAULT_OPTIONS
        )

        # Should pass transport="tls"
        self.proton.generate_wireguard_config.assert_called_once()
        call_kwargs = self.proton.generate_wireguard_config.call_args[1]
        assert call_kwargs["transport"] == "tls"

        # Socket type should be "tls"
        upload_kwargs = self.router.proton_wg.upload_proton_wg_config.call_args[1]
        assert upload_kwargs["socket_type"] == "tls"

    def test_connect(self):
        ri = self._sample_router_info()
        health = self.strategy_tcp.connect(self.router, ri)

        self.router.proton_wg.start_proton_wg_tunnel.assert_called_once_with(
            iface="protonwg0",
            mark="0x10000",
            table_num=100,
            tunnel_id=1,
        )
        self.router.proton_wg.get_proton_wg_health.assert_called_once_with("protonwg0")
        assert health == "green"

    def test_disconnect(self):
        ri = self._sample_router_info()
        self.strategy_tcp.disconnect(self.router, ri)

        self.router.proton_wg.stop_proton_wg_tunnel.assert_called_once_with(
            iface="protonwg0",
            mark="0x10000",
            table_num=100,
            tunnel_id=1,
        )

    def test_delete_stops_then_deletes(self):
        ri = self._sample_router_info()
        self.strategy_tcp.delete(self.router, ri)

        # Stop is called first (best-effort)
        self.router.proton_wg.stop_proton_wg_tunnel.assert_called_once_with(
            iface="protonwg0",
            mark="0x10000",
            table_num=100,
            tunnel_id=1,
        )

        # Then delete
        self.router.proton_wg.delete_proton_wg_config.assert_called_once_with(
            iface="protonwg0",
            tunnel_id=1,
        )

    def test_delete_tolerates_stop_failure(self):
        """Best-effort stop: if stop raises, delete still proceeds."""
        ri = self._sample_router_info()
        self.router.proton_wg.stop_proton_wg_tunnel.side_effect = Exception("tunnel not running")

        # Should not raise
        self.strategy_tcp.delete(self.router, ri)
        self.router.proton_wg.delete_proton_wg_config.assert_called_once()

    def test_switch_server(self):
        profile = {
            "name": "TCPProfile",
            "wg_key": "existing_ed25519_key",
        }
        old_ri = self._sample_router_info()

        new_ri, server_info, wg_key, cert_expiry = self.strategy_tcp.switch_server(
            self.router, self.proton, profile, self.server,
            DEFAULT_OPTIONS, old_ri,
        )

        # Should reuse existing wg_key
        self.proton.generate_wireguard_config.assert_called_once_with(
            self.server,
            profile_name="TCPProfile",
            netshield=2,
            moderate_nat=False,
            nat_pmp=False,
            vpn_accelerator=True,
            existing_wg_key="existing_ed25519_key",
            transport="tcp",
            port=None,
            custom_dns=None,
            ipv6=False,
        )

        # Should call proton_wg.update_config_live with the conf content
        self.router.proton_wg.update_config_live.assert_called_once()
        call_args = self.router.proton_wg.update_config_live.call_args[0]
        assert call_args[0] == "protonwg0"
        conf_content = call_args[1]
        assert "PrivateKey = test_private_key" in conf_content
        assert "PublicKey = test_public_key" in conf_content
        assert "Endpoint = 1.2.3.4:51820" in conf_content

        # router_info is None (in-place update)
        assert new_ri is None
        assert server_info == SAMPLE_SERVER_INFO
        assert wg_key == SAMPLE_WG_KEY
        assert cert_expiry == SAMPLE_CERT_EXPIRY

    def test_get_health(self):
        ri = self._sample_router_info()
        health = self.strategy_tcp.get_health(self.router, ri)

        self.router.proton_wg.get_proton_wg_health.assert_called_once_with("protonwg0")
        assert health == "green"
