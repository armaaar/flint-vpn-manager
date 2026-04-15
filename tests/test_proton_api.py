"""Tests for proton_api.py — ProtonVPN API wrapper.

Unit tests mock the underlying Proton library.
Integration tests (marked @pytest.mark.integration) use a live ProtonVPN session.
"""

import time

import pytest
from unittest.mock import MagicMock, patch, PropertyMock

import proton_vpn.api as proton_api
from proton_vpn.api import ProtonAPI, FEATURE_MAP, NETSHIELD_DNS
from proton.vpn.session.servers.types import ServerFeatureEnum, LogicalServer, PhysicalServer


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_logical(name="CH#1", country="CH", city="Zurich", load=20,
                  score=1.0, features=0, tier=2, enabled=True,
                  entry_ip="1.2.3.4", x25519_pk="fakepk==", domain="node.protonvpn.net"):
    """Create a minimal LogicalServer dict for testing."""
    return LogicalServer({
        "ID": f"id-{name}",
        "Name": name,
        "EntryCountry": country,
        "ExitCountry": country,
        "City": city,
        "Load": load,
        "Score": score,
        "Features": features,
        "Tier": tier,
        "Status": 1 if enabled else 0,
        "Region": city,
        "Location": {"Lat": 47.0, "Long": 8.0},
        "Servers": [
            {
                "ID": f"phys-{name}",
                "EntryIP": entry_ip,
                "ExitIP": "5.6.7.8",
                "Domain": domain,
                "Status": 1,
                "Generation": "1",
                "Label": "",
                "X25519PublicKey": x25519_pk,
            }
        ],
    })


def _make_server_list(logicals, user_tier=2):
    """Create a ServerList from a list of LogicalServers."""
    from proton.vpn.session.servers.logicals import ServerList
    return ServerList(user_tier=user_tier, logicals=logicals)


@pytest.fixture
def mock_api():
    """Create a ProtonAPI with mocked internals, bypassing sync_wrapper."""
    with patch("proton_vpn.api.ProtonVPNAPI") as MockVPNAPI, \
         patch("proton_vpn.api.sync_wrapper", side_effect=lambda f: f):
        mock_instance = MockVPNAPI.return_value

        # Default: not logged in
        mock_instance.is_user_logged_in.return_value = False
        mock_instance.vpn_session_loaded = False
        mock_instance.server_list = None

        api = ProtonAPI()
        api._api = mock_instance
        yield api, mock_instance


# ── Unit Tests ────────────────────────────────────────────────────────────────

class TestProtonAPIInit:
    def test_creates_instance(self, mock_api):
        api, _ = mock_api
        assert api is not None

    def test_not_logged_in_by_default(self, mock_api):
        api, mock = mock_api
        mock.is_user_logged_in.return_value = False
        assert api.is_logged_in is False


class TestLogin:
    def test_successful_login(self, mock_api):
        api, mock = mock_api
        from proton.vpn.session.dataclasses import LoginResult
        expected = LoginResult(success=True, authenticated=True, twofa_required=False)
        api._sync_login = MagicMock(return_value=expected)

        result = api.login("user", "pass")
        assert result.success is True
        assert result.twofa_required is False
        api._sync_login.assert_called_once_with("user", "pass")

    def test_2fa_required(self, mock_api):
        api, mock = mock_api
        from proton.vpn.session.dataclasses import LoginResult
        expected = LoginResult(success=False, authenticated=True, twofa_required=True)
        api._sync_login = MagicMock(return_value=expected)

        result = api.login("user", "pass")
        assert result.success is False
        assert result.twofa_required is True

    def test_bad_credentials(self, mock_api):
        api, mock = mock_api
        from proton.vpn.session.dataclasses import LoginResult
        expected = LoginResult(success=False, authenticated=False, twofa_required=False)
        api._sync_login = MagicMock(return_value=expected)

        result = api.login("user", "wrong")
        assert result.success is False
        assert result.authenticated is False


class TestSubmit2FA:
    def test_valid_code(self, mock_api):
        api, mock = mock_api
        from proton.vpn.session.dataclasses import LoginResult
        expected = LoginResult(success=True, authenticated=True, twofa_required=False)
        api._sync_2fa = MagicMock(return_value=expected)

        result = api.submit_2fa("123456")
        assert result.success is True
        api._sync_2fa.assert_called_once_with("123456")


class TestGetServers:
    def test_not_logged_in_raises(self, mock_api):
        api, mock = mock_api
        mock.vpn_session_loaded = False
        with pytest.raises(RuntimeError, match="Not logged in"):
            api.get_servers()

    def test_returns_all_servers(self, mock_api):
        api, mock = mock_api
        logicals = [
            _make_logical("CH#1", "CH", "Zurich", 20),
            _make_logical("US#1", "US", "New York", 30),
            _make_logical("UK#1", "UK", "London", 40),
        ]
        mock.vpn_session_loaded = True
        mock.server_list = _make_server_list(logicals)

        servers = api.get_servers()
        assert len(servers) == 3
        names = {s["name"] for s in servers}
        assert names == {"CH#1", "US#1", "UK#1"}

    def test_filter_by_country(self, mock_api):
        api, mock = mock_api
        logicals = [
            _make_logical("CH#1", "CH", "Zurich"),
            _make_logical("CH#2", "CH", "Geneva"),
            _make_logical("US#1", "US", "New York"),
        ]
        mock.vpn_session_loaded = True
        mock.server_list = _make_server_list(logicals)

        servers = api.get_servers(country="CH")
        assert len(servers) == 2
        assert all(s["country_code"] == "CH" for s in servers)

    def test_filter_by_city(self, mock_api):
        api, mock = mock_api
        logicals = [
            _make_logical("CH#1", "CH", "Zurich"),
            _make_logical("CH#2", "CH", "Geneva"),
        ]
        mock.vpn_session_loaded = True
        mock.server_list = _make_server_list(logicals)

        servers = api.get_servers(city="Zurich")
        assert len(servers) == 1
        assert servers[0]["city"] == "Zurich"

    def test_filter_by_feature_streaming(self, mock_api):
        api, mock = mock_api
        logicals = [
            _make_logical("CH#1", features=ServerFeatureEnum.STREAMING),
            _make_logical("CH#2", features=0),
            _make_logical("CH#3", features=ServerFeatureEnum.STREAMING | ServerFeatureEnum.P2P),
        ]
        mock.vpn_session_loaded = True
        mock.server_list = _make_server_list(logicals)

        servers = api.get_servers(feature="streaming")
        assert len(servers) == 2
        assert all("streaming" in s["features"] for s in servers)

    def test_filter_by_feature_p2p(self, mock_api):
        api, mock = mock_api
        logicals = [
            _make_logical("CH#1", features=ServerFeatureEnum.P2P),
            _make_logical("CH#2", features=0),
        ]
        mock.vpn_session_loaded = True
        mock.server_list = _make_server_list(logicals)

        servers = api.get_servers(feature="p2p")
        assert len(servers) == 1
        assert servers[0]["p2p"] is True

    def test_filter_available_only(self, mock_api):
        api, mock = mock_api
        logicals = [
            _make_logical("CH#1", tier=2, enabled=True),    # accessible (user tier 2)
            _make_logical("CH#2", tier=3, enabled=True),    # PM only, not accessible
            _make_logical("CH#3", tier=2, enabled=False),   # disabled
        ]
        mock.vpn_session_loaded = True
        mock.server_list = _make_server_list(logicals, user_tier=2)

        servers = api.get_servers(available_only=True)
        assert len(servers) == 1
        assert servers[0]["name"] == "CH#1"

    def test_combined_filters(self, mock_api):
        api, mock = mock_api
        logicals = [
            _make_logical("UK#1", "UK", "London", features=ServerFeatureEnum.STREAMING),
            _make_logical("UK#2", "UK", "Manchester", features=ServerFeatureEnum.STREAMING),
            _make_logical("UK#3", "UK", "London", features=0),
            _make_logical("US#1", "US", "New York", features=ServerFeatureEnum.STREAMING),
        ]
        mock.vpn_session_loaded = True
        mock.server_list = _make_server_list(logicals)

        servers = api.get_servers(country="UK", feature="streaming")
        assert len(servers) == 2
        assert all(s["country_code"] == "UK" and s["streaming"] for s in servers)


class TestServerToDict:
    def test_contains_required_fields(self, mock_api):
        api, _ = mock_api
        server = _make_logical("CH#1", "CH", "Zurich", 25, 1.5,
                               features=ServerFeatureEnum.P2P | ServerFeatureEnum.STREAMING)
        result = api._server_to_dict(server)

        assert result["id"] == "id-CH#1"
        assert result["name"] == "CH#1"
        assert result["country_code"] == "CH"
        assert result["city"] == "Zurich"
        assert result["load"] == 25
        assert result["score"] == 1.5
        assert result["p2p"] is True
        assert result["streaming"] is True
        assert result["secure_core"] is False
        assert "p2p" in result["features"]
        assert "streaming" in result["features"]


def _mock_persistent_cert_api(mock):
    """Set up the mock to handle persistent certificate API calls."""
    mock_session = MagicMock()
    mock_session.api_request.return_value = {
        "Code": 1000,
        "ExpirationTime": 1807264162,
        "RefreshTime": 1799380162,
        "Mode": "persistent",
        "DeviceName": "FlintVPN-test",
        "Certificate": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
    }
    mock._session_holder.session = mock_session
    return mock_session


class TestGenerateWireGuardConfig:
    def test_generates_valid_config(self, mock_api):
        api, mock = mock_api
        server = _make_logical("CH#1", entry_ip="1.2.3.4", x25519_pk="serverpk==")
        _mock_persistent_cert_api(mock)

        config, info, wg_key, cert_expiry = api.generate_wireguard_config(server)

        assert "[Interface]" in config
        assert "PrivateKey = " in config
        assert "Address = 10.2.0.2/32" in config
        assert "[Peer]" in config
        assert "PublicKey = serverpk==" in config
        assert "AllowedIPs = 0.0.0.0/0" in config
        assert "Endpoint = 1.2.3.4:51820" in config
        assert "::" not in config  # No IPv6
        assert wg_key  # Ed25519 key returned for storage
        assert cert_expiry == 1807264162

    def test_persistent_cert_api_called_with_correct_params(self, mock_api):
        api, mock = mock_api
        server = _make_logical("CH#1")
        mock_session = _mock_persistent_cert_api(mock)

        api.generate_wireguard_config(
            server, profile_name="MyVPN",
            netshield=2, moderate_nat=True, vpn_accelerator=False,
        )

        call_args = mock_session.api_request.call_args
        req_body = call_args[1]["jsondata"] if "jsondata" in call_args[1] else call_args[0][1]
        assert req_body["Mode"] == "persistent"
        assert req_body["DeviceName"] == "FlintVPN-MyVPN"
        assert req_body["Duration"] == "525600 min"
        assert req_body["Features"]["NetShieldLevel"] == 2
        assert req_body["Features"]["RandomNAT"] is False  # moderate_nat inverted
        assert req_body["Features"]["SplitTCP"] is False

    def test_reuses_existing_key(self, mock_api):
        """When existing_wg_key is provided, the same X25519 key is used."""
        api, mock = mock_api
        server = _make_logical("CH#1")
        _mock_persistent_cert_api(mock)

        # First call: generate fresh key
        _, _, key1, _ = api.generate_wireguard_config(server)

        # Second call: reuse key
        config, _, key2, _ = api.generate_wireguard_config(
            server, existing_wg_key=key1,
        )

        assert key1 == key2  # Same Ed25519 key returned
        # Config should have the same WG private key
        for line in config.splitlines():
            if line.startswith("PrivateKey"):
                pk = line.split("=", 1)[1].strip()
                # Verify it's deterministically derived from the same Ed25519 key
                assert pk == api.get_wireguard_x25519_key(key1)

    def test_netshield_dns(self, mock_api):
        api, mock = mock_api
        server = _make_logical("CH#1")
        _mock_persistent_cert_api(mock)

        # All NetShield levels use 10.2.0.1 (filtering is server-side via cert)
        for level in (0, 1, 2):
            config, _, _, _ = api.generate_wireguard_config(server, netshield=level)
            assert "DNS = 10.2.0.1" in config

    def test_returns_server_info(self, mock_api):
        api, mock = mock_api
        server = _make_logical("UK#5", "UK", "London", 43)
        _mock_persistent_cert_api(mock)

        _, info, _, _ = api.generate_wireguard_config(server)

        assert info["name"] == "UK#5"
        assert info["country_code"] == "UK"
        assert info["city"] == "London"
        assert info["load"] == 43
        assert "endpoint" in info
        assert "physical_server_domain" in info


class TestGenerateOpenVPNConfig:
    def test_generates_valid_config(self, mock_api):
        api, mock = mock_api
        server = _make_logical("CH#1", entry_ip="1.2.3.4")

        mock_up = MagicMock()
        mock_up.username = "vpnuser"
        mock_up.password = "vpnpass"
        mock_creds = MagicMock()
        mock_creds.userpass_credentials = mock_up
        mock_account = MagicMock()
        mock_account.vpn_credentials = mock_creds
        mock.account_data = mock_account

        config, info, username, password = api.generate_openvpn_config(server)

        assert "client" in config
        assert "remote 1.2.3.4" in config
        assert "proto udp" in config
        assert "auth-user-pass" in config
        assert "<ca>" in config
        assert "<tls-crypt>" in config
        assert username == "vpnuser"
        assert password == "vpnpass"
        assert info["protocol"] == "openvpn-udp"

    def test_tcp_protocol(self, mock_api):
        api, mock = mock_api
        server = _make_logical("CH#1", entry_ip="1.2.3.4")
        mock_up = MagicMock()
        mock_up.username = "vpnuser"
        mock_up.password = "vpnpass"
        mock_creds = MagicMock()
        mock_creds.userpass_credentials = mock_up
        mock_account = MagicMock()
        mock_account.vpn_credentials = mock_creds
        mock.account_data = mock_account

        config, info, _, _ = api.generate_openvpn_config(server, protocol="tcp")
        assert "proto tcp" in config
        assert "remote 1.2.3.4 443" in config
        assert info["protocol"] == "openvpn-tcp"

    def test_netshield_suffix(self, mock_api):
        api, mock = mock_api
        server = _make_logical("CH#1")
        mock_up = MagicMock()
        mock_up.username = "vpnuser"
        mock_up.password = "vpnpass"
        mock_creds = MagicMock()
        mock_creds.userpass_credentials = mock_up
        mock_account = MagicMock()
        mock_account.vpn_credentials = mock_creds
        mock.account_data = mock_account

        _, _, user0, _ = api.generate_openvpn_config(server, netshield=0)
        assert user0 == "vpnuser"

        _, _, user1, _ = api.generate_openvpn_config(server, netshield=1)
        assert user1 == "vpnuser+f1"

        _, _, user2, _ = api.generate_openvpn_config(server, netshield=2)
        assert user2 == "vpnuser+f2"


class TestGetCountries:
    def test_returns_grouped_countries(self, mock_api):
        api, mock = mock_api
        logicals = [
            _make_logical("CH#1", "CH", "Zurich"),
            _make_logical("CH#2", "CH", "Geneva"),
            _make_logical("US#1", "US", "New York"),
        ]
        mock.vpn_session_loaded = True
        mock.server_list = _make_server_list(logicals)

        countries = api.get_countries()
        assert len(countries) == 2
        codes = {c["code"] for c in countries}
        assert "CH" in codes
        assert "US" in codes

        ch = next(c for c in countries if c["code"] == "CH")
        assert ch["server_count"] == 2
        assert len(ch["cities"]) == 2


class TestServerRefresh:
    def test_server_loads_expired_true(self, mock_api):
        api, mock = mock_api
        sl = _make_server_list([_make_logical("CH#1")])
        sl._loads_expiration_time = 0  # expired
        mock.vpn_session_loaded = True
        mock.server_list = sl
        assert api.server_loads_expired is True

    def test_server_loads_expired_false(self, mock_api):
        api, mock = mock_api
        sl = _make_server_list([_make_logical("CH#1")])
        sl._loads_expiration_time = time.time() + 3600  # far future
        mock.vpn_session_loaded = True
        mock.server_list = sl
        assert api.server_loads_expired is False

    def test_server_list_expired_true(self, mock_api):
        api, mock = mock_api
        sl = _make_server_list([_make_logical("CH#1")])
        sl._expiration_time = 0  # expired
        mock.vpn_session_loaded = True
        mock.server_list = sl
        assert api.server_list_expired is True

    def test_server_list_expired_false(self, mock_api):
        api, mock = mock_api
        sl = _make_server_list([_make_logical("CH#1")])
        sl._expiration_time = time.time() + 86400  # far future
        mock.vpn_session_loaded = True
        mock.server_list = sl
        assert api.server_list_expired is False

    def test_staleness_none_when_not_logged_in(self, mock_api):
        api, mock = mock_api
        mock.vpn_session_loaded = False
        assert api.server_loads_expired is False
        assert api.server_list_expired is False

    def test_refresh_server_loads_calls_session(self, mock_api):
        api, mock = mock_api
        mock_session = MagicMock()
        mock_session.update_server_loads = MagicMock(return_value=None)
        mock._session_holder.session = mock_session

        with patch("proton_vpn.api.sync_wrapper") as mock_sw:
            mock_sw.return_value = MagicMock()
            api.refresh_server_loads()
            mock_sw.assert_called_once_with(mock_session.update_server_loads)
            mock_sw.return_value.assert_called_once()

    def test_refresh_server_list_calls_session(self, mock_api):
        api, mock = mock_api
        mock_session = MagicMock()
        mock_session.fetch_server_list = MagicMock(return_value=None)
        mock._session_holder.session = mock_session

        with patch("proton_vpn.api.sync_wrapper") as mock_sw:
            mock_sw.return_value = MagicMock()
            api.refresh_server_list()
            mock_sw.assert_called_once_with(mock_session.fetch_server_list)
            mock_sw.return_value.assert_called_once()


class TestGetServerByName:
    def test_finds_server(self, mock_api):
        api, mock = mock_api
        logicals = [_make_logical("CH#10")]
        mock.vpn_session_loaded = True
        mock.server_list = _make_server_list(logicals)

        server = api.get_server_by_name("CH#10")
        assert server.name == "CH#10"

    def test_not_found_raises(self, mock_api):
        api, mock = mock_api
        logicals = [_make_logical("CH#1")]
        mock.vpn_session_loaded = True
        mock.server_list = _make_server_list(logicals)

        from proton.vpn.session.exceptions import ServerNotFoundError
        with pytest.raises(ServerNotFoundError):
            api.get_server_by_name("NONEXISTENT#99")


# ── Integration Tests ─────────────────────────────────────────────────────────

@pytest.mark.integration
class TestProtonAPIIntegration:
    """Integration tests using a live ProtonVPN session.

    These require an active ProtonVPN session (e.g. from the GTK app).
    Run with: pytest tests/test_proton_api.py -m integration
    """

    @pytest.fixture
    def live_api(self):
        api = ProtonAPI()
        if not api.is_logged_in:
            pytest.skip("No active ProtonVPN session found")
        if api.server_list is None:
            pytest.skip("Server list not available (cache may be corrupted)")
        return api

    def test_is_logged_in(self, live_api):
        assert live_api.is_logged_in is True

    def test_has_server_list(self, live_api):
        assert live_api.server_list is not None
        assert len(live_api.server_list) > 0

    def test_get_servers_returns_data(self, live_api):
        servers = live_api.get_servers()
        assert len(servers) > 100  # Should have thousands
        first = servers[0]
        assert "name" in first
        assert "country_code" in first
        assert "load" in first

    def test_get_servers_by_country(self, live_api):
        servers = live_api.get_servers(country="US")
        assert len(servers) > 10
        assert all(s["country_code"] == "US" for s in servers)

    def test_get_servers_by_feature(self, live_api):
        streaming = live_api.get_servers(feature="streaming")
        assert len(streaming) > 0
        assert all("streaming" in s["features"] for s in streaming)

    def test_get_countries(self, live_api):
        countries = live_api.get_countries()
        assert len(countries) > 50
        us = next((c for c in countries if c["code"] == "US"), None)
        assert us is not None
        assert us["server_count"] > 100

    def test_generate_wireguard_config(self, live_api):
        """Live test: reuses the same key across runs to avoid leaking
        new 'Unnamed' device registrations in the Proton account."""
        servers = live_api.get_servers(country="US")
        server = live_api.get_server_by_id(servers[0]["id"])

        # Use a fixed test key so repeated runs reuse the same device
        # (existing_wg_key skips cert registration — no new device created)
        _TEST_KEY = "dGVzdF9rZXlfZm9yX2xpdmVfaW50ZWdyYXRpb24xMjM="
        config, info, wg_key, cert_expiry = live_api.generate_wireguard_config(
            server, profile_name="LiveTest", existing_wg_key=_TEST_KEY,
        )

        assert "[Interface]" in config
        assert "PrivateKey" in config
        assert "[Peer]" in config
        assert "PublicKey" in config
        assert "Endpoint" in config
        assert "::" not in config  # No IPv6
        assert info["country_code"] == "US"
        assert wg_key == _TEST_KEY  # Same key returned
        assert cert_expiry == 0  # Existing key skips registration

    def test_user_tier(self, live_api):
        assert live_api.user_tier >= 2  # Plus or higher


class TestGenerateWireGuardConfigIPv6:
    """Tests for dual-stack IPv6 WireGuard config generation."""

    def test_ipv6_config_has_dual_stack_addresses(self, mock_api):
        api, mock = mock_api
        server = _make_logical("CH#1", features=16)  # 16 = IPV6
        _mock_persistent_cert_api(mock)

        config, info, wg_key, cert_expiry = api.generate_wireguard_config(
            server, ipv6=True
        )

        assert "Address = 10.2.0.2/32, 2a07:b944::2:2/128" in config
        assert "AllowedIPs = 0.0.0.0/0, ::/0" in config
        assert "2a07:b944::2:1" in config  # IPv6 DNS
        assert "10.2.0.1" in config  # IPv4 DNS still present

    def test_ipv6_false_produces_ipv4_only(self, mock_api):
        api, mock = mock_api
        server = _make_logical("CH#1", features=16)
        _mock_persistent_cert_api(mock)

        config, info, wg_key, cert_expiry = api.generate_wireguard_config(
            server, ipv6=False
        )

        assert "Address = 10.2.0.2/32" in config
        assert "::" not in config
        assert "AllowedIPs = 0.0.0.0/0" in config
        assert "::/0" not in config

    def test_custom_dns_with_ipv6_overrides_both(self, mock_api):
        api, mock = mock_api
        server = _make_logical("CH#1", features=16)
        _mock_persistent_cert_api(mock)

        config, info, wg_key, cert_expiry = api.generate_wireguard_config(
            server, ipv6=True, custom_dns="1.1.1.1"
        )

        assert "DNS = 1.1.1.1" in config
        assert "2a07:b944::2:1" not in config  # Custom DNS replaces both

    def test_ipv6_dns_accepted_as_custom(self, mock_api):
        api, mock = mock_api
        server = _make_logical("CH#1")
        _mock_persistent_cert_api(mock)

        config, info, wg_key, cert_expiry = api.generate_wireguard_config(
            server, custom_dns="2001:4860:4860::8888"
        )
        assert "DNS = 2001:4860:4860::8888" in config

    def test_server_to_dict_includes_ipv6_flag(self, mock_api):
        api, mock = mock_api
        server = _make_logical("CH#1", features=16)  # IPV6
        _mock_persistent_cert_api(mock)

        _, info, _, _ = api.generate_wireguard_config(server)
        assert info["ipv6"] is True

    def test_server_to_dict_ipv6_false_when_no_feature(self, mock_api):
        api, mock = mock_api
        server = _make_logical("CH#1", features=0)
        _mock_persistent_cert_api(mock)

        _, info, _, _ = api.generate_wireguard_config(server)
        assert info["ipv6"] is False
