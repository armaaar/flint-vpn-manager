"""ProtonVPN API wrapper for FlintVPN Manager.

Thin wrapper around the official proton-vpn-api-core library.
Handles authentication (including 2FA/TOTP), server list queries,
and WireGuard config generation. All methods are synchronous
(using sync_wrapper internally) for use with Flask.

Usage:
    api = ProtonAPI()
    result = api.login("user@pm.me", "password")
    if result.twofa_required:
        result = api.submit_2fa("123456")
    servers = api.get_servers(country="GB", feature="streaming")
    config = api.generate_wireguard_config(servers[0])
"""

import re
import time
from typing import Optional

from proton.session.api import sync_wrapper
from proton.vpn.core.api import ProtonVPNAPI
from proton.vpn.core.session_holder import ClientTypeMetadata
from proton.vpn.session.dataclasses import LoginResult
from proton.vpn.session.servers.logicals import ServerList
from proton.vpn.session.servers.types import (
    LogicalServer,
    PhysicalServer,
    ServerFeatureEnum,
    TierEnum,
)
from proton.vpn.connection.constants import CA_CERT

# Feature name → enum mapping for user-facing filters
FEATURE_MAP = {
    "secure_core": ServerFeatureEnum.SECURE_CORE,
    "tor": ServerFeatureEnum.TOR,
    "p2p": ServerFeatureEnum.P2P,
    "streaming": ServerFeatureEnum.STREAMING,
    "ipv6": ServerFeatureEnum.IPV6,
}

# NetShield level → DNS suffix mapping
# These are encoded in the Proton certificate features, but for WireGuard
# configs we use the filtering DNS address directly.
NETSHIELD_DNS = {
    0: "10.2.0.1",         # Off — standard Proton DNS
    1: "10.2.0.1",         # Malware blocking (server-side via certificate)
    2: "10.2.0.1",         # Malware + ads blocking (server-side via certificate)
}

# Regex to match IPv6 lines in WireGuard configs
_IPV6_PATTERN = re.compile(r".*::.*")


class ProtonAPI:
    """Synchronous wrapper around ProtonVPN's official async API."""

    def __init__(self):
        metadata = ClientTypeMetadata(type="gui")
        self._api = ProtonVPNAPI(client_type_metadata=metadata)
        self._sync_login = sync_wrapper(self._api.login)
        self._sync_2fa = sync_wrapper(self._api.submit_2fa_code)
        self._sync_logout = sync_wrapper(self._api.logout)

    @property
    def is_logged_in(self) -> bool:
        return self._api.is_user_logged_in()

    @property
    def vpn_session_loaded(self) -> bool:
        return self._api.vpn_session_loaded

    @property
    def user_tier(self) -> int:
        return self._api.user_tier

    @property
    def account_name(self) -> str:
        return self._api.account_name

    def login(self, username: str, password: str) -> LoginResult:
        """Log in with username and password.

        Returns LoginResult with:
          - success=True → fully logged in, session data loaded
          - twofa_required=True → call submit_2fa() next
          - success=False, twofa_required=False → bad credentials
        """
        return self._sync_login(username, password)

    def submit_2fa(self, code: str) -> LoginResult:
        """Submit 2FA/TOTP code after login returned twofa_required=True."""
        return self._sync_2fa(code)

    def logout(self):
        """Log out and clear session."""
        self._sync_logout()

    @property
    def server_list(self) -> Optional[ServerList]:
        """The current server list, or None if not logged in."""
        if not self.vpn_session_loaded:
            return None
        return self._api.server_list

    def get_servers(
        self,
        country: Optional[str] = None,
        city: Optional[str] = None,
        feature: Optional[str] = None,
        available_only: bool = True,
    ) -> list[dict]:
        """Get filtered server list as dicts for JSON serialization.

        Args:
            country: 2-letter country code (e.g. "GB", "US")
            city: City name (e.g. "London", "New York")
            feature: Feature filter: "streaming", "p2p", "secure_core", "tor"
            available_only: Only return enabled servers the user can access

        Returns:
            List of server dicts with: id, name, country, country_code, city,
            load, score, features, enabled, entry_country, exit_ip
        """
        sl = self.server_list
        if sl is None:
            raise RuntimeError("Not logged in or session data not loaded.")

        servers = sl.logicals

        if available_only:
            servers = ServerList.get_available_servers(servers, sl.user_tier)

        if feature and feature in FEATURE_MAP:
            servers = ServerList.get_servers_with_features(
                servers, request_features=FEATURE_MAP[feature]
            )

        if country:
            servers = ServerList.get_servers_in_country_code(servers, country)

        if city:
            servers = ServerList.get_servers_in_city(servers, city)

        return [self._server_to_dict(s) for s in servers]

    def get_server_by_id(self, server_id: str) -> LogicalServer:
        """Get a specific server by its ID."""
        sl = self.server_list
        if sl is None:
            raise RuntimeError("Not logged in or session data not loaded.")
        return sl.get_by_id(server_id)

    def get_server_by_name(self, name: str) -> LogicalServer:
        """Get a specific server by name (e.g. 'CH#10')."""
        sl = self.server_list
        if sl is None:
            raise RuntimeError("Not logged in or session data not loaded.")
        return sl.get_by_name(name)

    def get_countries(self) -> list[dict]:
        """Get all countries with server counts, grouped and sorted."""
        sl = self.server_list
        if sl is None:
            raise RuntimeError("Not logged in or session data not loaded.")

        countries = sl.group_by_country(cities=True)
        return [
            {
                "code": c.code.upper(),
                "name": c.name,
                "server_count": len(c.servers),
                "free": c.free,
                "features": [f.name.lower() for f in c.features],
                "cities": [
                    {
                        "name": city.name,
                        "server_count": len(city.servers),
                    }
                    for city in c.cities
                ],
            }
            for c in countries
        ]

    def generate_wireguard_config(
        self,
        server: LogicalServer,
        netshield: int = 0,
        moderate_nat: bool = False,
        nat_pmp: bool = False,
        vpn_accelerator: bool = True,
    ) -> tuple[str, dict]:
        """Generate a WireGuard .conf for a server, stripping IPv6.

        Args:
            server: LogicalServer to connect to
            netshield: 0=off, 1=malware, 2=malware+ads
            moderate_nat: Enable moderate NAT (gaming)
            nat_pmp: Enable NAT-PMP port forwarding
            vpn_accelerator: Enable VPN Accelerator

        Returns:
            Tuple of (config_string, server_info_dict).
            config_string is a valid WireGuard .conf with no IPv6 lines.
            server_info_dict contains the server details for storage.
        """
        account = self._api.account_data
        creds = account.vpn_credentials.pubkey_credentials
        physical = server.get_random_physical_server()

        # Build feature suffix for server name (used in Proton's X-PM-netzone header)
        # These are baked into the certificate, not the WireGuard config itself.
        # The DNS address determines NetShield level.
        dns = NETSHIELD_DNS.get(netshield, "10.2.0.1")

        config_lines = [
            "[Interface]",
            f"PrivateKey = {creds.wg_private_key}",
            "Address = 10.2.0.2/32",
            f"DNS = {dns}",
            "",
            "[Peer]",
            f"PublicKey = {physical.x25519_pk}",
            "AllowedIPs = 0.0.0.0/0",
            f"Endpoint = {physical.entry_ip}:51820",
        ]

        config = "\n".join(config_lines) + "\n"

        server_info = self._server_to_dict(server)
        server_info["physical_server_domain"] = physical.domain
        server_info["endpoint"] = f"{physical.entry_ip}:51820"

        return config, server_info

    def get_openvpn_credentials(self) -> tuple[str, str]:
        """Get ProtonVPN OpenVPN username and password.

        These are special VPN credentials, different from the Proton account login.
        """
        account = self._api.account_data
        creds = account.vpn_credentials.userpass_credentials
        return creds.username, creds.password

    def generate_openvpn_config(
        self,
        server: LogicalServer,
        protocol: str = "udp",
        netshield: int = 0,
    ) -> tuple[str, dict]:
        """Generate an OpenVPN .ovpn config for a server.

        Uses the current ProtonVPN CA certificate from the official SDK and
        tls-crypt (not tls-auth) with the correct static key. Auth is via
        username/password since the GL.iNet router's OpenVPN client expects it.

        Args:
            server: LogicalServer to connect to
            protocol: "udp" or "tcp"
            netshield: 0=off, 1=malware, 2=malware+ads (encoded in username suffix)

        Returns:
            Tuple of (config_string, server_info_dict, username, password).
        """
        physical = server.get_random_physical_server()
        username, password = self.get_openvpn_credentials()

        # ProtonVPN encodes NetShield and other features in the username suffix
        # +f1 = NetShield malware, +f2 = NetShield malware+ads
        suffix = ""
        if netshield == 1:
            suffix += "+f1"
        elif netshield == 2:
            suffix += "+f2"

        ovpn_username = username + suffix

        # Port selection based on protocol
        if protocol == "tcp":
            port = 443
            proto = "tcp"
        else:
            port = 1194
            proto = "udp"

        # CA cert from the official ProtonVPN SDK (2019, valid until 2039)
        ca_cert = CA_CERT.strip()

        # Build .ovpn config matching official ProtonVPN v2 template
        # but with username/password auth for GL.iNet router compatibility
        config = f"""client
dev tun
proto {proto}

remote {physical.entry_ip} {port}

remote-random
resolv-retry infinite
nobind
cipher AES-256-GCM
verb 3

tun-mtu 1500
mssfix 0
persist-key
persist-tun

reneg-sec 0

remote-cert-tls server

auth-user-pass /etc/openvpn/profiles/{{CLIENT_ID}}/auth/username_password.txt

<ca>
{ca_cert}
</ca>

<tls-crypt>
-----BEGIN OpenVPN Static key V1-----
6acef03f62675b4b1bbd03e53b187727
423cea742242106cb2916a8a4c829756
3d22c7e5cef430b1103c6f66eb1fc5b3
75a672f158e2e2e936c3faa48b035a6d
e17beaac23b5f03b10b868d53d03521d
8ba115059da777a60cbfd7b2c9c57472
78a15b8f6e68a3ef7fd583ec9f398c8b
d4735dab40cbd1e3c62a822e97489186
c30a0b48c7c38ea32ceb056d3fa5a710
e10ccc7a0ddb363b08c3d2777a3395e1
0c0b6080f56309192ab5aacd4b45f55d
a61fc77af39bd81a19218a79762c3386
2df55785075f37d8c71dc8a42097ee43
344739a0dd48d03025b0450cf1fb5e8c
aeb893d9a96d1f15519bb3c4dcb40ee3
16672ea16c012664f8a9f11255518deb
-----END OpenVPN Static key V1-----
</tls-crypt>
"""

        server_info = self._server_to_dict(server)
        server_info["physical_server_domain"] = physical.domain
        server_info["endpoint"] = f"{physical.entry_ip}:{port}"
        server_info["protocol"] = "openvpn-" + protocol

        return config, server_info, ovpn_username, password

    def server_to_dict(self, server: LogicalServer) -> dict:
        """Public wrapper around _server_to_dict for callers that resolve
        a LogicalServer to a JSON-serializable dict on demand (Stage 7)."""
        return self._server_to_dict(server)

    def _server_to_dict(self, server: LogicalServer) -> dict:
        """Convert a LogicalServer to a JSON-serializable dict."""
        return {
            "id": server.id,
            "name": server.name,
            "country": server.exit_country_name,
            "country_code": server.exit_country.upper(),
            "entry_country_code": server.entry_country.upper(),
            "city": server.city or "",
            "load": server.load,
            "score": server.score,
            "features": [f.name.lower() for f in server.features],
            "enabled": server.enabled,
            "tier": int(server.tier),
            "secure_core": ServerFeatureEnum.SECURE_CORE in server.features,
            "streaming": ServerFeatureEnum.STREAMING in server.features,
            "p2p": ServerFeatureEnum.P2P in server.features,
        }
