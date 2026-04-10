"""ProtonVPN API wrapper for FlintVPN Manager.

Thin wrapper around the official proton-vpn-api-core library.
Handles authentication (including 2FA/TOTP), server list queries,
and WireGuard/OpenVPN config generation. All methods are synchronous
(using sync_wrapper internally) for use with Flask.

WireGuard configs use **persistent-mode certificates** (365-day validity,
no local agent required). Each VPN profile gets its own Ed25519 key pair,
registered with Proton as a named "device". The router is fully standalone
after config upload — no Surface Go dependency for ongoing VPN operation.

Usage:
    api = ProtonAPI()
    result = api.login("user@pm.me", "password")
    if result.twofa_required:
        result = api.submit_2fa("123456")
    servers = api.get_servers(country="GB", feature="streaming")
    config, info, key, expiry = api.generate_wireguard_config(servers[0], "MyProfile", opts)
"""

import base64
import logging
import re
import time
from typing import Optional

from proton.session.api import sync_wrapper
from proton.vpn.core.api import ProtonVPNAPI
from proton.vpn.core.session_holder import ClientTypeMetadata
from proton.vpn.session.dataclasses import LoginResult
from proton.vpn.session.key_mgr import KeyHandler
from proton.vpn.session.servers.logicals import ServerList
from proton.vpn.session.servers.types import (
    LogicalServer,
    PhysicalServer,
    ServerFeatureEnum,
    TierEnum,
)
from proton.vpn.connection.constants import CA_CERT

log = logging.getLogger("flintvpn")

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

    def set_alternative_routing(self, enabled: bool):
        """Enable or disable alternative routing (DoH-based transport fallback).

        When enabled (default), API calls automatically fall back to
        DNS-over-HTTPS routing through third-party infrastructure when
        Proton's servers are directly unreachable. Useful in censored networks.
        """
        try:
            session = self._api._session_holder.session
            if hasattr(session, '_transport'):
                transport = session._transport
                if hasattr(transport, 'transport_choices'):
                    from proton.session.transports.aiohttp import AiohttpTransport
                    from proton.session.transports.alternativerouting import AlternativeRoutingTransport
                    if enabled:
                        transport.transport_choices = [
                            (0, AiohttpTransport),
                            (5, AlternativeRoutingTransport),
                        ]
                    else:
                        transport.transport_choices = [
                            (0, AiohttpTransport),
                        ]
                    log.info(f"Alternative routing {'enabled' if enabled else 'disabled'}")
        except Exception as e:
            log.warning(f"Failed to set alternative routing: {e}")

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

    @property
    def server_list_expired(self) -> bool:
        """True if the full server list needs re-downloading (>3h old)."""
        sl = self.server_list
        return sl is not None and sl.expired

    @property
    def server_loads_expired(self) -> bool:
        """True if server loads/scores need refreshing (>15min old)."""
        sl = self.server_list
        return sl is not None and sl.loads_expired

    def refresh_server_list(self):
        """Full server list refresh (~3h interval). Network call to Proton API."""
        session = self._api._session_holder.session
        sync_wrapper(session.fetch_server_list)()
        log.info("Server list refreshed (full)")

    def refresh_server_loads(self):
        """Lightweight server loads/scores refresh (~15min interval)."""
        session = self._api._session_holder.session
        sync_wrapper(session.update_server_loads)()
        log.info("Server loads refreshed")

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

        countries = sl.group_by_country(group_by_city=True)
        return [
            {
                "code": c.code.upper(),
                "name": c.name,
                "server_count": len(c.servers),
                "free": c.free,
                "features": [f.name.lower() for f in c.features],
                "cities": [
                    {
                        "name": loc.name,
                        "server_count": len(loc.servers),
                    }
                    for loc in c.locations
                ],
            }
            for c in countries
        ]

    # ── Persistent WireGuard certificates ─────────────────────────────────
    #
    # Each VPN profile gets its own Ed25519 key pair, registered with Proton
    # as a persistent "device" (365-day cert). The X25519 WG key is derived
    # deterministically from the Ed25519 key. No local agent required —
    # features are baked into the certificate at generation time.
    #
    # The old session-mode path (7-day cert + local agent) is not used.

    PERSISTENT_CERT_DURATION_MIN = 525600  # 365 days

    # WireGuard port by transport mode
    WG_PORTS = {"udp": 51820, "tcp": 443, "tls": 443}

    # Available alternate ports per protocol (from Proton's /vpn/v2/clientconfig)
    AVAILABLE_PORTS = {
        "wireguard": {"udp": [443, 88, 1224, 51820, 500, 4500]},
        "wireguard-tcp": {"tcp": [443], "tls": [443]},
        "openvpn": {"udp": [80, 51820, 4569, 1194, 5060], "tcp": [443, 7770, 8443]},
    }

    def generate_wireguard_config(
        self,
        server: LogicalServer,
        profile_name: str = "Unnamed",
        netshield: int = 0,
        moderate_nat: bool = False,
        nat_pmp: bool = False,
        vpn_accelerator: bool = True,
        existing_wg_key: Optional[str] = None,
        transport: str = "udp",
        port: Optional[int] = None,
        custom_dns: Optional[str] = None,
    ) -> tuple[str, dict, str, int]:
        """Generate a WireGuard .conf with a persistent (365-day) certificate.

        Each call with a new key registers a named "device" in the user's
        Proton account. Reusing an existing key (via `existing_wg_key`)
        skips re-registration (the cert is per-key, not per-server).

        Args:
            server: LogicalServer to connect to.
            profile_name: Human-readable name shown in Proton's device list.
            netshield: 0=off, 1=malware, 2=malware+ads.
            moderate_nat: Enable moderate NAT (gaming).
            nat_pmp: Enable NAT-PMP port forwarding.
            vpn_accelerator: Enable VPN Accelerator.
            existing_wg_key: Base64 Ed25519 private key from a previous call.
                If provided, reuses the same key pair (no cert registration).
                If None, generates a fresh key pair and registers.
            transport: "udp" (kernel WG), "tcp", or "tls" (proton-wg).

        Returns:
            Tuple of (config_string, server_info_dict, wg_key_b64, cert_expiry).
            - config_string: valid WireGuard .conf.
            - server_info_dict: server details for storage.
            - wg_key_b64: Ed25519 private key (base64) to persist in profile_store.
            - cert_expiry: Unix timestamp when the persistent cert expires (0 if unchanged).
        """
        # 1. Key pair: reuse existing or generate fresh
        if existing_wg_key:
            kh = KeyHandler(base64.b64decode(existing_wg_key))
            cert_expiry = 0  # Caller keeps existing cert_expiry
        else:
            kh = KeyHandler()
            cert_expiry = self._register_persistent_cert(
                kh, profile_name,
                netshield=netshield,
                moderate_nat=moderate_nat,
                nat_pmp=nat_pmp,
                vpn_accelerator=vpn_accelerator,
            )

        # 2. Build the WireGuard config
        physical = server.get_random_physical_server()
        if custom_dns:
            # Validate DNS: must be a single valid IPv4 address.
            # UCI stores DNS as a single string value — comma-separated
            # would break the GL.iNet vpn-client's DNS resolution.
            import ipaddress as _ipaddress
            custom_dns = custom_dns.strip()
            try:
                _ipaddress.IPv4Address(custom_dns)
            except ValueError:
                raise ValueError(f"Invalid DNS address: {custom_dns!r}")
            dns = custom_dns
        else:
            dns = NETSHIELD_DNS.get(netshield, "10.2.0.1")
        if port is None:
            port = self.WG_PORTS.get(transport, 51820)

        config_lines = [
            "[Interface]",
            f"PrivateKey = {kh.x25519_sk_str}",
            "Address = 10.2.0.2/32",
            f"DNS = {dns}",
            "",
            "[Peer]",
            f"PublicKey = {physical.x25519_pk}",
            "AllowedIPs = 0.0.0.0/0",
            f"Endpoint = {physical.entry_ip}:{port}",
        ]

        config = "\n".join(config_lines) + "\n"

        server_info = self._server_to_dict(server)
        server_info["physical_server_domain"] = physical.domain
        server_info["endpoint"] = f"{physical.entry_ip}:{port}"

        return config, server_info, kh.ed25519_sk_str, cert_expiry

    def refresh_wireguard_cert(
        self,
        wg_key_b64: str,
        profile_name: str = "Unnamed",
        netshield: int = 0,
        moderate_nat: bool = False,
        nat_pmp: bool = False,
        vpn_accelerator: bool = True,
    ) -> int:
        """Refresh a persistent WireGuard certificate without changing the key.

        Call this when the cert is approaching expiry, or when VPN options
        change (features are baked into the cert at generation time).

        Args:
            wg_key_b64: Base64 Ed25519 private key from the profile.
            profile_name: Device name in Proton's dashboard.
            netshield, moderate_nat, nat_pmp, vpn_accelerator: Feature flags.

        Returns:
            New cert_expiry Unix timestamp.
        """
        kh = KeyHandler(base64.b64decode(wg_key_b64))
        return self._register_persistent_cert(
            kh, profile_name,
            netshield=netshield,
            moderate_nat=moderate_nat,
            nat_pmp=nat_pmp,
            vpn_accelerator=vpn_accelerator,
        )

    def get_wireguard_x25519_key(self, wg_key_b64: str) -> str:
        """Derive the X25519 WireGuard private key from a stored Ed25519 key.

        Used when switching servers (same key, new peer) to rebuild the
        WG config without re-registering the certificate.
        """
        kh = KeyHandler(base64.b64decode(wg_key_b64))
        return kh.x25519_sk_str

    def _register_persistent_cert(
        self,
        kh: KeyHandler,
        profile_name: str,
        netshield: int = 0,
        moderate_nat: bool = False,
        nat_pmp: bool = False,
        vpn_accelerator: bool = True,
    ) -> int:
        """Register or refresh a persistent certificate with Proton's API.

        Returns the cert expiry as a Unix timestamp.
        """
        features = {}
        if netshield:
            features["NetShieldLevel"] = netshield
        if moderate_nat:
            features["RandomNAT"] = False  # Proton inverts: moderate_nat = NOT random
        if not vpn_accelerator:
            features["SplitTCP"] = False
        if nat_pmp:
            features["PortForwarding"] = True

        req = {
            "ClientPublicKey": kh.ed25519_pk_pem,
            "ClientPublicKeyMode": "EC",
            "Mode": "persistent",
            "DeviceName": profile_name if profile_name.startswith("FlintVPN") else f"FlintVPN-{profile_name}",
            "Duration": f"{self.PERSISTENT_CERT_DURATION_MIN} min",
        }
        if features:
            req["Features"] = features

        session = self._api._session_holder.session
        resp = session.api_request("/vpn/v1/certificate", jsondata=req)

        cert_expiry = resp.get("ExpirationTime", 0)
        log.info(
            f"Persistent cert registered: device='{profile_name}', "
            f"expires in {(cert_expiry - time.time()) / 86400:.0f} days"
        )
        return cert_expiry

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
        moderate_nat: bool = False,
        nat_pmp: bool = False,
        vpn_accelerator: bool = True,
        port: Optional[int] = None,
    ) -> tuple[str, dict]:
        """Generate an OpenVPN .ovpn config for a server.

        Uses the current ProtonVPN CA certificate from the official SDK and
        tls-crypt (not tls-auth) with the correct static key. Auth is via
        username/password since the GL.iNet router's OpenVPN client expects it.

        Args:
            server: LogicalServer to connect to
            protocol: "udp" or "tcp"
            netshield: 0=off, 1=malware, 2=malware+ads (encoded in username suffix)
            moderate_nat: Enable moderate NAT (gaming)
            nat_pmp: Enable NAT-PMP port forwarding
            vpn_accelerator: Enable VPN Accelerator (split TCP)

        Returns:
            Tuple of (config_string, server_info_dict, username, password).
        """
        physical = server.get_random_physical_server()
        username, password = self.get_openvpn_credentials()

        # ProtonVPN encodes features in the username suffix (same as official client).
        # Suffixes: +f{level} NetShield, +nr moderate NAT, +pmp port forwarding,
        # +nst disable VPN Accelerator (split TCP).
        suffix = ""
        if netshield:
            suffix += f"+f{netshield}"
        if moderate_nat:
            suffix += "+nr"
        if nat_pmp:
            suffix += "+pmp"
        if not vpn_accelerator:
            suffix += "+nst"

        ovpn_username = username + suffix

        # Port selection based on protocol
        if protocol == "tcp":
            proto = "tcp"
            if port is None:
                port = 443
        else:
            proto = "udp"
            if port is None:
                port = 1194

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

    def get_server_entry_ips(self, server_ids: list[str]) -> list[dict]:
        """Resolve server IDs to entry IPs for latency probing.

        Returns:
            List of {id, entry_ip} dicts. Skips IDs not found in the server list.
        """
        sl = self.server_list
        if sl is None:
            return []
        result = []
        for sid in server_ids:
            try:
                server = sl.get_by_id(sid)
                physical = server.get_random_physical_server()
                result.append({"id": sid, "entry_ip": physical.entry_ip})
            except Exception:
                continue
        return result

    def get_location(self) -> dict:
        """Get the current physical location as seen by ProtonVPN.

        Calls ``GET /vpn/v1/location`` which returns the exit IP, country,
        and ISP as seen from Proton's servers.

        Returns:
            Dict with keys: ip, country, isp, lat, lon.
        """
        session = self._api._session_holder.session
        resp = session.api_request("/vpn/v1/location")
        return {
            "ip": resp.get("IP", ""),
            "country": resp.get("Country", ""),
            "isp": resp.get("ISP", ""),
            "lat": resp.get("Lat"),
            "lon": resp.get("Long"),
        }

    def get_sessions(self) -> list:
        """Get the list of active VPN sessions.

        Calls ``GET /vpn/v1/sessions`` which returns all currently connected
        VPN sessions for the user's account.

        Returns:
            List of dicts with keys: session_id, exit_ip, protocol.
        """
        session = self._api._session_holder.session
        resp = session.api_request("/vpn/v1/sessions")
        sessions_raw = resp.get("Sessions", [])
        return [
            {
                "session_id": s.get("SessionID", ""),
                "exit_ip": s.get("ExitIP", ""),
                "protocol": s.get("Protocol", ""),
            }
            for s in sessions_raw
        ]

    def get_available_ports(self) -> dict:
        """Return the available ports per protocol for the port selection UI."""
        return dict(self.AVAILABLE_PORTS)

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
            "tor": ServerFeatureEnum.TOR in server.features,
        }
