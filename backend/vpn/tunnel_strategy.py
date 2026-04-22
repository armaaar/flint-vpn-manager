"""Tunnel Strategy — Strategy Pattern for VPN protocol handling.

Abstracts the protocol-specific operations (create, delete, connect,
disconnect, switch_server, get_health) behind a common interface so
callers don't need if/elif chains on vpn_protocol.

Three concrete strategies:
  - WireGuardStrategy:   kernel WireGuard UDP via vpn-client
  - OpenVPNStrategy:     OpenVPN via vpn-client
  - ProtonWGStrategy:    userspace WireGuard TCP/TLS via proton-wg binary
"""

import logging
from abc import ABC, abstractmethod

from consts import (
    HEALTH_RED,
    PROTO_OPENVPN,
    PROTO_WIREGUARD,
    PROTO_WIREGUARD_TCP,
    PROTO_WIREGUARD_TLS,
)

try:
    from proton.vpn.session.servers.types import ServerFeatureEnum
except ImportError:
    ServerFeatureEnum = None

log = logging.getLogger("flintvpn")


def _server_has_ipv6(server) -> bool:
    """Return True if the Proton server supports IPv6 inside the tunnel."""
    if ServerFeatureEnum is None:
        return False
    try:
        return ServerFeatureEnum.IPV6 in server.features
    except Exception:
        return False


# ── Helpers ──────────────────────────────────────────────────────────────────


def _parse_wg_config(config_str: str) -> dict:
    """Extract key fields from a WireGuard config string.

    Parses PrivateKey, PublicKey, Endpoint, and DNS from a standard
    WireGuard .conf format. Falls back to ``10.2.0.1`` for DNS if the
    field is missing.

    Returns:
        Dict with keys: private_key, public_key, endpoint, dns.
    """
    result = {"private_key": "", "public_key": "", "endpoint": "", "dns": "10.2.0.1"}
    for line in config_str.strip().splitlines():
        line = line.strip()
        if line.startswith("PrivateKey"):
            result["private_key"] = line.split("=", 1)[1].strip()
        elif line.startswith("PublicKey"):
            result["public_key"] = line.split("=", 1)[1].strip()
        elif line.startswith("Endpoint"):
            result["endpoint"] = line.split("=", 1)[1].strip()
        elif line.startswith("DNS"):
            result["dns"] = line.split("=", 1)[1].strip()
    return result


# ── ABC ──────────────────────────────────────────────────────────────────────


class TunnelStrategy(ABC):
    """Abstract base for VPN tunnel lifecycle operations.

    Each concrete strategy encapsulates the protocol-specific details of
    creating, deleting, connecting, disconnecting, switching servers, and
    reading health for one kind of VPN tunnel.
    """

    @abstractmethod
    def create(self, router, proton, profile_name, server, options, transport="udp"):
        """Generate a VPN config via Proton and upload it to the router.

        Args:
            router: RouterAPI instance.
            proton: ProtonAPI instance (must be logged in).
            profile_name: Human-readable name for the tunnel.
            server: Proton LogicalServer object.
            options: Dict with keys netshield, moderate_nat, nat_pmp,
                     vpn_accelerator.
            transport: Transport hint (``"udp"``, ``"tcp"``, ``"tls"``).

        Returns:
            Tuple of (router_info, server_info, wg_key_or_None,
            cert_expiry_or_None).
        """

    @abstractmethod
    def delete(self, router, router_info):
        """Tear down the tunnel and clean up all router-side resources.

        Args:
            router: RouterAPI instance.
            router_info: The ``router_info`` dict stored in the profile.
        """

    @abstractmethod
    def connect(self, router, router_info):
        """Bring the tunnel up and return its health.

        Args:
            router: RouterAPI instance.
            router_info: The ``router_info`` dict stored in the profile.

        Returns:
            Health string (green, amber, red, connecting).
        """

    @abstractmethod
    def disconnect(self, router, router_info):
        """Bring the tunnel down.

        Args:
            router: RouterAPI instance.
            router_info: The ``router_info`` dict stored in the profile.
        """

    @abstractmethod
    def switch_server(self, router, proton, profile, server, options, old_router_info):
        """Switch the tunnel to a different Proton server.

        The exact mechanism is protocol-dependent: WireGuard can hot-swap
        peers in place, while OpenVPN must delete and recreate.

        Args:
            router: RouterAPI instance.
            proton: ProtonAPI instance.
            profile: Full profile dict (includes wg_key, name, etc.).
            server: New Proton LogicalServer object.
            options: Dict with keys netshield, moderate_nat, nat_pmp,
                     vpn_accelerator.
            old_router_info: The current ``router_info`` dict.

        Returns:
            Tuple of (new_router_info_or_None, server_info,
            wg_key_or_None, cert_expiry_or_None).  ``None`` for
            router_info means it did not change (in-place update).
        """

    @abstractmethod
    def get_health(self, router, router_info):
        """Read the live tunnel health from the router.

        Args:
            router: RouterAPI instance.
            router_info: The ``router_info`` dict stored in the profile.

        Returns:
            Health string (green, amber, red, connecting).
        """


# ── WireGuard (kernel UDP) ───────────────────────────────────────────────────


class WireGuardStrategy(TunnelStrategy):
    """Kernel WireGuard UDP tunnel managed by the GL.iNet vpn-client service."""

    def create(self, router, proton, profile_name, server, options, transport="udp"):
        """Generate a WireGuard config and upload the peer + route policy rule.

        Calls ``proton.generate_wireguard_config`` to get a persistent-mode
        certificate, parses the resulting .conf, and uploads via
        ``router.upload_wireguard_config``.

        Returns:
            (router_info, server_info, wg_key, cert_expiry)
        """
        ipv6 = _server_has_ipv6(server)
        config_str, server_info, wg_key, cert_expiry = proton.generate_wireguard_config(
            server,
            profile_name=profile_name,
            netshield=options.get("netshield", 0),
            moderate_nat=options.get("moderate_nat", False),
            nat_pmp=options.get("nat_pmp", False),
            vpn_accelerator=options.get("vpn_accelerator", True),
            transport="udp",
            port=options.get("port"),
            custom_dns=options.get("custom_dns"),
            ipv6=ipv6,
        )
        wg = _parse_wg_config(config_str)
        router_info = router.wireguard.upload_wireguard_config(
            profile_name=profile_name,
            private_key=wg["private_key"],
            public_key=wg["public_key"],
            endpoint=wg["endpoint"],
            dns=wg["dns"],
            ipv6=ipv6,
        )
        return router_info, server_info, wg_key, cert_expiry

    def delete(self, router, router_info):
        """Delete the WireGuard peer and route policy rule from the router."""
        router.wireguard.delete_wireguard_config(
            router_info["peer_id"],
            router_info["rule_name"],
        )

    def connect(self, router, router_info):
        """Enable the route policy rule and let vpn-client bring the tunnel up.

        Returns:
            Live tunnel health string.
        """
        router.tunnel.bring_tunnel_up(router_info["rule_name"])
        return router.tunnel.get_tunnel_health(router_info["rule_name"])

    def disconnect(self, router, router_info):
        """Disable the route policy rule and let vpn-client tear the tunnel down."""
        router.tunnel.bring_tunnel_down(router_info["rule_name"])

    def switch_server(self, router, proton, profile, server, options, old_router_info):
        """WireGuard fast path: in-place UCI update + live ``wg set`` peer swap.

        Reuses the profile's existing persistent Ed25519 key so no new
        certificate registration is needed. The route policy rule, peer_id,
        device assignments, and section position all remain unchanged.

        Returns:
            (None, server_info, wg_key, cert_expiry) -- ``None`` because
            router_info does not change.
        """
        ipv6 = _server_has_ipv6(server)
        existing_wg_key = profile.get("wg_key")
        config_str, server_info, wg_key, cert_expiry = proton.generate_wireguard_config(
            server,
            profile_name=profile.get("name", "Unnamed"),
            netshield=options.get("netshield", 0),
            moderate_nat=options.get("moderate_nat", False),
            nat_pmp=options.get("nat_pmp", False),
            vpn_accelerator=options.get("vpn_accelerator", True),
            existing_wg_key=existing_wg_key,
            transport="udp",
            port=options.get("port"),
            custom_dns=options.get("custom_dns"),
            ipv6=ipv6,
        )
        wg = _parse_wg_config(config_str)

        peer_id = old_router_info.get("peer_id", "")
        rule_name = old_router_info["rule_name"]
        if not peer_id:
            raise ValueError("WireGuard profile missing peer_id")

        router.wireguard.update_wireguard_peer_live(
            peer_id=peer_id,
            rule_name=rule_name,
            private_key=wg["private_key"],
            public_key=wg["public_key"],
            endpoint=wg["endpoint"],
            dns=wg["dns"] or "10.2.0.1",
        )
        return None, server_info, wg_key, cert_expiry

    def get_health(self, router, router_info):
        """Read tunnel health from the vpn-client managed interface.

        Returns:
            Health string (green, amber, red, connecting).
        """
        return router.tunnel.get_tunnel_health(router_info["rule_name"])


# ── OpenVPN ──────────────────────────────────────────────────────────────────


class OpenVPNStrategy(TunnelStrategy):
    """OpenVPN tunnel managed by the GL.iNet vpn-client service."""

    def create(self, router, proton, profile_name, server, options, transport="udp"):
        """Generate an OpenVPN config and upload the client + route policy rule.

        Calls ``proton.generate_openvpn_config`` then
        ``router.upload_openvpn_config``.

        Args:
            transport: Ignored for OpenVPN (protocol comes from options).

        Returns:
            (router_info, server_info, None, None)
        """
        ovpn_proto = options.get("ovpn_protocol", transport)
        config_str, server_info, ovpn_user, ovpn_pass = proton.generate_openvpn_config(
            server,
            protocol=ovpn_proto,
            netshield=options.get("netshield", 0),
            moderate_nat=options.get("moderate_nat", False),
            nat_pmp=options.get("nat_pmp", False),
            vpn_accelerator=options.get("vpn_accelerator", True),
            port=options.get("port"),
        )
        router_info = router.openvpn.upload_openvpn_config(
            profile_name=profile_name,
            ovpn_config=config_str,
            username=ovpn_user,
            password=ovpn_pass,
        )
        return router_info, server_info, None, None

    def delete(self, router, router_info):
        """Delete the OpenVPN client config and route policy rule."""
        router.openvpn.delete_openvpn_config(
            router_info["client_uci_id"],
            router_info["rule_name"],
        )

    def connect(self, router, router_info):
        """Enable the route policy rule and let vpn-client start OpenVPN.

        Returns:
            Live tunnel health string.
        """
        router.tunnel.bring_tunnel_up(router_info["rule_name"])
        return router.tunnel.get_tunnel_health(router_info["rule_name"])

    def disconnect(self, router, router_info):
        """Disable the route policy rule and let vpn-client stop OpenVPN."""
        router.tunnel.bring_tunnel_down(router_info["rule_name"])

    def switch_server(self, router, proton, profile, server, options, old_router_info):
        """OpenVPN delete-and-recreate path (brief flicker).

        OpenVPN does not support hot config reload, so the old client +
        route policy rule must be torn down and a new one created. Section
        position, device assignments, and enabled state are captured before
        deletion and restored afterwards.

        Returns:
            (new_router_info, server_info, None, None)
        """
        rule_name = old_router_info["rule_name"]
        client_uci_id = old_router_info.get("client_uci_id", "")
        if not client_uci_id:
            raise ValueError("OpenVPN profile missing client_uci_id")

        # 1. Capture devices currently assigned (router-canonical via from_mac).
        old_assigned_macs = []
        try:
            old_assigned_macs = [
                t.lower() for t in router.policy.from_mac_tokens(rule_name)
            ]
        except Exception as exc:
            log.warning("switch_server(ovpn): failed to read from_mac: %s", exc)

        # 2. Capture section order + enabled state for post-upload restoration.
        old_rule_index = None
        old_rule_order = []
        old_was_enabled = False
        try:
            existing_rules = router.policy.get_flint_vpn_rules()
            old_rule_order = [
                r.get("rule_name", "")
                for r in existing_rules
                if r.get("rule_name", "")
            ]
            if rule_name in old_rule_order:
                old_rule_index = old_rule_order.index(rule_name)
            for r in existing_rules:
                if r.get("rule_name") == rule_name:
                    old_was_enabled = r.get("enabled", "0") == "1"
                    break
        except Exception as exc:
            log.warning("switch_server(ovpn): failed to read rule order: %s", exc)

        # 3. Tear down old client + rule (flicker window).
        try:
            router.openvpn.delete_openvpn_config(client_uci_id, rule_name)
        except Exception as exc:
            log.warning("switch_server(ovpn): delete failed: %s", exc)

        # 4. Generate new config and upload.
        ovpn_proto = (
            "tcp"
            if profile.get("server", {}).get("protocol", "").endswith("tcp")
            else "udp"
        )
        config_str, server_info, ovpn_user, ovpn_pass = proton.generate_openvpn_config(
            server,
            protocol=ovpn_proto,
            netshield=options.get("netshield", 0),
            moderate_nat=options.get("moderate_nat", False),
            nat_pmp=options.get("nat_pmp", False),
            vpn_accelerator=options.get("vpn_accelerator", True),
            port=options.get("port"),
        )
        new_ri = router.openvpn.upload_openvpn_config(
            profile_name=profile["name"],
            ovpn_config=config_str,
            username=ovpn_user,
            password=ovpn_pass,
        )

        # 5. Restore section position so dashboard order is preserved.
        if old_rule_index is not None and new_ri.get("rule_name"):
            try:
                new_order = [r for r in old_rule_order if r != rule_name]
                new_order.insert(old_rule_index, new_ri["rule_name"])
                router.policy.reorder_vpn_rules(new_order)
            except Exception as exc:
                log.warning("switch_server(ovpn): reorder failed: %s", exc)

        # 6. Re-attach devices to the new rule.
        for mac in old_assigned_macs:
            try:
                router.devices.set_device_vpn(mac, new_ri["rule_name"])
            except Exception as exc:
                log.warning("switch_server(ovpn): reassign %s failed: %s", mac, exc)

        # 7. Only bring the new tunnel up if the old one was running.
        if old_was_enabled:
            router.tunnel.bring_tunnel_up(new_ri["rule_name"])

        return new_ri, server_info, None, None

    def get_health(self, router, router_info):
        """Read tunnel health from the vpn-client managed interface.

        Returns:
            Health string (green, amber, red, connecting).
        """
        return router.tunnel.get_tunnel_health(router_info["rule_name"])


# ── ProtonWG (userspace WireGuard TCP/TLS) ───────────────────────────────────


class ProtonWGStrategy(TunnelStrategy):
    """Userspace WireGuard TCP/TLS tunnel via the proton-wg binary.

    Managed entirely by Flint VPN Manager outside vpn-client. Supports both TCP
    and TLS transports (set at construction time).
    """

    def __init__(self, transport: str = "tcp"):
        """Initialize with the transport type.

        Args:
            transport: ``"tcp"`` or ``"tls"``.
        """
        self.transport = transport

    def create(self, router, proton, profile_name, server, options, transport="udp"):
        """Generate a WireGuard config and upload proton-wg files to the router.

        Calls ``proton.generate_wireguard_config`` with the instance's
        transport, parses the result, and writes the ``.conf`` + ``.env``
        files via ``router.upload_proton_wg_config``.

        Returns:
            (router_info, server_info, wg_key, cert_expiry)
        """
        ipv6 = _server_has_ipv6(server)
        config_str, server_info, wg_key, cert_expiry = proton.generate_wireguard_config(
            server,
            profile_name=profile_name,
            netshield=options.get("netshield", 0),
            moderate_nat=options.get("moderate_nat", False),
            nat_pmp=options.get("nat_pmp", False),
            vpn_accelerator=options.get("vpn_accelerator", True),
            transport=self.transport,
            port=options.get("port"),
            custom_dns=options.get("custom_dns"),
            ipv6=ipv6,
        )
        wg = _parse_wg_config(config_str)
        router_info = router.proton_wg.upload_proton_wg_config(
            profile_name=profile_name,
            private_key=wg["private_key"],
            public_key=wg["public_key"],
            endpoint=wg["endpoint"],
            socket_type=self.transport,
            dns=wg["dns"],
            ipv6=ipv6,
        )
        return router_info, server_info, wg_key, cert_expiry

    def delete(self, router, router_info):
        """Stop the proton-wg tunnel (best-effort) then delete all config files.

        Calls ``stop_proton_wg_tunnel`` first so the process, interface,
        routing, and firewall are cleaned up before removing the config.
        """
        try:
            router.proton_wg.stop_proton_wg_tunnel(
                iface=router_info.get("tunnel_name", ""),
                mark=router_info.get("mark", ""),
                table_num=router_info.get("table_num", 0),
                tunnel_id=router_info.get("tunnel_id", 0),
            )
        except Exception:
            pass  # Best-effort stop before delete
        router.proton_wg.delete_proton_wg_config(
            iface=router_info.get("tunnel_name", ""),
            tunnel_id=router_info.get("tunnel_id", 0),
        )

    def connect(self, router, router_info):
        """Start the proton-wg userspace tunnel and return its health.

        Returns:
            Live tunnel health string.
        """
        router.proton_wg.start_proton_wg_tunnel(
            iface=router_info["tunnel_name"],
            mark=router_info["mark"],
            table_num=router_info["table_num"],
            tunnel_id=router_info["tunnel_id"],
        )
        return router.proton_wg.get_proton_wg_health(router_info["tunnel_name"])

    def disconnect(self, router, router_info):
        """Stop the proton-wg userspace tunnel (process + routing + firewall)."""
        router.proton_wg.stop_proton_wg_tunnel(
            iface=router_info["tunnel_name"],
            mark=router_info["mark"],
            table_num=router_info["table_num"],
            tunnel_id=router_info["tunnel_id"],
        )

    def switch_server(self, router, proton, profile, server, options, old_router_info):
        """ProtonWG fast path: rewrite config file + ``wg setconf``.

        Same zero-flicker approach as kernel WireGuard. The config file is
        overwritten and applied to the running interface with
        ``wg setconf``. No process restart needed.

        Returns:
            (None, server_info, wg_key, cert_expiry) -- ``None`` because
            router_info does not change.
        """
        ipv6 = _server_has_ipv6(server)
        existing_wg_key = profile.get("wg_key")
        config_str, server_info, wg_key, cert_expiry = proton.generate_wireguard_config(
            server,
            profile_name=profile.get("name", "Unnamed"),
            netshield=options.get("netshield", 0),
            moderate_nat=options.get("moderate_nat", False),
            nat_pmp=options.get("nat_pmp", False),
            vpn_accelerator=options.get("vpn_accelerator", True),
            existing_wg_key=existing_wg_key,
            transport=self.transport,
            port=options.get("port"),
            custom_dns=options.get("custom_dns"),
            ipv6=ipv6,
        )
        wg = _parse_wg_config(config_str)

        iface = old_router_info.get("tunnel_name", "protonwg0")
        allowed_ips = "0.0.0.0/0, ::/0" if ipv6 else "0.0.0.0/0"
        wg_conf = (
            f"[Interface]\n"
            f"PrivateKey = {wg['private_key']}\n"
            f"\n"
            f"[Peer]\n"
            f"PublicKey = {wg['public_key']}\n"
            f"AllowedIPs = {allowed_ips}\n"
            f"Endpoint = {wg['endpoint']}\n"
            f"PersistentKeepalive = 25\n"
        )
        router.proton_wg.update_config_live(iface, wg_conf)

        return None, server_info, wg_key, cert_expiry

    def get_health(self, router, router_info):
        """Read tunnel health from the proton-wg userspace interface.

        Returns:
            Health string (green, amber, red, connecting).
        """
        return router.proton_wg.get_proton_wg_health(router_info["tunnel_name"])


# ── Factory ──────────────────────────────────────────────────────────────────


def get_strategy(vpn_protocol: str) -> TunnelStrategy:
    """Return the appropriate TunnelStrategy for a VPN protocol string.

    Args:
        vpn_protocol: One of ``"wireguard"``, ``"openvpn"``,
            ``"wireguard-tcp"``, ``"wireguard-tls"``.

    Returns:
        A TunnelStrategy instance.

    Raises:
        ValueError: If the protocol string is not recognized.
    """
    if vpn_protocol == PROTO_WIREGUARD:
        return WireGuardStrategy()
    if vpn_protocol == PROTO_OPENVPN:
        return OpenVPNStrategy()
    if vpn_protocol == PROTO_WIREGUARD_TCP:
        return ProtonWGStrategy("tcp")
    if vpn_protocol == PROTO_WIREGUARD_TLS:
        return ProtonWGStrategy("tls")
    raise ValueError(f"Unknown VPN protocol: {vpn_protocol!r}")
