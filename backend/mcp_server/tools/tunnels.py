"""Tunnel control tools — connect, disconnect, switch server, change protocol/type."""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from mcp_server.api_client import FlintAPI


def register(mcp: FastMCP, api: FlintAPI) -> None:
    @mcp.tool()
    def flint_connect(profile_id: str) -> str:
        """Bring a VPN group's tunnel up.

        Establishes the VPN connection on the router. If Smart Protocol is enabled
        in the group's options, failed connections will automatically retry with
        alternative protocols in the background.

        Args:
            profile_id: The VPN group's unique ID.
        """
        result = api.post(f"/api/profiles/{profile_id}/connect")
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_disconnect(profile_id: str) -> str:
        """Bring a VPN group's tunnel down.

        Tears down the VPN connection. Devices in this group will lose internet
        access if kill switch is enabled, or route through WAN directly if not.

        Args:
            profile_id: The VPN group's unique ID.
        """
        result = api.post(f"/api/profiles/{profile_id}/disconnect")
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_switch_server(
        profile_id: str,
        server_id: str,
        options: str | None = None,
        server_scope: str | None = None,
    ) -> str:
        """Change the VPN server for a group.

        For WireGuard: hot-swaps the config without tearing down the tunnel.
        For OpenVPN: tears down and recreates the tunnel with the new server.

        Args:
            profile_id: The VPN group's unique ID.
            server_id: New ProtonVPN server ID (use flint_browse_servers to find one).
            options: Optional JSON string of VPN options to update alongside the switch.
            server_scope: Optional JSON string of server scope filter to update.
        """
        body: dict = {"server_id": server_id}
        if options:
            body["options"] = json.loads(options)
        if server_scope:
            body["server_scope"] = json.loads(server_scope)
        result = api.put(f"/api/profiles/{profile_id}/server", json=body)
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_change_protocol(
        profile_id: str,
        vpn_protocol: str,
        server_id: str | None = None,
        options: str | None = None,
        server_scope: str | None = None,
        ovpn_protocol: str = "udp",
    ) -> str:
        """Change the VPN protocol for a group.

        Tears down the existing tunnel and recreates it with the new protocol.
        May require a different server if the current one doesn't support the
        new protocol.

        Args:
            profile_id: The VPN group's unique ID.
            vpn_protocol: New protocol — "wireguard", "wireguard-tcp", "wireguard-tls", or "openvpn".
            server_id: Optional new server ID (required if current server doesn't support the new protocol).
            options: Optional JSON string of VPN options.
            server_scope: Optional JSON string of server scope filter.
            ovpn_protocol: For OpenVPN — "udp" or "tcp". Default "udp".
        """
        body: dict = {"vpn_protocol": vpn_protocol, "ovpn_protocol": ovpn_protocol}
        if server_id:
            body["server_id"] = server_id
        if options:
            body["options"] = json.loads(options)
        if server_scope:
            body["server_scope"] = json.loads(server_scope)
        result = api.put(f"/api/profiles/{profile_id}/protocol", json=body)
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_change_group_type(
        profile_id: str,
        type: str,
        vpn_protocol: str = "wireguard",
        server_id: str | None = None,
        options: str | None = None,
        kill_switch: bool = True,
        server_scope: str | None = None,
        ovpn_protocol: str = "udp",
    ) -> str:
        """Change a group's type (vpn <-> no_vpn <-> no_internet).

        Changing to VPN type requires a server_id. Changing away from VPN tears
        down the tunnel.

        Args:
            profile_id: The group's unique ID.
            type: New group type — "vpn", "no_vpn", or "no_internet".
            vpn_protocol: For VPN — "wireguard", "wireguard-tcp", "wireguard-tls", or "openvpn".
            server_id: Required when changing to VPN type.
            options: Optional JSON string of VPN options.
            kill_switch: For VPN — block traffic if tunnel drops. Default true.
            server_scope: Optional JSON string of server scope filter.
            ovpn_protocol: For OpenVPN — "udp" or "tcp".
        """
        body: dict = {
            "type": type,
            "vpn_protocol": vpn_protocol,
            "kill_switch": kill_switch,
            "ovpn_protocol": ovpn_protocol,
        }
        if server_id:
            body["server_id"] = server_id
        if options:
            body["options"] = json.loads(options)
        if server_scope:
            body["server_scope"] = json.loads(server_scope)
        result = api.put(f"/api/profiles/{profile_id}/type", json=body)
        return json.dumps(result, indent=2)
