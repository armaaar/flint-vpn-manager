"""Group management tools — CRUD, reorder, guest."""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from mcp_server.api_client import FlintAPI


def register(mcp: FastMCP, api: FlintAPI) -> None:
    @mcp.tool()
    def flint_list_groups() -> str:
        """List all VPN, NoVPN, and NoInternet groups with live tunnel health.

        Returns a JSON array of groups, each containing:
        - id, name, type ("vpn" | "no_vpn" | "no_internet"), color, icon
        - status ("connected" | "disconnected" | "connecting"), health, kill_switch
        - server_info (name, country, city, load) for VPN groups
        - device_count, options (netshield, moderate_nat, etc.)
        - is_guest (bool): whether this is the auto-assignment target

        This is the main dashboard view — call it to see the current network state.
        """
        result = api.get("/api/profiles")
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_create_group(
        name: str,
        type: str,
        vpn_protocol: str = "wireguard",
        server_id: str | None = None,
        color: str = "#3498db",
        icon: str = "🔒",
        is_guest: bool = False,
        kill_switch: bool = True,
        options: str | None = None,
        server_scope: str | None = None,
        ovpn_protocol: str = "udp",
        adblock: bool = False,
    ) -> str:
        """Create a new group for routing devices.

        Args:
            name: Display name for the group (e.g. "US Streaming", "Printers").
            type: Group type — "vpn", "no_vpn" (direct internet), or "no_internet" (LAN only).
            vpn_protocol: For VPN groups — "wireguard", "wireguard-tcp", "wireguard-tls", or "openvpn".
            server_id: For VPN groups — the ProtonVPN server ID. Use flint_browse_servers to find one.
            color: Hex color for the dashboard card (e.g. "#e74c3c").
            icon: Emoji icon for the group.
            is_guest: If true, new devices auto-assign to this group.
            kill_switch: For VPN groups — block traffic if tunnel drops.
            options: JSON string of VPN options: {"netshield": 0|1|2, "moderate_nat": bool, "nat_pmp": bool, "vpn_accelerator": bool, "custom_dns": str|null, "port": int|null}.
            server_scope: JSON string of server scope filter: {"countries": ["US"], "cities": ["New York"], "features": ["streaming"]}.
            ovpn_protocol: For OpenVPN — "udp" or "tcp".
            adblock: Enable DNS ad blocking for this group.
        """
        body: dict = {
            "name": name,
            "type": type,
            "vpn_protocol": vpn_protocol,
            "color": color,
            "icon": icon,
            "is_guest": is_guest,
            "kill_switch": kill_switch,
            "ovpn_protocol": ovpn_protocol,
            "adblock": adblock,
        }
        if server_id:
            body["server_id"] = server_id
        if options:
            body["options"] = json.loads(options)
        if server_scope:
            body["server_scope"] = json.loads(server_scope)
        result = api.post("/api/profiles", json=body)
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_update_group(
        profile_id: str,
        name: str | None = None,
        color: str | None = None,
        icon: str | None = None,
        kill_switch: bool | None = None,
        options: str | None = None,
        adblock: bool | None = None,
    ) -> str:
        """Update a group's metadata or VPN options.

        Only pass fields you want to change — omitted fields stay unchanged.

        Args:
            profile_id: The group's unique ID (from flint_list_groups).
            name: New display name.
            color: New hex color.
            icon: New emoji icon.
            kill_switch: Enable/disable kill switch (VPN groups only).
            options: JSON string of VPN options to update: {"netshield": 0|1|2, "moderate_nat": bool, "nat_pmp": bool, "vpn_accelerator": bool, "custom_dns": str|null, "port": int|null}.
            adblock: Enable/disable DNS ad blocking for this group.
        """
        body: dict = {}
        if name is not None:
            body["name"] = name
        if color is not None:
            body["color"] = color
        if icon is not None:
            body["icon"] = icon
        if kill_switch is not None:
            body["kill_switch"] = kill_switch
        if options is not None:
            body["options"] = json.loads(options)
        if adblock is not None:
            body["adblock"] = adblock
        result = api.put(f"/api/profiles/{profile_id}", json=body)
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_delete_group(profile_id: str) -> str:
        """Delete a group. Tears down the VPN tunnel if connected and unassigns all devices.

        WARNING: This is destructive — devices in this group will lose their VPN routing.

        Args:
            profile_id: The group's unique ID.
        """
        result = api.delete(f"/api/profiles/{profile_id}")
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_reorder_groups(profile_ids: list[str]) -> str:
        """Set the display order of groups on the dashboard.

        The order also determines routing priority on the router.

        Args:
            profile_ids: Ordered list of ALL group IDs (first = top of dashboard).
        """
        result = api.put("/api/profiles/reorder", json={"profile_ids": profile_ids})
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_set_guest_group(profile_id: str) -> str:
        """Set a group as the guest auto-assignment target.

        New devices that appear on the network will automatically be assigned
        to this group. Only one group can be the guest group at a time.

        Args:
            profile_id: The group's unique ID.
        """
        result = api.put(f"/api/profiles/{profile_id}/guest")
        return json.dumps(result, indent=2)
