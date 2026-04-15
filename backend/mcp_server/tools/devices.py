"""Device management tools — list, assign, label, refresh."""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from mcp_server.api_client import FlintAPI


def register(mcp: FastMCP, api: FlintAPI) -> None:
    @mcp.tool()
    def flint_list_devices() -> str:
        """List all devices on the network with their current group assignment.

        Returns a JSON array of devices, each with:
        - mac, ip, hostname, label, device_class
        - online (bool), speed (Mbps), signal (dBm, WiFi only)
        - profile_id (group they're assigned to, or null if unassigned)
        - network_zone (which WiFi network they're on)

        Data is fetched live from the router (DHCP leases + ARP + gl-clients).
        """
        result = api.get("/api/devices")
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_assign_device(mac: str, profile_id: str | None) -> str:
        """Assign a device to a group by MAC address.

        Updates the router's routing policy so the device's traffic routes
        through the group's VPN tunnel (or direct/blocked for NoVPN/NoInternet).

        Pass profile_id as null/None to unassign the device (routes via WAN).

        Args:
            mac: Device MAC address (e.g. "AA:BB:CC:DD:EE:FF").
            profile_id: Group ID to assign to, or null to unassign.
        """
        result = api.put(f"/api/devices/{mac}/profile", json={"profile_id": profile_id})
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_label_device(
        mac: str,
        label: str,
        device_class: str | None = None,
    ) -> str:
        """Set a custom display name and device class for a device.

        Labels sync bidirectionally with the GL.iNet router UI.

        Args:
            mac: Device MAC address.
            label: Custom name (e.g. "Ahmed's Laptop", "Living Room TV").
            device_class: Device type — "computer", "phone", "tablet", "printer",
                         "tv", "speaker", "camera", "iot", "game_console", or null.
        """
        body: dict = {"label": label}
        if device_class is not None:
            body["device_class"] = device_class
        result = api.put(f"/api/devices/{mac}/label", json=body)
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_refresh() -> str:
        """Trigger an immediate device discovery poll and server score refresh.

        Forces the app to re-scan DHCP leases, refresh tunnel handshakes,
        and update ProtonVPN server scores if stale. Also re-syncs adblock
        ipsets with current device assignments.
        """
        result = api.post("/api/refresh")
        return json.dumps(result, indent=2)
