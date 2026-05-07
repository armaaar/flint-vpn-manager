"""Settings and network status tools."""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from mcp_server.api_client import FlintAPI


def register(mcp: FastMCP, api: FlintAPI) -> None:
    @mcp.tool()
    def flint_get_settings() -> str:
        """Get all non-sensitive app settings.

        Returns JSON with: router_ip, alternative_routing,
        auto_optimize_enabled, auto_optimize_hour, global_ipv6_enabled, etc.
        """
        result = api.get("/api/settings")
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_update_settings(settings: str) -> str:
        """Update app settings.

        Args:
            settings: JSON string of settings to update. Supported fields:
                - router_ip (str): Router LAN IP address
                - alternative_routing (bool): Use alternative API routing for Proton
                - auto_optimize_enabled (bool): Enable daily server optimization
                - auto_optimize_hour (int, 0-23): Hour to run auto-optimizer
                - global_ipv6_enabled (bool): Enable IPv6 globally
        """
        body = json.loads(settings)
        result = api.put("/api/settings", json=body)
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_get_router_ip() -> str:
        """Get the router's public IPv4 and IPv6 as seen from the internet.

        Probed from the router itself via curl, so this is the WAN egress
        (what every WAN-routed device on the LAN shares), not the management
        host's egress. Returns JSON with: ipv4, ipv6 (either may be null).
        Cached for 30 seconds.
        """
        result = api.get("/api/router-ip")
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_get_vpn_status() -> str:
        """Get ProtonVPN account and session status.

        Returns JSON with:
        - logged_in (bool)
        - account_name, user_tier, tier_name (when logged in)
        - server_count, server_list_expired, loads_expired (when logged in)

        Use this for diagnostics — check if the Proton session is healthy.
        """
        result = api.get("/api/vpn-status")
        return json.dumps(result, indent=2)
