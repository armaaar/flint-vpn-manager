"""FlintVPN MCP Server — manage your local network via Claude.

Exposes the FlintVPN REST API as MCP tools so a Claude session with no
project context can manage VPN tunnels, device routing, LAN access, and
network settings on a GL.iNet Flint 2 router.

Requires the Flask backend to be running at http://localhost:5000.

Usage:
    python -m mcp_server.server          # stdio transport (for Claude Code)
"""

from __future__ import annotations

import os

from mcp.server.fastmcp import FastMCP

from mcp_server.api_client import FlintAPI
from mcp_server.tools import (
    session,
    groups,
    tunnels,
    servers,
    devices,
    settings,
    adblock,
    lan_access,
    logs,
    vpn_bypass,
)

BASE_URL = os.environ.get("FLINTVPN_API_URL", "http://localhost:5000")

mcp = FastMCP(
    "flint-vpn",
    instructions=(
        "FlintVPN Manager — manage ProtonVPN tunnels and device routing on a "
        "GL.iNet Flint 2 router.\n\n"
        "WORKFLOW:\n"
        "1. Call flint_get_status to check if the app is locked or unlocked.\n"
        "2. If locked, call flint_unlock with the master password.\n"
        "3. Use flint_list_groups and flint_list_devices to see the current state.\n"
        "4. Manage groups, tunnels, devices, servers, settings, adblock, "
        "LAN networks, and logs.\n\n"
        "IMPORTANT: The router is the source of truth for tunnel state and "
        "device assignments. All reads are live from the router via SSH — "
        "data returned is a point-in-time snapshot, not a live stream."
    ),
)

api = FlintAPI(BASE_URL)

# Register all tool modules
session.register(mcp, api)
groups.register(mcp, api)
tunnels.register(mcp, api)
servers.register(mcp, api)
devices.register(mcp, api)
settings.register(mcp, api)
adblock.register(mcp, api)
lan_access.register(mcp, api)
vpn_bypass.register(mcp, api)
logs.register(mcp, api)

if __name__ == "__main__":
    mcp.run()
