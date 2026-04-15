"""Session lifecycle tools — status, unlock, lock."""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from mcp_server.api_client import FlintAPI


def register(mcp: FastMCP, api: FlintAPI) -> None:
    @mcp.tool()
    def flint_get_status() -> str:
        """Check whether the FlintVPN app needs first-time setup, is locked, or is unlocked.

        Returns JSON with:
        - status: "setup-needed" | "locked" | "unlocked"
        - proton_logged_in (bool, only when unlocked): whether ProtonVPN session is active

        This is the first tool to call — it tells you what state the app is in.
        If status is "locked", call flint_unlock next.
        """
        result = api.get("/api/status")
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_unlock(master_password: str) -> str:
        """Unlock the FlintVPN session with the master password.

        Required before any management operations. Decrypts stored credentials,
        connects to the router via SSH, and starts background threads.

        Args:
            master_password: The master password set during first-time setup.
        """
        result = api.post("/api/unlock", json={"master_password": master_password})
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_lock() -> str:
        """Lock the FlintVPN session.

        Stops background threads (device tracker, auto-optimizer) and clears
        decrypted credentials from memory. The VPN tunnels keep running on the
        router — locking only affects the management session.
        """
        result = api.post("/api/lock")
        return json.dumps(result, indent=2)
