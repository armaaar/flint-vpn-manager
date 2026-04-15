"""Log viewing tools."""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from mcp_server.api_client import FlintAPI


def register(mcp: FastMCP, api: FlintAPI) -> None:
    @mcp.tool()
    def flint_list_logs() -> str:
        """List available log files with size and last modified time.

        Returns a JSON array of logs: app.log (actions), error.log (exceptions),
        access.log (HTTP requests).
        """
        result = api.get("/api/logs")
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_read_log(name: str, lines: int = 100) -> str:
        """Read the last N lines of a log file.

        Args:
            name: Log file name — "app" (actions), "error" (exceptions), or "access" (HTTP).
            lines: Number of lines to read from the end (default 100).
        """
        result = api.get(f"/api/logs/{name}", lines=lines)
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_clear_log(name: str) -> str:
        """Clear a log file.

        Args:
            name: Log file name — "app", "error", or "access".
        """
        result = api.delete(f"/api/logs/{name}")
        return json.dumps(result, indent=2)
