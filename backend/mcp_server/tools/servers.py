"""Server browsing tools ��� browse, countries, ports, latency, preferences."""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from mcp_server.api_client import FlintAPI


def register(mcp: FastMCP, api: FlintAPI) -> None:
    @mcp.tool()
    def flint_browse_servers(
        profile_id: str,
        country: str | None = None,
        city: str | None = None,
        feature: str | None = None,
    ) -> str:
        """Browse ProtonVPN servers with optional filters.

        Returns a JSON array of servers with: id, name, country, city, load (%),
        score, features, enabled, tier, secure_core, streaming, p2p, blacklisted,
        favourite.

        Use flint_get_server_countries first to see available countries and cities.

        Args:
            profile_id: A VPN group ID (used to determine accessible servers based on protocol).
            country: Filter by 2-letter country code (e.g. "US", "CH", "GB").
            city: Filter by city name (e.g. "New York", "Zurich").
            feature: Filter by feature — "streaming", "p2p", "secure_core", "tor".
        """
        params = {}
        if country:
            params["country"] = country
        if city:
            params["city"] = city
        if feature:
            params["feature"] = feature
        result = api.get(f"/api/profiles/{profile_id}/servers", **params)
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_get_server_countries() -> str:
        """List all available ProtonVPN countries with server counts and cities.

        Returns a JSON array of countries, each with:
        - code (2-letter), name, server_count, free (bool), features
        - cities: [{name, server_count}]

        Use this to discover what countries and cities are available before
        calling flint_browse_servers.
        """
        result = api.get("/api/server-countries")
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_get_available_ports() -> str:
        """Get available VPN ports per protocol for port override configuration.

        Returns a JSON object mapping protocol names to lists of available ports.
        Use this when configuring a custom port in group options.
        """
        result = api.get("/api/available-ports")
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_probe_latency(server_ids: list[str]) -> str:
        """Measure TCP latency from the router to specific VPN servers.

        Probes are run from the router (not the local machine) for accurate
        results. Each server is probed once; results are in milliseconds.

        Args:
            server_ids: List of ProtonVPN server IDs to probe.

        Returns JSON: {latencies: {server_id: ms_or_null}}
        """
        result = api.post("/api/probe-latency", json={"server_ids": server_ids})
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_get_server_preferences() -> str:
        """Get the server blacklist and favourites lists.

        Returns JSON with:
        - blacklist: [server_id, ...] — servers excluded from auto-optimizer
        - favourites: [server_id, ...] — preferred servers for auto-optimizer
        """
        result = api.get("/api/settings/server-preferences")
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_toggle_server_preference(
        server_id: str,
        list_name: str,
        action: str,
    ) -> str:
        """Add or remove a server from the blacklist or favourites.

        Blacklist and favourites are mutually exclusive — adding to one removes
        from the other.

        Args:
            server_id: The ProtonVPN server ID.
            list_name: Which list — "blacklist" or "favourites".
            action: What to do — "add" or "remove".
        """
        if action == "add":
            result = api.post(f"/api/settings/server-preferences/{list_name}/{server_id}")
        else:
            result = api.delete(f"/api/settings/server-preferences/{list_name}/{server_id}")
        return json.dumps(result, indent=2)
