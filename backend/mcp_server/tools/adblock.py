"""DNS ad blocker tools."""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from mcp_server.api_client import FlintAPI


def register(mcp: FastMCP, api: FlintAPI) -> None:
    @mcp.tool()
    def flint_get_adblock_settings() -> str:
        """Get the DNS ad blocker configuration.

        Returns JSON with:
        - enabled_sources: list of active blocklist URLs
        - custom_domains: list of manually blocked domains
        - available_presets: built-in blocklist options with name, URL, domain count
        - last_update: when blocklists were last downloaded
        - domain_count: total unique blocked domains
        """
        result = api.get("/api/settings/adblock")
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_update_adblock_settings(
        blocklist_sources: str | None = None,
        custom_domains: str | None = None,
    ) -> str:
        """Update the DNS ad blocker configuration.

        After updating, call flint_update_blocklist_now to download and apply.

        Args:
            blocklist_sources: JSON array of blocklist URLs to enable.
                Use flint_get_adblock_settings to see available presets.
            custom_domains: JSON array of domains to block manually
                (e.g. ["ads.example.com", "tracker.example.com"]).
        """
        body: dict = {}
        if blocklist_sources is not None:
            body["blocklist_sources"] = json.loads(blocklist_sources)
        if custom_domains is not None:
            body["custom_domains"] = json.loads(custom_domains)
        result = api.put("/api/settings/adblock", json=body)
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_update_blocklist_now() -> str:
        """Download all configured blocklists and apply them to the router immediately.

        Downloads, merges, deduplicates, and uploads the combined blocklist
        to the router's dnsmasq. This can take 10-30 seconds depending on
        blocklist size.
        """
        result = api.post("/api/settings/adblock/update-now")
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_search_blocked_domains(
        search: str = "",
        page: int = 1,
        limit: int = 50,
    ) -> str:
        """Search the active blocklist for specific domains.

        Runs on-router for performance. Use this to verify whether a domain
        is being blocked.

        Args:
            search: Domain substring to search for (e.g. "facebook", "tracker").
            page: Page number (1-based).
            limit: Results per page (default 50).
        """
        result = api.get("/api/settings/adblock/domains",
                         search=search, page=page, limit=limit)
        return json.dumps(result, indent=2)
