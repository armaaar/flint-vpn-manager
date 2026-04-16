"""VPN bypass exception tools — manage VPN traffic bypass rules."""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from mcp_server.api_client import FlintAPI


def register(mcp: FastMCP, api: FlintAPI) -> None:
    @mcp.tool()
    def flint_list_vpn_bypass() -> str:
        """List all VPN bypass exceptions and available presets.

        Returns:
        - exceptions: active bypass rules (each with scope, rules, enabled status)
        - presets: available templates (built-in like 'lol', 'valorant' + custom)
        - dnsmasq_full_installed: whether domain-based rules are supported
        """
        result = api.get("/api/vpn-bypass")
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_add_vpn_bypass(
        name: str,
        scope: str = "global",
        scope_target: str = "",
        scope_targets: str = "",
        preset_id: str = "",
        rules: str = "",
    ) -> str:
        """Add a VPN bypass exception so matching traffic skips the VPN tunnel.

        Use preset_id for built-in presets ('lol', 'valorant') or provide
        custom rules as a JSON array.

        Args:
            name: Display name for this exception (e.g. "League of Legends")
            scope: "global" (all devices) or "custom" (selected groups/devices)
            scope_target: Single target — profile_id or MAC address. Use
                         scope_targets for multiple.
            scope_targets: JSON array of target IDs (profile_ids and/or MAC
                          addresses). Use for multiple groups/devices.
            preset_id: ID of a built-in or custom preset to use as template.
                      If provided, rules from the preset are copied.
            rules: JSON array of rule objects, each with:
                   - type: "cidr", "domain", or "port"
                   - value: the CIDR, domain, or port range
                   - protocol: "tcp" or "udp" (only for port type)
                   Example: '[{"type":"cidr","value":"10.0.0.0/8"}]'
        """
        body: dict = {"name": name, "scope": scope}
        if scope_targets:
            body["scope_target"] = json.loads(scope_targets)
        elif scope_target:
            body["scope_target"] = [scope_target]
        if preset_id:
            body["preset_id"] = preset_id
        if rules:
            body["rules"] = json.loads(rules)
        result = api.post("/api/vpn-bypass/exceptions", json=body)
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_toggle_vpn_bypass(exception_id: str, enabled: bool) -> str:
        """Enable or disable a VPN bypass exception.

        Args:
            exception_id: The exception ID (e.g. "byp_a1b2c3d4")
            enabled: True to enable, False to disable
        """
        result = api.put(
            f"/api/vpn-bypass/exceptions/{exception_id}/toggle",
            json={"enabled": enabled},
        )
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_remove_vpn_bypass(exception_id: str) -> str:
        """Remove a VPN bypass exception permanently.

        Args:
            exception_id: The exception ID to delete (e.g. "byp_a1b2c3d4")
        """
        result = api.delete(f"/api/vpn-bypass/exceptions/{exception_id}")
        return json.dumps(result, indent=2)
