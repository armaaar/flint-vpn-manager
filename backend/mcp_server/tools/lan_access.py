"""LAN access control tools — network CRUD, rules, isolation, IPv6, exceptions."""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from mcp_server.api_client import FlintAPI


def register(mcp: FastMCP, api: FlintAPI) -> None:
    @mcp.tool()
    def flint_list_networks() -> str:
        """List all networks (WiFi zones) on the router.

        Returns a JSON array of networks, each with:
        - zone_id, name, ssid_2g, ssid_5g, subnet, gateway
        - device_count, isolation (bool), ipv6 (bool)
        - is_main (bool): the primary LAN network (cannot be deleted)
        """
        result = api.get("/api/lan-access/networks")
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_create_network(config: str) -> str:
        """Create a new WiFi network with its own zone, bridge, subnet, and SSIDs.

        Creates a fully isolated network segment on the router. Each network
        gets its own DHCP range, firewall zone, and WiFi SSIDs (2.4GHz + 5GHz).

        Note: Creating a network requires a WiFi driver reload (~5 seconds of
        WiFi downtime for all clients).

        Args:
            config: JSON string with network configuration:
                - name (str, required): Network name (used for zone ID, max 8 chars)
                - ssid_2g (str): 2.4GHz SSID name
                - ssid_5g (str): 5GHz SSID name
                - password (str): WiFi password (min 8 chars)
                - subnet (str): e.g. "192.168.9.0/24" (must not overlap existing)
        """
        body = json.loads(config)
        result = api.post("/api/lan-access/networks", json=body)
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_update_network(zone_id: str, config: str) -> str:
        """Update an existing network (rename SSIDs, change WiFi password, etc.).

        Args:
            zone_id: The network's zone identifier (from flint_list_networks).
            config: JSON string with fields to update:
                - ssid_2g, ssid_5g (str): New SSID names
                - password (str): New WiFi password
        """
        body = json.loads(config)
        result = api.put(f"/api/lan-access/networks/{zone_id}", json=body)
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_delete_network(zone_id: str) -> str:
        """Delete a network and all its resources (zone, bridge, SSIDs, firewall rules).

        WARNING: All devices on this network will be disconnected. The main LAN
        network cannot be deleted.

        Requires a WiFi driver reload (~5 seconds of WiFi downtime).

        Args:
            zone_id: The network's zone identifier.
        """
        result = api.delete(f"/api/lan-access/networks/{zone_id}")
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_list_network_devices(zone_id: str) -> str:
        """List devices in a specific network zone.

        Combines DHCP leases and ARP table entries for the network's subnet.

        Args:
            zone_id: The network's zone identifier.
        """
        result = api.get(f"/api/lan-access/networks/{zone_id}/devices")
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_update_access_rules(rules: str) -> str:
        """Set cross-network zone forwarding rules.

        Controls which networks can communicate with each other. By default,
        networks are isolated — traffic between zones is blocked.

        Args:
            rules: JSON array of access rules, each with:
                - from_zone (str): Source network zone ID
                - to_zone (str): Destination network zone ID
                - policy (str): "accept" or "drop"
        """
        body = json.loads(rules)
        result = api.put("/api/lan-access/rules", json=body)
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_set_isolation(zone_id: str, enabled: bool) -> str:
        """Toggle WiFi AP isolation for a network.

        When enabled, devices on the same SSID cannot see each other (no
        direct L2 communication). Useful for guest networks.

        Args:
            zone_id: The network's zone identifier.
            enabled: True to enable isolation, False to disable.
        """
        result = api.put(f"/api/lan-access/isolation/{zone_id}",
                         json={"enabled": enabled})
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_set_network_ipv6(zone_id: str, enabled: bool) -> str:
        """Toggle IPv6 for a specific network zone.

        Args:
            zone_id: The network's zone identifier.
            enabled: True to enable IPv6, False to disable.
        """
        result = api.put(f"/api/lan-access/ipv6/{zone_id}",
                         json={"enabled": enabled})
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_list_exceptions() -> str:
        """List all LAN access device exceptions.

        Exceptions allow specific devices to bypass zone forwarding rules
        and communicate across networks.

        Returns a JSON array of exceptions with: id, from_ip, to_ip, direction.
        """
        result = api.get("/api/lan-access/exceptions")
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_add_exception(
        from_ip: str,
        to_ip: str,
        direction: str = "both",
    ) -> str:
        """Add a device exception allowing cross-network traffic.

        Args:
            from_ip: Source IP or subnet (e.g. "192.168.8.100" or "192.168.8.0/24").
            to_ip: Destination IP or subnet.
            direction: Traffic direction — "both", "inbound", or "outbound".
        """
        result = api.post("/api/lan-access/exceptions", json={
            "from_ip": from_ip,
            "to_ip": to_ip,
            "direction": direction,
        })
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_remove_exception(exception_id: str) -> str:
        """Remove a LAN access device exception.

        Args:
            exception_id: The exception's unique ID (from flint_list_exceptions).
        """
        result = api.delete(f"/api/lan-access/exceptions/{exception_id}")
        return json.dumps(result, indent=2)
