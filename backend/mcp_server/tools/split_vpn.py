"""Split VPN tools — third-party VPNs (e.g. a company VPN) for selected destinations.

A Split VPN runs a third-party VPN client (currently Barracuda CloudGen) on
the router and carries only selected destinations (work domains / IP ranges)
for selected groups. Those groups keep their Proton VPN for everything else.
"""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from mcp_server.api_client import FlintAPI

# Connecting performs the full VPN handshake on the router (incl. OTP
# verification) and can take up to ~2.5 minutes.
CONNECT_TIMEOUT = 210.0
# Installing the runtime verifies the local runtime/ files and uploads them to the router.
INSTALL_TIMEOUT = 660.0


def register(mcp: FastMCP, api: FlintAPI) -> None:
    @mcp.tool()
    def flint_list_split_vpns(live: bool = True) -> str:
        """List all Split VPNs, the router runtime status, and the slot limit.

        A Split VPN is a third-party VPN (e.g. a company Barracuda VPN) that
        carries only selected destinations (domains / IP ranges) for selected
        groups; those groups keep their Proton VPN for everything else.

        Args:
            live: True (default) to include live connection status read from
                  the router; False for stored config only (faster).

        Returns:
        - vpns: each with id, name, server, port, tunnel_mode, username,
          group_ids, domains, cidrs, use_pushed_routes, enabled,
          pushed_routes, pushed_dns, last_connected_at, has_password, and
          status {state, ip, gateway, dns, routes, connected, error?}
        - runtime: {installed, files?, local_files?, error?} — whether the
          VPN client binaries are on the router, and which install sources
          ({barracuda_archive, qemu}) exist in the app's local runtime/ folder
          (see flint_install_split_vpn_runtime)
        - max: maximum number of Split VPNs supported
        """
        result = api.get("/api/split-vpns", live="1" if live else "0")
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_create_split_vpn(
        name: str,
        server: str,
        group_ids: list[str],
        username: str | None = None,
        password: str | None = None,
        master_password: str | None = None,
        secret_ref: str | None = None,
        totp_secret: str | None = None,
        domains: list[str] | None = None,
        cidrs: list[str] | None = None,
        port: int = 691,
        tunnel_mode: str = "TCP",
        use_pushed_routes: bool = True,
        enabled: bool = True,
        auto_connect: bool = True,
        connect_mode: str = "always",
        presence_macs: list[str] | None = None,
        presence_grace_min: int = 5,
        yield_to_device_tunnel: bool = True,
    ) -> str:
        """Create a Split VPN (Barracuda CloudGen). Does not connect it.

        Credentials come from one of two places:
        - secret_ref (preferred): name of an entry under ``split_vpns`` in the
          SOPS secrets file (secrets/flint.enc.yaml) holding username,
          password and totp_secret. No secrets pass through the tool call.
        - password (+ totp_secret) stored encrypted by the app, which needs
          the app's master password. Ask the human; never guess.
        With a TOTP secret the app generates the one-time codes itself.

        Args:
            name: Display name (e.g. "Work VPN")
            server: VPN server hostname or IP
            username: VPN account username (optional with secret_ref if the
                      SOPS entry has one)
            password: VPN account password (stored encrypted; omit with secret_ref)
            master_password: Flint VPN Manager master password, required to
                             write the encrypted password
            secret_ref: SOPS entry name under split_vpns (e.g. "work")
            group_ids: Group (profile) IDs whose devices use this VPN for the
                       selected destinations. Groups must have internet access.
            totp_secret: Base32 TOTP secret or otpauth://totp/... URI used to
                         generate one-time codes (stored encrypted)
            domains: Domains routed through this VPN (subdomains included),
                     e.g. ["corp.example.com"]
            cidrs: IPv4 networks routed through this VPN, e.g. ["10.20.0.0/16"].
                   Default routes (0.0.0.0/0) are rejected.
            port: Server port (default 691)
            tunnel_mode: "TCP" (default), "UDP" or "HYBRID"
            use_pushed_routes: Also route networks the server pushes on connect
            enabled: Whether routing rules are active
            auto_connect: Connect automatically after unlock and reconnect
                          when the tunnel drops (needs totp_secret)
            connect_mode: "always", or "presence" = hold the session only while
                          one of presence_macs is home (the account allows one
                          session; the router releases it when the laptop leaves
                          so the laptop's own client can connect elsewhere)
            presence_macs: device MACs whose presence decides (presence mode)
            presence_grace_min: minutes to keep the session after they leave
            yield_to_device_tunnel: stand by while a presence device runs its
                                    own VPN client
        """
        body: dict = {
            "name": name,
            "server": server,
            "port": port,
            "tunnel_mode": tunnel_mode,
            "group_ids": group_ids,
            "domains": domains or [],
            "cidrs": cidrs or [],
            "use_pushed_routes": use_pushed_routes,
            "enabled": enabled,
            "auto_connect": auto_connect,
            "connect_mode": connect_mode,
            "presence_macs": presence_macs or [],
            "presence_grace_min": presence_grace_min,
            "yield_to_device_tunnel": yield_to_device_tunnel,
        }
        for key, val in (("username", username), ("password", password),
                         ("master_password", master_password), ("secret_ref", secret_ref),
                         ("totp_secret", totp_secret)):
            if val:
                body[key] = val
        result = api.post("/api/split-vpns", json=body)
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_update_split_vpn(
        vpn_id: str,
        name: str | None = None,
        server: str | None = None,
        port: int | None = None,
        tunnel_mode: str | None = None,
        username: str | None = None,
        group_ids: list[str] | None = None,
        domains: list[str] | None = None,
        cidrs: list[str] | None = None,
        use_pushed_routes: bool | None = None,
        enabled: bool | None = None,
        auto_connect: bool | None = None,
        connect_mode: str | None = None,
        presence_macs: list[str] | None = None,
        presence_grace_min: int | None = None,
        yield_to_device_tunnel: bool | None = None,
        secret_ref: str | None = None,
        password: str | None = None,
        totp_secret: str | None = None,
        master_password: str | None = None,
    ) -> str:
        """Update a Split VPN. Only the fields you pass are changed.

        List fields (group_ids, domains, cidrs) REPLACE the existing list —
        pass the full desired list, not just additions.

        To change the stored account password and/or TOTP secret pass them
        together with master_password (the app's master password). Omit them
        to keep the current credentials.

        Args:
            vpn_id: Split VPN ID (e.g. "sv_a1b2c3d4")
            name: Display name
            server: VPN server hostname or IP
            port: Server port
            tunnel_mode: "TCP", "UDP" or "HYBRID"
            username: VPN account username
            group_ids: Group (profile) IDs that use this VPN (full list)
            domains: Domains routed through this VPN (full list)
            cidrs: IPv4 networks routed through this VPN (full list)
            use_pushed_routes: Also route networks the server pushes on connect
            enabled: Whether routing rules are active
            auto_connect: Connect automatically / reconnect when it drops
            connect_mode: "always" or "presence" (see flint_create_split_vpn)
            presence_macs: device MACs whose presence decides (full list)
            presence_grace_min: minutes to keep the session after they leave
            yield_to_device_tunnel: stand by while a device runs its own client
            secret_ref: SOPS entry name for credentials ("" to switch back to
                        app-stored credentials)
            password: New VPN account password (requires master_password)
            totp_secret: New TOTP secret or otpauth URI (requires master_password)
            master_password: Flint VPN Manager master password
        """
        fields = {
            "name": name,
            "server": server,
            "port": port,
            "tunnel_mode": tunnel_mode,
            "username": username,
            "group_ids": group_ids,
            "domains": domains,
            "cidrs": cidrs,
            "use_pushed_routes": use_pushed_routes,
            "enabled": enabled,
            "auto_connect": auto_connect,
            "connect_mode": connect_mode,
            "presence_macs": presence_macs,
            "presence_grace_min": presence_grace_min,
            "yield_to_device_tunnel": yield_to_device_tunnel,
            "secret_ref": secret_ref,
        }
        body: dict = {k: v for k, v in fields.items() if v is not None}
        if password:
            body["password"] = password
        if totp_secret:
            body["totp_secret"] = totp_secret
        if password or totp_secret:
            body["master_password"] = master_password or ""
        result = api.put(f"/api/split-vpns/{vpn_id}", json=body)
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_delete_split_vpn(vpn_id: str) -> str:
        """Delete a Split VPN permanently (disconnects it first and removes
        its routing rules and router files).

        Args:
            vpn_id: Split VPN ID to delete (e.g. "sv_a1b2c3d4")
        """
        result = api.delete(f"/api/split-vpns/{vpn_id}")
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_connect_split_vpn(vpn_id: str, otp: str | None = None) -> str:
        """Connect a Split VPN.

        The stored password is used, and the one-time code is generated from
        the stored TOTP secret — normally pass only vpn_id. Pass otp only if
        no TOTP secret is stored (has_totp false). Can take up to ~2.5
        minutes. Requires the router runtime (flint_install_split_vpn_runtime).

        Args:
            vpn_id: Split VPN ID (e.g. "sv_a1b2c3d4")
            otp: Optional explicit one-time code (overrides the TOTP secret)

        Returns the connection status, the client log, and the exit code (rc).
        If it fails, check the log for the reason (wrong OTP, auth failure).
        """
        result = api.post(
            f"/api/split-vpns/{vpn_id}/connect",
            json={"otp": otp} if otp else {},
            timeout=CONNECT_TIMEOUT,
        )
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_disconnect_split_vpn(vpn_id: str) -> str:
        """Disconnect a Split VPN. Its config is kept. Auto-reconnect is
        paused until the next manual connect.

        Args:
            vpn_id: Split VPN ID (e.g. "sv_a1b2c3d4")
        """
        result = api.post(f"/api/split-vpns/{vpn_id}/disconnect")
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_get_split_vpn_log(vpn_id: str) -> str:
        """Get the VPN client log for a Split VPN from the router.

        Useful for diagnosing failed connects or dropped connections.

        Args:
            vpn_id: Split VPN ID (e.g. "sv_a1b2c3d4")
        """
        result = api.get(f"/api/split-vpns/{vpn_id}/log")
        return json.dumps(result, indent=2)

    @mcp.tool()
    def flint_install_split_vpn_runtime() -> str:
        """Install the Split VPN client runtime on the router.

        Nothing is downloaded: verifies the files in the app's local
        runtime/ folder (Barracuda 5.3.10 archive from the vendor portal,
        pinned checksum; qemu built by tools/qemu/build.sh) and uploads them
        to the router. Fails naming the file if one is missing. Needed once
        before any Split VPN can connect (check runtime.installed in
        flint_list_split_vpns). Can take several minutes.
        """
        result = api.post("/api/split-vpns/runtime/install", timeout=INSTALL_TIMEOUT)
        return json.dumps(result, indent=2)
