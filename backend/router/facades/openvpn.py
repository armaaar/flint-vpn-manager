"""Router OpenVPN facade — OpenVPN client config management.

Extracted from router_api.py. Handles UCI-based client creation,
config file management, and deletion.
"""

from consts import PROTO_OPENVPN


class RouterOpenvpn:
    """Facade for OpenVPN config on the GL.iNet Flint 2."""

    def __init__(self, uci, service_ctl, alloc_tunnel_id, ssh):
        self._uci = uci
        self._service_ctl = service_ctl
        self._alloc_tunnel_id = alloc_tunnel_id
        self._ssh = ssh  # raw exec for mkdir, chmod; write_file for configs

    def _next_ovpn_client_id(self) -> int:
        """Find the next available numeric client ID (9051-9099)."""
        existing = self._ssh.exec(
            "uci show ovpnclient 2>/dev/null | grep '=clients' | "
            "sed 's/ovpnclient\\.\\([0-9_]*\\)=clients/\\1/'"
        )
        used = set()
        for line in existing.strip().splitlines():
            parts = line.strip().split("_")
            if len(parts) >= 2:
                try:
                    used.add(int(parts[1]))
                except ValueError:
                    pass
        for cid in range(9051, 9100):
            if cid not in used:
                return cid
        raise RuntimeError("No available OpenVPN client IDs")

    def upload_openvpn_config(
        self,
        profile_name: str,
        ovpn_config: str,
        username: str,
        password: str,
    ) -> dict:
        """Create an OpenVPN client config and route policy rule."""
        group_id = "28216"
        client_num = self._next_ovpn_client_id()
        client_uci_id = f"{group_id}_{client_num}"
        profile_dir = f"/etc/openvpn/profiles/{client_uci_id}"

        self._ssh.exec(f"mkdir -p {profile_dir}/auth")

        ovpn_config_fixed = ovpn_config.replace("{CLIENT_ID}", client_uci_id)
        self._ssh.write_file(f"{profile_dir}/config.ovpn", ovpn_config_fixed)
        self._ssh.write_file(
            f"{profile_dir}/auth/username_password.txt",
            f"{username}\n{password}\n"
        )
        self._ssh.exec(f"chmod 600 {profile_dir}/auth/username_password.txt")

        self._uci.batch_set(f"ovpnclient.{client_uci_id}", {
            "_type": "clients",
            "group_id": group_id,
            "client_id": str(client_num),
            "name": profile_name,
            "path": f"{profile_dir}/config.ovpn",
            "proto": "udp",
            "client_auth": "1",
        }, "ovpnclient")

        tunnel_id = self._alloc_tunnel_id(self._ssh)
        rule_name = f"fvpn_rule_ovpn_{client_num}"
        self._uci.batch_set(f"route_policy.{rule_name}", {
            "_type": "rule",
            "name": profile_name,
            "enabled": "0",
            "killswitch": "1",
            "tunnel_id": str(tunnel_id),
            "via_type": "openvpn",
            "group_id": group_id,
            "client_id": str(client_num),
            "from_type": "ipset",
            "from": f"src_mac_{tunnel_id}",
        }, "route_policy")

        return {
            "client_id": str(client_num),
            "client_uci_id": client_uci_id,
            "group_id": group_id,
            "tunnel_id": tunnel_id,
            "rule_name": rule_name,
            "vpn_protocol": PROTO_OPENVPN,
        }

    def update_openvpn_client(
        self,
        client_uci_id: str,
        ovpn_config: str,
        username: str,
        password: str,
    ):
        """Update an existing OpenVPN client's config file in place."""
        profile_dir = f"/etc/openvpn/profiles/{client_uci_id}"
        ovpn_config_fixed = ovpn_config.replace("{CLIENT_ID}", client_uci_id)
        self._ssh.write_file(f"{profile_dir}/config.ovpn", ovpn_config_fixed)
        self._ssh.write_file(
            f"{profile_dir}/auth/username_password.txt",
            f"{username}\n{password}\n",
        )
        self._ssh.exec(f"chmod 600 {profile_dir}/auth/username_password.txt")

    def delete_openvpn_config(self, client_uci_id: str, rule_name: str):
        """Remove an OpenVPN client config and route policy rule."""
        self._uci.set(f"route_policy.{rule_name}.enabled", "0")
        self._uci.commit("route_policy")
        self._service_ctl.restart("vpn-client")
        self._uci.delete(f"route_policy.{rule_name}")
        self._uci.commit("route_policy")
        self._uci.delete(f"ovpnclient.{client_uci_id}")
        self._uci.commit("ovpnclient")
        profile_dir = f"/etc/openvpn/profiles/{client_uci_id}"
        self._ssh.exec(f"rm -rf {profile_dir} 2>/dev/null")
        self._service_ctl.restart("vpn-client")
