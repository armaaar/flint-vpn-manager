"""Router WireGuard facade — kernel WireGuard peer config management.

Extracted from router_api.py. Handles UCI-based peer creation, live
peer hot-swap via ``wg set``, and deletion.
"""

from consts import PROTO_WIREGUARD


class RouterWireguard:
    """Facade for kernel WireGuard config on the GL.iNet Flint 2."""

    def __init__(self, uci, service_ctl, alloc_tunnel_id, ssh):
        self._uci = uci
        self._service_ctl = service_ctl
        self._alloc_tunnel_id = alloc_tunnel_id
        self._ssh = ssh  # raw exec for wg set/show

    def _next_peer_id(self) -> int:
        """Find the next available numeric peer ID (9001-9050)."""
        existing = self._ssh.exec(
            "uci show wireguard 2>/dev/null | grep '=peers' | "
            "sed \"s/wireguard\\.peer_\\([0-9]*\\)=peers/\\1/\" | grep '^[0-9]'"
        )
        used = set()
        for line in existing.strip().splitlines():
            try:
                used.add(int(line.strip()))
            except ValueError:
                pass
        for pid in range(9001, 9051):
            if pid not in used:
                return pid
        raise RuntimeError("No available peer IDs (max 50 Flint VPN Manager WireGuard configs)")

    def upload_wireguard_config(
        self,
        profile_name: str,
        private_key: str,
        public_key: str,
        endpoint: str,
        address: str = "10.2.0.2/32",
        dns: str = "10.2.0.1",
        allowed_ips: str = "0.0.0.0/0",
        mtu: int = 1420,
        keepalive: int = 25,
        ipv6: bool = False,
    ) -> dict:
        """Create a WireGuard peer config and route policy rule on the router."""
        peer_num = self._next_peer_id()
        peer_id = f"peer_{peer_num}"
        group_id = "1957"

        self._uci.batch_set(f"wireguard.{peer_id}", {
            "_type": "peers",
            "group_id": group_id,
            "name": profile_name,
            "address_v4": address,
            "private_key": private_key,
            "public_key": public_key,
            "end_point": endpoint,
            "allowed_ips": allowed_ips,
            "dns": dns,
            "presharedkey": "",
            "mtu": str(mtu),
            "persistent_keepalive": str(keepalive),
        }, "wireguard")

        tunnel_id = self._alloc_tunnel_id(self._ssh)
        rule_name = f"fvpn_rule_{peer_num}"
        self._uci.batch_set(f"route_policy.{rule_name}", {
            "_type": "rule",
            "name": profile_name,
            "enabled": "0",
            "killswitch": "1",
            "tunnel_id": str(tunnel_id),
            "via_type": "wireguard",
            "peer_id": str(peer_num),
            "group_id": group_id,
            "from_type": "ipset",
            "from": f"src_mac_{tunnel_id}",
        }, "route_policy")

        return {
            "peer_id": peer_id,
            "peer_num": str(peer_num),
            "group_id": group_id,
            "tunnel_id": tunnel_id,
            "rule_name": rule_name,
            "vpn_protocol": PROTO_WIREGUARD,
            "ipv6": ipv6,
        }

    def update_wireguard_peer_live(
        self,
        peer_id: str,
        rule_name: str,
        private_key: str,
        public_key: str,
        endpoint: str,
        dns: str = "10.2.0.1",
    ):
        """Update an existing WireGuard peer in place AND apply it live."""
        old_public_key = self._ssh.exec(
            f"uci -q get wireguard.{peer_id}.public_key 2>/dev/null || true"
        ).strip()

        self._ssh.exec(
            f"uci set wireguard.{peer_id}.private_key='{private_key}' && "
            f"uci set wireguard.{peer_id}.public_key='{public_key}' && "
            f"uci set wireguard.{peer_id}.end_point='{endpoint}' && "
            f"uci set wireguard.{peer_id}.dns='{dns}' && "
            "uci commit wireguard"
        )

        iface = ""
        try:
            iface = self._ssh.exec(
                f"uci -q get route_policy.{rule_name}.via 2>/dev/null || true"
            ).strip()
        except Exception:
            iface = ""
        if not iface or not iface.startswith("wgclient"):
            return

        try:
            wg_check = self._ssh.exec(
                f"wg show {iface} 2>/dev/null | head -1 || true"
            ).strip()
        except Exception:
            wg_check = ""
        if not wg_check.startswith("interface:"):
            return

        cmd_parts = [f"wg set {iface}"]
        cmd_parts.append(
            f"peer {public_key}"
            f" allowed-ips 0.0.0.0/0"
            f" endpoint {endpoint}"
            f" persistent-keepalive 25"
        )
        if old_public_key and old_public_key != public_key:
            cmd_parts.append(f"peer {old_public_key} remove")
        try:
            self._ssh.exec(" ".join(cmd_parts))
        except Exception:
            pass

    def delete_wireguard_config(self, peer_id: str, rule_name: str):
        """Remove a WireGuard config and route policy rule."""
        self._uci.set(f"route_policy.{rule_name}.enabled", "0")
        self._uci.commit("route_policy")
        self._service_ctl.restart("vpn-client")
        self._uci.delete(f"route_policy.{rule_name}")
        self._uci.commit("route_policy")
        self._uci.delete(f"wireguard.{peer_id}")
        self._uci.commit("wireguard")
        self._service_ctl.restart("vpn-client")
