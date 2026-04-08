"""Router API for GL.iNet Flint 2 (GL-MT6000) management via SSH.

Manages WireGuard tunnels, route policies (MAC→tunnel), firewall rules,
DHCP leases, and tunnel health via Paramiko SSH + UCI commands.

Architecture:
    - WireGuard configs stored in /etc/config/wireguard (UCI)
    - Network interfaces in /etc/config/network (proto=wgclient)
    - Route policies in /etc/config/route_policy (MAC→tunnel mapping)
    - DHCP leases read from /tmp/dhcp.leases (dnsmasq format)
    - Firewall rules for no-internet profiles via iptables
    - Tunnel health via `wg show` handshake timestamps
    - Changes applied via `rtp2.sh` (route policy) or `ifup`/`ifdown`
"""

import re
import time
from typing import Optional

import paramiko

import profile_store as ps

# WireGuard mark base for route policy (matches rtp2.sh)
WG_MARK_BASE = 0x1000

# Max simultaneous WireGuard client interfaces (firmware limit)
MAX_WG_INTERFACES = 5


class RouterAPI:
    """SSH-based API for managing the GL.iNet Flint 2 router."""

    def __init__(
        self,
        host: str,
        password: Optional[str] = None,
        username: str = "root",
        port: int = 22,
        key_filename: Optional[str] = None,
    ):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.key_filename = key_filename
        self._client: Optional[paramiko.SSHClient] = None

    def connect(self):
        """Establish SSH connection to the router.

        Tries key-based auth first (if key_filename provided), falls back to password.
        Also tries default SSH keys from ~/.ssh/ if no explicit method specified.
        """
        if self._client is not None:
            try:
                self._client.exec_command("echo ok", timeout=5)
                return  # Already connected
            except Exception:
                self._client = None

        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs = {
            "hostname": self.host,
            "port": self.port,
            "username": self.username,
            "timeout": 10,
        }

        if self.key_filename:
            connect_kwargs["key_filename"] = self.key_filename
        elif self.password:
            connect_kwargs["password"] = self.password
            connect_kwargs["look_for_keys"] = True
        else:
            # Try default SSH keys
            connect_kwargs["look_for_keys"] = True

        self._client.connect(**connect_kwargs)

    def write_file(self, remote_path: str, content: str):
        """Write a file to the router via SSH stdin pipe.

        Sends content directly through the SSH channel's stdin to avoid
        all shell escaping, heredoc, and encoding issues.
        """
        self.connect()
        # Use cat to write stdin to file — no escaping needed
        _, stdout, stderr = self._client.exec_command(
            f"cat > {remote_path}", timeout=30
        )
        stdout.channel.sendall(content.encode("utf-8"))
        stdout.channel.shutdown_write()
        stdout.channel.recv_exit_status()

    def disconnect(self):
        """Close SSH connection."""
        if self._client:
            self._client.close()
            self._client = None

    def exec(self, command: str, timeout: int = 30) -> str:
        """Execute a command via SSH and return stdout.

        Automatically reconnects if the SSH connection was dropped.
        Raises RuntimeError if the command exits with non-zero status.
        """
        for attempt in range(2):
            try:
                self.connect()
                _, stdout, stderr = self._client.exec_command(command, timeout=timeout)
                exit_code = stdout.channel.recv_exit_status()
                out = stdout.read().decode("utf-8", errors="replace").strip()
                err = stderr.read().decode("utf-8", errors="replace").strip()
                if exit_code != 0 and err:
                    raise RuntimeError(f"Command failed (exit {exit_code}): {err}")
                return out
            except (ConnectionResetError, EOFError, paramiko.SSHException) as e:
                if attempt == 0:
                    self._client = None  # Force reconnect
                    continue
                raise RuntimeError(f"SSH connection lost: {e}") from e

    # ── DHCP Leases ───────────────────────────────────────────────────────

    def get_dhcp_leases(self) -> list[dict]:
        """Parse DHCP leases from /tmp/dhcp.leases.

        Returns list of dicts with: mac, ip, hostname, expiry (unix timestamp).
        """
        raw = self.exec("cat /tmp/dhcp.leases 2>/dev/null || echo ''")
        leases = []
        for line in raw.strip().splitlines():
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 4:
                leases.append({
                    "expiry": int(parts[0]),
                    "mac": parts[1].lower(),
                    "ip": parts[2],
                    "hostname": parts[3] if parts[3] != "*" else "",
                })
        return leases

    def get_client_details(self) -> dict:
        """Get rich client data from GL.iNet's client tracking.

        Returns dict keyed by lowercase MAC with: name, alias, device_class,
        online, iface (2.4G/5G/cable), rx (bytes/s), tx (bytes/s),
        total_rx, total_tx, ip, signal_dbm, link_speed_mbps.
        """
        result = {}

        # GL.iNet client list (live stats: speed, traffic, online status)
        try:
            raw = self.exec("ubus call gl-clients list 2>/dev/null || echo '{}'")
            import json
            data = json.loads(raw)
            for mac_upper, info in data.get("clients", {}).items():
                mac = mac_upper.lower()
                result[mac] = {
                    "name": info.get("name", ""),
                    "online": info.get("online", False),
                    "iface": info.get("iface", ""),
                    "rx_speed": info.get("rx", 0),      # bytes/s
                    "tx_speed": info.get("tx", 0),      # bytes/s
                    "total_rx": int(info.get("total_rx", 0)),
                    "total_tx": int(info.get("total_tx", 0)),
                    "ip": info.get("ip", ""),
                }
        except Exception:
            pass

        # GL.iNet client config (user-set alias and device class)
        try:
            raw = self.exec(
                "uci show gl-client 2>/dev/null | grep -E 'mac|alias|class'"
            )
            current_mac = None
            for line in raw.strip().splitlines():
                if ".mac=" in line:
                    current_mac = line.split("=", 1)[1].strip("'").lower()
                    if current_mac not in result:
                        result[current_mac] = {}
                elif ".alias=" in line and current_mac:
                    result[current_mac]["alias"] = line.split("=", 1)[1].strip("'")
                elif ".class=" in line and current_mac:
                    result[current_mac]["device_class"] = line.split("=", 1)[1].strip("'")
        except Exception:
            pass

        # WiFi signal strength from iwinfo
        try:
            raw = self.exec(
                "for iface in $(iwinfo 2>&1 | grep ESSID | awk '{print $1}'); do "
                "iwinfo $iface assoclist 2>&1; done"
            )
            current_mac = None
            for line in raw.strip().splitlines():
                line = line.strip()
                # MAC line: "A4:F9:33:1C:B6:78  -18 dBm / ..."
                if "dBm" in line and len(line) > 17 and line[2] == ":":
                    parts = line.split()
                    current_mac = parts[0].lower()
                    if current_mac not in result:
                        result[current_mac] = {}
                    try:
                        result[current_mac]["signal_dbm"] = int(parts[1])
                    except (ValueError, IndexError):
                        pass
                # TX line with link speed
                elif line.startswith("TX:") and current_mac:
                    try:
                        speed_str = line.split(",")[0].replace("TX:", "").strip()
                        speed = float(speed_str.split()[0])
                        result[current_mac]["link_speed_mbps"] = speed
                    except (ValueError, IndexError):
                        pass
        except Exception:
            pass

        return result

    # ── WireGuard Config Management ───────────────────────────────────────

    def _next_tunnel_id(self) -> int:
        """Find the next available tunnel_id for route policy."""
        existing = self.exec(
            "uci show route_policy 2>/dev/null | grep 'tunnel_id=' | "
            "sed \"s/.*='\\([^']*\\)'/\\1/\""
        )
        used = set()
        for line in existing.strip().splitlines():
            try:
                used.add(int(line.strip()))
            except ValueError:
                pass
        # Start from 300 to avoid conflicts with built-in IDs
        for tid in range(300, 400):
            if tid not in used:
                return tid
        raise RuntimeError("No available tunnel IDs")

    def _next_peer_id(self) -> int:
        """Find the next available numeric peer ID for GL.iNet-compatible naming.

        Uses range 9001-9099 to avoid conflicts with GL.iNet's own peer numbering.
        """
        existing = self.exec(
            "uci show wireguard 2>/dev/null | grep '=peers' | "
            "sed \"s/wireguard\\.peer_\\([0-9]*\\)=peers/\\1/\" | grep '^[0-9]'"
        )
        used = set()
        for line in existing.strip().splitlines():
            try:
                used.add(int(line.strip()))
            except ValueError:
                pass
        # Use 9001-9050 for WireGuard to avoid collisions with OpenVPN IDs (9051-9099).
        for pid in range(9001, 9051):
            if pid not in used:
                return pid
        raise RuntimeError("No available peer IDs (max 50 FlintVPN WireGuard configs)")

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
    ) -> dict:
        """Create a WireGuard peer config and network interface on the router.

        Uses GL.iNet-compatible naming (peer_XXXX under group_1957 "FromApp")
        so configs are visible in the GL.iNet router dashboard as a fallback.

        Args:
            profile_name: Human-readable name (used in the config's name field)
            private_key: WireGuard private key (base64)
            public_key: Server's WireGuard public key (base64)
            endpoint: Server endpoint (ip:port)
            address: Client tunnel address
            dns: DNS server for the tunnel
            allowed_ips: Allowed IPs (typically 0.0.0.0/0)
            mtu: MTU value
            keepalive: Persistent keepalive interval in seconds

        Returns:
            Dict with: interface_name, peer_id, group_id, tunnel_id, rule_name
        """
        # GL.iNet-compatible naming: peer_XXXX under group_1957 (FromApp/manual)
        peer_num = self._next_peer_id()
        peer_id = f"peer_{peer_num}"
        group_id = "1957"  # GL.iNet's "FromApp" group for manual configs

        # Create WireGuard peer config (batched)
        self.exec(
            f"uci set wireguard.{peer_id}=peers && "
            f"uci set wireguard.{peer_id}.group_id='{group_id}' && "
            f"uci set wireguard.{peer_id}.name='{profile_name}' && "
            f"uci set wireguard.{peer_id}.address_v4='{address}' && "
            f"uci set wireguard.{peer_id}.private_key='{private_key}' && "
            f"uci set wireguard.{peer_id}.public_key='{public_key}' && "
            f"uci set wireguard.{peer_id}.end_point='{endpoint}' && "
            f"uci set wireguard.{peer_id}.allowed_ips='{allowed_ips}' && "
            f"uci set wireguard.{peer_id}.dns='{dns}' && "
            f"uci set wireguard.{peer_id}.presharedkey='' && "
            f"uci set wireguard.{peer_id}.mtu='{mtu}' && "
            f"uci set wireguard.{peer_id}.persistent_keepalive='{keepalive}' && "
            "uci commit wireguard"
        )

        # Create route policy rule (batched)
        # IMPORTANT: via_type MUST be 'wireguard' (not 'wgclient') for rtp2.sh
        # to recognize it. peer_id and group_id MUST be set so rtp2.sh can
        # match the rule to the wireguard peer and create the network interface.
        # We do NOT create the network interface ourselves — vpn-client does that.
        tunnel_id = self._next_tunnel_id()
        rule_name = f"fvpn_rule_{peer_num}"
        self.exec(
            f"uci set route_policy.{rule_name}=rule && "
            f"uci set route_policy.{rule_name}.name='{profile_name}' && "
            f"uci set route_policy.{rule_name}.enabled='0' && "
            f"uci set route_policy.{rule_name}.killswitch='1' && "
            f"uci set route_policy.{rule_name}.tunnel_id='{tunnel_id}' && "
            f"uci set route_policy.{rule_name}.via_type='wireguard' && "
            f"uci set route_policy.{rule_name}.peer_id='{peer_num}' && "
            f"uci set route_policy.{rule_name}.group_id='{group_id}' && "
            f"uci set route_policy.{rule_name}.from_type='ipset' && "
            f"uci set route_policy.{rule_name}.from='src_mac_{tunnel_id}' && "
            "uci commit route_policy"
        )

        return {
            "peer_id": peer_id,
            "peer_num": str(peer_num),
            "group_id": group_id,
            "tunnel_id": tunnel_id,
            "rule_name": rule_name,
        }

    # ── OpenVPN Config Management ──────────────────────────────────────────

    def _next_ovpn_client_id(self) -> int:
        """Find the next available numeric client ID for OpenVPN configs.

        Uses range 9001-9099 to avoid conflicts with GL.iNet's own numbering.
        """
        existing = self.exec(
            "uci show ovpnclient 2>/dev/null | grep '=clients' | "
            "sed 's/ovpnclient\\.\\([0-9_]*\\)=clients/\\1/'"
        )
        used = set()
        for line in existing.strip().splitlines():
            # Client IDs are in format "groupid_clientid"
            parts = line.strip().split("_")
            if len(parts) >= 2:
                try:
                    used.add(int(parts[1]))
                except ValueError:
                    pass
        # Start from 9051 to avoid collisions with WireGuard peer IDs (9001-9049).
        # The router's setup_instance_via.lua matches instances by peer_id without
        # checking protocol, so overlapping IDs cause WG rules to bind to OVPN interfaces.
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
        """Create an OpenVPN client config on the router.

        Uses GL.iNet-compatible naming under group 28216 (FromApp/manual)
        so configs are visible in the router dashboard.

        Args:
            profile_name: Human-readable name
            ovpn_config: Full .ovpn config file content
            username: ProtonVPN OpenVPN username (with feature suffix)
            password: ProtonVPN OpenVPN password

        Returns:
            Dict with: client_id, client_uci_id, group_id, tunnel_id, rule_name
        """
        group_id = "28216"  # GL.iNet's "FromApp" group for manual OpenVPN configs
        client_num = self._next_ovpn_client_id()
        client_uci_id = f"{group_id}_{client_num}"
        profile_dir = f"/etc/openvpn/profiles/{client_uci_id}"

        # Create the profile directory and write config + auth files
        self.exec(f"mkdir -p {profile_dir}/auth")

        # Write files via SFTP to avoid heredoc/escaping issues with certs
        ovpn_config_fixed = ovpn_config.replace("{CLIENT_ID}", client_uci_id)
        self.write_file(f"{profile_dir}/config.ovpn", ovpn_config_fixed)
        self.write_file(
            f"{profile_dir}/auth/username_password.txt",
            f"{username}\n{password}\n"
        )
        self.exec(f"chmod 600 {profile_dir}/auth/username_password.txt")

        # Create UCI client entry
        self.exec(
            f"uci set ovpnclient.{client_uci_id}=clients && "
            f"uci set ovpnclient.{client_uci_id}.group_id='{group_id}' && "
            f"uci set ovpnclient.{client_uci_id}.client_id='{client_num}' && "
            f"uci set ovpnclient.{client_uci_id}.name='{profile_name}' && "
            f"uci set ovpnclient.{client_uci_id}.path='{profile_dir}/config.ovpn' && "
            f"uci set ovpnclient.{client_uci_id}.proto='udp' && "
            f"uci set ovpnclient.{client_uci_id}.client_auth='1' && "
            "uci commit ovpnclient"
        )

        # Create route policy rule
        tunnel_id = self._next_tunnel_id()
        rule_name = f"fvpn_rule_ovpn_{client_num}"
        self.exec(
            f"uci set route_policy.{rule_name}=rule && "
            f"uci set route_policy.{rule_name}.name='{profile_name}' && "
            f"uci set route_policy.{rule_name}.enabled='0' && "
            f"uci set route_policy.{rule_name}.killswitch='1' && "
            f"uci set route_policy.{rule_name}.tunnel_id='{tunnel_id}' && "
            f"uci set route_policy.{rule_name}.via_type='openvpn' && "
            f"uci set route_policy.{rule_name}.group_id='{group_id}' && "
            f"uci set route_policy.{rule_name}.client_id='{client_num}' && "
            f"uci set route_policy.{rule_name}.from_type='ipset' && "
            f"uci set route_policy.{rule_name}.from='src_mac_{tunnel_id}' && "
            "uci commit route_policy"
        )

        return {
            "client_id": str(client_num),
            "client_uci_id": client_uci_id,
            "group_id": group_id,
            "tunnel_id": tunnel_id,
            "rule_name": rule_name,
            "vpn_protocol": "openvpn",
        }

    def delete_openvpn_config(self, client_uci_id: str, rule_name: str):
        """Remove an OpenVPN client config and route policy rule."""
        # Disable rule
        self.exec(
            f"uci set route_policy.{rule_name}.enabled='0' 2>/dev/null; "
            "uci commit route_policy"
        )

        # Let vpn-client clean up the interface
        self.exec("/etc/init.d/vpn-client restart &>/dev/null")

        # Delete rule and client config
        self.exec(f"uci delete route_policy.{rule_name} 2>/dev/null; uci commit route_policy")
        self.exec(f"uci delete ovpnclient.{client_uci_id} 2>/dev/null; uci commit ovpnclient")

        # Remove config files
        profile_dir = f"/etc/openvpn/profiles/{client_uci_id}"
        self.exec(f"rm -rf {profile_dir} 2>/dev/null")

        # Restart to apply
        self.exec("/etc/init.d/vpn-client restart &>/dev/null")

    def delete_wireguard_config(self, peer_id: str, rule_name: str):
        """Remove a WireGuard config and route policy rule.

        Disables the rule first, then restarts vpn-client to clean up
        the network interface. Never deletes network interfaces directly.
        """
        # Disable rule first
        self.exec(
            f"uci set route_policy.{rule_name}.enabled='0' 2>/dev/null; "
            "uci commit route_policy"
        )

        # Restart vpn-client to let it clean up the network interface
        self.exec("/etc/init.d/vpn-client restart &>/dev/null")

        # Delete rule and peer config
        self.exec(f"uci delete route_policy.{rule_name} 2>/dev/null; uci commit route_policy")
        self.exec(f"uci delete wireguard.{peer_id} 2>/dev/null; uci commit wireguard")

        # Restart again to apply final state
        self.exec("/etc/init.d/vpn-client restart &>/dev/null")

    # ── Tunnel Control ────────────────────────────────────────────────────
    #
    # CRITICAL: We NEVER create network interfaces (wgclientN) directly.
    # We NEVER call rtp2.sh directly. We NEVER call ifup/ifdown.
    #
    # The GL.iNet vpn-client system (rtp2.sh + setup_instance_via.lua)
    # manages network interfaces. We only:
    #   1. Set route policy rules (enabled/disabled, via_type, peer_id, etc.)
    #   2. Run `/etc/init.d/vpn-client restart` to apply changes
    #
    # The vpn-client reads our rules, finds the matching wireguard peer,
    # creates/destroys the network interface, and sets up routing.

    def bring_tunnel_up(self, rule_name: str, **_kwargs):
        """Bring a VPN tunnel up by enabling its route policy rule.

        The vpn-client service will create the network interface and
        start the WireGuard tunnel automatically.
        """
        # Verify the rule exists
        rule_exists = self.exec(
            f"uci get route_policy.{rule_name}.tunnel_id 2>/dev/null || echo 'MISSING'"
        ).strip()
        if rule_exists == "MISSING":
            raise RuntimeError(f"Route policy rule {rule_name} does not exist.")

        # Enable the rule
        self.exec(
            f"uci set route_policy.{rule_name}.enabled='1' && "
            "uci commit route_policy"
        )

        # Let vpn-client create the interface and start the tunnel
        self.exec("/etc/init.d/vpn-client restart")

    def bring_tunnel_down(self, rule_name: str, **_kwargs):
        """Bring a VPN tunnel down by disabling its route policy rule.

        Disables kill switch before disabling the rule to prevent devices
        from losing internet when the tunnel goes down.
        """
        # Disable kill switch first so devices don't lose internet
        self.exec(
            f"uci set route_policy.{rule_name}.killswitch='0' && "
            f"uci set route_policy.{rule_name}.enabled='0' && "
            "uci commit route_policy"
        )

        # Let vpn-client clean up
        self.exec("/etc/init.d/vpn-client restart")

        # Restore kill switch setting (stays saved for next connect)
        self.exec(
            f"uci set route_policy.{rule_name}.killswitch='1' && "
            "uci commit route_policy"
        )

    def get_rule_interface(self, rule_name: str) -> Optional[str]:
        """Get the network interface name assigned to a rule by vpn-client.

        Returns the interface name (e.g. 'wgclient1') or None if not assigned.
        """
        via = self.exec(
            f"uci get route_policy.{rule_name}.via 2>/dev/null || echo ''"
        ).strip()
        return via if via and (via.startswith("wgclient") or via.startswith("ovpnclient")) else None

    def get_tunnel_status(self, rule_name: str) -> dict:
        """Get tunnel status by rule name.

        Returns dict with: up, connecting, interface, handshake_seconds_ago, rx_bytes, tx_bytes
        """
        result = {"up": False, "connecting": False, "interface": None, "handshake_seconds_ago": None, "rx_bytes": 0, "tx_bytes": 0}

        # Check if rule is enabled
        enabled = self.exec(
            f"uci get route_policy.{rule_name}.enabled 2>/dev/null || echo '0'"
        ).strip()
        if enabled != "1":
            return result

        iface = self.get_rule_interface(rule_name)
        if not iface:
            # Rule enabled but no interface yet — connecting
            result["connecting"] = True
            return result

        result["interface"] = iface

        # Check if interface is up
        up_check = self.exec(
            f"ifstatus {iface} 2>/dev/null | "
            "jsonfilter -e '@.up' 2>/dev/null || echo 'false'"
        )
        result["up"] = up_check.strip().lower() == "true"

        if not result["up"]:
            # Interface exists but not up — connecting
            if iface.startswith("wgclient"):
                state = self.exec(f"cat /tmp/wireguard/{iface}_state 2>/dev/null || echo ''").strip()
                if state == "connecting":
                    result["connecting"] = True
            elif iface.startswith("ovpnclient"):
                # Check if openvpn process is running for this interface
                proc = self.exec(f"ps | grep 'openvpn.*{iface}' | grep -v grep | head -1").strip()
                if proc:
                    result["connecting"] = True
            return result

        if iface.startswith("wgclient"):
            # WireGuard: get handshake info
            wg_output = self.exec(f"wg show {iface} latest-handshakes 2>/dev/null || echo ''")
            for line in wg_output.strip().splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        handshake_ts = int(parts[1])
                        if handshake_ts > 0:
                            result["handshake_seconds_ago"] = int(time.time()) - handshake_ts
                    except ValueError:
                        pass
        elif iface.startswith("ovpnclient"):
            # OpenVPN: interface is up = connected (no handshake concept)
            # Set handshake to 0 so health shows green
            result["handshake_seconds_ago"] = 0

        # Get transfer stats
        transfer = self.exec(f"wg show {iface} transfer 2>/dev/null || echo ''")
        for line in transfer.strip().splitlines():
            parts = line.split()
            if len(parts) >= 3:
                try:
                    result["rx_bytes"] = int(parts[1])
                    result["tx_bytes"] = int(parts[2])
                except ValueError:
                    pass

        return result

    def get_tunnel_health(self, rule_name: str) -> str:
        """Get tunnel health as a color/status: green, amber, red, connecting.

        green: handshake within 3 minutes (or OVPN interface up)
        amber: handshake 3-10 minutes ago
        red: no handshake in 10+ minutes or tunnel down
        connecting: tunnel is being established
        """
        status = self.get_tunnel_status(rule_name)
        if status.get("connecting"):
            return "connecting"
        if not status["up"]:
            return "red"
        if status["handshake_seconds_ago"] is None:
            return "red"
        if status["handshake_seconds_ago"] <= 180:
            return "green"
        if status["handshake_seconds_ago"] <= 600:
            return "amber"
        return "red"

    # ── Device Policy (MAC → Tunnel) ──────────────────────────────────────

    def _from_mac_tokens(self, rule_name: str) -> list:
        """Return the raw MAC tokens stored in route_policy.{rule}.from_mac.

        Preserves case so del_list can match exactly. UCI returns list values
        as space-separated tokens; some configs use literal-quoted form.
        """
        raw = self.exec(
            f"uci -q get route_policy.{rule_name}.from_mac 2>/dev/null || echo ''"
        )
        tokens = []
        for token in raw.replace("'", " ").split():
            token = token.strip()
            if ":" in token and len(token) == 17:
                tokens.append(token)
        return tokens

    def set_device_vpn(self, mac: str, rule_name: str):
        """Add a device (by MAC) to a VPN tunnel's route policy rule.

        Uses ipset for immediate effect (no daemon restart) plus uci commit
        for persistence across reboots. Never calls rtp2.sh — that script
        takes locks and can corrupt route policies.
        """
        mac = mac.lower()
        existing_tokens = [t.lower() for t in self._from_mac_tokens(rule_name)]
        if mac in existing_tokens:
            return  # Already assigned
        ipset_name = self.exec(
            f"uci get route_policy.{rule_name}.from 2>/dev/null || echo ''"
        ).strip()
        self.exec(f"uci add_list route_policy.{rule_name}.from_mac='{mac}'")
        self.exec("uci commit route_policy")
        if ipset_name:
            self.exec(f"ipset add {ipset_name} {mac} 2>/dev/null || true")

    def remove_device_from_vpn(self, mac: str, rule_name: str):
        """Remove a device (by MAC) from a VPN tunnel's route policy rule.

        Matches the stored MAC token case-insensitively but uses the EXACT
        stored case in `uci del_list` (UCI requires exact-match for list
        entries). Also tries the ipset in both cases as a safety net.
        """
        mac_lower = mac.lower()
        for token in self._from_mac_tokens(rule_name):
            if token.lower() == mac_lower:
                # Use the EXACT stored case for del_list to match
                self.exec(
                    f"uci del_list route_policy.{rule_name}.from_mac='{token}'"
                )
                self.exec("uci commit route_policy")
                ipset_name = self.exec(
                    f"uci get route_policy.{rule_name}.from 2>/dev/null || echo ''"
                ).strip()
                if ipset_name:
                    # ipset is case-insensitive but try both for safety
                    self.exec(f"ipset del {ipset_name} {token} 2>/dev/null || true")
                    if token != mac_lower:
                        self.exec(f"ipset del {ipset_name} {mac_lower} 2>/dev/null || true")
                return  # Done — there's at most one entry per rule

    def remove_device_from_all_vpn(self, mac: str):
        """Remove a device from ALL FlintVPN route policy rules.

        Iterates every fvpn rule, matches the MAC case-insensitively, and
        deletes using the EXACT stored case so UCI del_list succeeds.
        """
        mac_lower = mac.lower()
        rules = self.get_flint_vpn_rules()
        any_removed = False
        for rule in rules:
            rule_name = rule.get("rule_name", "")
            if not rule_name:
                continue
            tokens = self._from_mac_tokens(rule_name)
            for token in tokens:
                if token.lower() == mac_lower:
                    self.exec(
                        f"uci del_list route_policy.{rule_name}.from_mac='{token}'"
                    )
                    ipset_name = self.exec(
                        f"uci get route_policy.{rule_name}.from 2>/dev/null || echo ''"
                    ).strip()
                    if ipset_name:
                        self.exec(f"ipset del {ipset_name} {token} 2>/dev/null || true")
                        if token != mac_lower:
                            self.exec(f"ipset del {ipset_name} {mac_lower} 2>/dev/null || true")
                    any_removed = True
                    break  # next rule
        if any_removed:
            self.exec("uci commit route_policy")

    # ── No Internet (Firewall) ────────────────────────────────────────────

    def set_device_no_internet(self, mac: str, ip: str):
        """Block a device's WAN traffic while allowing LAN access.

        Creates firewall rules: allow LAN traffic, reject WAN traffic from this IP.
        """
        rule_name = f"fvpn_noinet_{mac.replace(':', '')}"

        # Remove from any VPN policy first
        self.remove_device_from_all_vpn(mac)

        # Batch UCI commands in a single SSH call
        self.exec(
            f"uci set firewall.{rule_name}_lan=rule && "
            f"uci set firewall.{rule_name}_lan.name='FlintVPN NoInternet LAN {mac}' && "
            f"uci set firewall.{rule_name}_lan.src='lan' && "
            f"uci set firewall.{rule_name}_lan.src_ip='{ip}' && "
            f"uci set firewall.{rule_name}_lan.dest='lan' && "
            f"uci set firewall.{rule_name}_lan.target='ACCEPT' && "
            f"uci set firewall.{rule_name}_drop=rule && "
            f"uci set firewall.{rule_name}_drop.name='FlintVPN NoInternet DROP {mac}' && "
            f"uci set firewall.{rule_name}_drop.src='lan' && "
            f"uci set firewall.{rule_name}_drop.src_ip='{ip}' && "
            f"uci set firewall.{rule_name}_drop.dest='wan' && "
            f"uci set firewall.{rule_name}_drop.target='REJECT' && "
            "uci commit firewall && "
            "/etc/init.d/firewall reload &>/dev/null &"
        )

    def remove_device_no_internet(self, mac: str):
        """Remove no-internet firewall rules for a device."""
        rule_name = f"fvpn_noinet_{mac.replace(':', '')}"
        self.exec(f"uci delete firewall.{rule_name}_lan 2>/dev/null")
        self.exec(f"uci delete firewall.{rule_name}_drop 2>/dev/null")
        self.exec("uci commit firewall")
        self.exec("/etc/init.d/firewall reload &>/dev/null &")

    # ── Kill Switch ───────────────────────────────────────────────────────

    def set_kill_switch(self, rule_name: str, enabled: bool):
        """Enable or disable kill switch on a route policy rule.

        When enabled and the tunnel drops, assigned devices lose WAN access.
        Killswitch state is consulted by the next packet — no daemon restart
        or rtp2.sh call needed. uci commit is sufficient for persistence.
        """
        self.exec(
            f"uci set route_policy.{rule_name}.killswitch='{1 if enabled else 0}'"
        )
        self.exec("uci commit route_policy")

    def get_kill_switch(self, rule_name: str) -> bool:
        """Read the live kill switch state for a route policy rule.

        Source of truth is the router's UCI config. Never cached locally.
        """
        ks = self.exec(
            f"uci get route_policy.{rule_name}.killswitch 2>/dev/null || echo '0'"
        ).strip()
        return ks == "1"

    def get_profile_name(self, rule_name: str) -> str:
        """Read the live profile name from route_policy.{rule}.name."""
        return self.exec(
            f"uci get route_policy.{rule_name}.name 2>/dev/null || echo ''"
        ).strip()

    def get_device_assignments(self) -> dict:
        """Return {mac: rule_name} for every device in any FlintVPN rule's from_mac.

        Stage 5: VPN device assignments are router-canonical. This is the live
        source of truth replacing local profile_store.device_assignments.

        Recognizes both named sections (fvpn_rule_*) and anonymous sections
        (@rule[N]) created by the GL.iNet UI when it edits a rule. Filters
        to FlintVPN-managed rules by checking group_id.
        """
        rules = self.get_flint_vpn_rules()
        out = {}
        for rule in rules:
            rule_name = rule.get("rule_name")
            if not rule_name:
                continue
            # from_mac may already be parsed by uci show — could be a string
            # like "'aa:bb:cc:dd:ee:ff' 'cc:dd:ee:ff:00:11'" or a single MAC.
            raw = rule.get("from_mac", "")
            if not raw:
                continue
            for token in raw.replace("'", " ").split():
                token = token.strip().lower()
                if ":" in token and len(token) == 17:
                    out[token] = rule_name
        return out

    def rename_profile(self, rule_name: str, new_name: str,
                       peer_id: str = "", client_uci_id: str = ""):
        """Rename a VPN profile by updating all 3 router UCI fields atomically.

        Stage 4: profile name is router-canonical. The name lives in:
          - route_policy.{rule_name}.name
          - wireguard.{peer_id}.name        (for WireGuard tunnels)
          - ovpnclient.{client_uci_id}.name (for OpenVPN tunnels)

        At least one of peer_id or client_uci_id must be provided.
        """
        # Escape single quotes in the name to avoid shell injection
        safe_name = new_name.replace("'", "'\\''")
        cmds = [f"uci set route_policy.{rule_name}.name='{safe_name}'"]
        commits = ["uci commit route_policy"]
        if peer_id:
            cmds.append(f"uci set wireguard.{peer_id}.name='{safe_name}'")
            commits.append("uci commit wireguard")
        if client_uci_id:
            cmds.append(f"uci set ovpnclient.{client_uci_id}.name='{safe_name}'")
            commits.append("uci commit ovpnclient")
        self.exec(" && ".join(cmds + commits))

    # ── Static DHCP Leases ────────────────────────────────────────────────

    def set_static_lease(self, mac: str, ip: str, hostname: str = ""):
        """Create a static DHCP lease so the device always gets the same IP."""
        mac = mac.lower()
        lease_id = f"fvpn_{mac.replace(':', '')}"

        self.exec(f"uci set dhcp.{lease_id}=host")
        self.exec(f"uci set dhcp.{lease_id}.mac='{mac}'")
        self.exec(f"uci set dhcp.{lease_id}.ip='{ip}'")
        if hostname:
            self.exec(f"uci set dhcp.{lease_id}.name='{hostname}'")
        self.exec("uci commit dhcp")
        self.exec("/etc/init.d/dnsmasq reload &>/dev/null &")

    def remove_static_lease(self, mac: str):
        """Remove a static DHCP lease."""
        lease_id = f"fvpn_{mac.replace(':', '')}"
        self.exec(f"uci delete dhcp.{lease_id} 2>/dev/null; uci commit dhcp")
        self.exec("/etc/init.d/dnsmasq reload &>/dev/null &")

    # ── mDNS Reflection ──────────────────────────────────────────────────

    def setup_mdns_reflection(self, interface_name: str):
        """Enable mDNS/avahi reflection between a WG tunnel and LAN.

        Needed for Chromecast/AirPlay discovery across tunnel boundaries.
        """
        # Check if avahi is installed
        avahi_check = self.exec("which avahi-daemon 2>/dev/null || echo ''")
        if not avahi_check:
            return  # avahi not installed, skip

        # Get the L3 device for this interface
        l3_dev = self.exec(
            f"ifstatus {interface_name} 2>/dev/null | "
            "jsonfilter -e '@.l3_device' 2>/dev/null || echo ''"
        ).strip()

        if not l3_dev:
            return

        # Add to avahi reflector config
        avahi_conf = "/etc/avahi/avahi-daemon.conf"
        self.exec(
            f"grep -q 'enable-reflector=yes' {avahi_conf} 2>/dev/null || "
            f"sed -i 's/enable-reflector=no/enable-reflector=yes/' {avahi_conf} 2>/dev/null"
        )
        self.exec("/etc/init.d/avahi-daemon restart &>/dev/null &")

    # ── Utility ───────────────────────────────────────────────────────────

    def get_flint_vpn_rules(self) -> list[dict]:
        """Get all FlintVPN route policy rules.

        Returns rules whose UCI section starts with 'fvpn_rule' (created by us)
        OR whose group_id matches the FlintVPN groups (1957 for WG, 28216 for OVPN).
        The latter handles the case where the GL.iNet UI replaced our named
        section with an anonymous '@rule[N]' section after editing.

        Returns list of dicts with: rule_name (section name or '@rule[N]'),
        name, enabled, tunnel_id, via, killswitch, from_mac, peer_id, client_id, etc.
        """
        # Pull the entire route_policy config in one SSH call so we can spot
        # FlintVPN-managed rules even if the section was anonymized.
        raw = self.exec("uci show route_policy 2>/dev/null || echo ''")
        rules = {}
        for line in raw.strip().splitlines():
            if not line.strip() or "=" not in line:
                continue
            key, val = line.split("=", 1)
            val = val.strip("'")
            # key format: route_policy.<section>(.<field>)?
            # where <section> may be 'fvpn_rule_9001' or '@rule[4]'
            after_prefix = key[len("route_policy."):] if key.startswith("route_policy.") else key
            if "." in after_prefix:
                section, field = after_prefix.split(".", 1)
            else:
                section = after_prefix
                field = None
            if section not in rules:
                rules[section] = {"rule_name": section}
            if field is not None:
                rules[section][field] = val
            else:
                rules[section]["_section_type"] = val

        # Filter to FlintVPN-managed rules:
        #   - section name starts with 'fvpn_rule' (the names we create), OR
        #   - section is type 'rule' AND group_id is one of FlintVPN's groups
        fvpn_rules = []
        for section, data in rules.items():
            if section.startswith("fvpn_rule"):
                fvpn_rules.append(data)
                continue
            if data.get("_section_type") != "rule":
                continue
            gid = data.get("group_id", "")
            if gid in ("1957", "28216"):  # FromApp groups for WG and OVPN
                fvpn_rules.append(data)
        return fvpn_rules

    def reorder_vpn_rules(self, rule_names: list) -> None:
        """Stage 10: reorder route_policy sections to match the given list.

        Section order in /etc/config/route_policy IS the source of truth for
        VPN display order (after Stage 5). This rewrites the file so subsequent
        `uci show route_policy` queries return sections in the new order, and
        the router evaluates rules in that priority.

        Only the listed rule_names are reordered; other route_policy sections
        (global, defaults, gl_process*) keep their existing positions.
        """
        if not rule_names:
            return
        cmds = []
        for i, rule_name in enumerate(rule_names):
            cmds.append(f"uci reorder route_policy.{rule_name}={i}")
        cmds.append("uci commit route_policy")
        self.exec(" && ".join(cmds))

    def heal_anonymous_rule_section(self, anon_section: str, target_name: str):
        """Rename an anonymous route_policy section back to its FlintVPN name.

        When the GL.iNet UI edits a rule, it sometimes replaces the named
        section (e.g. fvpn_rule_9001) with an anonymous one (@rule[4]).
        This method restores the named section in-place.
        """
        if not anon_section.startswith("@rule"):
            return  # Already named — nothing to do
        if not target_name:
            return
        try:
            self.exec(
                f"uci rename route_policy.{anon_section}={target_name} && "
                f"uci commit route_policy"
            )
        except Exception:
            pass  # Best effort — won't break the read path

    def get_flint_vpn_peers(self) -> list[dict]:
        """Get all FlintVPN WireGuard peer configs (peer_9001 through peer_9099).

        Returns list of dicts with peer UCI fields.
        """
        raw = self.exec(
            "uci show wireguard 2>/dev/null | grep 'wireguard\\.peer_90'"
        )
        peers = {}
        for line in raw.strip().splitlines():
            if not line.strip() or "=" not in line:
                continue
            key, val = line.split("=", 1)
            val = val.strip("'")
            parts = key.split(".")
            if len(parts) >= 3:
                peer_id = parts[1]
                field = parts[2]
                if peer_id not in peers:
                    peers[peer_id] = {"peer_id": peer_id}
                peers[peer_id][field] = val

        return list(peers.values())

    def get_active_interfaces(self) -> list[str]:
        """Get list of active WireGuard client interface names."""
        raw = self.exec(
            "uci show network 2>/dev/null | grep \"proto='wgclient'\" | "
            "cut -d. -f2"
        )
        active = []
        for iface in raw.strip().splitlines():
            iface = iface.strip()
            if iface:
                disabled = self.exec(
                    f"uci get network.{iface}.disabled 2>/dev/null || echo '1'"
                ).strip()
                if disabled != "1":
                    active.append(iface)
        return active

    # ── LAN Access Control ───────────────────────────────────────────────

    def lan_init_chain(self, lan_subnet: str = "192.168.8.0/24",
                       gateway_ip: str = "192.168.8.1"):
        """Create fvpn_lan chain in FORWARD with base rules. Idempotent."""
        self.exec(
            "iptables -N fvpn_lan 2>/dev/null; "
            "iptables -C FORWARD -j fvpn_lan 2>/dev/null || "
            "iptables -I FORWARD 1 -j fvpn_lan"
        )

    def lan_sync_group_ipsets(self, short_id: str, macs: list[str],
                               ips: list[str]):
        """Create/update MAC and IP ipsets for a group."""
        mac_set = f"fvpn_lmac_{short_id}"
        ip_set = f"fvpn_lip_{short_id}"

        cmds = [
            f"ipset create {mac_set} hash:mac -exist",
            f"ipset flush {mac_set}",
            f"ipset create {ip_set} hash:ip -exist",
            f"ipset flush {ip_set}",
        ]
        for mac in macs:
            cmds.append(f"ipset add {mac_set} {mac}")
        for ip in ips:
            if ip:
                cmds.append(f"ipset add {ip_set} {ip}")

        self.exec(" && ".join(cmds))

    def lan_destroy_group_ipsets(self, short_id: str):
        """Remove both ipsets for a group."""
        self.exec(
            f"ipset destroy fvpn_lmac_{short_id} 2>/dev/null; "
            f"ipset destroy fvpn_lip_{short_id} 2>/dev/null"
        )

    def lan_rebuild_rules(self, rules: list[str],
                          lan_subnet: str = "192.168.8.0/24",
                          gateway_ip: str = "192.168.8.1"):
        """Flush and rebuild all rules in the fvpn_lan chain.

        Args:
            rules: List of iptables rule strings (without 'iptables -A fvpn_lan')
            lan_subnet: LAN subnet in CIDR notation
            gateway_ip: Router gateway IP (always allowed)
        """
        cmds = ["iptables -F fvpn_lan"]

        # Base rules
        cmds.append(
            "iptables -A fvpn_lan -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN"
        )
        cmds.append(f"iptables -A fvpn_lan ! -s {lan_subnet} -j RETURN")
        cmds.append(f"iptables -A fvpn_lan ! -d {lan_subnet} -j RETURN")
        cmds.append(f"iptables -A fvpn_lan -s {gateway_ip} -j RETURN")
        cmds.append(f"iptables -A fvpn_lan -d {gateway_ip} -j RETURN")

        # Device override + group rules
        for rule in rules:
            cmds.append(f"iptables -A fvpn_lan {rule}")

        self.exec(" && ".join(cmds))

    def lan_cleanup_all(self):
        """Remove the fvpn_lan chain and all fvpn_l* ipsets."""
        self.exec(
            "iptables -D FORWARD -j fvpn_lan 2>/dev/null; "
            "iptables -F fvpn_lan 2>/dev/null; "
            "iptables -X fvpn_lan 2>/dev/null"
        )
        # Destroy all our ipsets
        raw = self.exec("ipset list -n 2>/dev/null || echo ''")
        for name in raw.strip().splitlines():
            name = name.strip()
            if name.startswith("fvpn_lmac_") or name.startswith("fvpn_lip_"):
                self.exec(f"ipset destroy {name} 2>/dev/null")


def generate_lan_rules(data: dict, device_ips: Optional[dict] = None) -> tuple[list, dict]:
    """Generate iptables rules and ipset contents from profile store data.

    Stage 8: device_ips is now passed in by the caller (sourced live from
    router DHCP leases) instead of read from profile_store. The legacy field
    is still honored as a fallback for tests / backwards compat.

    Returns:
        (rules, ipsets) where:
        - rules: list of iptables rule arg strings for fvpn_lan chain
          (device overrides first, then group rules)
        - ipsets: {short_id: (macs, ips)} for each group needing an ipset
    """
    rules_device = []  # Higher priority
    rules_group = []
    ipsets = {}  # short_id -> (macs, ips)

    # Build group membership maps
    profiles = {p["id"]: p for p in data.get("profiles", [])}
    assignments = data.get("device_assignments", {})
    if device_ips is None:
        device_ips = data.get("device_ips", {})  # legacy fallback
    overrides = data.get("device_lan_overrides", {})

    # Group members: {profile_id: [(mac, ip), ...]}
    group_members = {}
    for mac, pid in assignments.items():
        if pid and pid in profiles:
            group_members.setdefault(pid, []).append(
                (mac, device_ips.get(mac, ""))
            )

    def _short_id(profile_id: str) -> str:
        return profile_id[:8]

    # Determine which groups need ipsets (any non-allowed setting references them)
    groups_needing_ipsets = set()

    # Check group-level settings
    for pid, p in profiles.items():
        lan = p.get("lan_access", {})
        if lan.get("outbound") == "group_only" or lan.get("inbound") == "group_only":
            groups_needing_ipsets.add(pid)

    # Check device overrides that use group_only
    for mac, ovr in overrides.items():
        pid = assignments.get(mac)
        if pid and (ovr.get("outbound") == "group_only" or ovr.get("inbound") == "group_only"):
            groups_needing_ipsets.add(pid)

    # Build ipsets for groups that need them
    for pid in groups_needing_ipsets:
        members = group_members.get(pid, [])
        macs = [m for m, _ in members]
        ips = [ip for _, ip in members if ip]
        ipsets[_short_id(pid)] = (macs, ips)

    # Generate rules for each device
    all_restricted_macs = set()

    for mac, pid in assignments.items():
        if not pid or pid not in profiles:
            continue

        effective = ps.get_effective_lan_access(mac, data)
        ip = device_ips.get(mac, "")
        short = _short_id(pid)
        has_override = mac in overrides and overrides[mac].get("outbound") is not None or \
                       mac in overrides and overrides[mac].get("inbound") is not None

        target_list = rules_device if has_override else rules_group

        # Outbound rules (MAC-based, always reliable)
        if effective["outbound"] == "blocked":
            target_list.append(f"-m mac --mac-source {mac} -j DROP")
            all_restricted_macs.add(mac)
        elif effective["outbound"] == "group_only":
            target_list.append(
                f"-m mac --mac-source {mac} "
                f"-m set ! --match-set fvpn_lip_{short} dst -j DROP"
            )
            all_restricted_macs.add(mac)

        # Inbound rules (IP-based, needs IP)
        if ip and effective["inbound"] == "blocked":
            target_list.append(f"-d {ip} -j DROP")
            all_restricted_macs.add(mac)
        elif ip and effective["inbound"] == "group_only":
            target_list.append(
                f"-d {ip} "
                f"-m set ! --match-set fvpn_lmac_{short} src -j DROP"
            )
            all_restricted_macs.add(mac)

    # Device overrides first (higher priority), then group rules
    return rules_device + rules_group, ipsets
