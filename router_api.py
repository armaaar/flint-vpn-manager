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

    def read_file(self, remote_path: str) -> Optional[str]:
        """Read a file from the router. Returns None if missing or empty."""
        try:
            raw = self.exec(f"cat {remote_path} 2>/dev/null || true")
        except Exception:
            return None
        return raw if raw else None

    def get_router_fingerprint(self) -> str:
        """Stable identifier for the physical router (br-lan MAC)."""
        try:
            return self.exec(
                "cat /sys/class/net/br-lan/address 2>/dev/null || true"
            ).strip()
        except Exception:
            return ""

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
        """Find the next available tunnel_id.

        Checks BOTH route_policy UCI rules (kernel WG + OVPN) AND
        existing src_mac_* ipsets (proton-wg tunnels) to avoid collisions.
        """
        # IDs used by route_policy (kernel WG + OVPN)
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
        # IDs used by proton-wg (ipset names are src_mac_<tunnel_id>)
        ipsets = self.exec(
            "ipset list -n 2>/dev/null | grep '^src_mac_'"
        )
        for line in ipsets.strip().splitlines():
            line = line.strip()
            if line.startswith("src_mac_"):
                try:
                    used.add(int(line.split("_")[-1]))
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
            "vpn_protocol": "wireguard",
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

    def update_wireguard_peer_live(
        self,
        peer_id: str,
        rule_name: str,
        private_key: str,
        public_key: str,
        endpoint: str,
        dns: str = "10.2.0.1",
    ):
        """Update an existing WireGuard peer in place AND apply it live.

        WireGuard's design supports hot peer add/remove via `wg set` without
        tearing down the interface. The flow:
          1. Read the old peer's public key from UCI (so we can remove it).
          2. Update the peer's UCI fields (private_key, public_key, end_point,
             dns) so the new config persists across reboots and survives a
             vpn-client restart from elsewhere.
          3. If the rule is mapped to a running wgclient<N> interface,
             atomically swap peers via `wg set`: add the new peer first,
             then remove the old one. The data plane keeps flowing through
             the new peer immediately — no interface tear-down, no flicker.
          4. If the rule isn't currently running, just commit UCI; the next
             vpn-client restart will pick it up.

        Used by `_switch_server` for the WireGuard fast path. Avoids the
        delete-and-recreate flicker that the OpenVPN path still has.
        """
        # 1. Capture the old public key BEFORE we overwrite it.
        old_public_key = self.exec(
            f"uci -q get wireguard.{peer_id}.public_key 2>/dev/null || true"
        ).strip()

        # 2. Update UCI for persistence (idempotent).
        self.exec(
            f"uci set wireguard.{peer_id}.private_key='{private_key}' && "
            f"uci set wireguard.{peer_id}.public_key='{public_key}' && "
            f"uci set wireguard.{peer_id}.end_point='{endpoint}' && "
            f"uci set wireguard.{peer_id}.dns='{dns}' && "
            "uci commit wireguard"
        )

        # 3. Find the live wgclient interface (if any) bound to this rule.
        iface = ""
        try:
            iface = self.exec(
                f"uci -q get route_policy.{rule_name}.via 2>/dev/null || true"
            ).strip()
        except Exception:
            iface = ""
        if not iface or not iface.startswith("wgclient"):
            return  # Not running — UCI commit alone is enough.

        # Verify the interface is actually up before trying to wg set on it.
        try:
            wg_check = self.exec(
                f"wg show {iface} 2>/dev/null | head -1 || true"
            ).strip()
        except Exception:
            wg_check = ""
        if not wg_check.startswith("interface:"):
            return  # Interface not running — nothing to update live.

        # 4. Atomic peer swap. wg set processes args left-to-right, so we
        # add the new peer first (so traffic has somewhere to go), then
        # remove the old one. This is the WireGuard-recommended hot-swap.
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
            self.exec(" ".join(cmd_parts))
        except Exception as e:
            # Best-effort; if wg set fails the UCI is already updated and
            # the next vpn-client restart will eventually apply it.
            pass

    def update_openvpn_client(
        self,
        client_uci_id: str,
        ovpn_config: str,
        username: str,
        password: str,
    ):
        """Update an existing OpenVPN client's config file in place.

        Same purpose as `update_wireguard_peer`: swap to a different server
        without deleting the route_policy rule. Overwrites the .ovpn file
        and the auth file under /etc/openvpn/profiles/<client_uci_id>/.
        After the file write, vpn-client must be restarted.
        """
        profile_dir = f"/etc/openvpn/profiles/{client_uci_id}"
        ovpn_config_fixed = ovpn_config.replace("{CLIENT_ID}", client_uci_id)
        self.write_file(f"{profile_dir}/config.ovpn", ovpn_config_fixed)
        self.write_file(
            f"{profile_dir}/auth/username_password.txt",
            f"{username}\n{password}\n",
        )
        self.exec(f"chmod 600 {profile_dir}/auth/username_password.txt")

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

    # ── proton-wg (WireGuard TCP/TLS) Management ──────────────────────────
    #
    # proton-wg is a userspace WireGuard implementation (ProtonVPN's
    # wireguard-go fork) that supports TCP and TLS transports. It runs
    # as a standalone process on the router, completely outside vpn-client.
    # FlintVPN manages its full lifecycle: process, interface, routing,
    # firewall, and ipset.
    #
    # Fwmark range: 0x6000, 0x7000, 0x9000, 0xf000 (4 slots)
    # Interface names: protonwg0–protonwg3
    # Routing tables: 1006, 1007, 1009, 1015 (derived from mark >> 12)

    PROTON_WG_MARKS = ["0x6000", "0x7000", "0x9000", "0xf000"]
    PROTON_WG_DIR = "/etc/fvpn/protonwg"
    PROTON_WG_BIN = "/usr/bin/proton-wg"

    def _next_proton_wg_slot(self) -> tuple[str, str, int]:
        """Find the next available proton-wg slot.

        Returns (interface_name, mark_hex, table_num).
        Checks both live interfaces AND config files to avoid slot collisions
        (a disconnected tunnel still owns its slot if its config exists).
        Cleans up truly orphaned interfaces (no config + no process).
        Raises RuntimeError if all 4 slots are genuinely in use.
        """
        # Check live interfaces
        existing_ifaces = self.exec(
            "ip link show 2>/dev/null | grep protonwg | awk -F: '{print $2}' | tr -d ' '"
        ).strip().splitlines()
        live = set(x.strip() for x in existing_ifaces if x.strip())

        # Check config files (a conf or env file means the slot is reserved)
        existing_configs = self.exec(
            f"ls {self.PROTON_WG_DIR}/protonwg*.conf {self.PROTON_WG_DIR}/protonwg*.env 2>/dev/null"
        ).strip()
        reserved = set()
        for path in existing_configs.splitlines():
            path = path.strip()
            # Extract interface name: /etc/fvpn/protonwg/protonwg0.conf → protonwg0
            fname = path.rsplit("/", 1)[-1].rsplit(".", 1)[0]
            if fname.startswith("protonwg"):
                reserved.add(fname)

        used = live | reserved

        for i, mark in enumerate(self.PROTON_WG_MARKS):
            iface = f"protonwg{i}"
            table_num = 1000 + (int(mark, 16) >> 12)

            if iface not in used:
                return iface, mark, table_num

            # Slot is in use — but is it truly occupied?
            # If the interface exists without a config file AND no process,
            # it's an orphan from a crash. Clean it up.
            if iface in live and iface not in reserved:
                pid = self.exec(
                    f"for p in $(pidof proton-wg 2>/dev/null); do "
                    f"grep -qz 'PROTON_WG_INTERFACE_NAME={iface}' /proc/$p/environ 2>/dev/null && echo $p; "
                    f"done"
                ).strip()
                if not pid:
                    self.exec(f"ip link del {iface} 2>/dev/null; true")
                    return iface, mark, table_num

        raise RuntimeError("WireGuard TCP/TLS limit reached (4 max)")

    def upload_proton_wg_config(
        self,
        profile_name: str,
        private_key: str,
        public_key: str,
        endpoint: str,
        socket_type: str = "tcp",
        dns: str = "10.2.0.1",
    ) -> dict:
        """Write a proton-wg config and env file to the router.

        Does NOT start the tunnel — call start_proton_wg_tunnel() after.

        Returns router_info dict with interface, mark, tunnel_id, etc.
        """
        iface, mark, table_num = self._next_proton_wg_slot()
        tunnel_id = self._next_tunnel_id()

        # Ensure directory and init.d service exist
        self.exec(f"mkdir -p {self.PROTON_WG_DIR}")
        self.ensure_proton_wg_initd()

        # Write WG config (no [Interface] Address/DNS — we set those via ip commands)
        wg_conf = (
            f"[Interface]\n"
            f"PrivateKey = {private_key}\n"
            f"\n"
            f"[Peer]\n"
            f"PublicKey = {public_key}\n"
            f"AllowedIPs = 0.0.0.0/0\n"
            f"Endpoint = {endpoint}\n"
            f"PersistentKeepalive = 25\n"
        )
        self.write_file(f"{self.PROTON_WG_DIR}/{iface}.conf", wg_conf)

        # Write env file (includes FlintVPN metadata for mangle rule rebuild)
        env = (
            f"PROTON_WG_INTERFACE_NAME={iface}\n"
            f"PROTON_WG_SOCKET_TYPE={socket_type}\n"
            f"PROTON_WG_SERVER_NAME_STRATEGY=1\n"
            f"FVPN_TUNNEL_ID={tunnel_id}\n"
            f"FVPN_MARK={mark}\n"
            f"FVPN_IPSET=src_mac_{tunnel_id}\n"
        )
        self.write_file(f"{self.PROTON_WG_DIR}/{iface}.env", env)

        # Create the ipset for device MAC assignment
        ipset_name = f"src_mac_{tunnel_id}"
        self.exec(f"ipset create {ipset_name} hash:mac -exist")

        return {
            "tunnel_name": iface,
            "tunnel_id": tunnel_id,
            "mark": mark,
            "table_num": table_num,
            "ipset_name": ipset_name,
            "socket_type": socket_type,
            "vpn_protocol": f"wireguard-{socket_type}",
            "rule_name": f"fvpn_pwg_{iface}",  # pseudo rule_name for profile_store
        }

    def start_proton_wg_tunnel(self, iface: str, mark: str, table_num: int,
                                tunnel_id: int, dns: str = "10.2.0.1") -> None:
        """Start a proton-wg tunnel: process, interface, routing, firewall.

        Idempotent: if the tunnel is already running, stops it first.
        The config and env files must already exist (via upload_proton_wg_config).
        """
        conf_path = f"{self.PROTON_WG_DIR}/{iface}.conf"
        env_path = f"{self.PROTON_WG_DIR}/{iface}.env"
        ipset_name = f"src_mac_{tunnel_id}"

        # Check binary exists
        bin_check = self.exec(f"[ -x {self.PROTON_WG_BIN} ] && echo ok || echo missing").strip()
        if bin_check != "ok":
            raise RuntimeError(f"proton-wg binary not found at {self.PROTON_WG_BIN}")

        # If already running, stop first (idempotent connect)
        link = self.exec(f"ip link show {iface} 2>/dev/null | head -1")
        if iface in link:
            try:
                self.stop_proton_wg_tunnel(iface, mark, table_num, tunnel_id)
            except Exception:
                # Force cleanup of orphaned interface
                self.exec(f"ip link del {iface} 2>/dev/null; true")

        # 0. Ensure ipset exists (may have been lost on reboot/reconnect)
        self.exec(f"ipset create {ipset_name} hash:mac -exist")

        # 0b. Ensure env file exists (stop_proton_wg_tunnel removes it;
        #     reconnecting needs it recreated from the stored metadata)
        env_exists = self.exec(f"[ -f {env_path} ] && echo yes || echo no").strip()
        if env_exists != "yes":
            socket_type = "tcp"  # Default; caller should pass this
            # Try to infer socket_type from the conf endpoint port
            conf_content = self.exec(f"cat {conf_path} 2>/dev/null").strip()
            if ":443" in conf_content:
                socket_type = "tcp"  # Could be tcp or tls — check mark
            env = (
                f"PROTON_WG_INTERFACE_NAME={iface}\n"
                f"PROTON_WG_SOCKET_TYPE={socket_type}\n"
                f"PROTON_WG_SERVER_NAME_STRATEGY=1\n"
                f"FVPN_TUNNEL_ID={tunnel_id}\n"
                f"FVPN_MARK={mark}\n"
                f"FVPN_IPSET={ipset_name}\n"
            )
            self.write_file(env_path, env)

        # 1. Start proton-wg process (sources env, runs in background)
        self.exec(
            f"(. {env_path} && export PROTON_WG_INTERFACE_NAME PROTON_WG_SOCKET_TYPE "
            f"PROTON_WG_SERVER_NAME_STRATEGY && "
            f"{self.PROTON_WG_BIN} > /tmp/{iface}.log 2>&1) &"
        )

        # 2. Wait for interface to appear (up to 5s)
        for _ in range(10):
            out = self.exec(f"ip link show {iface} 2>/dev/null | head -1")
            if iface in out:
                break
            time.sleep(0.5)
        else:
            raise RuntimeError(f"proton-wg interface {iface} did not appear within 5s")

        # 3. Apply WG config
        self.exec(f"wg setconf {iface} {conf_path}")

        # 4. Set up IP + bring interface up
        self.exec(
            f"ip addr add 10.2.0.2/32 dev {iface} 2>/dev/null; "
            f"ip link set {iface} up"
        )

        # 5. Routing table + ip rules
        self.exec(
            f"ip route add default dev {iface} table {table_num} 2>/dev/null; "
            f"ip route add blackhole default metric 254 table {table_num} 2>/dev/null; "
            f"ip rule add fwmark {mark}/0xf000 lookup {table_num} priority 6000 2>/dev/null"
        )

        # 6. Firewall: create zone + forwarding via UCI, then reload.
        #    MUST happen BEFORE the mangle MARK rules (step 7) because
        #    firewall reload destroys all ephemeral iptables rules.
        #    NOTE: `list device` binds the zone to the raw interface name
        #    so fw3 populates the zone chains (ACCEPT, MASQUERADE, etc.).
        #    Without it, fw3 creates empty chains and nothing gets forwarded.
        self.exec(
            f"uci set firewall.fvpn_zone_{iface}=zone && "
            f"uci set firewall.fvpn_zone_{iface}.name='{iface}' && "
            f"uci add_list firewall.fvpn_zone_{iface}.device='{iface}' && "
            f"uci set firewall.fvpn_zone_{iface}.input='DROP' && "
            f"uci set firewall.fvpn_zone_{iface}.output='ACCEPT' && "
            f"uci set firewall.fvpn_zone_{iface}.forward='REJECT' && "
            f"uci set firewall.fvpn_zone_{iface}.masq='1' && "
            f"uci set firewall.fvpn_zone_{iface}.mtu_fix='1' && "
            f"uci set firewall.fvpn_fwd_{iface}=forwarding && "
            f"uci set firewall.fvpn_fwd_{iface}.src='lan' && "
            f"uci set firewall.fvpn_fwd_{iface}.dest='{iface}' && "
            f"uci commit firewall && "
            f"/etc/init.d/firewall reload >/dev/null 2>&1"
        )

        # 7. Rebuild ALL proton-wg mangle MARK rules (not just this tunnel).
        #    Firewall reload (step 6) destroys ALL ephemeral iptables rules,
        #    so we must recreate rules for every active proton-wg tunnel.
        self._rebuild_proton_wg_mangle_rules()

        # 8. Wait for WG handshake (up to 15s)
        for _ in range(15):
            hs = self.exec(f"wg show {iface} latest-handshakes 2>/dev/null")
            if hs.strip() and "\t0" not in hs:
                return  # Handshake succeeded
            time.sleep(1)
        # Don't raise — the tunnel may still connect shortly after

    def stop_proton_wg_tunnel(self, iface: str, mark: str, table_num: int,
                               tunnel_id: int) -> None:
        """Stop a proton-wg tunnel: kill process, clean up routing + firewall."""
        chain = f"TUNNEL{tunnel_id}_ROUTE_POLICY"
        ipset_name = f"src_mac_{tunnel_id}"

        # 1. Remove mangle chain from ROUTE_POLICY and delete it
        self.exec(
            f"iptables -t mangle -D ROUTE_POLICY -j {chain} 2>/dev/null; "
            f"iptables -t mangle -F {chain} 2>/dev/null; "
            f"iptables -t mangle -X {chain} 2>/dev/null; true"
        )

        # 2. Remove ip rules + routes
        self.exec(
            f"ip rule del fwmark {mark}/0xf000 lookup {table_num} 2>/dev/null; "
            f"ip route flush table {table_num} 2>/dev/null; true"
        )

        # 3. Kill ONLY this tunnel's proton-wg process (not all of them)
        #    The process has the interface name in /proc/pid/environ
        pid = self.exec(
            f"for p in $(pidof proton-wg); do "
            f"grep -qz 'PROTON_WG_INTERFACE_NAME={iface}' /proc/$p/environ 2>/dev/null && echo $p; "
            f"done"
        ).strip()
        if pid:
            self.exec(f"kill {pid} 2>/dev/null; true")
        time.sleep(1)

        # 4. Remove the interface (proton-wg may have already cleaned it up)
        self.exec(f"ip link del {iface} 2>/dev/null; true")

        # 5. NOTE: env file is NOT deleted here — it's config, not runtime state.
        #    It's needed for reconnect and for _next_proton_wg_slot to know
        #    the slot is reserved. Deleted only by delete_proton_wg_config.

        # 6. Remove firewall zone + forwarding (UCI), reload, then rebuild
        #    mangle rules for the remaining active tunnels
        self.exec(
            f"uci delete firewall.fvpn_zone_{iface} 2>/dev/null; "
            f"uci delete firewall.fvpn_fwd_{iface} 2>/dev/null; "
            f"uci commit firewall 2>/dev/null; "
            f"/etc/init.d/firewall reload >/dev/null 2>&1; true"
        )
        self._rebuild_proton_wg_mangle_rules()

        # 7. Clean up log file
        self.exec(f"rm -f /tmp/{iface}.log")

    def _rebuild_proton_wg_mangle_rules(self) -> None:
        """Rebuild mangle MARK rules for ALL active proton-wg tunnels.

        Reads FVPN_TUNNEL_ID, FVPN_MARK, FVPN_IPSET from each env file
        in /etc/fvpn/protonwg/ to create the iptables chains. Also writes
        a firewall include script so rules survive future firewall reloads.
        """
        envs = self.exec(f"ls {self.PROTON_WG_DIR}/*.env 2>/dev/null || true").strip()
        if not envs:
            # No more tunnels — clean up firewall include, stale script,
            # and any orphaned TUNNEL*_ROUTE_POLICY mangle chains
            self.exec(
                f"rm -f {self.PROTON_WG_DIR}/mangle_rules.sh; "
                f"uci delete firewall.fvpn_pwg_mangle 2>/dev/null; "
                f"uci commit firewall 2>/dev/null; true"
            )
            # Remove any lingering TUNNEL*_ROUTE_POLICY chains from ROUTE_POLICY
            stale = self.exec(
                "iptables -t mangle -S ROUTE_POLICY 2>/dev/null | "
                "grep -oP 'TUNNEL\\d+_ROUTE_POLICY' | sort -u"
            ).strip()
            for chain in stale.splitlines():
                chain = chain.strip()
                if not chain or chain == "TUNNEL100_ROUTE_POLICY":
                    continue  # Don't touch the default policy
                self.exec(
                    f"iptables -t mangle -D ROUTE_POLICY -j {chain} 2>/dev/null; "
                    f"iptables -t mangle -F {chain} 2>/dev/null; "
                    f"iptables -t mangle -X {chain} 2>/dev/null; true"
                )
            return

        tunnels = []
        for env_path in envs.splitlines():
            env_path = env_path.strip()
            if not env_path:
                continue
            env_content = self.exec(f"cat {env_path} 2>/dev/null").strip()
            vals = {}
            for line in env_content.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    vals[k] = v
            iface = vals.get("PROTON_WG_INTERFACE_NAME", "")
            tid = vals.get("FVPN_TUNNEL_ID", "")
            mark = vals.get("FVPN_MARK", "")
            ipset_name = vals.get("FVPN_IPSET", "")
            if not (iface and tid and mark and ipset_name):
                continue
            # Only create mangle rules for tunnels whose interface is UP
            link = self.exec(f"ip link show {iface} 2>/dev/null | head -1")
            if iface in link:
                tunnels.append((iface, mark, ipset_name, tid))

        # Build iptables commands
        cmds = []
        for iface, mark, ipset_name, tid in tunnels:
            chain = f"TUNNEL{tid}_ROUTE_POLICY"
            cmds.append(f"iptables -t mangle -N {chain} 2>/dev/null")
            cmds.append(f"iptables -t mangle -F {chain}")
            cmds.append(
                f"iptables -t mangle -A {chain} -m comment --comment '{iface}' "
                f"-m mark --mark 0x0/0xf000 -m set --match-set {ipset_name} src "
                f"-j MARK --set-xmark {mark}/0xf000"
            )
            cmds.append(
                f"iptables -t mangle -C ROUTE_POLICY -j {chain} 2>/dev/null || "
                f"iptables -t mangle -I ROUTE_POLICY 1 -j {chain}"
            )

        if cmds:
            self.exec("; ".join(cmds))

        # Write as firewall include so rules survive future reloads
        script = "#!/bin/sh\n# Auto-generated by FlintVPN — proton-wg mangle rules\n"
        script += "# Re-applied on every firewall reload\n\n"
        for cmd in cmds:
            script += cmd + "\n"
        self.write_file(f"{self.PROTON_WG_DIR}/mangle_rules.sh", script)
        self.exec(f"chmod +x {self.PROTON_WG_DIR}/mangle_rules.sh")

        # Register as firewall include (idempotent)
        self.exec(
            f"uci -q get firewall.fvpn_pwg_mangle >/dev/null 2>&1 || ("
            f"uci set firewall.fvpn_pwg_mangle=include && "
            f"uci set firewall.fvpn_pwg_mangle.type='script' && "
            f"uci set firewall.fvpn_pwg_mangle.path='{self.PROTON_WG_DIR}/mangle_rules.sh' && "
            f"uci set firewall.fvpn_pwg_mangle.reload='1' && "
            f"uci commit firewall)"
        )

    def delete_proton_wg_config(self, iface: str, tunnel_id: int) -> None:
        """Delete proton-wg config files, ipset, and rebuild mangle rules.

        Call after stop_proton_wg_tunnel. Also cleans up the firewall
        include if no more proton-wg tunnels remain.
        """
        ipset_name = f"src_mac_{tunnel_id}"
        self.exec(
            f"rm -f {self.PROTON_WG_DIR}/{iface}.conf {self.PROTON_WG_DIR}/{iface}.env; "
            f"ipset destroy {ipset_name} 2>/dev/null; true"
        )
        # Rebuild mangle rules (updates the firewall include script, or
        # cleans up the include entirely if no tunnels remain)
        self._rebuild_proton_wg_mangle_rules()

    def ensure_proton_wg_initd(self) -> None:
        """Install the proton-wg init.d service for boot persistence.

        Creates /etc/init.d/fvpn-protonwg that starts all proton-wg tunnels
        on boot by reading .env files from /etc/fvpn/protonwg/. Idempotent.
        """
        script = r"""#!/bin/sh /etc/rc.common
START=99
STOP=10
USE_PROCD=1

PROTON_WG_DIR="/etc/fvpn/protonwg"
PROTON_WG_BIN="/usr/bin/proton-wg"

start_service() {
    [ -x "$PROTON_WG_BIN" ] || return
    for envfile in "$PROTON_WG_DIR"/*.env; do
        [ -f "$envfile" ] || continue
        . "$envfile"
        iface="$PROTON_WG_INTERFACE_NAME"
        [ -z "$iface" ] && continue
        conffile="$PROTON_WG_DIR/$iface.conf"
        [ -f "$conffile" ] || continue

        procd_open_instance "$iface"
        procd_set_param env $(cat "$envfile" | tr '\n' ' ')
        procd_set_param command "$PROTON_WG_BIN"
        procd_set_param stdout 1
        procd_set_param stderr 1
        procd_close_instance

        # Wait for interface, then set up networking + routing
        (sleep 3 && \
         wg setconf "$iface" "$conffile" 2>/dev/null && \
         ip addr add 10.2.0.2/32 dev "$iface" 2>/dev/null && \
         ip link set "$iface" up 2>/dev/null && \
         # Routing table + ip rule (from env metadata)
         tid="$FVPN_TUNNEL_ID" && \
         mark="$FVPN_MARK" && \
         table_num=$((1000 + 0x$(echo "$mark" | sed 's/0x//;s/000//'))) && \
         ip route add default dev "$iface" table "$table_num" 2>/dev/null && \
         ip route add blackhole default metric 254 table "$table_num" 2>/dev/null && \
         ip rule add fwmark "$mark"/0xf000 lookup "$table_num" priority 6000 2>/dev/null \
        ) &
    done

    # Apply mangle rules (firewall include handles subsequent reloads)
    if [ -x "$PROTON_WG_DIR/mangle_rules.sh" ]; then
        (sleep 5 && "$PROTON_WG_DIR/mangle_rules.sh") &
    fi
}
"""
        self.write_file("/etc/init.d/fvpn-protonwg", script)
        self.exec("chmod +x /etc/init.d/fvpn-protonwg && /etc/init.d/fvpn-protonwg enable 2>/dev/null; true")

    def get_proton_wg_health(self, iface: str) -> str:
        """Get health of a proton-wg tunnel. Same semantics as get_tunnel_health."""
        # Check interface exists and is UP
        link = self.exec(f"ip link show {iface} 2>/dev/null | head -1")
        if iface not in link or "UP" not in link:
            return "red"

        # Check handshake age (same logic as get_tunnel_health)
        hs_output = self.exec(f"wg show {iface} latest-handshakes 2>/dev/null").strip()
        if not hs_output:
            return "connecting"

        try:
            parts = hs_output.split("\t")
            if len(parts) >= 2:
                hs_time = int(parts[1])
                if hs_time == 0:
                    return "connecting"
                age = int(time.time()) - hs_time
                if age <= 180:
                    return "green"
                elif age <= 600:
                    return "amber"
        except (ValueError, IndexError):
            pass
        return "red"

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
        """Remove a device from ALL FlintVPN route policy rules AND proton-wg ipsets.

        Iterates every fvpn rule, matches the MAC case-insensitively, and
        deletes using the EXACT stored case so UCI del_list succeeds.
        Also removes from any proton-wg src_mac_* ipsets.
        """
        mac_lower = mac.lower()
        mac_upper = mac.upper()
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

        # Also remove from proton-wg ipsets (managed outside route_policy)
        pwg_ipsets = self.exec(
            "ipset list -n 2>/dev/null | grep '^src_mac_'"
        ).strip()
        for ipset_name in pwg_ipsets.splitlines():
            ipset_name = ipset_name.strip()
            if not ipset_name:
                continue
            self.exec(
                f"ipset del {ipset_name} {mac_upper} 2>/dev/null; "
                f"ipset del {ipset_name} {mac_lower} 2>/dev/null; true"
            )

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

    # ── FlintVPN UCI Helpers ───────────────────────────────────────────────
    #
    # The new LAN access execution layer is pure UCI: per-group `config ipset`
    # (hash:ip) sections + `config rule` sections referencing them via
    # `option ipset 'name dir'` and `option extra '-m set ! ...'` for negation.
    # No custom `fvpn_lan` chain. fw3 manages everything; rules survive reboot
    # natively from `list entry` lines.
    #
    # Spike-validated on Flint 2 firmware 4.8.4: `firewall reload` is ~0.22s
    # and does NOT disrupt VPN tunnels (handshake unchanged, mangle table
    # preserved, MARK rules survived).
    #
    # Naming conventions (all UCI section names + ipset names):
    #   fvpn_lan_<short_id>_ips      — per-group IP membership
    #   fvpn_extra_<short_id>_<dir>_ips — per-(group, direction) MAC-exception IPs
    #   fvpn_devovr_<mac_no_colons>_<dir>_ips — per-device override exception IPs
    #   fvpn_noint_ips               — global NoInternet membership
    #   fvpn_lan_<short_id>_<dir>_<role>  — UCI rule sections (role = drop/accept/excN)
    #   fvpn_devovr_<mac_no_colons>_<dir>_<role>
    #   fvpn_noint_block             — single global rule for noint

    def fvpn_uci_apply(self, uci_batch: str, reload: bool = True) -> None:
        """Apply a multi-line UCI batch script and optionally reload firewall.

        Writes the batch to /tmp/fvpn_uci_batch.txt via write_file (which uses
        the proven `cat >` stdin pipe), then `uci batch < /tmp/fvpn_uci_batch.txt
        && uci commit firewall`. If `reload=True`, also runs
        `/etc/init.d/firewall reload` in the foreground (~0.22s, no VPN drop).

        Empty batch with reload=False is a no-op. Empty batch with reload=True
        just reloads.
        """
        has_batch = bool(uci_batch.strip())
        if not has_batch and not reload:
            return

        if has_batch:
            tmp_path = "/tmp/fvpn_uci_batch.txt"
            self.write_file(tmp_path, uci_batch)
            self.exec(
                f"uci batch < {tmp_path} && uci commit firewall && rm -f {tmp_path}"
            )
        if reload:
            # Foreground reload. Suppress fw3's stdout chatter; let stderr
            # warnings through. Spike confirms ~0.22s, no VPN drop.
            self.exec("/etc/init.d/firewall reload >/dev/null 2>&1; true")

    def fvpn_ipset_membership(
        self, set_name: str, add: list, remove: list
    ) -> None:
        """Apply add/remove ipset membership ops for one set in a single SSH call.

        Idempotent: uses `-exist` and `|| true` so duplicates / missing
        entries don't error out. Caller is responsible for the matching UCI
        dual-write (via fvpn_uci_apply with add_list/del_list).
        """
        if not add and not remove:
            return
        cmds = []
        for entry in remove:
            cmds.append(f"ipset del {set_name} {entry} 2>/dev/null || true")
        for entry in add:
            cmds.append(f"ipset add {set_name} {entry} -exist 2>/dev/null || true")
        if cmds:
            self.exec(" ; ".join(cmds))

    def fvpn_ipset_create(self, set_name: str, set_type: str = "hash:ip") -> None:
        """Create a kernel ipset if it doesn't exist (for runtime use)."""
        self.exec(f"ipset create {set_name} {set_type} -exist 2>/dev/null || true")

    def fvpn_ipset_destroy(self, set_name: str) -> None:
        """Destroy a kernel ipset (best-effort)."""
        self.exec(f"ipset destroy {set_name} 2>/dev/null || true")

    def fvpn_lan_full_state(self) -> dict:
        """Read live router state for FlintVPN LAN sections + ipsets.

        Returns a dict matching the shape produced by
        `lan_sync.serialize_lan_state` so the reconciler can compute a diff:

            {
              "ipsets": {set_name: [ip, ...], ...},
              "rules": {section_name: {field: value, ...}, ...},
            }

        Only `fvpn_*` sections and ipsets are returned. The kernel ipset
        membership is read live; the UCI `entry` lists are not consulted
        (they're the persistence layer, not the runtime truth).
        """
        out = {"ipsets": {}, "rules": {}}

        # 1. UCI rule + ipset sections
        try:
            raw = self.exec("uci show firewall 2>/dev/null | grep -E '\\.fvpn_'")
        except Exception:
            raw = ""
        # uci show output: firewall.<section>=<type> or firewall.<section>.<field>=<value>
        for line in raw.strip().splitlines():
            line = line.strip()
            if not line or "=" not in line:
                continue
            key, val = line.split("=", 1)
            val = val.strip("'")
            if not key.startswith("firewall."):
                continue
            after = key[len("firewall."):]
            if "." in after:
                section, field = after.split(".", 1)
            else:
                section, field = after, None
            if not section.startswith("fvpn_"):
                continue
            entry = out["rules"].setdefault(section, {})
            if field is None:
                entry["_type"] = val
            else:
                # UCI list values come back with each item on its own line in
                # `uci show` (multiple lines like firewall.X.entry='ip1' and
                # firewall.X.entry='ip2'). We collect them.
                if field in entry:
                    cur = entry[field]
                    if isinstance(cur, list):
                        cur.append(val)
                    else:
                        entry[field] = [cur, val]
                else:
                    entry[field] = val

        # Separate config-ipset sections from config-rule sections.
        ipset_sections = {}
        rule_sections = {}
        for section, fields in out["rules"].items():
            if fields.get("_type") == "ipset":
                # Pull entries (may be string or list) into a list
                entries = fields.get("entry", [])
                if isinstance(entries, str):
                    entries = [entries]
                # Use the UCI section's `name` if set, else section name
                ipset_name = fields.get("name", section)
                ipset_sections[ipset_name] = {
                    "section": section,
                    "entries": list(entries),
                    "match": fields.get("match", "ip"),
                    "storage": fields.get("storage", "hash"),
                }
            elif fields.get("_type") == "rule":
                rule_sections[section] = {k: v for k, v in fields.items() if k != "_type"}

        # 2. Live kernel ipset membership for the sets we know about
        live_membership = {}
        for ipset_name in ipset_sections.keys():
            try:
                raw = self.exec(
                    f"ipset list {ipset_name} 2>/dev/null | "
                    "awk 'p{print} /^Members:/{p=1}' || true"
                )
                live_membership[ipset_name] = [
                    l.strip() for l in raw.strip().splitlines() if l.strip()
                ]
            except Exception:
                live_membership[ipset_name] = []

        # Final shape: ipsets keyed by set_name → live IP list
        out["ipsets"] = live_membership
        # Also expose UCI section names so the diff can issue add_list/del_list
        # against the right firewall.X.entry field.
        out["ipset_uci"] = {
            name: info["section"] for name, info in ipset_sections.items()
        }
        out["ipset_uci_entries"] = {
            name: info["entries"] for name, info in ipset_sections.items()
        }
        out["rules"] = rule_sections
        return out

    def fvpn_lan_wipe_all(self) -> None:
        """Delete every fvpn_* UCI section and destroy every fvpn_* kernel ipset.

        Used by `cli.py reset-local-state` and the migration step. Reloads
        firewall once at the end to clear any leftover iptables rules.
        """
        # 1. Delete all fvpn_* UCI sections
        try:
            raw = self.exec(
                "uci show firewall 2>/dev/null | grep -oE 'fvpn_[a-zA-Z0-9_]+' | sort -u"
            )
        except Exception:
            raw = ""
        sections = [s.strip() for s in raw.strip().splitlines() if s.strip()]
        if sections:
            cmds = [f"uci -q delete firewall.{s}" for s in sections]
            cmds.append("uci commit firewall")
            self.exec(" ; ".join(cmds))
        # 2. Destroy all fvpn_* kernel ipsets
        try:
            raw = self.exec(
                "ipset list -n 2>/dev/null | grep -E '^fvpn_' || true"
            )
        except Exception:
            raw = ""
        for name in raw.strip().splitlines():
            name = name.strip()
            if name.startswith("fvpn_"):
                self.exec(f"ipset destroy {name} 2>/dev/null || true")
        # 3. Tear down the legacy fvpn_lan chain if it still exists
        self.exec(
            "iptables -D FORWARD -j fvpn_lan 2>/dev/null; "
            "iptables -F fvpn_lan 2>/dev/null; "
            "iptables -X fvpn_lan 2>/dev/null; true"
        )
        # 4. Reload firewall to clear any orphan iptables rules
        try:
            self.exec("/etc/init.d/firewall reload 2>&1 >/dev/null; true")
        except Exception:
            pass


