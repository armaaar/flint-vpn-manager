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

import time
from typing import Optional

import paramiko

from consts import (
    HEALTH_AMBER,
    HEALTH_CONNECTING,
    HEALTH_GREEN,
    HEALTH_RED,
    PROTO_OPENVPN,
    PROTO_WIREGUARD,
    PROTO_WIREGUARD_TCP,
    PROTO_WIREGUARD_TLS,
)

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

    def _uci_batch(self, section, fields, commit, add_lists=None):
        """Execute a batch of UCI set commands atomically.

        Args:
            section: Full UCI section path, e.g. "wireguard.peer_9001"
            fields: Dict of field_name → value. Key "_type" emits "uci set section=value".
            commit: UCI config to commit, e.g. "wireguard"
            add_lists: Optional dict of field_name → value for "uci add_list" commands.
        """
        cmds = []
        for key, val in fields.items():
            if key == "_type":
                cmds.append(f"uci set {section}={val}")
            else:
                cmds.append(f"uci set {section}.{key}='{val}'")
        for key, val in (add_lists or {}).items():
            cmds.append(f"uci add_list {section}.{key}='{val}'")
        cmds.append(f"uci commit {commit}")
        self.exec(" && ".join(cmds))

    @staticmethod
    def _parse_uci_show(raw, prefix):
        """Parse 'uci show <config>' output into {section: {field: value}}.

        Args:
            raw: Raw output from 'uci show ...'
            prefix: The config prefix to strip, e.g. "route_policy"

        Returns:
            Dict mapping section names to field dicts. The "_type" key holds the
            section type. Fields that appear multiple times become lists.
        """
        sections = {}
        dot_prefix = prefix + "."
        for line in raw.strip().splitlines():
            line = line.strip()
            if not line or "=" not in line:
                continue
            key, val = line.split("=", 1)
            val = val.strip("'")
            if not key.startswith(dot_prefix):
                continue
            after = key[len(dot_prefix):]
            if "." in after:
                section, field = after.split(".", 1)
            else:
                section = after
                field = None
            entry = sections.setdefault(section, {})
            if field is None:
                entry["_type"] = val
            elif field in entry:
                cur = entry[field]
                if isinstance(cur, list):
                    cur.append(val)
                else:
                    entry[field] = [cur, val]
            else:
                entry[field] = val
        return sections

    # ── Facade Properties ────────────────────────────────────────────────
    #
    # Lazy-initialized sub-modules that group related methods. The original
    # methods are kept below as thin delegates for backward compatibility.

    @property
    def policy(self):
        if not hasattr(self, "_policy_facade"):
            from router_policy import RouterPolicy
            self._policy_facade = RouterPolicy(self)
        return self._policy_facade

    @property
    def tunnel(self):
        if not hasattr(self, "_tunnel_facade"):
            from router_tunnel import RouterTunnel
            self._tunnel_facade = RouterTunnel(self)
        return self._tunnel_facade

    @property
    def firewall(self):
        if not hasattr(self, "_firewall_facade"):
            from router_firewall import RouterFirewall
            self._firewall_facade = RouterFirewall(self)
        return self._firewall_facade

    @property
    def devices(self):
        if not hasattr(self, "_devices_facade"):
            from router_devices import RouterDevices
            self._devices_facade = RouterDevices(self, self.policy)
        return self._devices_facade

    @property
    def adblock(self):
        if not hasattr(self, "_adblock_facade"):
            from router_adblock import RouterAdblock
            self._adblock_facade = RouterAdblock(self)
        return self._adblock_facade

    # ── Delegates: Devices ───────────────────────────────────────────────

    def get_dhcp_leases(self) -> list[dict]:
        return self.devices.get_dhcp_leases()

    def get_client_details(self) -> dict:
        return self.devices.get_client_details()

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
        self._uci_batch(f"wireguard.{peer_id}", {
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

        # Create route policy rule (batched)
        # IMPORTANT: via_type MUST be 'wireguard' (not 'wgclient') for rtp2.sh
        # to recognize it. peer_id and group_id MUST be set so rtp2.sh can
        # match the rule to the wireguard peer and create the network interface.
        # We do NOT create the network interface ourselves — vpn-client does that.
        tunnel_id = self._next_tunnel_id()
        rule_name = f"fvpn_rule_{peer_num}"
        self._uci_batch(f"route_policy.{rule_name}", {
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
        self._uci_batch(f"ovpnclient.{client_uci_id}", {
            "_type": "clients",
            "group_id": group_id,
            "client_id": str(client_num),
            "name": profile_name,
            "path": f"{profile_dir}/config.ovpn",
            "proto": "udp",
            "client_auth": "1",
        }, "ovpnclient")

        # Create route policy rule
        tunnel_id = self._next_tunnel_id()
        rule_name = f"fvpn_rule_ovpn_{client_num}"
        self._uci_batch(f"route_policy.{rule_name}", {
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
            "vpn_protocol": {"tcp": PROTO_WIREGUARD_TCP, "tls": PROTO_WIREGUARD_TLS}[socket_type],
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
            return HEALTH_RED

        # Check handshake age (same logic as get_tunnel_health)
        hs_output = self.exec(f"wg show {iface} latest-handshakes 2>/dev/null").strip()
        if not hs_output:
            return HEALTH_CONNECTING

        try:
            parts = hs_output.split("\t")
            if len(parts) >= 2:
                hs_time = int(parts[1])
                if hs_time == 0:
                    return HEALTH_CONNECTING
                age = int(time.time()) - hs_time
                if age <= 180:
                    return HEALTH_GREEN
                elif age <= 600:
                    return HEALTH_AMBER
        except (ValueError, IndexError):
            pass
        return HEALTH_RED

    # ── Delegates: Tunnel ───────────────────────────────────────────────

    def bring_tunnel_up(self, rule_name: str, **_kwargs):
        return self.tunnel.bring_tunnel_up(rule_name, **_kwargs)

    def bring_tunnel_down(self, rule_name: str, **_kwargs):
        return self.tunnel.bring_tunnel_down(rule_name, **_kwargs)

    def get_rule_interface(self, rule_name: str) -> Optional[str]:
        return self.tunnel.get_rule_interface(rule_name)

    def get_tunnel_status(self, rule_name: str) -> dict:
        return self.tunnel.get_tunnel_status(rule_name)

    def get_tunnel_health(self, rule_name: str) -> str:
        return self.tunnel.get_tunnel_health(rule_name)

    # ── Delegates: Device Policy ────────────────────────────────────────

    def from_mac_tokens(self, rule_name: str) -> list:
        return self.policy.from_mac_tokens(rule_name)

    def set_device_vpn(self, mac: str, rule_name: str):
        return self.devices.set_device_vpn(mac, rule_name)

    def remove_device_from_vpn(self, mac: str, rule_name: str):
        return self.devices.remove_device_from_vpn(mac, rule_name)

    def remove_device_from_all_vpn(self, mac: str):
        return self.devices.remove_device_from_all_vpn(mac)

    # ── Delegates: Kill Switch + Profile Naming ─────────────────────────

    def set_kill_switch(self, rule_name: str, enabled: bool):
        return self.policy.set_kill_switch(rule_name, enabled)

    def get_kill_switch(self, rule_name: str) -> bool:
        return self.policy.get_kill_switch(rule_name)

    def get_profile_name(self, rule_name: str) -> str:
        return self.policy.get_profile_name(rule_name)

    def get_device_assignments(self) -> dict:
        return self.devices.get_device_assignments()

    def rename_profile(self, rule_name: str, new_name: str,
                       peer_id: str = "", client_uci_id: str = ""):
        return self.policy.rename_profile(rule_name, new_name, peer_id, client_uci_id)

    # ── Delegates: Static DHCP Leases ───────────────────────────────────

    def set_static_lease(self, mac: str, ip: str, hostname: str = ""):
        return self.devices.set_static_lease(mac, ip, hostname)

    def remove_static_lease(self, mac: str):
        return self.devices.remove_static_lease(mac)

    # ── Delegates: mDNS ─────────────────────────────────────────────────

    def setup_mdns_reflection(self, interface_name: str):
        return self.firewall.setup_mdns_reflection(interface_name)

    # ── Delegates: Policy ───────────────────────────────────────────────

    def get_flint_vpn_rules(self) -> list[dict]:
        return self.policy.get_flint_vpn_rules()

    def reorder_vpn_rules(self, rule_names: list) -> None:
        return self.policy.reorder_vpn_rules(rule_names)

    def heal_anonymous_rule_section(self, anon_section: str, target_name: str):
        return self.policy.heal_anonymous_rule_section(anon_section, target_name)

    def get_flint_vpn_peers(self) -> list[dict]:
        return self.policy.get_flint_vpn_peers()

    def get_active_interfaces(self) -> list[str]:
        return self.policy.get_active_interfaces()

    # ── Delegates: Firewall ──────────────────────────────────────────────

    def fvpn_uci_apply(self, uci_batch: str, reload: bool = True) -> None:
        return self.firewall.fvpn_uci_apply(uci_batch, reload)

    def fvpn_ipset_membership(
        self, set_name: str, add: list, remove: list
    ) -> None:
        return self.firewall.fvpn_ipset_membership(set_name, add, remove)

    def fvpn_ipset_create(self, set_name: str, set_type: str = "hash:ip") -> None:
        return self.firewall.fvpn_ipset_create(set_name, set_type)

    def fvpn_ipset_destroy(self, set_name: str) -> None:
        return self.firewall.fvpn_ipset_destroy(set_name)



