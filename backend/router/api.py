"""Router API for GL.iNet Flint 2 (GL-MT6000) management via SSH.

Two-layer architecture:
  - **Tool layer** (router_tools/): Uci, Ipset, Iptables, Iproute, ServiceCtl
  - **Feature layer**: RouterPolicy, RouterTunnel, RouterFirewall, RouterDevices,
    RouterWireguard, RouterOpenvpn, RouterProtonWG, RouterAdblock, RouterLanAccess

This class provides the SSH transport (connect/exec/write_file/read_file),
lazy-loads both layers, and exposes backward-compatible delegate methods.
"""

import os
import subprocess
import tempfile
from typing import Optional

import paramiko

# WireGuard mark base for route policy (matches rtp2.sh)
WG_MARK_BASE = 0x1000

# Max simultaneous WireGuard client interfaces (firmware limit)
MAX_WG_INTERFACES = 5

# Proton-WG constants (re-exported for backward compat)
PROTON_WG_DIR = "/etc/fvpn/protonwg"


class RouterAPI:
    """SSH-based API for managing the GL.iNet Flint 2 router."""

    # Re-export for backward compatibility (ipset_ops, profile_healer, etc.)
    PROTON_WG_DIR = PROTON_WG_DIR

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

    # ── SSH Transport ────────────────────────────────────────────────────

    def connect(self):
        """Establish SSH connection to the router."""
        if self._client is not None:
            try:
                self._client.exec_command("echo ok", timeout=5)
                return
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
            connect_kwargs["look_for_keys"] = True

        self._client.connect(**connect_kwargs)

    def disconnect(self):
        """Close SSH connection."""
        if self._client:
            self._client.close()
            self._client = None

    def exec(self, command: str, timeout: int = 30) -> str:
        """Execute a command via SSH and return stdout."""
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
                    self._client = None
                    continue
                raise RuntimeError(f"SSH connection lost: {e}") from e

    def write_file(self, remote_path: str, content: str):
        """Write a file to the router.

        Small files (<1MB) use SSH stdin pipe. Large files use a local
        temp file + ``scp`` to avoid Dropbear channel buffer limits.
        """
        data = content.encode("utf-8")
        # Dropbear SSH drops large stdin pipes; use scp for files >= 1MB
        _SCP_THRESHOLD = 1_000_000
        if len(data) < _SCP_THRESHOLD:
            self.connect()
            _, stdout, stderr = self._client.exec_command(
                f"cat > {remote_path}", timeout=30
            )
            stdout.channel.sendall(data)
            stdout.channel.shutdown_write()
            stdout.channel.recv_exit_status()
        else:
            with tempfile.NamedTemporaryFile(
                mode="wb", suffix=".tmp", delete=False
            ) as f:
                f.write(data)
                tmp_path = f.name
            try:
                scp_args = [
                    "scp", "-O", "-q",
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=/dev/null",
                    "-P", str(self.port),
                ]
                if self.key_filename:
                    scp_args += ["-i", self.key_filename]
                scp_args += [
                    tmp_path,
                    f"{self.username}@{self.host}:{remote_path}",
                ]
                result = subprocess.run(
                    scp_args, capture_output=True, timeout=120
                )
                if result.returncode != 0:
                    raise RuntimeError(
                        f"scp failed: {result.stderr.decode(errors='replace')}"
                    )
            finally:
                os.unlink(tmp_path)

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

    # ── Backward-compat helpers (delegate to tool layer) ─────────────────

    def _uci_batch(self, section, fields, commit, add_lists=None):
        """Delegates to ``self.uci.batch_set()``."""
        self.uci.batch_set(section, fields, commit, add_lists)

    @staticmethod
    def _parse_uci_show(raw, prefix):
        """Delegates to ``Uci.parse_show()``."""
        from router.tools.uci import Uci
        return Uci.parse_show(raw, prefix)

    # ── Tool Layer Properties ────────────────────────────────────────────

    @property
    def uci(self):
        if not hasattr(self, "_uci_tool"):
            from router.tools.uci import Uci
            self._uci_tool = Uci(self)
        return self._uci_tool

    @property
    def ipset_tool(self):
        if not hasattr(self, "_ipset_tool"):
            from router.tools.ipset import Ipset
            self._ipset_tool = Ipset(self)
        return self._ipset_tool

    @property
    def iptables(self):
        if not hasattr(self, "_iptables_tool"):
            from router.tools.iptables import Iptables
            self._iptables_tool = Iptables(self)
        return self._iptables_tool

    @property
    def iproute(self):
        if not hasattr(self, "_iproute_tool"):
            from router.tools.iproute import Iproute
            self._iproute_tool = Iproute(self)
        return self._iproute_tool

    @property
    def service_ctl(self):
        if not hasattr(self, "_service_ctl_tool"):
            from router.tools.service_ctl import ServiceCtl
            self._service_ctl_tool = ServiceCtl(self)
        return self._service_ctl_tool

    @property
    def ip6tables(self):
        if not hasattr(self, "_ip6tables_tool"):
            from router.tools.iptables import Ip6tables
            self._ip6tables_tool = Ip6tables(self)
        return self._ip6tables_tool

    # ── Feature Layer Properties ─────────────────────────────────────────

    @property
    def policy(self):
        if not hasattr(self, "_policy_facade"):
            from router.facades.policy import RouterPolicy
            self._policy_facade = RouterPolicy(self.uci, self)
        return self._policy_facade

    @property
    def tunnel(self):
        if not hasattr(self, "_tunnel_facade"):
            from router.facades.tunnel import RouterTunnel
            self._tunnel_facade = RouterTunnel(
                self.uci, self.service_ctl, self,
                ipv6_mangle_rebuild=lambda: self.proton_wg._rebuild_ipv6_mangle_rules(),
            )
        return self._tunnel_facade

    @property
    def firewall(self):
        if not hasattr(self, "_firewall_facade"):
            from router.facades.firewall import RouterFirewall
            self._firewall_facade = RouterFirewall(
                self.uci, self.ipset_tool, self.service_ctl, self,
            )
        return self._firewall_facade

    @property
    def devices(self):
        if not hasattr(self, "_devices_facade"):
            from router.facades.devices import RouterDevices
            self._devices_facade = RouterDevices(
                self.uci, self.ipset_tool, self.iproute, self.service_ctl,
                self.policy, self,
            )
        return self._devices_facade

    @property
    def adblock(self):
        if not hasattr(self, "_adblock_facade"):
            from router.facades.adblock import RouterAdblock
            self._adblock_facade = RouterAdblock(
                self.uci, self.ipset_tool, self.iptables, self.service_ctl, self,
                ip6tables=self.ip6tables,
            )
        return self._adblock_facade

    @property
    def lan_access(self):
        if not hasattr(self, "_lan_access_facade"):
            from router.facades.lan_access import RouterLanAccess
            self._lan_access_facade = RouterLanAccess(
                self.uci, self.iptables, self.service_ctl, self,
                ip6tables=self.ip6tables,
            )
        return self._lan_access_facade

    @property
    def wireguard(self):
        if not hasattr(self, "_wireguard_facade"):
            from router.facades.wireguard import RouterWireguard
            from router.tunnel_id_alloc import next_tunnel_id
            self._wireguard_facade = RouterWireguard(
                self.uci, self.service_ctl, next_tunnel_id, self,
            )
        return self._wireguard_facade

    @property
    def openvpn(self):
        if not hasattr(self, "_openvpn_facade"):
            from router.facades.openvpn import RouterOpenvpn
            from router.tunnel_id_alloc import next_tunnel_id
            self._openvpn_facade = RouterOpenvpn(
                self.uci, self.service_ctl, next_tunnel_id, self,
            )
        return self._openvpn_facade

    @property
    def proton_wg(self):
        if not hasattr(self, "_proton_wg_facade"):
            from router.facades.proton_wg import RouterProtonWG
            from router.tunnel_id_alloc import next_tunnel_id
            self._proton_wg_facade = RouterProtonWG(
                self.uci, self.ipset_tool, self.iptables, self.iproute,
                self.service_ctl, next_tunnel_id, self,
            )
        return self._proton_wg_facade

    # ── Shared helpers ───────────────────────────────────────────────────

    # ── Backward-compat ID helpers (used by tests) ────────────────────────

    def _next_tunnel_id(self) -> int:
        from router.tunnel_id_alloc import next_tunnel_id
        return next_tunnel_id(self)

    def _next_peer_id(self) -> int:
        return self.wireguard._next_peer_id()

    def _next_ovpn_client_id(self) -> int:
        return self.openvpn._next_ovpn_client_id()
