"""Service control tool wrapper.

Wraps ``/etc/init.d/<service>`` and ``wifi`` commands for managing
OpenWrt services on the router.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from router.tools import SshExecutor


class ServiceCtl:
    """Typed wrapper around OpenWrt init.d and wifi commands."""

    def __init__(self, ssh: SshExecutor):
        self._ssh = ssh

    # ── init.d service control ──────────────────────────────────────────

    def _initd(self, name: str, action: str, background: bool = False) -> None:
        """Run an init.d action on a named service."""
        bg = " &" if background else ""
        self._ssh.exec(
            f"/etc/init.d/{name} {action} >/dev/null 2>&1; true{bg}"
        )

    def reload(self, name: str, background: bool = False) -> None:
        """Reload a service."""
        self._initd(name, "reload", background)

    def restart(self, name: str, background: bool = False) -> None:
        """Restart a service."""
        self._initd(name, "restart", background)

    def start(self, name: str, background: bool = False) -> None:
        """Start a service."""
        self._initd(name, "start", background)

    def stop(self, name: str, background: bool = False) -> None:
        """Stop a service."""
        self._initd(name, "stop", background)

    def enable(self, name: str) -> None:
        """Enable a service to start at boot."""
        self._ssh.exec(f"/etc/init.d/{name} enable 2>/dev/null; true")

    def disable(self, name: str) -> None:
        """Disable a service from starting at boot."""
        self._ssh.exec(f"/etc/init.d/{name} disable 2>/dev/null; true")

    # ── WiFi control ────────────────────────────────────────────────────

    def wifi_reload(self) -> None:
        """Reload WiFi configuration."""
        self._ssh.exec("wifi reload 2>/dev/null; true")

    def wifi_up(self) -> None:
        """Bring all WiFi interfaces up."""
        self._ssh.exec("wifi up 2>/dev/null; true")

    def wifi_down(self) -> None:
        """Bring all WiFi interfaces down."""
        self._ssh.exec("wifi down 2>/dev/null; true")
