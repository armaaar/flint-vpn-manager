"""ipset tool wrapper.

Provides consistent ``-exist`` flags, error suppression, and membership
parsing for kernel ipset operations on the router.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from router.tools import SshExecutor


class Ipset:
    """Typed wrapper around the ``ipset`` CLI."""

    def __init__(self, ssh: SshExecutor):
        self._ssh = ssh

    def create(self, name: str, set_type: str = "hash:mac") -> None:
        """Create an ipset (idempotent via ``-exist``)."""
        self._ssh.exec(f"ipset create {name} {set_type} -exist")

    def add(self, name: str, entry: str) -> None:
        """Add an entry to an ipset (idempotent via ``-exist``)."""
        self._ssh.exec(f"ipset add {name} {entry} -exist")

    def remove(self, name: str, entry: str) -> None:
        """Remove an entry from an ipset (idempotent)."""
        self._ssh.exec(f"ipset del {name} {entry} 2>/dev/null || true")

    def members(self, name: str) -> list[str]:
        """Return the current members of an ipset.

        Returns an empty list if the set doesn't exist or the command
        fails (e.g. SSH error).
        """
        try:
            raw = self._ssh.exec(
                f"ipset list {name} 2>/dev/null | awk 'p{{print}} /^Members:/{{p=1}}'"
            )
            return [m for m in raw.strip().splitlines() if m.strip()]
        except Exception:
            return []

    def flush(self, name: str) -> None:
        """Remove all entries from an ipset (idempotent)."""
        self._ssh.exec(f"ipset flush {name} 2>/dev/null || true")

    def destroy(self, name: str) -> None:
        """Destroy an ipset entirely (idempotent)."""
        self._ssh.exec(f"ipset destroy {name} 2>/dev/null || true")

    def list_names(self, prefix: str = "") -> list[str]:
        """List ipset names, optionally filtered by prefix."""
        cmd = "ipset list -n 2>/dev/null"
        if prefix:
            cmd += f" | grep '^{prefix}'"
        try:
            raw = self._ssh.exec(cmd)
            return [n for n in raw.strip().splitlines() if n.strip()]
        except Exception:
            return []

    def membership_batch(
        self,
        name: str,
        add: list[str] | None = None,
        remove: list[str] | None = None,
    ) -> None:
        """Apply bulk add/remove in a single SSH call."""
        parts: list[str] = []
        for entry in remove or []:
            parts.append(f"ipset del {name} {entry} 2>/dev/null || true")
        for entry in add or []:
            parts.append(f"ipset add {name} {entry} -exist")
        if parts:
            self._ssh.exec(" ; ".join(parts))
