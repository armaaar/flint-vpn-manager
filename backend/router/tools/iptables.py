"""iptables tool wrapper.

Provides chain lifecycle management and idempotent rule insertion for
the ``iptables`` CLI on the router.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from router.tools import SshExecutor


class Iptables:
    """Typed wrapper around the ``iptables`` CLI."""

    def __init__(self, ssh: SshExecutor):
        self._ssh = ssh

    # ── Chain lifecycle ─────────────────────────────────────────────────

    def ensure_chain(self, table: str, chain: str) -> None:
        """Create a chain if it doesn't exist (idempotent)."""
        self._ssh.exec(f"iptables -t {table} -N {chain} 2>/dev/null || true")

    def flush_chain(self, table: str, chain: str) -> None:
        """Remove all rules from a chain."""
        self._ssh.exec(f"iptables -t {table} -F {chain} 2>/dev/null || true")

    def delete_chain(
        self, table: str, parent_chain: str, chain: str
    ) -> None:
        """Remove jump from parent, flush, and delete a chain.

        All steps are idempotent — safe to call even if the chain
        doesn't exist.
        """
        self._ssh.exec(
            f"iptables -t {table} -D {parent_chain} -j {chain} 2>/dev/null; "
            f"iptables -t {table} -F {chain} 2>/dev/null; "
            f"iptables -t {table} -X {chain} 2>/dev/null; true"
        )

    # ── Rule operations ─────────────────────────────────────────────────

    def append(self, table: str, chain: str, *rule_args: str) -> None:
        """Append a rule to a chain."""
        args = " ".join(rule_args)
        self._ssh.exec(f"iptables -t {table} -A {chain} {args}")

    def insert_if_absent(
        self, table: str, parent_chain: str, *jump_args: str
    ) -> None:
        """Insert a rule at position 1 only if it doesn't already exist.

        Uses the ``-C ... || -I ...`` pattern.
        """
        args = " ".join(jump_args)
        self._ssh.exec(
            f"iptables -t {table} -C {parent_chain} {args} 2>/dev/null || "
            f"iptables -t {table} -I {parent_chain} 1 {args}"
        )

    def remove_rule(self, table: str, chain: str, *rule_args: str) -> None:
        """Remove a specific rule from a chain (idempotent)."""
        args = " ".join(rule_args)
        self._ssh.exec(
            f"iptables -t {table} -D {chain} {args} 2>/dev/null; true"
        )

    def list_rules(self, table: str, chain: str) -> list[str]:
        """List rules in a chain (``iptables -S``)."""
        try:
            raw = self._ssh.exec(
                f"iptables -t {table} -S {chain} 2>/dev/null"
            )
            return [r for r in raw.strip().splitlines() if r.strip()]
        except Exception:
            return []
