"""iproute2 tool wrapper.

Wraps ``ip link``, ``ip addr``, ``ip route``, ``ip rule``, and
``ip neigh`` commands for interface and routing management.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from router.tools import SshExecutor


class Iproute:
    """Typed wrapper around the ``ip`` (iproute2) CLI."""

    def __init__(self, ssh: SshExecutor):
        self._ssh = ssh

    # ── Link (interface) management ─────────────────────────────────────

    def link_exists(self, iface: str) -> bool:
        """Check whether a network interface exists."""
        try:
            out = self._ssh.exec(
                f"ip link show {iface} 2>/dev/null | head -1"
            )
            return bool(out.strip())
        except Exception:
            return False

    def link_delete(self, iface: str) -> None:
        """Delete a network interface (idempotent)."""
        self._ssh.exec(f"ip link del {iface} 2>/dev/null; true")

    def link_set_up(self, iface: str) -> None:
        """Bring an interface up."""
        self._ssh.exec(f"ip link set {iface} up")

    # ── Address management ──────────────────────────────────────────────

    def addr_add(self, addr: str, dev: str) -> None:
        """Add an IP address to an interface."""
        self._ssh.exec(f"ip addr add {addr} dev {dev} 2>/dev/null; true")

    # ── Route management ────────────────────────────────────────────────

    def route_add(
        self,
        dest: str,
        dev: str,
        table: int,
        metric: int | None = None,
    ) -> None:
        """Add a route to a specific table."""
        cmd = f"ip route add {dest} dev {dev} table {table}"
        if metric is not None:
            cmd += f" metric {metric}"
        self._ssh.exec(f"{cmd} 2>/dev/null; true")

    def route_add_blackhole(
        self, dest: str, table: int, metric: int | None = None
    ) -> None:
        """Add a blackhole route (kill switch)."""
        cmd = f"ip route add blackhole {dest} table {table}"
        if metric is not None:
            cmd += f" metric {metric}"
        self._ssh.exec(f"{cmd} 2>/dev/null; true")

    def route_flush_table(self, table: int) -> None:
        """Flush all routes in a routing table."""
        self._ssh.exec(f"ip route flush table {table} 2>/dev/null; true")

    # ── Rule (policy routing) management ────────────────────────────────

    def rule_add(
        self, fwmark: str, mask: str, table: int, priority: int
    ) -> None:
        """Add a policy routing rule matching a firewall mark."""
        self._ssh.exec(
            f"ip rule add fwmark {fwmark}/{mask} lookup {table} "
            f"priority {priority} 2>/dev/null; true"
        )

    def rule_del(self, fwmark: str, mask: str, table: int) -> None:
        """Remove a policy routing rule."""
        self._ssh.exec(
            f"ip rule del fwmark {fwmark}/{mask} lookup {table} "
            f"2>/dev/null; true"
        )

    # ── Neighbor (ARP) ──────────────────────────────────────────────────

    def neigh_show(self) -> str:
        """Read the ARP/neighbor table."""
        return self._ssh.exec(
            "ip neigh show 2>/dev/null || cat /proc/net/arp 2>/dev/null"
        )

    # ── IPv6 variants ──────────────────────────────────────────────────
    #
    # Mirror the IPv4 methods above using ``ip -6`` for dual-stack
    # routing.  GL.iNet's vpn-client only manages IPv4 rules, so
    # Flint VPN Manager must set up IPv6 routing independently.

    def addr_add_v6(self, addr: str, dev: str) -> None:
        """Add an IPv6 address to an interface."""
        self._ssh.exec(f"ip -6 addr add {addr} dev {dev} 2>/dev/null; true")

    def route_add_v6(
        self,
        dest: str,
        dev: str,
        table: int,
        metric: int | None = None,
    ) -> None:
        """Add an IPv6 route to a specific table."""
        cmd = f"ip -6 route add {dest} dev {dev} table {table}"
        if metric is not None:
            cmd += f" metric {metric}"
        self._ssh.exec(f"{cmd} 2>/dev/null; true")

    def route_add_blackhole_v6(
        self, dest: str, table: int, metric: int | None = None
    ) -> None:
        """Add an IPv6 blackhole route (kill switch)."""
        cmd = f"ip -6 route add blackhole {dest} table {table}"
        if metric is not None:
            cmd += f" metric {metric}"
        self._ssh.exec(f"{cmd} 2>/dev/null; true")

    def route_flush_table_v6(self, table: int) -> None:
        """Flush all IPv6 routes in a routing table."""
        self._ssh.exec(f"ip -6 route flush table {table} 2>/dev/null; true")

    def rule_add_v6(
        self, fwmark: str, mask: str, table: int, priority: int
    ) -> None:
        """Add an IPv6 policy routing rule matching a firewall mark."""
        self._ssh.exec(
            f"ip -6 rule add fwmark {fwmark}/{mask} lookup {table} "
            f"priority {priority} 2>/dev/null; true"
        )

    def rule_del_v6(self, fwmark: str, mask: str, table: int) -> None:
        """Remove an IPv6 policy routing rule."""
        self._ssh.exec(
            f"ip -6 rule del fwmark {fwmark}/{mask} lookup {table} "
            f"2>/dev/null; true"
        )

    def neigh_show_v6(self) -> str:
        """Read the IPv6 neighbor (NDP) table."""
        return self._ssh.exec("ip -6 neigh show 2>/dev/null")
