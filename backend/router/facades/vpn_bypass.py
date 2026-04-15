"""VPN Bypass facade — manages iptables/ipset/routing for VPN exception rules.

Allows specific traffic (by destination IP/CIDR, domain, or port) to bypass
VPN tunnels and route directly via WAN.  Works by pre-marking matching packets
with fwmark 0x8000/0xf000 in a dedicated ``FVPN_BYPASS`` mangle chain that
evaluates before tunnel chains in ``ROUTE_POLICY``.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from consts import (
    BYPASS_CHAIN,
    BYPASS_DNSMASQ_CONF,
    BYPASS_IPSET_PREFIX,
    BYPASS_MARK,
    BYPASS_MASK,
    BYPASS_PRIORITY,
    BYPASS_SCRIPT_PATH,
    BYPASS_TABLE,
)

if TYPE_CHECKING:
    from router.tools.iptables import Ip6tables, Iptables
    from router.tools.ipset import Ipset
    from router.tools.iproute import Iproute
    from router.tools.uci import Uci
    from router.tools.service_ctl import ServiceCtl
    from router.tools import SshExecutor

# Validation patterns
_SAFE_CIDR_RE = re.compile(
    r"^[0-9a-fA-F.:]+(/\d{1,3})?$"
)
_SAFE_DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$"
)
_SAFE_PORT_RE = re.compile(r"^[0-9]+([,:][0-9]+)*$")
_SAFE_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


class RouterVpnBypass:
    """Manages VPN bypass exception rules on the router.

    Creates a ``FVPN_BYPASS`` chain in the mangle table that marks matching
    packets with ``0x8000/0xf000``, causing tunnel chains to skip them.
    A dedicated routing table (1008) routes bypass traffic via WAN.
    """

    def __init__(
        self,
        uci: Uci,
        ipset: Ipset,
        iptables: Iptables,
        iproute: Iproute,
        service_ctl: ServiceCtl,
        ssh: SshExecutor,
        ip6tables: Ip6tables | None = None,
    ):
        self._uci = uci
        self._ipset = ipset
        self._iptables = iptables
        self._iproute = iproute
        self._service_ctl = service_ctl
        self._ssh = ssh
        self._ip6tables = ip6tables

    # ── Main entry point ───────────────────────────────────────────────

    def apply_all(
        self,
        exceptions: list[dict],
        group_ipset_map: dict[str, str],
    ) -> None:
        """Rebuild all bypass rules from the full exception list.

        Args:
            exceptions: All bypass exception dicts from config.json.
            group_ipset_map: Maps profile_id → MAC ipset name for
                group-scoped exceptions.
        """
        enabled = [e for e in exceptions if e.get("enabled")]
        if not enabled:
            self.cleanup()
            return

        cmds = self._build_all_commands(enabled, group_ipset_map)

        # Execute immediately
        if cmds:
            self._ssh.exec("; ".join(cmds))

        # Write firewall include script for persistence
        self._write_firewall_include(cmds)
        self._uci.ensure_firewall_include(
            "fvpn_vpn_bypass", BYPASS_SCRIPT_PATH,
        )

        # Write dnsmasq config for domain rules
        has_domains = self._write_dnsmasq_config(enabled)
        if has_domains:
            self._ssh.exec("killall -HUP dnsmasq 2>/dev/null; true")

    def cleanup(self) -> None:
        """Remove all bypass artifacts from the router."""
        # Remove mangle chain
        self._iptables.delete_chain("mangle", "ROUTE_POLICY", BYPASS_CHAIN)
        if self._ip6tables:
            self._ip6tables.delete_chain("mangle", "ROUTE_POLICY", BYPASS_CHAIN)

        # Remove all bypass ipsets
        for name in self._ipset.list_names(BYPASS_IPSET_PREFIX):
            self._ipset.destroy(name)

        # Remove routing rules and table
        self._iproute.rule_del(BYPASS_MARK, BYPASS_MASK, BYPASS_TABLE)
        self._iproute.route_flush_table(BYPASS_TABLE)

        # Remove dnsmasq config
        self._ssh.exec(f"rm -f {BYPASS_DNSMASQ_CONF}")
        self._ssh.exec("killall -HUP dnsmasq 2>/dev/null; true")

        # Remove firewall include script
        self._ssh.exec(f"rm -f {BYPASS_SCRIPT_PATH}")
        self._uci.delete(f"firewall.fvpn_vpn_bypass")
        self._uci.commit("firewall")

    # ── dnsmasq integration ────────────────────────────────────────────

    def check_dnsmasq_full(self) -> bool:
        """Check whether dnsmasq-full (with ipset support) is installed."""
        out = self._ssh.exec(
            "opkg list-installed 2>/dev/null | grep '^dnsmasq-full' || true"
        )
        return "dnsmasq-full" in out

    def install_dnsmasq_full(self) -> str:
        """Install dnsmasq-full on the router (replaces standard dnsmasq)."""
        return self._ssh.exec(
            "opkg update && opkg install dnsmasq-full --force-overwrite",
            timeout=120,
        )

    # ── Internal: command generation ───────────────────────────────────

    def _build_all_commands(
        self,
        enabled: list[dict],
        group_ipset_map: dict[str, str],
    ) -> list[str]:
        """Generate the full list of shell commands for all enabled exceptions."""
        cmds: list[str] = []

        # 1. Create and populate per-exception ipsets (for CIDR + domain rules)
        for exc in enabled:
            cidrs = [
                r["value"] for r in exc.get("rules", [])
                if r.get("type") == "cidr" and _SAFE_CIDR_RE.match(r.get("value", ""))
            ]
            domains = [
                r["value"] for r in exc.get("rules", [])
                if r.get("type") == "domain" and _SAFE_DOMAIN_RE.match(r.get("value", ""))
            ]
            if cidrs or domains:
                ipset_name = self._ipset_name(exc["id"])
                cmds.append(f"ipset create {ipset_name} hash:net -exist")
                cmds.append(f"ipset flush {ipset_name}")
                for cidr in cidrs:
                    cmds.append(f"ipset add {ipset_name} {cidr} -exist")

        # 2. Delete old bypass jump + create/flush chain
        cmds.append(
            f"iptables -t mangle -D ROUTE_POLICY -j {BYPASS_CHAIN} 2>/dev/null; true"
        )
        cmds.append(f"iptables -t mangle -N {BYPASS_CHAIN} 2>/dev/null || true")
        cmds.append(f"iptables -t mangle -F {BYPASS_CHAIN}")

        # 3. Build per-exception rules in the chain
        for exc in enabled:
            src_match = self._source_match(
                exc.get("scope", "global"),
                exc.get("scope_target"),
                group_ipset_map,
            )
            if src_match is None:
                # Invalid scope (e.g., group no longer exists) — skip
                continue

            rules = exc.get("rules", [])
            has_ipset = any(
                r.get("type") in ("cidr", "domain")
                for r in rules
            )
            port_rules = [
                r for r in rules
                if r.get("type") == "port"
                and _SAFE_PORT_RE.match(r.get("value", "").replace(":", ","))
            ]

            # IP/domain match via ipset
            if has_ipset:
                ipset_name = self._ipset_name(exc["id"])
                rule_parts = [f"-m set --match-set {ipset_name} dst"]
                if src_match:
                    rule_parts.insert(0, src_match)
                rule_parts.append(
                    f"-j MARK --set-xmark {BYPASS_MARK}/{BYPASS_MASK}"
                )
                cmds.append(
                    f"iptables -t mangle -A {BYPASS_CHAIN} {' '.join(rule_parts)}"
                )

            # Port match rules
            for pr in port_rules:
                proto = pr.get("protocol", "tcp")
                if proto not in ("tcp", "udp"):
                    continue
                ports = pr["value"]
                rule_parts = [f"-p {proto}", f"-m multiport --dports {ports}"]
                if src_match:
                    rule_parts.insert(0, src_match)
                rule_parts.append(
                    f"-j MARK --set-xmark {BYPASS_MARK}/{BYPASS_MASK}"
                )
                cmds.append(
                    f"iptables -t mangle -A {BYPASS_CHAIN} {' '.join(rule_parts)}"
                )

        # 4. Insert bypass chain jump at position 1 of ROUTE_POLICY
        cmds.append(
            f"iptables -t mangle -I ROUTE_POLICY 1 -j {BYPASS_CHAIN}"
        )

        # 5. Set up WAN bypass routing table
        cmds.extend(self._routing_commands())

        return cmds

    def _routing_commands(self) -> list[str]:
        """Commands to set up the WAN bypass routing table."""
        return [
            # Remove stale rule first (idempotent)
            f"ip rule del fwmark {BYPASS_MARK}/{BYPASS_MASK} lookup {BYPASS_TABLE} 2>/dev/null; true",
            f"ip rule add fwmark {BYPASS_MARK}/{BYPASS_MASK} lookup {BYPASS_TABLE} priority {BYPASS_PRIORITY}",
            f"ip route flush table {BYPASS_TABLE} 2>/dev/null; true",
            # Read WAN gateway dynamically
            "WAN_GW=$(ip route show default | awk '{print $3}' | head -1)",
            "WAN_DEV=$(ip route show default | awk '{print $5}' | head -1)",
            f'[ -n "$WAN_GW" ] && ip route add default via $WAN_GW dev $WAN_DEV table {BYPASS_TABLE} || true',
        ]

    def _source_match(
        self,
        scope: str,
        scope_target: str | None,
        group_ipset_map: dict[str, str],
    ) -> str | None:
        """Build the iptables source match fragment for a scope.

        Returns:
            Empty string for global scope, a match fragment for group/device,
            or None if the scope target is invalid.
        """
        if scope == "global":
            return ""
        if scope == "group":
            if not scope_target:
                return None
            ipset_name = group_ipset_map.get(scope_target)
            if not ipset_name:
                return None
            return f"-m set --match-set {ipset_name} src"
        if scope == "device":
            if not scope_target or not _SAFE_MAC_RE.match(scope_target):
                return None
            return f"-m mac --mac-source {scope_target}"
        return None

    # ── Internal: persistence ──────────────────────────────────────────

    def _write_firewall_include(self, cmds: list[str]) -> None:
        """Write the firewall include script for reboot persistence."""
        lines = [
            "#!/bin/sh",
            "# FlintVPN bypass exceptions — auto-generated",
            "# Re-applied on every firewall reload",
            "",
        ]
        for cmd in cmds:
            lines.append(cmd)

        script = "\n".join(lines) + "\n"
        self._ssh.exec("mkdir -p /etc/fvpn")
        self._ssh.write_file(BYPASS_SCRIPT_PATH, script)
        self._ssh.exec(f"chmod +x {BYPASS_SCRIPT_PATH}")

    def _write_dnsmasq_config(self, enabled: list[dict]) -> bool:
        """Write dnsmasq ipset config for domain-based bypass rules.

        Returns True if any domain rules were written.
        """
        # Collect domain→ipset mappings
        lines = [
            "# FlintVPN bypass — auto-generated dnsmasq ipset config",
        ]
        has_domains = False

        for exc in enabled:
            domains = [
                r["value"] for r in exc.get("rules", [])
                if r.get("type") == "domain"
                and _SAFE_DOMAIN_RE.match(r.get("value", ""))
            ]
            if not domains:
                continue
            has_domains = True
            ipset_name = self._ipset_name(exc["id"])
            # dnsmasq-full ipset syntax: ipset=/domain1/domain2/.../ipset_name
            domain_path = "/".join(domains)
            lines.append(f"ipset=/{domain_path}/{ipset_name}")

        if has_domains:
            self._ssh.exec("mkdir -p /etc/dnsmasq.d")
            self._ssh.write_file(BYPASS_DNSMASQ_CONF, "\n".join(lines) + "\n")
        else:
            # Clean up stale config
            self._ssh.exec(f"rm -f {BYPASS_DNSMASQ_CONF}")

        return has_domains

    # ── Helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _ipset_name(exc_id: str) -> str:
        """Derive the ipset name for an exception ID."""
        # Use the short ID part (e.g., "byp_a1b2c3d4" → "fvpn_byp_a1b2c3d4")
        return f"{BYPASS_IPSET_PREFIX}{exc_id.replace('byp_', '')}"
