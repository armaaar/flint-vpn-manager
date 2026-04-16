"""VPN Bypass facade — manages iptables/ipset/routing for VPN exception rules.

Allows specific traffic (by destination IP/CIDR, domain, or port) to bypass
VPN tunnels and route directly via WAN.  Works by pre-marking matching packets
with fwmark 0x8000/0xf000 in a dedicated ``FVPN_BYPASS`` mangle chain that
evaluates before tunnel chains in ``ROUTE_POLICY``.

Each exception contains **rule blocks**.  Rules within a block are ANDed
(one iptables rule with multiple ``-m`` matches).  Blocks within an
exception are ORed (separate iptables rules — any match marks the packet).
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

        # Write dnsmasq config for domain rules.
        # ipset= directives require a full dnsmasq restart (HUP is not enough).
        # Run in background to avoid blocking unlock (~12-15s on Flint 2).
        has_domains = self._write_dnsmasq_config(enabled)
        if has_domains:
            self._ssh.exec(
                "/etc/init.d/dnsmasq restart >/dev/null 2>&1 &"
            )

    def cleanup(self) -> None:
        """Remove all bypass artifacts from the router."""
        self._iptables.delete_chain("mangle", "ROUTE_POLICY", BYPASS_CHAIN)
        if self._ip6tables:
            self._ip6tables.delete_chain("mangle", "ROUTE_POLICY", BYPASS_CHAIN)

        for name in self._ipset.list_names(BYPASS_IPSET_PREFIX):
            self._ipset.destroy(name)

        self._iproute.rule_del(BYPASS_MARK, BYPASS_MASK, BYPASS_TABLE)
        self._iproute.route_flush_table(BYPASS_TABLE)

        self._ssh.exec(f"rm -f {BYPASS_DNSMASQ_CONF}")
        self._ssh.exec("/etc/init.d/dnsmasq restart >/dev/null 2>&1 &")

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

        # 1. Create and populate per-block ipsets
        #    Ipsets must be pre-created for BOTH cidr and domain blocks:
        #    - CIDRs are added statically here
        #    - Domains are populated by dnsmasq at DNS resolution time
        for exc in enabled:
            for bi, block in enumerate(exc.get("rule_blocks", [])):
                cidrs = [
                    r["value"] for r in block.get("rules", [])
                    if r.get("type") == "cidr"
                    and _SAFE_CIDR_RE.match(r.get("value", ""))
                ]
                has_domains = any(
                    r.get("type") == "domain" for r in block.get("rules", [])
                )
                if cidrs or has_domains:
                    ipset_name = self._block_ipset_name(exc["id"], bi)
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

        # 3. Build per-block iptables rules (blocks ORed, rules within ANDed)
        for exc in enabled:
            src_matches = self._source_matches(
                exc.get("scope", "global"),
                exc.get("scope_target"),
                group_ipset_map,
            )
            if not src_matches:
                continue

            for src_match in src_matches:
                for bi, block in enumerate(exc.get("rule_blocks", [])):
                    rule_cmd = self._build_block_rule(
                        exc["id"], bi, block, src_match,
                    )
                    if rule_cmd:
                        cmds.append(rule_cmd)

        # 4. Insert bypass chain jump at position 1 of ROUTE_POLICY
        cmds.append(
            f"iptables -t mangle -I ROUTE_POLICY 1 -j {BYPASS_CHAIN}"
        )

        # 5. Set up WAN bypass routing table
        cmds.extend(self._routing_commands())

        return cmds

    def _build_block_rule(
        self,
        exc_id: str,
        block_index: int,
        block: dict,
        src_match: str,
    ) -> str | None:
        """Build a single iptables rule for one block (rules ANDed).

        Within a block:
        - Multiple CIDRs → one ipset (destination matches ANY)
        - Multiple domains → same ipset (resolved IPs added by dnsmasq)
        - Multiple port rules → combined multiport (ANY port matches)
        - CIDR/domain ipset AND port match = both must match (AND)
        """
        rules = block.get("rules", [])
        if not rules:
            return None

        parts: list[str] = []

        # Source scope match
        if src_match:
            parts.append(src_match)

        # IP/domain match via per-block ipset
        has_cidr = any(r.get("type") == "cidr" for r in rules)
        has_domain = any(r.get("type") == "domain" for r in rules)
        if has_cidr or has_domain:
            ipset_name = self._block_ipset_name(exc_id, block_index)
            parts.append(f"-m set --match-set {ipset_name} dst")

        # Port match — combine all port rules in the block
        port_rules = [
            r for r in rules
            if r.get("type") == "port"
            and r.get("protocol") in ("tcp", "udp")
            and _SAFE_PORT_RE.match(r.get("value", "").replace(":", ","))
        ]
        if port_rules:
            # Group by protocol
            for proto in ("tcp", "udp"):
                proto_ports = [
                    r["value"] for r in port_rules
                    if r.get("protocol") == proto
                ]
                if proto_ports:
                    ports_str = ",".join(proto_ports)
                    parts.append(f"-p {proto} -m multiport --dports {ports_str}")
                    break  # iptables allows only one -p per rule

        if not parts or (not has_cidr and not has_domain and not port_rules):
            return None

        parts.append(f"-j MARK --set-xmark {BYPASS_MARK}/{BYPASS_MASK}")
        return f"iptables -t mangle -A {BYPASS_CHAIN} {' '.join(parts)}"

    def _routing_commands(self) -> list[str]:
        """Commands to set up the WAN bypass routing table."""
        return [
            f"ip rule del fwmark {BYPASS_MARK}/{BYPASS_MASK} lookup {BYPASS_TABLE} 2>/dev/null; true",
            f"ip rule add fwmark {BYPASS_MARK}/{BYPASS_MASK} lookup {BYPASS_TABLE} priority {BYPASS_PRIORITY}",
            f"ip route flush table {BYPASS_TABLE} 2>/dev/null; true",
            "WAN_GW=$(ip route show default | awk '{print $3}' | head -1)",
            "WAN_DEV=$(ip route show default | awk '{print $5}' | head -1)",
            f'[ -n "$WAN_GW" ] && ip route add default via $WAN_GW dev $WAN_DEV table {BYPASS_TABLE} || true',
        ]

    def _source_matches(
        self,
        scope: str,
        scope_target: str | list | None,
        group_ipset_map: dict[str, str],
    ) -> list[str]:
        """Build iptables source match fragments for a scope.

        Returns a list of match fragments — one per target.  For global
        scope returns ``[""]``.  Targets can be mixed — MAC addresses
        (devices) and profile IDs (groups) are auto-detected.
        """
        if scope == "global":
            return [""]

        # Normalise to list
        targets = scope_target if isinstance(scope_target, list) else [scope_target]
        targets = [t for t in targets if t]
        if not targets:
            return []

        result: list[str] = []
        for target in targets:
            if _SAFE_MAC_RE.match(target):
                # Device MAC
                result.append(f"-m mac --mac-source {target}")
            elif target in group_ipset_map:
                # Group profile ID
                result.append(f"-m set --match-set {group_ipset_map[target]} src")
        return result

    # ── Internal: persistence ──────────────────────────────────────────

    def _write_firewall_include(self, cmds: list[str]) -> None:
        """Write the firewall include script for reboot persistence."""
        lines = [
            "#!/bin/sh",
            "# FlintVPN bypass exceptions — auto-generated",
            "# Re-applied on every firewall reload",
            "",
        ]
        lines.extend(cmds)
        script = "\n".join(lines) + "\n"
        self._ssh.exec("mkdir -p /etc/fvpn")
        self._ssh.write_file(BYPASS_SCRIPT_PATH, script)
        self._ssh.exec(f"chmod +x {BYPASS_SCRIPT_PATH}")

    def _write_dnsmasq_config(self, enabled: list[dict]) -> bool:
        """Write dnsmasq ipset config for domain-based bypass rules.

        Each block with domain rules gets its own ipset→dnsmasq mapping.
        """
        lines = ["# FlintVPN bypass — auto-generated dnsmasq ipset config"]
        has_domains = False

        for exc in enabled:
            for bi, block in enumerate(exc.get("rule_blocks", [])):
                domains = [
                    r["value"] for r in block.get("rules", [])
                    if r.get("type") == "domain"
                    and _SAFE_DOMAIN_RE.match(r.get("value", ""))
                ]
                if not domains:
                    continue
                has_domains = True
                ipset_name = self._block_ipset_name(exc["id"], bi)
                domain_path = "/".join(domains)
                lines.append(f"ipset=/{domain_path}/{ipset_name}")

        if has_domains:
            self._ssh.exec("mkdir -p /tmp/dnsmasq.d")
            self._ssh.write_file(BYPASS_DNSMASQ_CONF, "\n".join(lines) + "\n")
        else:
            self._ssh.exec(f"rm -f {BYPASS_DNSMASQ_CONF}")

        return has_domains

    # ── Helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _block_ipset_name(exc_id: str, block_index: int) -> str:
        """Derive the ipset name for an exception block.

        Format: ``fvpn_byp_{short_id}_b{index}``
        """
        short = exc_id.replace("byp_", "")
        return f"{BYPASS_IPSET_PREFIX}{short}_b{block_index}"
