"""Router policy facade — route policy, kill switch, profile naming.

Delegates to tool-layer objects (Uci) via explicit tool injection.
"""

from router.tools.uci import Uci, _quote


class RouterPolicy:
    """Facade for route_policy UCI operations on the GL.iNet Flint 2."""

    def __init__(self, uci, ssh):
        self._uci = uci
        self._ssh = ssh  # raw exec for grep/pipe commands

    # ── Flint VPN Manager Rule Queries ────────────────────────────────────────────

    def get_flint_vpn_rules(self) -> list[dict]:
        """Get all Flint VPN Manager route policy rules.

        Returns rules whose UCI section starts with 'fvpn_rule' (created by us)
        OR whose group_id matches the Flint VPN Manager groups (1957 for WG, 28216 for OVPN).
        The latter handles the case where the GL.iNet UI replaced our named
        section with an anonymous '@rule[N]' section after editing.

        Returns list of dicts with: rule_name (section name or '@rule[N]'),
        name, enabled, tunnel_id, via, killswitch, from_mac, peer_id, client_id, etc.
        """
        parsed = self._uci.show("route_policy")

        for section, data in parsed.items():
            data["rule_name"] = section
            if "_type" in data:
                data["_section_type"] = data.pop("_type")

        fvpn_rules = []
        for section, data in parsed.items():
            if section.startswith("fvpn_rule"):
                fvpn_rules.append(data)
                continue
            if data.get("_section_type") != "rule":
                continue
            gid = data.get("group_id", "")
            if gid in ("1957", "28216"):
                fvpn_rules.append(data)
        return fvpn_rules

    def reorder_vpn_rules(self, rule_names: list) -> None:
        """Reorder route_policy sections to match the given list.

        Section order in /etc/config/route_policy IS the source of truth for
        VPN display order. Only the listed rule_names are reordered; other
        route_policy sections keep their existing positions.
        """
        if not rule_names:
            return
        for i, rule_name in enumerate(rule_names):
            self._uci.reorder(f"route_policy.{rule_name}", i)
        self._uci.commit("route_policy")

    def heal_anonymous_rule_section(self, anon_section: str, target_name: str):
        """Rename an anonymous route_policy section back to its Flint VPN Manager name.

        When the GL.iNet UI edits a rule, it sometimes replaces the named
        section (e.g. fvpn_rule_9001) with an anonymous one (@rule[4]).
        This method restores the named section in-place.
        """
        if not anon_section.startswith("@rule"):
            return
        if not target_name:
            return
        try:
            self._uci.rename(f"route_policy.{anon_section}", target_name)
        except Exception:
            pass

    def get_flint_vpn_peers(self) -> list[dict]:
        """Get all Flint VPN Manager WireGuard peer configs (peer_9001 through peer_9099).

        Returns list of dicts with peer UCI fields.
        """
        raw = self._ssh.exec(
            "uci show wireguard 2>/dev/null | grep 'wireguard\\.peer_90'"
        )
        parsed = Uci.parse_show(raw, "wireguard")
        result = []
        for section, fields in parsed.items():
            fields["peer_id"] = section
            fields.pop("_type", None)
            result.append(fields)
        return result

    # ── Kill Switch ──────────────────────────────────────────────────────

    def set_kill_switch(self, rule_name: str, enabled: bool):
        """Enable or disable kill switch on a route policy rule.

        When enabled and the tunnel drops, assigned devices lose WAN access.
        uci commit is sufficient for persistence.
        """
        self._uci.set(
            f"route_policy.{rule_name}.killswitch",
            "1" if enabled else "0",
        )
        self._uci.commit("route_policy")

    def get_kill_switch(self, rule_name: str) -> bool:
        """Read the live kill switch state for a route policy rule."""
        ks = self._uci.get(
            f"route_policy.{rule_name}.killswitch", "0"
        ).strip()
        return ks == "1"

    # ── Profile Naming ───────────────────────────────────────────────────

    def get_profile_name(self, rule_name: str) -> str:
        """Read the live profile name from route_policy.{rule}.name."""
        return self._uci.get(f"route_policy.{rule_name}.name").strip()

    def rename_profile(self, rule_name: str, new_name: str,
                       peer_id: str = "", client_uci_id: str = ""):
        """Rename a VPN profile by updating all 3 router UCI fields atomically.

        The name lives in:
          - route_policy.{rule_name}.name
          - wireguard.{peer_id}.name        (for WireGuard tunnels)
          - ovpnclient.{client_uci_id}.name (for OpenVPN tunnels)

        At least one of peer_id or client_uci_id must be provided.
        """
        safe_name = _quote(new_name)
        cmds = [f"uci set route_policy.{rule_name}.name='{safe_name}'"]
        commits = ["uci commit route_policy"]
        if peer_id:
            cmds.append(f"uci set wireguard.{peer_id}.name='{safe_name}'")
            commits.append("uci commit wireguard")
        if client_uci_id:
            cmds.append(f"uci set ovpnclient.{client_uci_id}.name='{safe_name}'")
            commits.append("uci commit ovpnclient")
        self._uci.multi(cmds + commits)

    # ── MAC Token Helpers ────────────────────────────────────────────────

    def from_mac_tokens(self, rule_name: str) -> list:
        """Return the raw MAC tokens stored in route_policy.{rule}.from_mac.

        Preserves case so del_list can match exactly.
        """
        raw = self._uci.get(f"route_policy.{rule_name}.from_mac")
        tokens = []
        for token in raw.replace("'", " ").split():
            token = token.strip()
            if ":" in token and len(token) == 17:
                tokens.append(token)
        return tokens

    # ── Active Interfaces ────────────────────────────────────────────────

    def get_active_interfaces(self) -> list[str]:
        """Get list of active WireGuard client interface names."""
        raw = self._ssh.exec(
            "uci show network 2>/dev/null | grep \"proto='wgclient'\" | "
            "cut -d. -f2"
        )
        active = []
        for iface in raw.strip().splitlines():
            iface = iface.strip()
            if iface:
                disabled = self._uci.get(
                    f"network.{iface}.disabled", "1"
                ).strip()
                if disabled != "1":
                    active.append(iface)
        return active
