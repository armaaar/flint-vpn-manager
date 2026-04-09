"""Router firewall facade — UCI ipsets, LAN rules, mDNS reflection.

Delegates SSH execution to the RouterAPI instance passed as ``ssh``.
"""

from router_api import RouterAPI


class RouterFirewall:
    """Facade for firewall and ipset operations on the GL.iNet Flint 2."""

    def __init__(self, ssh):
        self._ssh = ssh

    # ── UCI Apply ────────────────────────────────────────────────────────

    def fvpn_uci_apply(self, uci_batch: str, reload: bool = True) -> None:
        """Apply a multi-line UCI batch script and optionally reload firewall.

        Writes the batch to /tmp/fvpn_uci_batch.txt via write_file (which uses
        the proven ``cat >`` stdin pipe), then ``uci batch < /tmp/fvpn_uci_batch.txt
        && uci commit firewall``. If ``reload=True``, also runs
        ``/etc/init.d/firewall reload`` in the foreground (~0.22s, no VPN drop).

        Empty batch with reload=False is a no-op. Empty batch with reload=True
        just reloads.
        """
        has_batch = bool(uci_batch.strip())
        if not has_batch and not reload:
            return

        if has_batch:
            tmp_path = "/tmp/fvpn_uci_batch.txt"
            self._ssh.write_file(tmp_path, uci_batch)
            self._ssh.exec(
                f"uci batch < {tmp_path} && uci commit firewall && rm -f {tmp_path}"
            )
        if reload:
            self._ssh.exec("/etc/init.d/firewall reload >/dev/null 2>&1; true")

    # ── Ipset Operations ─────────────────────────────────────────────────

    def fvpn_ipset_membership(
        self, set_name: str, add: list, remove: list
    ) -> None:
        """Apply add/remove ipset membership ops for one set in a single SSH call.

        Idempotent: uses ``-exist`` and ``|| true`` so duplicates / missing
        entries don't error out.
        """
        if not add and not remove:
            return
        cmds = []
        for entry in remove:
            cmds.append(f"ipset del {set_name} {entry} 2>/dev/null || true")
        for entry in add:
            cmds.append(f"ipset add {set_name} {entry} -exist 2>/dev/null || true")
        if cmds:
            self._ssh.exec(" ; ".join(cmds))

    def fvpn_ipset_create(self, set_name: str, set_type: str = "hash:ip") -> None:
        """Create a kernel ipset if it doesn't exist (for runtime use)."""
        self._ssh.exec(f"ipset create {set_name} {set_type} -exist 2>/dev/null || true")

    def fvpn_ipset_destroy(self, set_name: str) -> None:
        """Destroy a kernel ipset (best-effort)."""
        self._ssh.exec(f"ipset destroy {set_name} 2>/dev/null || true")

    # ── LAN Full State ───────────────────────────────────────────────────

    def fvpn_lan_full_state(self) -> dict:
        """Read live router state for FlintVPN LAN sections + ipsets.

        Returns a dict matching the shape produced by
        ``lan_sync.serialize_lan_state`` so the reconciler can compute a diff:

            {
              "ipsets": {set_name: [ip, ...], ...},
              "rules": {section_name: {field: value, ...}, ...},
            }

        Only ``fvpn_*`` sections and ipsets are returned.
        """
        out = {"ipsets": {}, "rules": {}}

        try:
            raw = self._ssh.exec("uci show firewall 2>/dev/null | grep -E '\\.fvpn_'")
        except Exception:
            raw = ""
        all_sections = RouterAPI._parse_uci_show(raw, "firewall")

        ipset_sections = {}
        rule_sections = {}
        for section, fields in all_sections.items():
            if fields.get("_type") == "ipset":
                entries = fields.get("entry", [])
                if isinstance(entries, str):
                    entries = [entries]
                ipset_name = fields.get("name", section)
                ipset_sections[ipset_name] = {
                    "section": section,
                    "entries": list(entries),
                    "match": fields.get("match", "ip"),
                    "storage": fields.get("storage", "hash"),
                }
            elif fields.get("_type") == "rule":
                rule_sections[section] = {k: v for k, v in fields.items() if k != "_type"}

        live_membership = {}
        for ipset_name in ipset_sections.keys():
            try:
                raw = self._ssh.exec(
                    f"ipset list {ipset_name} 2>/dev/null | "
                    "awk 'p{print} /^Members:/{p=1}' || true"
                )
                live_membership[ipset_name] = [
                    l.strip() for l in raw.strip().splitlines() if l.strip()
                ]
            except Exception:
                live_membership[ipset_name] = []

        out["ipsets"] = live_membership
        out["ipset_uci"] = {
            name: info["section"] for name, info in ipset_sections.items()
        }
        out["ipset_uci_entries"] = {
            name: info["entries"] for name, info in ipset_sections.items()
        }
        out["rules"] = rule_sections
        return out

    # ── LAN Wipe ─────────────────────────────────────────────────────────

    def fvpn_lan_wipe_all(self) -> None:
        """Delete every fvpn_* UCI section and destroy every fvpn_* kernel ipset.

        Used by ``cli.py reset-local-state`` and the migration step. Reloads
        firewall once at the end to clear any leftover iptables rules.
        """
        try:
            raw = self._ssh.exec(
                "uci show firewall 2>/dev/null | grep -oE 'fvpn_[a-zA-Z0-9_]+' | sort -u"
            )
        except Exception:
            raw = ""
        sections = [s.strip() for s in raw.strip().splitlines() if s.strip()]
        if sections:
            cmds = [f"uci -q delete firewall.{s}" for s in sections]
            cmds.append("uci commit firewall")
            self._ssh.exec(" ; ".join(cmds))
        try:
            raw = self._ssh.exec(
                "ipset list -n 2>/dev/null | grep -E '^fvpn_' || true"
            )
        except Exception:
            raw = ""
        for name in raw.strip().splitlines():
            name = name.strip()
            if name.startswith("fvpn_"):
                self._ssh.exec(f"ipset destroy {name} 2>/dev/null || true")
        self._ssh.exec(
            "iptables -D FORWARD -j fvpn_lan 2>/dev/null; "
            "iptables -F fvpn_lan 2>/dev/null; "
            "iptables -X fvpn_lan 2>/dev/null; true"
        )
        try:
            self._ssh.exec("/etc/init.d/firewall reload 2>&1 >/dev/null; true")
        except Exception:
            pass

    # ── mDNS Reflection ──────────────────────────────────────────────────

    def setup_mdns_reflection(self, interface_name: str):
        """Enable mDNS/avahi reflection between a WG tunnel and LAN.

        Needed for Chromecast/AirPlay discovery across tunnel boundaries.
        """
        avahi_check = self._ssh.exec("which avahi-daemon 2>/dev/null || echo ''")
        if not avahi_check:
            return

        l3_dev = self._ssh.exec(
            f"ifstatus {interface_name} 2>/dev/null | "
            "jsonfilter -e '@.l3_device' 2>/dev/null || echo ''"
        ).strip()

        if not l3_dev:
            return

        avahi_conf = "/etc/avahi/avahi-daemon.conf"
        self._ssh.exec(
            f"grep -q 'enable-reflector=yes' {avahi_conf} 2>/dev/null || "
            f"sed -i 's/enable-reflector=no/enable-reflector=yes/' {avahi_conf} 2>/dev/null"
        )
        self._ssh.exec("/etc/init.d/avahi-daemon restart &>/dev/null &")
