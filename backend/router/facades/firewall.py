"""Router firewall facade — UCI ipsets, LAN rules, mDNS reflection.

Delegates to tool-layer objects (Uci, Ipset, ServiceCtl) via explicit
tool injection.
"""


class RouterFirewall:
    """Facade for firewall and ipset operations on the GL.iNet Flint 2."""

    def __init__(self, uci, ipset, service_ctl, ssh):
        self._uci = uci
        self._ipset = ipset
        self._service_ctl = service_ctl
        self._ssh = ssh  # raw exec for avahi, ifstatus

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
            self._uci.batch(uci_batch, "firewall")
        if reload:
            self._service_ctl.reload("firewall")

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
        self._ipset.membership_batch(set_name, add=add, remove=remove)

    def fvpn_ipset_create(self, set_name: str, set_type: str = "hash:ip") -> None:
        """Create a kernel ipset if it doesn't exist (for runtime use)."""
        self._ipset.create(set_name, set_type)

    def fvpn_ipset_destroy(self, set_name: str) -> None:
        """Destroy a kernel ipset (best-effort)."""
        self._ipset.destroy(set_name)

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
        self._service_ctl.restart("avahi-daemon", background=True)
