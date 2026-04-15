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

    # ── IPv6 Leak Prevention ───────────────────────────────────────────

    def ensure_ipv6_router_enabled(self) -> None:
        """Enable IPv6 at the router level with NAT6 mode.

        Idempotent: checks current state before making changes.
        Enables the kernel IPv6 stack, configures WAN6 for DHCPv6,
        and enables IPv6 on all FlintVPN-managed LAN networks.
        """
        SYSCTL_FILE = "/etc/sysctl.d/99-fvpn-ipv6.conf"

        # 1. Check if already enabled
        state = self._ssh.exec(
            "sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo 1"
        ).strip()
        if state == "0":
            # IPv6 kernel already enabled — check WAN6
            wan6_disabled = self._uci.get("network.wan6.disabled", "0").strip()
            if wan6_disabled == "0":
                return  # Already fully enabled

        # 2. Enable kernel IPv6
        self._ssh.exec(
            "sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1; "
            "sysctl -w net.ipv6.conf.default.disable_ipv6=0 >/dev/null 2>&1"
        )
        # Persist across reboots
        self._ssh.write_file(SYSCTL_FILE, (
            "net.ipv6.conf.all.disable_ipv6=0\n"
            "net.ipv6.conf.default.disable_ipv6=0\n"
        ))

        # 3. Configure WAN6 for NAT6 (DHCPv6 from ISP)
        self._uci.set("network.wan6.disabled", "0")
        self._uci.set("network.wan6.proto", "dhcpv6")
        self._uci.set("network.wan.ipv6", "1")
        self._uci.commit("network")

        # 4. Bring WAN6 up (safe — only affects WAN6 interface)
        self._ssh.exec("ubus call network.interface.wan6 up 2>/dev/null; true")

        # 5. Reload services to pick up IPv6 changes
        self._service_ctl.reload("dnsmasq")
        self._service_ctl.reload("firewall")

    def disable_ipv6_router(self) -> None:
        """Disable IPv6 at the router level. Idempotent."""
        SYSCTL_FILE = "/etc/sysctl.d/99-fvpn-ipv6.conf"

        # 1. Disable kernel IPv6
        self._ssh.exec(
            "sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1; "
            "sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1"
        )
        self._ssh.exec(f"rm -f {SYSCTL_FILE}")

        # 2. Disable WAN6
        self._uci.set("network.wan6.disabled", "1")
        self._uci.commit("network")

        # 3. Bring WAN6 down
        self._ssh.exec("ubus call network.interface.wan6 down 2>/dev/null; true")

        self._service_ctl.reload("firewall")

    def ensure_ipv6_leak_protection(self) -> None:
        """Block all IPv6 forwarding to prevent leaks.

        Writes a firewall include script that sets the FORWARD chain
        default policy to DROP and only allows ESTABLISHED/RELATED return
        traffic.  Re-applied on every ``firewall reload``.

        Later phases (Phase 4) will evolve this into selective
        per-tunnel forwarding.
        """
        from consts import IPV6_FWD_SCRIPT

        script = (
            "#!/bin/sh\n"
            "# Auto-generated by FlintVPN — IPv6 leak prevention\n"
            "# Re-applied on every firewall reload\n\n"
            "ip6tables -P FORWARD DROP\n"
            "ip6tables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT\n"
        )
        self._ssh.write_file(IPV6_FWD_SCRIPT, script)
        self._ssh.exec(f"chmod +x {IPV6_FWD_SCRIPT}")
        self._uci.ensure_firewall_include("fvpn_ipv6_fwd", IPV6_FWD_SCRIPT)

    def remove_ipv6_leak_protection(self) -> None:
        """Remove the IPv6 FORWARD block and firewall include."""
        from consts import IPV6_FWD_SCRIPT

        self._uci.delete("firewall.fvpn_ipv6_fwd")
        self._uci.commit("firewall")
        self._ssh.exec(f"rm -f {IPV6_FWD_SCRIPT}")

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
