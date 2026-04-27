"""Router facade for LAN access control — network discovery and zone rules.

Reads wireless/network/firewall UCI config to discover networks (SSIDs),
manages fw3 zone forwarding entries for cross-network access, and applies
per-device iptables exception rules.

Tool-layer objects (Uci, Iptables, ServiceCtl) are injected directly.
The raw ``ssh`` handle is kept only for bulk uci show, sed, ifup, wifi
driver reload, and write_file calls.
"""

import ipaddress
import re

from router.tools.uci import Uci

_SAFE_NAME_RE = re.compile(r'^[a-zA-Z0-9_-]+$')
_SAFE_IP_RE = re.compile(r'^[0-9a-fA-F.:/%]+$')

# Zone names to skip in cross-network rules (wan is managed separately)
_SKIP_ZONES = {"wan"}
# Prefixes used by vpn-client / Flint VPN Manager for tunnel interfaces — not real LANs
_VPN_ZONE_PREFIXES = ("wgclient", "ovpnclient", "protonwg", "wgserver", "ovpnserver")


class RouterLanAccess:
    """Facade for cross-network access control on the GL.iNet Flint 2."""

    def __init__(self, uci, iptables, service_ctl, ssh, ip6tables=None):
        self._uci = uci
        self._ip6tables = ip6tables
        self._iptables = iptables
        self._service_ctl = service_ctl
        self._ssh = ssh  # raw exec for uci show (bulk), sed, ifup, wifi driver; write_file for scripts

    # ── Network Discovery ─────────────────────────────────────────────

    def get_networks(self) -> list[dict]:
        """Discover networks from UCI wireless + network + firewall config.

        Returns a list of network dicts, each with:
          id, zone, ssids, bridge, subnet, isolation, enabled, device_count
        """
        raw = self._ssh.exec(
            "uci show wireless 2>/dev/null; echo '===SPLIT==='; "
            "uci show network 2>/dev/null; echo '===SPLIT==='; "
            "uci show firewall 2>/dev/null"
        )
        parts = raw.split("===SPLIT===")
        wireless = Uci.parse_show(parts[0] if len(parts) > 0 else "", "wireless")
        network = Uci.parse_show(parts[1] if len(parts) > 1 else "", "network")
        firewall = Uci.parse_show(parts[2] if len(parts) > 2 else "", "firewall")

        # Build zone → network name mapping from firewall zones
        zone_to_networks = {}
        for section, fields in firewall.items():
            if fields.get("_type") != "zone":
                continue
            zone_name = fields.get("name", "")
            if not zone_name or zone_name in _SKIP_ZONES:
                continue
            if any(zone_name.startswith(p) for p in _VPN_ZONE_PREFIXES):
                continue
            net_names = fields.get("network", [])
            if isinstance(net_names, str):
                net_names = [net_names]
            zone_to_networks[zone_name] = net_names

        # Build network name → interface info from network config
        net_info = {}
        for section, fields in network.items():
            if fields.get("_type") != "interface":
                continue
            ipaddr = fields.get("ipaddr", "")
            netmask = fields.get("netmask", "255.255.255.0")
            bridge = fields.get("device", f"br-{section}")
            disabled = fields.get("disabled", "0") == "1"
            subnet = ""
            if ipaddr:
                try:
                    iface = ipaddress.IPv4Interface(f"{ipaddr}/{netmask}")
                    subnet = str(iface.network)
                except ValueError:
                    subnet = f"{ipaddr}/24"
            ip6assign = fields.get("ip6assign", "")
            net_info[section] = {
                "ipaddr": ipaddr, "netmask": netmask,
                "bridge": bridge, "subnet": subnet, "disabled": disabled,
                "ipv6_enabled": bool(ip6assign),
            }

        # Build wifi-iface → network mapping
        wifi_ifaces = {}
        for section, fields in wireless.items():
            if fields.get("_type") != "wifi-iface":
                continue
            net_name = fields.get("network", "")
            disabled = fields.get("disabled", "0") == "1"
            device_name = fields.get("device", "")
            wifi_ifaces.setdefault(net_name, []).append({
                "section": section,
                "device": device_name,
                "ssid": fields.get("ssid", ""),
                "ifname": fields.get("ifname", ""),
                "band": _band_from_device(device_name, wireless),
                "isolate": fields.get("isolate", "0") == "1",
                "disabled": disabled,
                "encryption": fields.get("encryption", ""),
                "hidden": fields.get("hidden", "0") == "1",
                "password": fields.get("key", ""),
            })

        # Get device counts per subnet
        try:
            leases = self._ssh.exec("cat /tmp/dhcp.leases 2>/dev/null || echo ''")
        except Exception:
            leases = ""
        device_counts = _count_devices_per_subnet(leases, net_info)

        # Assemble network list
        networks = []
        for zone_name, net_names in zone_to_networks.items():
            primary_net = net_names[0] if net_names else zone_name
            info = net_info.get(primary_net, {})
            ifaces = wifi_ifaces.get(primary_net, [])

            ssids = [
                {"name": w["ssid"], "iface": w["ifname"], "band": w["band"],
                 "section": w["section"], "device": w["device"],
                 "encryption": w["encryption"],
                 "hidden": w["hidden"], "password": w["password"],
                 "disabled": w["disabled"]}
                for w in ifaces
            ]

            radios = {}
            for w in ifaces:
                dev = w.get("device", "")
                if dev and dev not in radios:
                    radio = wireless.get(dev, {})
                    radios[dev] = {
                        "device": dev,
                        "band": w["band"],
                        "channel": radio.get("channel", "auto"),
                        "txpower": radio.get("txpower", "100"),
                        "htmode": radio.get("htmode", ""),
                        "hwmode": radio.get("hwmode", ""),
                        "random_bssid": radio.get("random_bssid", "0") == "1",
                        "country": radio.get("country", ""),
                    }
            isolation = any(w["isolate"] for w in ifaces)
            enabled = not info.get("disabled", False) and any(not w["disabled"] for w in ifaces)
            if not ifaces and not info.get("disabled", False):
                enabled = True

            networks.append({
                "id": zone_name,
                "zone": zone_name,
                "ssids": ssids,
                "bridge": info.get("bridge", f"br-{primary_net}"),
                "subnet": info.get("subnet", ""),
                "isolation": isolation,
                "enabled": enabled,
                "device_count": device_counts.get(info.get("subnet", ""), 0),
                "ipv6_enabled": info.get("ipv6_enabled", False),
            })

        return networks

    def get_zone_forwardings(self) -> list[dict]:
        """Read all firewall forwarding entries between LAN-side zones."""
        raw = self._ssh.exec("uci show firewall 2>/dev/null || echo ''")
        firewall = Uci.parse_show(raw, "firewall")

        forwardings = []
        for section, fields in firewall.items():
            if fields.get("_type") != "forwarding":
                continue
            src = fields.get("src", "")
            dest = fields.get("dest", "")
            if src in _SKIP_ZONES or dest in _SKIP_ZONES:
                continue
            if any(src.startswith(p) or dest.startswith(p) for p in _VPN_ZONE_PREFIXES):
                continue
            if not src or not dest:
                continue
            forwardings.append({"src": src, "dest": dest, "section": section})
        return forwardings

    # ── Zone Forwarding Rules ─────────────────────────────────────────

    def set_zone_forwarding(self, src_zone: str, dest_zone: str, allowed: bool) -> None:
        """Create or remove a firewall forwarding entry between two zones."""
        if not _SAFE_NAME_RE.match(src_zone) or not _SAFE_NAME_RE.match(dest_zone):
            raise ValueError(f"Invalid zone name: {src_zone!r} or {dest_zone!r}")
        existing = self.get_zone_forwardings()
        found = next(
            (f for f in existing if f["src"] == src_zone and f["dest"] == dest_zone),
            None,
        )

        if allowed and not found:
            self._ssh.exec(
                "uci add firewall forwarding; "
                f"uci set firewall.@forwarding[-1].src='{src_zone}'; "
                f"uci set firewall.@forwarding[-1].dest='{dest_zone}'; "
                "uci commit firewall"
            )
            self._service_ctl.reload("firewall")
        elif not allowed and found:
            section = found["section"]
            self._uci.delete(f"firewall.{section}")
            self._uci.commit("firewall")
            self._service_ctl.reload("firewall")

    # ── WiFi Isolation ────────────────────────────────────────────────

    def set_wifi_isolation(self, wifi_sections: list[str], enabled: bool) -> None:
        """Toggle AP isolation for wireless interfaces and reload WiFi once."""
        val = "1" if enabled else "0"
        for section in wifi_sections:
            if not _SAFE_NAME_RE.match(section):
                raise ValueError(f"Invalid wifi section: {section!r}")
            self._uci.set(f"wireless.{section}.isolate", val)
        if not wifi_sections:
            return
        self._uci.commit("wireless")
        self._service_ctl.wifi_reload()

    # ── IPv6 per-network ─────────────────────────────────────────────

    def set_ipv6(self, net_section: str, enabled: bool) -> None:
        """Enable or disable IPv6 (RA + DHCPv6 + prefix delegation) on a network.

        When enabling, allocates a /64 prefix from the router's ULA pool
        and configures dnsmasq to serve RA and DHCPv6 on the interface.
        """
        if not _SAFE_NAME_RE.match(net_section):
            raise ValueError(f"Invalid network section: {net_section!r}")

        if enabled:
            hint = self._next_ip6hint()
            self._uci.set(f"network.{net_section}.ip6assign", "64")
            self._uci.set(f"network.{net_section}.ip6hint", hint)
            self._uci.set(f"network.{net_section}.ip6ifaceid", "::1")
            self._uci.set(f"dhcp.{net_section}.dhcpv6", "server")
            self._uci.set(f"dhcp.{net_section}.ra", "server")
            self._uci.set(f"dhcp.{net_section}.ra_default", "1")
            # ra_flags: delete first to avoid duplicates, then add
            self._uci.delete(f"dhcp.{net_section}.ra_flags")
            self._uci.add_list(f"dhcp.{net_section}.ra_flags", "other-config")
            self._uci.add_list(f"dhcp.{net_section}.ra_flags", "managed-config")
        else:
            self._uci.delete(f"network.{net_section}.ip6assign")
            self._uci.delete(f"network.{net_section}.ip6hint")
            self._uci.delete(f"network.{net_section}.ip6ifaceid")
            self._uci.set(f"dhcp.{net_section}.dhcpv6", "disabled")
            self._uci.set(f"dhcp.{net_section}.ra", "disabled")
            self._uci.delete(f"dhcp.{net_section}.ra_default")
            self._uci.delete(f"dhcp.{net_section}.ra_flags")

        self._uci.commit("network", "dhcp")
        # Poke netifd to apply the prefix delegation on the bridge
        self._ssh.exec(
            f"ubus call network.interface.{net_section} up 2>/dev/null; true"
        )
        self._service_ctl.reload("dnsmasq")
        self._service_ctl.reload("firewall")

    def _next_ip6hint(self) -> str:
        """Find the next unused ip6hint value across all network interfaces."""
        raw = self._ssh.exec(
            "uci show network 2>/dev/null | grep 'ip6hint=' || true"
        )
        used = set()
        for line in raw.strip().splitlines():
            # network.lan.ip6hint='0000'
            val = line.split("=", 1)[-1].strip().strip("'\"")
            try:
                used.add(int(val, 16))
            except ValueError:
                pass
        for i in range(1, 256):
            if i not in used:
                return f"{i:04x}"
        return "00ff"

    # ── Device Exceptions ─────────────────────────────────────────────

    def apply_device_exceptions(self, exceptions: list[dict]) -> None:
        """Write iptables + ip6tables ACCEPT rules for device-level exceptions.

        Also installs LAN-destined ``ip rule`` overrides — see
        :py:meth:`_lan_subnets` for why filter ACCEPT alone is not enough.
        Pass an empty ``exceptions`` list to refresh the include script
        and routing rules without any device-specific ACCEPT entries —
        the routing override is unconditional and must run regardless.
        """
        for ipt in self._all_iptables():
            ipt.ensure_chain("filter", "fvpn_lan_exc")
            ipt.flush_chain("filter", "fvpn_lan_exc")

            for exc in exceptions:
                from_ip = exc.get("from_ip", "")
                to_ip = exc.get("to_ip", "")
                direction = exc.get("direction", "both")
                if not from_ip or not to_ip:
                    continue
                if not _SAFE_IP_RE.match(from_ip) or not _SAFE_IP_RE.match(to_ip):
                    continue
                # Determine address family and route to correct iptables binary
                is_v6 = ":" in from_ip or ":" in to_ip
                if is_v6 and ipt is self._iptables:
                    continue  # Skip IPv6 addresses in iptables
                if not is_v6 and ipt is not self._iptables:
                    continue  # Skip IPv4 addresses in ip6tables
                if direction in ("outbound", "both"):
                    ipt.append("filter", "fvpn_lan_exc",
                               f"-s {from_ip} -d {to_ip} -j ACCEPT")
                if direction in ("inbound", "both"):
                    ipt.append("filter", "fvpn_lan_exc",
                               f"-s {to_ip} -d {from_ip} -j ACCEPT")

            ipt.insert_if_absent("filter", "forwarding_rule", "-j fvpn_lan_exc")
            ipt.insert_if_absent(
                "filter", "forwarding_rule",
                "-m mark ! --mark 0x0/0xf000 -j ACCEPT",
            )

        # Apply the ip-rule routing override at runtime so the fix takes
        # effect immediately without waiting for a firewall reload.
        self._apply_lan_route_rules_runtime()
        # Enable subnet-broadcast forwarding (cross-subnet Wake-on-LAN).
        # Same lifecycle as the priority-50 rules: unconditional, applied
        # on every reapply, persisted via the same fw3 include below.
        self._apply_bc_forwarding_runtime()
        self._write_firewall_include(exceptions)

    def _all_iptables(self):
        """Yield iptables tool, and ip6tables if available."""
        yield self._iptables
        if self._ip6tables:
            yield self._ip6tables

    def cleanup_exceptions(self) -> None:
        """Remove all exception iptables/ip6tables rules and firewall include."""
        for ipt in self._all_iptables():
            ipt.delete_chain("filter", "forwarding_rule", "fvpn_lan_exc")
        # Remove the ip-rule routing overrides at runtime as well.
        self._remove_lan_route_rules_runtime()
        # Reset bc_forwarding to the kernel default (off) — the include
        # script that re-enabled it on every firewall reload is also gone.
        self._remove_bc_forwarding_runtime()
        self._ssh.exec("rm -f /etc/fvpn/lan_access_rules.sh")
        self._uci.delete("firewall.fvpn_lan_access")
        self._uci.commit("firewall")

    # ── LAN-destined route override ───────────────────────────────────
    #
    # WHY THIS EXISTS:
    #
    # On the Flint 2, vpn-client installs a policy-routing rule at priority
    # 100 — ``from all fwmark 0x8000/0xf000 lookup 1008`` — and table 1008
    # is just ``default via <gateway> dev eth1`` (the WAN). Any device that
    # doesn't match a tunnel ipset (typically devices in a ``no_internet``
    # group, but also unassigned MACs and bypass-only flows) gets the
    # fallback mark ``0x8000`` stamped by ``TUNNEL100_ROUTE_POLICY`` (the
    # "last sort default policy" chain). The mark also leaks onto the
    # *reply* direction via ``CONNMARK save``/``restore`` on udp dpt:53
    # in mangle PREROUTING/OUTPUT — i.e. the router's own DNS replies
    # carry the mark too.
    #
    # Without an override, ANY packet destined to a LAN subnet that
    # happens to carry mark 0x8000 hits ip rule 100 first and gets routed
    # to table 1008 → out the WAN. This affects:
    #
    #   1. Cross-bridge reply traffic (NoInternet device on br-X talking
    #      to a host on br-Y via a LAN exception — what 009869f originally
    #      fixed).
    #   2. **Locally-emitted traffic from the router itself** to an
    #      unassigned/NoInternet device — most importantly dnsmasq DNS
    #      replies. The reply packet has no ``iif`` (it's locally
    #      generated, ``iif lo``), so an ``iif br-X``-scoped rule does
    #      not catch it, and the reply silently leaves via WAN — visible
    #      on ``any`` capture but never on the destination bridge.
    #      (This was the ChromeCast-no-internet incident.)
    #   3. Traffic forwarded between *the same* bridge in unusual hairpin
    #      cases.
    #
    # The fix is to install higher-priority (priority 50) ip rules that
    # force any traffic destined to a LAN subnet — regardless of source
    # interface or how it originated — to use the LAN routing table 9910.
    # ``to <subnet>`` alone is the right selector: if the destination is
    # a LAN we own, the answer is always "deliver via the local bridge",
    # full stop. Filter ACCEPT in ``fvpn_lan_exc`` is still the gate for
    # whether the cross-bridge traffic is allowed — these rules only fix
    # the routing decision.
    #
    # IMPORTANT: This override is unconditional — installed on every
    # unlock and on every network create/update/delete, NOT gated on
    # whether LAN exceptions exist. Even a single-LAN setup with zero
    # exceptions needs it, because case (2) above (router-originated DNS
    # replies to unassigned devices) does not require any exceptions or
    # multiple bridges.
    #
    # See docs/internals/debugging-catalogue.md for the original incident
    # (cross-bridge LAN exceptions) and the ChromeCast incident
    # (locally-emitted DNS replies).

    _LAN_RULE_PRIORITY = 50
    _LAN_ROUTE_TABLE = 9910

    def _lan_subnets(self) -> list[str]:
        """Return CIDR subnets for every active LAN-side network.

        A "LAN-side network" is anything :py:meth:`get_networks` returns —
        which already excludes ``wan`` and tunnel interfaces. Disabled
        networks are skipped because their bridges have no IP address.
        """
        subnets = []
        try:
            networks = self.get_networks()
        except Exception:
            return subnets
        for net in networks:
            subnet = net.get("subnet", "")
            if not subnet:
                continue
            if not net.get("enabled", True):
                continue
            subnets.append(subnet)
        return subnets

    def _apply_lan_route_rules_runtime(self) -> None:
        """Install priority-50 ip rules at runtime for every LAN subnet.

        One rule per subnet, no ``iif`` selector — see class docstring re:
        why locally-emitted traffic (which has ``iif lo``, not a bridge)
        also needs to win against vpn-client's priority-100 fwmark rule.

        Idempotent: existing rules with the same priority + ``to`` selector
        are flushed first via a ``while ip rule del`` loop so a repeated
        apply doesn't accumulate duplicates.
        """
        subnets = self._lan_subnets()
        if not subnets:
            return
        cmds = []
        for subnet in subnets:
            cmds.append(
                f"while ip rule del priority {self._LAN_RULE_PRIORITY} "
                f"to {subnet} 2>/dev/null; do :; done"
            )
            cmds.append(
                f"ip rule add priority {self._LAN_RULE_PRIORITY} "
                f"to {subnet} lookup {self._LAN_ROUTE_TABLE} 2>/dev/null"
            )
        self._ssh.exec("; ".join(cmds))

    def _remove_lan_route_rules_runtime(self) -> None:
        """Strip every priority-50 ip rule we may have added.

        Uses the subnets as they exist *now* — if a network has since
        been deleted its rule will already be gone, so a missing ``ip
        rule del`` simply no-ops.
        """
        subnets = self._lan_subnets()
        if not subnets:
            return
        cmds = [
            f"while ip rule del priority {self._LAN_RULE_PRIORITY} "
            f"to {subnet} 2>/dev/null; do :; done"
            for subnet in subnets
        ]
        self._ssh.exec("; ".join(cmds))

    # ── Subnet-broadcast forwarding (cross-subnet Wake-on-LAN) ────────
    #
    # WHY THIS EXISTS:
    #
    # Wake-on-LAN magic packets are L2-only broadcast — they don't cross
    # subnets. When Home Assistant on br-lan (192.168.8.x) tries to wake
    # a device on br-fvpn_iot (192.168.10.x) via ``wake_tv(mac, subnet)``
    # it broadcasts to ``192.168.10.255`` (subnet-directed broadcast).
    # By default Linux drops directed broadcasts on the forwarding path
    # (``net.ipv4.conf.<iface>.bc_forwarding=0``, smurf-attack
    # protection). With ``bc_forwarding=1`` on the input + output bridge
    # interfaces, the kernel translates the IP broadcast into an L2
    # broadcast (``ff:ff:ff:ff:ff:ff``) on the egress bridge, which the
    # WoL listener on the target NIC then accepts.
    #
    # The cross-bridge ROUTING decision is already correct thanks to the
    # priority-50 ip rules above (they beat vpn-client's priority-100
    # fwmark rule for any traffic destined to a LAN subnet, broadcast or
    # unicast). The cross-bridge FORWARDING decision is gated by fw3
    # zone forwarding entries — so ``bc_forwarding=1`` only widens the
    # broadcast surface to zones the user has already explicitly bridged
    # (e.g. ``lan→fvpn_iot``). Same lifecycle as the priority-50 rules:
    # unconditional, applied on every ``apply_device_exceptions`` call,
    # persisted via the same fw3 include so it survives reboot.
    #
    # See docs/internals/debugging-catalogue.md for the original WoL
    # debugging story.

    def _apply_bc_forwarding_runtime(self) -> None:
        """Enable directed-broadcast forwarding on every active LAN bridge.

        Idempotent: ``sysctl -w`` always rewrites the value. Bridges that
        no longer exist silently fall back to the ``2>/dev/null || true``
        guard. Tunnel/VPN bridges are excluded by virtue of
        :py:meth:`get_networks` filtering on LAN-side zones only.
        """
        bridges = self._lan_bridges()
        if not bridges:
            return
        cmds = ["sysctl -wq net.ipv4.conf.all.bc_forwarding=1"]
        for bridge in bridges:
            cmds.append(
                f'sysctl -wq "net.ipv4.conf.{bridge}.bc_forwarding=1" '
                f"2>/dev/null || true"
            )
        self._ssh.exec("; ".join(cmds))

    def _remove_bc_forwarding_runtime(self) -> None:
        """Reset directed-broadcast forwarding to the kernel default (off).

        Mirrors :py:meth:`_remove_lan_route_rules_runtime`: called only
        from :py:meth:`cleanup_exceptions` when LAN access is being torn
        down entirely.
        """
        bridges = self._lan_bridges()
        if not bridges:
            return
        cmds = ["sysctl -wq net.ipv4.conf.all.bc_forwarding=0"]
        for bridge in bridges:
            cmds.append(
                f'sysctl -wq "net.ipv4.conf.{bridge}.bc_forwarding=0" '
                f"2>/dev/null || true"
            )
        self._ssh.exec("; ".join(cmds))

    def _lan_bridges(self) -> list[str]:
        """Return bridge interface names for every active LAN-side network.

        Same filter as :py:meth:`_lan_subnets` (enabled networks only,
        VPN/wan zones already excluded by :py:meth:`get_networks`), but
        emits the bridge name (e.g. ``br-lan``, ``br-fvpn_iot``)
        instead of the CIDR. Bridges with non-safe characters are
        skipped — defense against UCI-injected malformed values.
        """
        bridges = []
        try:
            networks = self.get_networks()
        except Exception:
            return bridges
        for net in networks:
            bridge = net.get("bridge", "")
            if not bridge or not net.get("enabled", True):
                continue
            if not _SAFE_NAME_RE.match(bridge):
                continue
            bridges.append(bridge)
        return bridges

    def _write_firewall_include(self, exceptions: list[dict]) -> None:
        """Write firewall include script for reboot persistence (dual-stack).

        The script also re-installs the priority-50 ``ip rule`` overrides
        described in :py:meth:`_lan_route_pairs` — these are kernel state
        that does NOT survive a router reboot, and ``firewall reload``
        re-runs every fw3 include so this is the canonical place to keep
        them in sync with the live network topology.
        """
        lines = [
            "#!/bin/sh",
            "# Flint VPN Manager LAN access exceptions — auto-generated",
        ]

        for binary in ("iptables", "ip6tables"):
            lines.append(f"{binary} -N fvpn_lan_exc 2>/dev/null || true")
            lines.append(f"{binary} -F fvpn_lan_exc")

        for exc in exceptions:
            from_ip = exc.get("from_ip", "")
            to_ip = exc.get("to_ip", "")
            direction = exc.get("direction", "both")
            if not from_ip or not to_ip:
                continue
            if not _SAFE_IP_RE.match(from_ip) or not _SAFE_IP_RE.match(to_ip):
                continue
            binary = "ip6tables" if (":" in from_ip or ":" in to_ip) else "iptables"
            if direction in ("outbound", "both"):
                lines.append(
                    f"{binary} -A fvpn_lan_exc -s {from_ip} -d {to_ip} -j ACCEPT"
                )
            if direction in ("inbound", "both"):
                lines.append(
                    f"{binary} -A fvpn_lan_exc -s {to_ip} -d {from_ip} -j ACCEPT"
                )

        for binary in ("iptables", "ip6tables"):
            lines.append(
                f"{binary} -C forwarding_rule -j fvpn_lan_exc 2>/dev/null || "
                f"{binary} -I forwarding_rule 1 -j fvpn_lan_exc"
            )
            lines.append(
                f"{binary} -C forwarding_rule -m mark ! --mark 0x0/0xf000 -j ACCEPT 2>/dev/null || "
                f"{binary} -I forwarding_rule -m mark ! --mark 0x0/0xf000 -j ACCEPT"
            )

        # LAN-destined route override (see _lan_subnets docstring for why
        # this is unconditional and ``iif``-less). Without these rules
        # vpn-client's priority-100 fwmark rule sends ANY 0x8000-marked
        # traffic destined to a LAN subnet out via WAN — including the
        # router's own dnsmasq DNS replies to unassigned devices, which
        # then never reach the device.
        subnets = self._lan_subnets()
        if subnets:
            lines.append("# LAN-destined route override — beats vpn-client's")
            lines.append("# priority-100 fwmark rule so any traffic destined to a")
            lines.append("# LAN subnet (forwarded OR locally-emitted) stays local")
            lines.append("# instead of leaking to WAN.")
            for subnet in subnets:
                lines.append(
                    f"while ip rule del priority {self._LAN_RULE_PRIORITY} "
                    f"to {subnet} 2>/dev/null; do :; done"
                )
                lines.append(
                    f"ip rule add priority {self._LAN_RULE_PRIORITY} "
                    f"to {subnet} lookup {self._LAN_ROUTE_TABLE} 2>/dev/null"
                )

        # Subnet-broadcast forwarding for cross-subnet Wake-on-LAN.
        # Linux drops directed broadcasts by default; bc_forwarding=1
        # lets the kernel translate an inbound IP broadcast (e.g.
        # 192.168.10.255) into an L2 broadcast on the egress bridge so
        # WoL packets actually reach the target NIC. fw3 zone forwarding
        # still gates which bridges may be reached. See class docstring.
        bridges = self._lan_bridges()
        if bridges:
            lines.append("# Subnet-broadcast forwarding — cross-subnet Wake-on-LAN.")
            lines.append("sysctl -wq net.ipv4.conf.all.bc_forwarding=1")
            for bridge in bridges:
                lines.append(
                    f'sysctl -wq "net.ipv4.conf.{bridge}.bc_forwarding=1" '
                    f"2>/dev/null || true"
                )

        script = "\n".join(lines) + "\n"
        self._ssh.write_file("/etc/fvpn/lan_access_rules.sh", script)
        self._ssh.exec("chmod +x /etc/fvpn/lan_access_rules.sh")

        # Register firewall include (idempotent)
        self._uci.ensure_firewall_include(
            "fvpn_lan_access", "/etc/fvpn/lan_access_rules.sh"
        )

    # ── Network CRUD ───────────────────────────────────────────────

    _DAT_PATHS = (
        "/etc/wireless/mediatek/mt7986-ax6000.dbdc.b0.dat",
        "/etc/wireless/mediatek/mt7986-ax6000.dbdc.b1.dat",
    )

    def enable_network(self, wifi_sections: list[str], net_section: str, enabled: bool) -> None:
        """Enable or disable a network (wireless + network interface)."""
        val = "0" if enabled else "1"
        for s in wifi_sections:
            if not _SAFE_NAME_RE.match(s):
                raise ValueError(f"Invalid section: {s!r}")
            self._uci.set(f"wireless.{s}.disabled", val)
        if net_section and _SAFE_NAME_RE.match(net_section):
            self._uci.set(f"network.{net_section}.disabled", val)
        self._uci.commit("wireless", "network")
        self._service_ctl.wifi_reload()

    def update_network_wireless(self, wifi_section: str, settings: dict) -> None:
        """Update wireless settings for one wifi-iface section."""
        if not _SAFE_NAME_RE.match(wifi_section):
            raise ValueError(f"Invalid section: {wifi_section!r}")
        allowed = {"ssid", "key", "encryption", "hidden", "isolate", "disabled"}
        any_set = False
        for key, val in settings.items():
            if key not in allowed:
                continue
            if key in ("ssid", "key") and not val:
                continue
            if key in ("hidden", "isolate", "disabled"):
                val = "1" if val else "0"
            self._uci.set(f"wireless.{wifi_section}.{key}", str(val))
            any_set = True
        if not any_set:
            return
        self._uci.commit("wireless")
        self._service_ctl.wifi_reload()

    def create_network(self, zone_id: str, ssid: str, password: str,
                       subnet_ip: str, isolation: bool = True) -> None:
        """Create a new WiFi network with full infrastructure."""
        if not _SAFE_NAME_RE.match(zone_id):
            raise ValueError(f"Invalid zone ID: {zone_id!r}")
        if not _SAFE_IP_RE.match(subnet_ip):
            raise ValueError(f"Invalid subnet IP: {subnet_ip!r}")

        # Increase BssidNum in .dat files
        bssid_num = self._get_bssid_num()
        new_num = bssid_num + 1
        for path in self._DAT_PATHS:
            self._ssh.exec(
                f"sed -i 's/^BssidNum={bssid_num}/BssidNum={new_num}/' {path}"
            )

        iface_2g = f"ra{bssid_num}"
        iface_5g = f"rax{bssid_num}"
        iso = "1" if isolation else "0"
        zn = f"fvpn_{zone_id}"

        # Build UCI batch with structured data (properly quoted)
        self._uci.batch_sections([
            # Wireless 2.4G
            (f"wireless.{zn}_2g", {
                "_type": "wifi-iface",
                "device": "mt798611", "network": zn, "mode": "ap",
                "ifname": iface_2g, "ssid": ssid, "encryption": "psk2",
                "key": password, "isolate": iso, "disabled": "0",
            }),
            # Wireless 5G
            (f"wireless.{zn}_5g", {
                "_type": "wifi-iface",
                "device": "mt798612", "network": zn, "mode": "ap",
                "ifname": iface_5g, "ssid": f"{ssid}-5G", "encryption": "psk2",
                "key": password, "isolate": iso, "disabled": "0",
            }),
            # Network interface (dual-stack: IPv4 static + IPv6 prefix delegation)
            (f"network.{zn}", {
                "_type": "interface",
                "proto": "static", "type": "bridge",
                "ipaddr": subnet_ip, "netmask": "255.255.255.0",
                "force_link": "1", "bridge_empty": "1",
                "ip6assign": "64",
                "ip6hint": self._next_ip6hint(),
                "ip6ifaceid": "::1",
            }),
            # Firewall zone
            (f"firewall.{zn}_zone", {
                "_type": "zone",
                "name": zn, "network": zn,
                "input": "REJECT", "output": "ACCEPT", "forward": "REJECT",
            }),
            # DHCP + DNS allow rules
            (f"firewall.{zn}_dhcp", {
                "_type": "rule",
                "name": f"Allow-DHCP-{zn}", "src": zn,
                "proto": "udp", "dest_port": "67-68", "target": "ACCEPT",
            }),
            (f"firewall.{zn}_dns", {
                "_type": "rule",
                "name": f"Allow-DNS-{zn}", "src": zn,
                "proto": "tcpudp", "dest_port": "53", "target": "ACCEPT",
            }),
            # mDNS allow (for avahi cross-network discovery reflection)
            (f"firewall.{zn}_mdns", {
                "_type": "rule",
                "name": f"Allow-mDNS-{zn}", "src": zn,
                "proto": "udp", "dest_port": "5353", "target": "ACCEPT",
            }),
            # WAN forwarding
            (f"firewall.{zn}_wan", {
                "_type": "forwarding",
                "src": zn, "dest": "wan",
            }),
            # DHCP pool (dual-stack: DHCPv4 + DHCPv6 + RA)
            (f"dhcp.{zn}", {
                "_type": "dhcp",
                "interface": zn, "start": "100", "limit": "150",
                "leasetime": "12h",
                "dhcpv6": "server", "ra": "server", "ra_default": "1",
            }),
        ], "wireless", "network", "firewall", "dhcp")
        self._ssh.exec(f"ifup fvpn_{zone_id} 2>/dev/null; true")
        self._reload_wifi_driver()

    def delete_network(self, zone_id: str) -> None:
        """Delete a Flint VPN Manager-created network and all its UCI sections."""
        if zone_id in ("lan", "guest"):
            raise ValueError(f"Cannot delete built-in network: {zone_id}")
        if not _SAFE_NAME_RE.match(zone_id):
            raise ValueError(f"Invalid zone ID: {zone_id!r}")

        prefix = zone_id if zone_id.startswith("fvpn_") else f"fvpn_{zone_id}"
        configs = ["wireless", "network", "firewall", "dhcp"]
        cmds = []
        for config in configs:
            raw = self._ssh.exec(f"uci show {config} 2>/dev/null || true")
            sections = Uci.parse_show(raw, config)
            for section in sections:
                if section.startswith(prefix):
                    cmds.append(f"uci -q delete {config}.{section}")
        if not cmds:
            return

        # Decrement BssidNum in .dat files
        bssid_num = self._get_bssid_num()
        if bssid_num > 2:
            new_num = bssid_num - 1
            for path in self._DAT_PATHS:
                cmds.append(f"sed -i 's/^BssidNum={bssid_num}/BssidNum={new_num}/' {path}")

        cmds.extend([
            "uci commit wireless", "uci commit network",
            "uci commit firewall", "uci commit dhcp",
        ])
        self._ssh.exec(" ; ".join(cmds))
        self._reload_wifi_driver()

    def _reload_wifi_driver(self) -> None:
        """Reload the MediaTek WiFi kernel module to pick up BssidNum changes."""
        reload_script = (
            "wifi down 2>/dev/null; "
            "rmmod mtk_warp_proxy 2>/dev/null; "
            "rmmod mt_wifi 2>/dev/null; "
            "sleep 1; "
            "insmod mt_wifi 2>/dev/null; "
            "insmod mtk_warp_proxy 2>/dev/null; "
            "sleep 1; "
            "wifi up 2>/dev/null; "
            "/etc/init.d/firewall reload >/dev/null 2>&1; "
            "/etc/init.d/dnsmasq reload >/dev/null 2>&1"
        )
        try:
            self._ssh.exec(
                f"sh -c '{reload_script}' </dev/null >/dev/null 2>&1 &"
            )
        except Exception:
            pass  # expected — WiFi drop kills SSH before command returns

    def _get_bssid_num(self) -> int:
        """Read current BssidNum from the 5G .dat file."""
        raw = self._ssh.exec(f"grep BssidNum {self._DAT_PATHS[1]} 2>/dev/null || echo 'BssidNum=2'")
        for line in raw.strip().splitlines():
            if line.startswith("BssidNum="):
                return int(line.split("=")[1])
        return 2


def _band_from_device(device_name: str, wireless: dict) -> str:
    """Resolve radio device to band label (2.4G/5G)."""
    info = wireless.get(device_name, {})
    band = info.get("band", "")
    if band == "2g":
        return "2.4G"
    if band == "5g":
        return "5G"
    if "11" in device_name:
        return "2.4G"
    if "12" in device_name:
        return "5G"
    return ""


def _count_devices_per_subnet(leases_raw: str, net_info: dict) -> dict:
    """Count DHCP leases per subnet. Returns {subnet_str: count}."""
    subnet_objs = {}
    for name, info in net_info.items():
        subnet_str = info.get("subnet", "")
        if subnet_str:
            try:
                subnet_objs[subnet_str] = ipaddress.IPv4Network(subnet_str, strict=False)
            except ValueError:
                pass

    counts = {s: 0 for s in subnet_objs}
    for line in leases_raw.strip().splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            ip = ipaddress.IPv4Address(parts[2])
            for subnet_str, net in subnet_objs.items():
                if ip in net:
                    counts[subnet_str] += 1
                    break
        except ValueError:
            continue
    return counts
