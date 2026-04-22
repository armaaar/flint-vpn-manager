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
        """Write iptables + ip6tables ACCEPT rules for device-level exceptions."""
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
        self._ssh.exec("rm -f /etc/fvpn/lan_access_rules.sh")
        self._uci.delete("firewall.fvpn_lan_access")
        self._uci.commit("firewall")

    def _write_firewall_include(self, exceptions: list[dict]) -> None:
        """Write firewall include script for reboot persistence (dual-stack)."""
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
