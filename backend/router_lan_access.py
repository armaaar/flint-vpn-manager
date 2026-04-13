"""Router facade for LAN access control — network discovery and zone rules.

Reads wireless/network/firewall UCI config to discover networks (SSIDs),
manages fw3 zone forwarding entries for cross-network access, and applies
per-device iptables exception rules.
"""

import ipaddress
import re

from router_api import RouterAPI

_SAFE_NAME_RE = re.compile(r'^[a-zA-Z0-9_-]+$')
_SAFE_IP_RE = re.compile(r'^[0-9./]+$')

# Zone names to skip in cross-network rules (wan is managed separately)
_SKIP_ZONES = {"wan"}
# Prefixes used by vpn-client / FlintVPN for tunnel interfaces — not real LANs
_VPN_ZONE_PREFIXES = ("wgclient", "ovpnclient", "protonwg", "wgserver", "ovpnserver")


class RouterLanAccess:
    """Facade for cross-network access control on the GL.iNet Flint 2."""

    def __init__(self, ssh):
        self._ssh = ssh

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
        wireless = RouterAPI._parse_uci_show(parts[0] if len(parts) > 0 else "", "wireless")
        network = RouterAPI._parse_uci_show(parts[1] if len(parts) > 1 else "", "network")
        firewall = RouterAPI._parse_uci_show(parts[2] if len(parts) > 2 else "", "firewall")

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
            net_info[section] = {
                "ipaddr": ipaddr, "netmask": netmask,
                "bridge": bridge, "subnet": subnet, "disabled": disabled,
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
            # Use the first network name as the primary
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

            # Radio settings (per-band, shared across all SSIDs on same radio)
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
            # Wired-only network (no wifi ifaces) is always "enabled"
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
            })

        return networks

    def get_zone_forwardings(self) -> list[dict]:
        """Read all firewall forwarding entries between LAN-side zones.

        Returns list of {"src": zone, "dest": zone, "index": uci_index}.
        """
        raw = self._ssh.exec("uci show firewall 2>/dev/null || echo ''")
        firewall = RouterAPI._parse_uci_show(raw, "firewall")

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
                "uci commit firewall; "
                "/etc/init.d/firewall reload >/dev/null 2>&1; true"
            )
        elif not allowed and found:
            section = found["section"]
            self._ssh.exec(
                f"uci delete firewall.{section}; "
                "uci commit firewall; "
                "/etc/init.d/firewall reload >/dev/null 2>&1; true"
            )

    # ── WiFi Isolation ────────────────────────────────────────────────

    def set_wifi_isolation(self, wifi_sections: list[str], enabled: bool) -> None:
        """Toggle AP isolation for wireless interfaces and reload WiFi once.

        Accepts a list of wifi sections to update in a single batch,
        avoiding multiple wifi reloads.
        """
        cmds = []
        val = "1" if enabled else "0"
        for section in wifi_sections:
            if not _SAFE_NAME_RE.match(section):
                raise ValueError(f"Invalid wifi section: {section!r}")
            cmds.append(f"uci set wireless.{section}.isolate='{val}'")
        if not cmds:
            return
        cmds.append("uci commit wireless")
        cmds.append("wifi reload 2>/dev/null; true")
        self._ssh.exec(" ; ".join(cmds))

    # ── Device Exceptions ─────────────────────────────────────────────

    def apply_device_exceptions(self, exceptions: list[dict]) -> None:
        """Write iptables ACCEPT rules for device-level exceptions.

        Each exception has: from_ip, to_ip, direction (outbound/inbound/both).
        Rules go into a dedicated fvpn_lan_exc chain, inserted into
        forwarding_rule (which runs before zone checks in FORWARD).
        Uses a dedicated chain to avoid flushing other features' rules.
        """
        cmds = [
            "iptables -N fvpn_lan_exc 2>/dev/null || true",
            "iptables -F fvpn_lan_exc",
        ]
        for exc in exceptions:
            from_ip = exc.get("from_ip", "")
            to_ip = exc.get("to_ip", "")
            direction = exc.get("direction", "both")
            if not from_ip or not to_ip:
                continue
            if not _SAFE_IP_RE.match(from_ip) or not _SAFE_IP_RE.match(to_ip):
                continue
            if direction in ("outbound", "both"):
                cmds.append(
                    f"iptables -A fvpn_lan_exc -s {from_ip} -d {to_ip} -j ACCEPT"
                )
            if direction in ("inbound", "both"):
                cmds.append(
                    f"iptables -A fvpn_lan_exc -s {to_ip} -d {from_ip} -j ACCEPT"
                )
        # Insert jump into forwarding_rule if not already present
        cmds.append(
            "iptables -C forwarding_rule -j fvpn_lan_exc 2>/dev/null || "
            "iptables -I forwarding_rule 1 -j fvpn_lan_exc"
        )
        # Allow VPN-routed traffic (fwmark != 0) from any zone — custom network
        # zones only forward to wan by default, not to VPN tunnel zones
        cmds.append(
            "iptables -C forwarding_rule -m mark ! --mark 0x0/0xf000 -j ACCEPT 2>/dev/null || "
            "iptables -I forwarding_rule -m mark ! --mark 0x0/0xf000 -j ACCEPT"
        )

        self._ssh.exec(" ; ".join(cmds))
        self._write_firewall_include(exceptions)

    def cleanup_exceptions(self) -> None:
        """Remove all exception iptables rules and firewall include."""
        self._ssh.exec(
            "iptables -D forwarding_rule -j fvpn_lan_exc 2>/dev/null; "
            "iptables -F fvpn_lan_exc 2>/dev/null; "
            "iptables -X fvpn_lan_exc 2>/dev/null; "
            "rm -f /etc/fvpn/lan_access_rules.sh; "
            "uci -q delete firewall.fvpn_lan_access 2>/dev/null; "
            "uci commit firewall 2>/dev/null; true"
        )

    def _write_firewall_include(self, exceptions: list[dict]) -> None:
        """Write firewall include script for reboot persistence."""
        lines = [
            "#!/bin/sh",
            "# FlintVPN LAN access exceptions — auto-generated",
            "iptables -N fvpn_lan_exc 2>/dev/null || true",
            "iptables -F fvpn_lan_exc",
        ]
        for exc in exceptions:
            from_ip = exc.get("from_ip", "")
            to_ip = exc.get("to_ip", "")
            direction = exc.get("direction", "both")
            if not from_ip or not to_ip:
                continue
            if not _SAFE_IP_RE.match(from_ip) or not _SAFE_IP_RE.match(to_ip):
                continue
            if direction in ("outbound", "both"):
                lines.append(
                    f"iptables -A fvpn_lan_exc -s {from_ip} -d {to_ip} -j ACCEPT"
                )
            if direction in ("inbound", "both"):
                lines.append(
                    f"iptables -A fvpn_lan_exc -s {to_ip} -d {from_ip} -j ACCEPT"
                )
        lines.append(
            "iptables -C forwarding_rule -j fvpn_lan_exc 2>/dev/null || "
            "iptables -I forwarding_rule 1 -j fvpn_lan_exc"
        )
        # Allow VPN-routed traffic from any zone (custom networks → VPN tunnels)
        lines.append(
            "iptables -C forwarding_rule -m mark ! --mark 0x0/0xf000 -j ACCEPT 2>/dev/null || "
            "iptables -I forwarding_rule -m mark ! --mark 0x0/0xf000 -j ACCEPT"
        )

        script = "\n".join(lines) + "\n"
        self._ssh.write_file("/etc/fvpn/lan_access_rules.sh", script)
        self._ssh.exec("chmod +x /etc/fvpn/lan_access_rules.sh")

        # Register firewall include if not already present
        try:
            check = self._ssh.exec(
                "uci -q get firewall.fvpn_lan_access 2>/dev/null || echo MISSING"
            ).strip()
        except Exception:
            check = "MISSING"

        if check == "MISSING":
            self._ssh.exec(
                "uci set firewall.fvpn_lan_access=include; "
                "uci set firewall.fvpn_lan_access.path='/etc/fvpn/lan_access_rules.sh'; "
                "uci set firewall.fvpn_lan_access.reload='1'; "
                "uci commit firewall"
            )


    # ── Network CRUD ───────────────────────────────────────────────

    _DAT_PATHS = (
        "/etc/wireless/mediatek/mt7986-ax6000.dbdc.b0.dat",
        "/etc/wireless/mediatek/mt7986-ax6000.dbdc.b1.dat",
    )

    def enable_network(self, wifi_sections: list[str], net_section: str, enabled: bool) -> None:
        """Enable or disable a network (wireless + network interface)."""
        val = "0" if enabled else "1"
        cmds = []
        for s in wifi_sections:
            if not _SAFE_NAME_RE.match(s):
                raise ValueError(f"Invalid section: {s!r}")
            cmds.append(f"uci set wireless.{s}.disabled='{val}'")
        if net_section and _SAFE_NAME_RE.match(net_section):
            cmds.append(f"uci set network.{net_section}.disabled='{val}'")
        cmds.extend(["uci commit wireless", "uci commit network", "wifi reload 2>/dev/null; true"])
        self._ssh.exec(" ; ".join(cmds))

    def update_network_wireless(self, wifi_section: str, settings: dict) -> None:
        """Update wireless settings for one wifi-iface section."""
        if not _SAFE_NAME_RE.match(wifi_section):
            raise ValueError(f"Invalid section: {wifi_section!r}")
        allowed = {"ssid", "key", "encryption", "hidden", "isolate", "disabled"}
        cmds = []
        for key, val in settings.items():
            if key not in allowed:
                continue
            if key in ("ssid", "key") and not val:
                continue
            if key in ("hidden", "isolate", "disabled"):
                val = "1" if val else "0"
            cmds.append(f"uci set wireless.{wifi_section}.{key}='{val}'")
        if not cmds:
            return
        cmds.extend(["uci commit wireless", "wifi reload 2>/dev/null; true"])
        self._ssh.exec(" ; ".join(cmds))

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

        # Build UCI batch
        lines = [
            # Wireless 2.4G
            f"set wireless.fvpn_{zone_id}_2g=wifi-iface",
            f"set wireless.fvpn_{zone_id}_2g.device='mt798611'",
            f"set wireless.fvpn_{zone_id}_2g.network='fvpn_{zone_id}'",
            f"set wireless.fvpn_{zone_id}_2g.mode='ap'",
            f"set wireless.fvpn_{zone_id}_2g.ifname='{iface_2g}'",
            f"set wireless.fvpn_{zone_id}_2g.ssid='{ssid}'",
            f"set wireless.fvpn_{zone_id}_2g.encryption='psk2'",
            f"set wireless.fvpn_{zone_id}_2g.key='{password}'",
            f"set wireless.fvpn_{zone_id}_2g.isolate='{iso}'",
            f"set wireless.fvpn_{zone_id}_2g.disabled='0'",
            # Wireless 5G
            f"set wireless.fvpn_{zone_id}_5g=wifi-iface",
            f"set wireless.fvpn_{zone_id}_5g.device='mt798612'",
            f"set wireless.fvpn_{zone_id}_5g.network='fvpn_{zone_id}'",
            f"set wireless.fvpn_{zone_id}_5g.mode='ap'",
            f"set wireless.fvpn_{zone_id}_5g.ifname='{iface_5g}'",
            f"set wireless.fvpn_{zone_id}_5g.ssid='{ssid}-5G'",
            f"set wireless.fvpn_{zone_id}_5g.encryption='psk2'",
            f"set wireless.fvpn_{zone_id}_5g.key='{password}'",
            f"set wireless.fvpn_{zone_id}_5g.isolate='{iso}'",
            f"set wireless.fvpn_{zone_id}_5g.disabled='0'",
            # Network interface
            f"set network.fvpn_{zone_id}=interface",
            f"set network.fvpn_{zone_id}.proto='static'",
            f"set network.fvpn_{zone_id}.type='bridge'",
            f"set network.fvpn_{zone_id}.ipaddr='{subnet_ip}'",
            f"set network.fvpn_{zone_id}.netmask='255.255.255.0'",
            f"set network.fvpn_{zone_id}.force_link='1'",
            f"set network.fvpn_{zone_id}.bridge_empty='1'",
            # Firewall zone
            f"set firewall.fvpn_{zone_id}_zone=zone",
            f"set firewall.fvpn_{zone_id}_zone.name='fvpn_{zone_id}'",
            f"set firewall.fvpn_{zone_id}_zone.network='fvpn_{zone_id}'",
            f"set firewall.fvpn_{zone_id}_zone.input='REJECT'",
            f"set firewall.fvpn_{zone_id}_zone.output='ACCEPT'",
            f"set firewall.fvpn_{zone_id}_zone.forward='REJECT'",
            # Allow DHCP + DNS from new zone
            f"set firewall.fvpn_{zone_id}_dhcp=rule",
            f"set firewall.fvpn_{zone_id}_dhcp.name='Allow-DHCP-fvpn_{zone_id}'",
            f"set firewall.fvpn_{zone_id}_dhcp.src='fvpn_{zone_id}'",
            f"set firewall.fvpn_{zone_id}_dhcp.proto='udp'",
            f"set firewall.fvpn_{zone_id}_dhcp.dest_port='67-68'",
            f"set firewall.fvpn_{zone_id}_dhcp.target='ACCEPT'",
            f"set firewall.fvpn_{zone_id}_dns=rule",
            f"set firewall.fvpn_{zone_id}_dns.name='Allow-DNS-fvpn_{zone_id}'",
            f"set firewall.fvpn_{zone_id}_dns.src='fvpn_{zone_id}'",
            f"set firewall.fvpn_{zone_id}_dns.proto='tcpudp'",
            f"set firewall.fvpn_{zone_id}_dns.dest_port='53'",
            f"set firewall.fvpn_{zone_id}_dns.target='ACCEPT'",
            # WAN forwarding
            f"set firewall.fvpn_{zone_id}_wan=forwarding",
            f"set firewall.fvpn_{zone_id}_wan.src='fvpn_{zone_id}'",
            f"set firewall.fvpn_{zone_id}_wan.dest='wan'",
            # DHCP
            f"set dhcp.fvpn_{zone_id}=dhcp",
            f"set dhcp.fvpn_{zone_id}.interface='fvpn_{zone_id}'",
            f"set dhcp.fvpn_{zone_id}.start='100'",
            f"set dhcp.fvpn_{zone_id}.limit='150'",
            f"set dhcp.fvpn_{zone_id}.leasetime='12h'",
        ]
        batch = "\n".join(lines) + "\n"
        self._ssh.write_file("/tmp/fvpn_uci_batch.txt", batch)
        # Step 1: apply UCI config (stays connected)
        self._ssh.exec(
            "uci batch < /tmp/fvpn_uci_batch.txt && "
            "uci commit wireless && uci commit network && "
            "uci commit firewall && uci commit dhcp && "
            "rm -f /tmp/fvpn_uci_batch.txt; "
            f"ifup fvpn_{zone_id} 2>/dev/null; true"
        )
        # Step 2: reload WiFi driver (drops WiFi → kills SSH).
        # Run detached so the command survives our SSH disconnect.
        self._reload_wifi_driver()

    def delete_network(self, zone_id: str) -> None:
        """Delete a FlintVPN-created network and all its UCI sections."""
        if zone_id in ("lan", "guest"):
            raise ValueError(f"Cannot delete built-in network: {zone_id}")
        if not _SAFE_NAME_RE.match(zone_id):
            raise ValueError(f"Invalid zone ID: {zone_id!r}")

        prefix = f"fvpn_{zone_id}"
        # Find and delete all matching sections across configs
        configs = ["wireless", "network", "firewall", "dhcp"]
        cmds = []
        for config in configs:
            raw = self._ssh.exec(f"uci show {config} 2>/dev/null || true")
            sections = RouterAPI._parse_uci_show(raw, config)
            for section in sections:
                if section.startswith(prefix):
                    cmds.append(f"uci -q delete {config}.{section}")
        if not cmds:
            return

        # Decrement BssidNum in .dat files
        bssid_num = self._get_bssid_num()
        if bssid_num > 2:  # never go below 2 (main + guest)
            new_num = bssid_num - 1
            for path in self._DAT_PATHS:
                cmds.append(f"sed -i 's/^BssidNum={bssid_num}/BssidNum={new_num}/' {path}")

        cmds.extend([
            "uci commit wireless", "uci commit network",
            "uci commit firewall", "uci commit dhcp",
        ])
        self._ssh.exec(" ; ".join(cmds))
        # Reload WiFi driver to remove interfaces (drops WiFi → kills SSH)
        self._reload_wifi_driver()

    def _reload_wifi_driver(self) -> None:
        """Reload the MediaTek WiFi kernel module to pick up BssidNum changes.

        MediaTek's mt_wifi reads BssidNum from .dat files only at module probe
        time. Adding/removing SSIDs requires unloading and reloading the module.
        This drops ALL WiFi connections for ~10-15 seconds.

        The command runs detached (& disown) so it survives our SSH disconnect
        (since WiFi going down kills the SSH session).
        """
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
    # Fallback: MediaTek naming convention
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
