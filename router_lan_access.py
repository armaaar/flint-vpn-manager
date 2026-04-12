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
            wifi_ifaces.setdefault(net_name, []).append({
                "section": section,
                "ssid": fields.get("ssid", ""),
                "ifname": fields.get("ifname", ""),
                "band": _band_from_device(fields.get("device", ""), wireless),
                "isolate": fields.get("isolate", "0") == "1",
                "disabled": disabled,
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
                 "section": w["section"]}
                for w in ifaces
            ]
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
