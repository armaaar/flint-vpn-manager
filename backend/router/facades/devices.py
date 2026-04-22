"""Router devices facade — DHCP leases, device assignments, static leases.

Tool-layer objects (Uci, Ipset, Iproute, ServiceCtl) are injected directly.
Cross-facade calls to RouterPolicy go through the ``policy`` parameter.
The raw ``ssh`` handle is kept only for ubus, cat, and iwinfo commands.
"""

import json


class RouterDevices:
    """Facade for device management on the GL.iNet Flint 2."""

    def __init__(self, uci, ipset, iproute, service_ctl, policy, ssh):
        self._uci = uci
        self._ipset = ipset
        self._iproute = iproute
        self._service_ctl = service_ctl
        self._policy = policy
        self._ssh = ssh  # raw exec for ubus, cat, iwinfo

    # ── DHCP Leases ──────────────────────────────────────────────────────

    def get_dhcp_leases(self) -> list[dict]:
        """Parse DHCP leases from /tmp/dhcp.leases.

        Returns list of dicts with: mac, ip, hostname, expiry (unix timestamp).
        """
        raw = self._ssh.exec("cat /tmp/dhcp.leases 2>/dev/null || echo ''")
        leases = []
        for line in raw.strip().splitlines():
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 4:
                leases.append({
                    "expiry": int(parts[0]),
                    "mac": parts[1].lower(),
                    "ip": parts[2],
                    "hostname": parts[3] if parts[3] != "*" else "",
                })
        return leases

    def get_ndp_neighbors(self) -> dict[str, list[str]]:
        """Read the IPv6 NDP neighbor table and return global IPv6 addresses per MAC.

        Returns:
            Dict mapping lowercase MAC → list of global-scope IPv6 addresses.
            Link-local (fe80::) addresses are filtered out.
        """
        result: dict[str, list[str]] = {}
        try:
            raw = self._iproute.neigh_show_v6()
            for line in raw.strip().splitlines():
                line = line.strip()
                if not line:
                    continue
                # Format: "2001:db8::1 dev br-lan lladdr aa:bb:cc:dd:ee:ff REACHABLE"
                parts = line.split()
                if len(parts) < 5 or "lladdr" not in parts or "dev" not in parts:
                    continue
                # Only include LAN-side bridges, skip WAN interfaces
                try:
                    dev = parts[parts.index("dev") + 1]
                except (ValueError, IndexError):
                    continue
                if not dev.startswith("br-"):
                    continue
                ipv6 = parts[0]
                # Skip link-local addresses
                if ipv6.startswith("fe80:"):
                    continue
                try:
                    mac_idx = parts.index("lladdr") + 1
                    mac = parts[mac_idx].lower()
                except (ValueError, IndexError):
                    continue
                if mac not in result:
                    result[mac] = []
                if ipv6 not in result[mac]:
                    result[mac].append(ipv6)
        except Exception:
            pass
        return result

    def get_arp_entries(self) -> list[dict]:
        """Parse the IPv4 ARP/neighbor table.

        Returns list of dicts with: mac, ip, dev, reachable.
        Only includes entries on LAN-side bridges (br-*).
        """
        raw = self._iproute.neigh_show()
        entries = []
        for line in raw.strip().splitlines():
            parts = line.split()
            if "lladdr" not in parts or "dev" not in parts or len(parts) < 6:
                continue
            try:
                dev = parts[parts.index("dev") + 1]
            except (ValueError, IndexError):
                continue
            if not dev.startswith("br-"):
                continue
            ip = parts[0]
            # Skip IPv6 addresses
            if ":" in ip and ip.count(":") > 1:
                continue
            try:
                mac = parts[parts.index("lladdr") + 1].lower()
                state = parts[parts.index("lladdr") + 2] if parts.index("lladdr") + 2 < len(parts) else ""
            except (ValueError, IndexError):
                continue
            entries.append({
                "mac": mac,
                "ip": ip,
                "dev": dev,
                "reachable": state in ("REACHABLE", "STALE", "DELAY", "PROBE"),
            })
        return entries

    def get_client_details(self) -> dict:
        """Get rich client data from GL.iNet's client tracking.

        Returns dict keyed by lowercase MAC with: name, alias, device_class,
        online, iface (2.4G/5G/cable), rx (bytes/s), tx (bytes/s),
        total_rx, total_tx, ip, signal_dbm, link_speed_mbps.
        """
        result = {}

        # GL.iNet client list (live stats: speed, traffic, online status)
        try:
            raw = self._ssh.exec("ubus call gl-clients list 2>/dev/null || echo '{}'")
            data = json.loads(raw)
            for mac_upper, info in data.get("clients", {}).items():
                mac = mac_upper.lower()
                result[mac] = {
                    "name": info.get("name", ""),
                    "online": info.get("online", False),
                    "iface": info.get("iface", ""),
                    "rx_speed": info.get("rx", 0),
                    "tx_speed": info.get("tx", 0),
                    "total_rx": int(info.get("total_rx", 0)),
                    "total_tx": int(info.get("total_tx", 0)),
                    "ip": info.get("ip", ""),
                    "online_time": info.get("online_time"),
                }
        except Exception:
            pass

        # GL.iNet client config (user-set alias and device class)
        try:
            raw = self._ssh.exec(
                "uci show gl-client 2>/dev/null | grep -E 'mac|alias|class'"
            )
            current_mac = None
            for line in raw.strip().splitlines():
                if ".mac=" in line:
                    current_mac = line.split("=", 1)[1].strip("'").lower()
                    if current_mac not in result:
                        result[current_mac] = {}
                elif ".alias=" in line and current_mac:
                    result[current_mac]["alias"] = line.split("=", 1)[1].strip("'")
                elif ".class=" in line and current_mac:
                    result[current_mac]["device_class"] = line.split("=", 1)[1].strip("'")
        except Exception:
            pass

        # ARP neighbor table — online fallback for devices on non-lan bridges
        try:
            raw = self._iproute.neigh_show()
            for line in raw.strip().splitlines():
                parts = line.split()
                if "lladdr" in parts and "dev" in parts and len(parts) >= 6:
                    try:
                        dev = parts[parts.index("dev") + 1]
                    except (ValueError, IndexError):
                        continue
                    # Only include LAN-side bridges, skip WAN interfaces
                    if not dev.startswith("br-"):
                        continue
                    try:
                        idx = parts.index("lladdr")
                        mac = parts[idx + 1].lower()
                        state = parts[idx + 2] if idx + 2 < len(parts) else ""
                    except (ValueError, IndexError):
                        continue
                    if mac not in result:
                        result[mac] = {}
                    ip = parts[0]
                    # Store IP from ARP for devices without a DHCP lease
                    if ip and ":" not in ip and not result[mac].get("ip"):
                        result[mac]["ip"] = ip
                    if state in ("REACHABLE", "STALE", "DELAY", "PROBE"):
                        result[mac]["online"] = True
                    if "iface" not in result[mac] and dev != "br-lan":
                        result[mac]["iface"] = dev.replace("br-", "")
        except Exception:
            pass

        # WiFi signal strength + band detection from iwinfo
        try:
            raw = self._ssh.exec(
                "for iface in $(iwinfo 2>&1 | grep ESSID | awk '{print $1}'); do "
                "echo \"IFACE:$iface\"; iwinfo $iface assoclist 2>&1; done"
            )
            current_mac = None
            current_iface = ""
            for line in raw.strip().splitlines():
                line = line.strip()
                if line.startswith("IFACE:"):
                    current_iface = line.split(":", 1)[1]
                    continue
                if "dBm" in line and len(line) > 17 and line[2] == ":":
                    parts = line.split()
                    current_mac = parts[0].lower()
                    if current_mac not in result:
                        result[current_mac] = {}
                    try:
                        result[current_mac]["signal_dbm"] = int(parts[1])
                    except (ValueError, IndexError):
                        pass
                    if current_iface.startswith("rax"):
                        result[current_mac]["iface"] = "5G"
                    elif current_iface.startswith("ra"):
                        result[current_mac]["iface"] = "2.4G"
                elif line.startswith("TX:") and current_mac:
                    try:
                        speed_str = line.split(",")[0].replace("TX:", "").strip()
                        speed = float(speed_str.split()[0])
                        result[current_mac]["link_speed_mbps"] = speed
                    except (ValueError, IndexError):
                        pass
        except Exception:
            pass

        return result

    # ── Device Assignments ───────────────────────────────────────────────

    def get_device_assignments(self) -> dict:
        """Return {mac: rule_name} for every device in any Flint VPN Manager rule's from_mac.

        VPN device assignments are router-canonical. This is the live
        source of truth.
        """
        rules = self._policy.get_flint_vpn_rules()
        out = {}
        for rule in rules:
            rule_name = rule.get("rule_name")
            if not rule_name:
                continue
            raw = rule.get("from_mac", "")
            if not raw:
                continue
            macs = raw if isinstance(raw, list) else raw.replace("'", " ").split()
            for token in macs:
                token = token.strip().lower()
                if ":" in token and len(token) == 17:
                    out[token] = rule_name
        return out

    def set_device_vpn(self, mac: str, rule_name: str):
        """Add a device (by MAC) to a VPN tunnel's route policy rule.

        Uses ipset for immediate effect plus uci commit for persistence.
        """
        mac = mac.lower()
        existing_tokens = [t.lower() for t in self._policy.from_mac_tokens(rule_name)]
        if mac in existing_tokens:
            return
        ipset_name = self._uci.get(f"route_policy.{rule_name}.from").strip()
        self._uci.add_list(f"route_policy.{rule_name}.from_mac", mac)
        self._uci.commit("route_policy")
        if ipset_name:
            self._ipset.add(ipset_name, mac)

    def remove_device_from_vpn(self, mac: str, rule_name: str):
        """Remove a device (by MAC) from a VPN tunnel's route policy rule.

        Matches the stored MAC token case-insensitively but uses the EXACT
        stored case in ``uci del_list``.
        """
        mac_lower = mac.lower()
        for token in self._policy.from_mac_tokens(rule_name):
            if token.lower() == mac_lower:
                self._uci.del_list(f"route_policy.{rule_name}.from_mac", token)
                self._uci.commit("route_policy")
                ipset_name = self._uci.get(f"route_policy.{rule_name}.from").strip()
                if ipset_name:
                    self._ipset.remove(ipset_name, token)
                    if token != mac_lower:
                        self._ipset.remove(ipset_name, mac_lower)
                return

    def remove_device_from_all_vpn(self, mac: str):
        """Remove a device from ALL Flint VPN Manager route policy rules AND proton-wg ipsets.

        Iterates every fvpn rule, matches the MAC case-insensitively, and
        deletes using the EXACT stored case so UCI del_list succeeds.
        """
        mac_lower = mac.lower()
        mac_upper = mac.upper()
        rules = self._policy.get_flint_vpn_rules()
        any_removed = False
        for rule in rules:
            rule_name = rule.get("rule_name", "")
            if not rule_name:
                continue
            tokens = self._policy.from_mac_tokens(rule_name)
            for token in tokens:
                if token.lower() == mac_lower:
                    self._uci.del_list(f"route_policy.{rule_name}.from_mac", token)
                    ipset_name = self._uci.get(f"route_policy.{rule_name}.from").strip()
                    if ipset_name:
                        self._ipset.remove(ipset_name, token)
                        if token != mac_lower:
                            self._ipset.remove(ipset_name, mac_lower)
                    any_removed = True
                    break
        if any_removed:
            self._uci.commit("route_policy")

        # Also remove from proton-wg ipsets (managed outside route_policy)
        # Check both pwg_mac_ (current) and src_mac_ (legacy) prefixes
        for ipset_name in self._ipset.list_names("pwg_mac_") + self._ipset.list_names("src_mac_"):
            self._ssh.exec(
                f"ipset del {ipset_name} {mac_upper} 2>/dev/null; "
                f"ipset del {ipset_name} {mac_lower} 2>/dev/null; true"
            )

    # ── Static DHCP Leases ───────────────────────────────────────────────

    def get_static_leases(self) -> list[dict]:
        """Return all DHCP static leases from UCI config.

        Returns list of dicts with: mac, ip, hostname.
        """
        sections = self._uci.show("dhcp")
        leases = []
        for name, fields in sections.items():
            if fields.get("_type") != "host":
                continue
            mac = fields.get("mac", "").lower()
            if not mac:
                continue
            leases.append({
                "mac": mac,
                "ip": fields.get("ip", ""),
                "hostname": fields.get("name", ""),
            })
        return leases

    def _remove_all_leases_for_mac(self, mac: str):
        """Remove any existing static lease sections for a MAC (fvpn_ or router)."""
        mac_lower = mac.lower()
        sections = self._uci.show("dhcp")
        for name, fields in sections.items():
            if fields.get("_type") != "host":
                continue
            if fields.get("mac", "").lower() == mac_lower:
                self._uci.delete(f"dhcp.{name}")

    def set_static_lease(self, mac: str, ip: str, hostname: str = ""):
        """Create a static DHCP lease so the device always gets the same IP.

        Removes any existing lease for this MAC first (including router-managed).
        """
        mac = mac.lower()
        self._remove_all_leases_for_mac(mac)
        lease_id = f"fvpn_{mac.replace(':', '')}"

        self._uci.set_type(f"dhcp.{lease_id}", "host")
        self._uci.set(f"dhcp.{lease_id}.mac", mac)
        self._uci.set(f"dhcp.{lease_id}.ip", ip)
        if hostname:
            self._uci.set(f"dhcp.{lease_id}.name", hostname)
        self._uci.commit("dhcp")
        self._service_ctl.reload("dnsmasq", background=True)

    def remove_static_lease(self, mac: str):
        """Remove all static DHCP leases for a MAC (fvpn_ and router-managed)."""
        self._remove_all_leases_for_mac(mac)
        self._uci.commit("dhcp")
        self._service_ctl.reload("dnsmasq", background=True)
