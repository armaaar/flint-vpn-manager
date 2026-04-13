"""Router devices facade — DHCP leases, device assignments, static leases.

Delegates SSH execution to the RouterAPI instance passed as ``ssh``.
Cross-facade calls to RouterPolicy go through the ``policy`` parameter.
"""

import json


class RouterDevices:
    """Facade for device management on the GL.iNet Flint 2."""

    def __init__(self, ssh, policy):
        self._ssh = ssh
        self._policy = policy

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
        # (gl-clients only tracks br-lan devices)
        try:
            raw = self._ssh.exec("ip neigh show 2>/dev/null || cat /proc/net/arp 2>/dev/null")
            for line in raw.strip().splitlines():
                parts = line.split()
                # ip neigh format: "IP dev IFACE lladdr MAC STATE"
                if "lladdr" in parts and len(parts) >= 6:
                    try:
                        idx = parts.index("lladdr")
                        mac = parts[idx + 1].lower()
                        state = parts[idx + 2] if idx + 2 < len(parts) else ""
                    except (ValueError, IndexError):
                        continue
                    if mac not in result:
                        result[mac] = {}
                    # Supplement online status — gl-clients only tracks br-lan,
                    # so ARP can upgrade offline→online for non-lan devices
                    if state in ("REACHABLE", "STALE", "DELAY", "PROBE"):
                        result[mac]["online"] = True
                    # Detect interface for bridge membership
                    if "iface" not in result[mac] and "dev" in parts:
                        try:
                            dev = parts[parts.index("dev") + 1]
                            if dev.startswith("br-") and dev != "br-lan":
                                result[mac]["iface"] = dev.replace("br-", "")
                        except (ValueError, IndexError):
                            pass
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
                    # Detect band from interface name: rax* = 5G, ra* = 2.4G
                    # Always override — iwinfo is the live truth for WiFi band
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
        """Return {mac: rule_name} for every device in any FlintVPN rule's from_mac.

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
        ipset_name = self._ssh.exec(
            f"uci get route_policy.{rule_name}.from 2>/dev/null || echo ''"
        ).strip()
        self._ssh.exec(f"uci add_list route_policy.{rule_name}.from_mac='{mac}'")
        self._ssh.exec("uci commit route_policy")
        if ipset_name:
            self._ssh.exec(f"ipset add {ipset_name} {mac} 2>/dev/null || true")

    def remove_device_from_vpn(self, mac: str, rule_name: str):
        """Remove a device (by MAC) from a VPN tunnel's route policy rule.

        Matches the stored MAC token case-insensitively but uses the EXACT
        stored case in ``uci del_list``.
        """
        mac_lower = mac.lower()
        for token in self._policy.from_mac_tokens(rule_name):
            if token.lower() == mac_lower:
                self._ssh.exec(
                    f"uci del_list route_policy.{rule_name}.from_mac='{token}'"
                )
                self._ssh.exec("uci commit route_policy")
                ipset_name = self._ssh.exec(
                    f"uci get route_policy.{rule_name}.from 2>/dev/null || echo ''"
                ).strip()
                if ipset_name:
                    self._ssh.exec(f"ipset del {ipset_name} {token} 2>/dev/null || true")
                    if token != mac_lower:
                        self._ssh.exec(f"ipset del {ipset_name} {mac_lower} 2>/dev/null || true")
                return

    def remove_device_from_all_vpn(self, mac: str):
        """Remove a device from ALL FlintVPN route policy rules AND proton-wg ipsets.

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
                    self._ssh.exec(
                        f"uci del_list route_policy.{rule_name}.from_mac='{token}'"
                    )
                    ipset_name = self._ssh.exec(
                        f"uci get route_policy.{rule_name}.from 2>/dev/null || echo ''"
                    ).strip()
                    if ipset_name:
                        self._ssh.exec(f"ipset del {ipset_name} {token} 2>/dev/null || true")
                        if token != mac_lower:
                            self._ssh.exec(f"ipset del {ipset_name} {mac_lower} 2>/dev/null || true")
                    any_removed = True
                    break
        if any_removed:
            self._ssh.exec("uci commit route_policy")

        # Also remove from proton-wg ipsets (managed outside route_policy)
        pwg_ipsets = self._ssh.exec(
            "ipset list -n 2>/dev/null | grep '^src_mac_'"
        ).strip()
        for ipset_name in pwg_ipsets.splitlines():
            ipset_name = ipset_name.strip()
            if not ipset_name:
                continue
            self._ssh.exec(
                f"ipset del {ipset_name} {mac_upper} 2>/dev/null; "
                f"ipset del {ipset_name} {mac_lower} 2>/dev/null; true"
            )

    # ── Static DHCP Leases ───────────────────────────────────────────────

    def set_static_lease(self, mac: str, ip: str, hostname: str = ""):
        """Create a static DHCP lease so the device always gets the same IP."""
        mac = mac.lower()
        lease_id = f"fvpn_{mac.replace(':', '')}"

        self._ssh.exec(f"uci set dhcp.{lease_id}=host")
        self._ssh.exec(f"uci set dhcp.{lease_id}.mac='{mac}'")
        self._ssh.exec(f"uci set dhcp.{lease_id}.ip='{ip}'")
        if hostname:
            self._ssh.exec(f"uci set dhcp.{lease_id}.name='{hostname}'")
        self._ssh.exec("uci commit dhcp")
        self._ssh.exec("/etc/init.d/dnsmasq reload &>/dev/null &")

    def remove_static_lease(self, mac: str):
        """Remove a static DHCP lease."""
        lease_id = f"fvpn_{mac.replace(':', '')}"
        self._ssh.exec(f"uci delete dhcp.{lease_id} 2>/dev/null; uci commit dhcp")
        self._ssh.exec("/etc/init.d/dnsmasq reload &>/dev/null &")
