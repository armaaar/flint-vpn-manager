"""LAN access business logic — cross-network rules and device exceptions.

Orchestrates RouterLanAccess (SSH/UCI) with local config.json persistence.
Separate from VPNService because LAN access and VPN routing are orthogonal.
"""

import ipaddress
import logging
import re
import uuid

import persistence.secrets_manager as sm

log = logging.getLogger("flintvpn")


class LanAccessService:
    """Manages cross-network access control."""

    def __init__(self, router):
        self.router = router

    # ── Read ──────────────────────────────────────────────────────────

    def get_lan_overview(self) -> dict:
        """Full overview: networks + access rules + exceptions."""
        networks = self.router.lan_access.get_networks()
        router_forwardings = self.router.lan_access.get_zone_forwardings()
        config = sm.get_config()
        exceptions = config.get("lan_access", {}).get("exceptions", [])

        # Build access rules from router forwarding state
        zone_ids = [n["id"] for n in networks]
        access_rules = []
        for src in zone_ids:
            for dest in zone_ids:
                if src == dest:
                    continue
                allowed = any(
                    f["src"] == src and f["dest"] == dest
                    for f in router_forwardings
                )
                access_rules.append({
                    "src_zone": src, "dest_zone": dest, "allowed": allowed,
                })

        return {
            "networks": networks,
            "access_rules": access_rules,
            "exceptions": exceptions,
        }

    def get_network_devices(self, zone_id: str) -> list:
        """Get devices in a specific network by matching IPs to subnets.

        Combines DHCP leases with ARP table entries so that devices with
        static IPs (no DHCP lease) still appear.
        """
        networks = self.router.lan_access.get_networks()
        target = next((n for n in networks if n["id"] == zone_id), None)
        if not target or not target.get("subnet"):
            return []

        try:
            subnet = ipaddress.IPv4Network(target["subnet"], strict=False)
        except ValueError:
            return []

        leases = self.router.devices.get_dhcp_leases()
        details = self.router.devices.get_client_details()

        seen_macs = set()
        devices = []
        for lease in leases:
            try:
                if ipaddress.IPv4Address(lease["ip"]) not in subnet:
                    continue
            except ValueError:
                continue

            mac = lease["mac"].lower()
            seen_macs.add(mac)
            client = details.get(mac, {})
            devices.append({
                "mac": mac,
                "ip": lease["ip"],
                "hostname": lease.get("hostname", ""),
                "display_name": client.get("alias") or client.get("name") or lease.get("hostname") or mac,
                "online": client.get("online", False),
                "iface": client.get("iface", ""),
            })

        # Supplement with ARP entries for devices without DHCP leases
        # (e.g. static-IP printers, IoT devices)
        arp_entries = self.router.devices.get_arp_entries()
        for entry in arp_entries:
            mac = entry["mac"].lower()
            if mac in seen_macs:
                continue
            try:
                if ipaddress.IPv4Address(entry["ip"]) not in subnet:
                    continue
            except ValueError:
                continue
            seen_macs.add(mac)
            client = details.get(mac, {})
            devices.append({
                "mac": mac,
                "ip": entry["ip"],
                "hostname": "",
                "display_name": client.get("alias") or client.get("name") or mac,
                "online": entry.get("reachable", False),
                "iface": client.get("iface", ""),
            })

        return devices

    # ── Access Rules ──────────────────────────────────────────────────

    def update_access_rules(self, rules: list[dict]) -> dict:
        """Apply zone forwarding changes to router and persist."""
        for rule in rules:
            src = rule.get("src_zone", "")
            dest = rule.get("dest_zone", "")
            allowed = rule.get("allowed", False)
            if not src or not dest or src == dest:
                continue
            try:
                self.router.lan_access.set_zone_forwarding(src, dest, allowed)
            except Exception as e:
                log.warning(f"Failed to set forwarding {src}→{dest}: {e}")

        # Persist locally for reference (router UCI is the source of truth
        # for forwardings, but we store the intent for the UI)
        config = sm.get_config()
        la = config.get("lan_access", {})
        la["rules"] = rules
        sm.update_config(lan_access=la)

        return {"success": True, "rules": rules}

    # ── Network CRUD ────────────────────────────────────────────────

    def create_network(self, data: dict) -> dict:
        """Create a new WiFi network with full infrastructure."""
        name = data.get("name", "").strip()
        password = data.get("password", "").strip()
        isolation = data.get("isolation", True)
        if not name:
            raise ValueError("Network name is required")
        if not password or len(password) < 8:
            raise ValueError("Password must be at least 8 characters")

        # fw3 zone name limit is 11 chars; zone name = "fvpn_" + zone_id → max 6
        zone_id = re.sub(r'[^a-z0-9]', '_', name.lower()).strip('_')[:6]
        if not zone_id:
            raise ValueError("Network name must contain at least one alphanumeric character")
        # Ensure uniqueness
        existing = {n["id"] for n in self.router.lan_access.get_networks()}
        base = zone_id
        n = 1
        while f"fvpn_{zone_id}" in existing:
            suffix = str(n)
            zone_id = base[:6 - len(suffix)] + suffix
            n += 1
        subnet_ip = self._pick_subnet()
        self.router.lan_access.create_network(zone_id, name, password, subnet_ip, isolation)
        self._sync_mdns()
        log.info(f"Created network '{name}' (zone=fvpn_{zone_id}, subnet={subnet_ip}/24)")
        return {"success": True, "zone_id": f"fvpn_{zone_id}"}

    def update_network(self, zone_id: str, data: dict) -> dict:
        """Update wireless settings for a network."""
        networks = self.router.lan_access.get_networks()
        target = next((n for n in networks if n["id"] == zone_id), None)
        if not target:
            raise ValueError(f"Network '{zone_id}' not found")

        # Handle enable/disable
        if "enabled" in data:
            sections = [s["section"] for s in target.get("ssids", []) if s.get("section")]
            net_section = zone_id if zone_id.startswith("fvpn_") else ""
            if not net_section:
                net_section = "guest" if zone_id == "guest" else ""
            self.router.lan_access.enable_network(sections, net_section, data["enabled"])

        # Handle per-SSID wireless settings
        for ssid_update in data.get("ssids", []):
            section = ssid_update.get("section", "")
            if not section:
                continue
            settings = {}
            for key in ("ssid", "key", "encryption", "hidden", "isolate", "disabled"):
                if key in ssid_update:
                    settings[key] = ssid_update[key]
            if settings:
                self.router.lan_access.update_network_wireless(section, settings)

        log.info(f"Updated network '{zone_id}'")
        return {"success": True}

    def delete_network(self, zone_id: str) -> dict:
        """Delete a FlintVPN-created network."""
        self.router.lan_access.delete_network(zone_id)
        # Clean config.json rules/exceptions referencing this zone
        config = sm.get_config()
        la = config.get("lan_access", {})
        la["rules"] = [r for r in la.get("rules", [])
                       if r.get("src_zone") != zone_id and r.get("dest_zone") != zone_id]
        la["exceptions"] = [e for e in la.get("exceptions", [])
                            if zone_id not in e.get("label", "")]
        sm.update_config(lan_access=la)
        self._sync_mdns()
        log.info(f"Deleted network '{zone_id}'")
        return {"success": True}

    def _pick_subnet(self) -> str:
        """Pick next available 192.168.{N}.1 subnet."""
        networks = self.router.lan_access.get_networks()
        used = set()
        for n in networks:
            subnet = n.get("subnet", "")
            if subnet:
                try:
                    net = ipaddress.IPv4Network(subnet, strict=False)
                    used.add(int(net.network_address.packed[2]))
                except ValueError:
                    pass
        for i in range(10, 255):
            if i not in used:
                return f"192.168.{i}.1"
        raise ValueError("No available subnets")

    # ── Isolation ─────────────────────────────────────────────────────

    def set_isolation(self, zone_id: str, enabled: bool) -> dict:
        """Toggle WiFi client isolation for all SSIDs in a network."""
        networks = self.router.lan_access.get_networks()
        target = next((n for n in networks if n["id"] == zone_id), None)
        if not target:
            raise ValueError(f"Network '{zone_id}' not found")

        sections = [s["section"] for s in target.get("ssids", []) if s.get("section")]
        if sections:
            self.router.lan_access.set_wifi_isolation(sections, enabled)

        return {"success": True, "zone": zone_id, "isolation": enabled}

    # ── IPv6 ─────────────────────────────────────────────────────────

    def set_ipv6(self, zone_id: str, enabled: bool) -> dict:
        """Enable or disable IPv6 on a network."""
        networks = self.router.lan_access.get_networks()
        target = next((n for n in networks if n["id"] == zone_id), None)
        if not target:
            raise ValueError(f"Network '{zone_id}' not found")

        self.router.lan_access.set_ipv6(zone_id, enabled)
        return {"success": True, "zone": zone_id, "ipv6_enabled": enabled}

    def _ip_to_zone(self, ip_or_subnet: str) -> str:
        """Resolve an IP or subnet string to its zone ID, or '' if unknown."""
        networks = self.router.lan_access.get_networks()
        for n in networks:
            subnet_str = n.get("subnet", "")
            if not subnet_str:
                continue
            try:
                subnet = ipaddress.IPv4Network(subnet_str, strict=False)
                # Direct subnet match (for "entire network" exceptions)
                if ip_or_subnet == subnet_str:
                    return n["id"]
                # Single IP match
                if "/" not in ip_or_subnet:
                    if ipaddress.IPv4Address(ip_or_subnet) in subnet:
                        return n["id"]
            except ValueError:
                continue
        return ""

    # ── Device Exceptions ─────────────────────────────────────────────

    def get_exceptions(self) -> list:
        """Read persisted exceptions from config.json."""
        config = sm.get_config()
        return config.get("lan_access", {}).get("exceptions", [])

    def add_exception(self, data: dict) -> dict:
        """Add a device exception, apply to router, persist."""
        exc = {
            "id": f"exc_{uuid.uuid4().hex[:8]}",
            "from_mac": data.get("from_mac", ""),
            "from_ip": data.get("from_ip", ""),
            "to_ip": data.get("to_ip", ""),
            "to_mac": data.get("to_mac", ""),
            "direction": data.get("direction", "both"),
            "label": data.get("label", ""),
        }
        if not exc["from_ip"] or not exc["to_ip"]:
            raise ValueError("from_ip and to_ip are required")

        # Same-network exceptions are useless — traffic stays within the bridge
        from_zone = self._ip_to_zone(exc["from_ip"])
        to_zone = self._ip_to_zone(exc["to_ip"])
        if from_zone and to_zone and from_zone == to_zone:
            raise ValueError("Exceptions only apply between different networks")

        config = sm.get_config()
        la = config.setdefault("lan_access", {})
        exceptions = la.setdefault("exceptions", [])
        exceptions.append(exc)
        sm.update_config(lan_access=la)

        self._apply_exceptions(exceptions)
        return {"success": True, "exception": exc}

    def remove_exception(self, exc_id: str) -> dict:
        """Remove a device exception by ID."""
        config = sm.get_config()
        la = config.get("lan_access", {})
        exceptions = la.get("exceptions", [])
        la["exceptions"] = [e for e in exceptions if e.get("id") != exc_id]
        sm.update_config(lan_access=la)

        self._apply_exceptions(la["exceptions"])
        return {"success": True}

    # ── Boot Recovery ─────────────────────────────────────────────────

    def reapply_all(self) -> None:
        """Re-apply exceptions and mDNS reflection to router. Called on unlock.

        Prunes stale exceptions whose IPs no longer belong to any current
        network subnet (e.g. after a router replacement) and stale forwarding
        rules whose zone names no longer exist.
        """
        config = sm.get_config()
        la = config.get("lan_access", {})
        exceptions = la.get("exceptions", [])
        rules = la.get("rules", [])

        # Prune stale exceptions / rules if there are any
        if exceptions or rules:
            try:
                networks = self.router.lan_access.get_networks()
            except Exception:
                networks = []
            changed = self._prune_stale_lan_config(la, networks)
            if changed:
                sm.update_config(lan_access=la)
            exceptions = la.get("exceptions", [])

        if exceptions:
            self._apply_exceptions(exceptions)
            log.info(f"LAN access: reapplied {len(exceptions)} exception(s)")

        self._sync_mdns()

    @staticmethod
    def _prune_stale_lan_config(la: dict, networks: list[dict]) -> bool:
        """Remove exceptions with IPs outside current subnets and rules
        referencing zones that don't exist.  Mutates *la* in-place.
        Returns True if anything was removed.
        """
        changed = False

        # Collect current subnets
        subnets = []
        current_zones = set()
        for net in networks:
            current_zones.add(net.get("zone", ""))
            subnet_str = net.get("subnet", "")
            if subnet_str:
                try:
                    subnets.append(ipaddress.IPv4Network(subnet_str, strict=False))
                except ValueError:
                    pass

        # Prune exceptions whose IPs don't belong to any current subnet
        if subnets:
            original = la.get("exceptions", [])
            valid = []
            for exc in original:
                from_ip = exc.get("from_ip", "")
                to_ip = exc.get("to_ip", "")
                try:
                    from_ok = any(ipaddress.IPv4Address(from_ip) in s for s in subnets)
                    to_ok = any(ipaddress.IPv4Address(to_ip) in s for s in subnets)
                except ValueError:
                    from_ok = to_ok = False
                if from_ok and to_ok:
                    valid.append(exc)
                else:
                    log.info(f"LAN access: pruned stale exception {exc.get('id', '?')} "
                             f"({from_ip} -> {to_ip})")
                    changed = True
            if changed:
                la["exceptions"] = valid

        # Prune forwarding rules referencing zones that don't exist
        if current_zones:
            original_rules = la.get("rules", [])
            valid_rules = []
            for rule in original_rules:
                src_zone = rule.get("src", "")
                dest_zone = rule.get("dest", "")
                if src_zone in current_zones and dest_zone in current_zones:
                    valid_rules.append(rule)
                else:
                    log.info(f"LAN access: pruned stale rule {src_zone} -> {dest_zone}")
                    changed = True
            if changed or len(valid_rules) != len(original_rules):
                la["rules"] = valid_rules
                changed = True

        return changed

    # ── Internal ──────────────────────────────────────────────────────

    def _apply_exceptions(self, exceptions: list) -> None:
        """Apply exception rules to router iptables."""
        try:
            self.router.lan_access.apply_device_exceptions(exceptions)
        except Exception as e:
            log.warning(f"Failed to apply LAN access exceptions: {e}")

    def _sync_mdns(self) -> None:
        """Ensure mDNS reflection is configured for all current networks."""
        try:
            networks = self.router.lan_access.get_networks()
            self.router.firewall.setup_mdns_for_networks(networks)
            log.info("mDNS reflection: synced")
        except Exception as e:
            log.warning(f"mDNS reflection sync failed: {e}")
