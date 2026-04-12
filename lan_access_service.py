"""LAN access business logic — cross-network rules and device exceptions.

Orchestrates RouterLanAccess (SSH/UCI) with local config.json persistence.
Separate from VPNService because LAN access and VPN routing are orthogonal.
"""

import ipaddress
import logging
import uuid

import secrets_manager as sm

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
        """Get devices in a specific network by matching IPs to subnets."""
        networks = self.router.lan_access.get_networks()
        target = next((n for n in networks if n["id"] == zone_id), None)
        if not target or not target.get("subnet"):
            return []

        try:
            subnet = ipaddress.IPv4Network(target["subnet"], strict=False)
        except ValueError:
            return []

        leases = self.router.get_dhcp_leases()
        details = self.router.get_client_details()

        devices = []
        for lease in leases:
            try:
                if ipaddress.IPv4Address(lease["ip"]) not in subnet:
                    continue
            except ValueError:
                continue

            mac = lease["mac"].lower()
            client = details.get(mac, {})
            devices.append({
                "mac": mac,
                "ip": lease["ip"],
                "hostname": lease.get("hostname", ""),
                "display_name": client.get("alias") or client.get("name") or lease.get("hostname") or mac,
                "online": client.get("online", False),
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
        """Re-apply exceptions from config.json to router. Called on unlock."""
        config = sm.get_config()
        exceptions = config.get("lan_access", {}).get("exceptions", [])
        if exceptions:
            self._apply_exceptions(exceptions)
            log.info(f"LAN access: reapplied {len(exceptions)} exception(s)")

    # ── Internal ──────────────────────────────────────────────────────

    def _apply_exceptions(self, exceptions: list) -> None:
        """Apply exception rules to router iptables."""
        try:
            self.router.lan_access.apply_device_exceptions(exceptions)
        except Exception as e:
            log.warning(f"Failed to apply LAN access exceptions: {e}")
