"""Device Service — Device assignment, listing, and caching.

Extracted from VPNService to separate device management from profile
lifecycle. Handles device discovery, assignment (VPN/non-VPN/proton-wg),
labeling, and TTL-based caching.
"""

import logging
import time
import threading

import persistence.profile_store as ps
from consts import (
    PROFILE_TYPE_VPN,
    PROTO_WIREGUARD,
)
from vpn.profile_keys import (
    local_router_key,
    router_rule_key,
    default_device,
    build_ip_to_network_map,
)

log = logging.getLogger("flintvpn")


class DeviceService:
    """Device assignment, listing, and caching."""

    def __init__(self, router, ipset_ops):
        self._router = router
        self._ipset = ipset_ops
        self._cache_lock = threading.Lock()
        self._cache = {"data": None, "ts": 0.0}
        self._CACHE_TTL = 5

    def resolve_assignments(self, store_data: dict) -> dict:
        """Return {mac: profile_id} merging router VPN assignments + local non-VPN.

        VPN assignments come from router.from_mac (canonical). Matching is by
        stable (vpn_protocol, peer_id|client_id) key -- survives section
        renames by the GL.iNet UI.
        Non-VPN/NoInternet assignments come from local profile_store.
        """
        # (protocol, id) -> local profile_id  AND  router_section_name -> local profile_id
        key_to_pid = {}
        rule_section_to_pid = {}
        for p in store_data.get("profiles", []):
            if p.get("type") == PROFILE_TYPE_VPN:
                k = local_router_key(p)
                if k[1]:
                    key_to_pid[k] = p["id"]
                rn = (p.get("router_info") or {}).get("rule_name")
                if rn:
                    rule_section_to_pid[rn] = p["id"]

        try:
            rules = self._router.policy.get_flint_vpn_rules()
        except Exception:
            rules = []
        # router section name -> local profile_id, resolved via stable key
        section_to_pid = {}
        for rule in rules:
            section = rule.get("rule_name", "")
            if not section:
                continue
            key = router_rule_key(rule)
            pid = key_to_pid.get(key) or rule_section_to_pid.get(section)
            if pid:
                section_to_pid[section] = pid

        try:
            vpn_assignments_raw = self._router.devices.get_device_assignments()
        except Exception:
            vpn_assignments_raw = {}

        out = {}
        for mac, section in vpn_assignments_raw.items():
            pid = section_to_pid.get(section)
            if pid:
                out[mac] = pid
            # Else: orphan rule on router -- device shows as unassigned

        # proton-wg profiles: read ipset membership directly
        for p in store_data.get("profiles", []):
            ri = p.get("router_info") or {}
            if not ri.get("vpn_protocol", "").startswith("wireguard-"):
                continue
            ipset_name = ri.get("ipset_name", f"src_mac_{ri.get('tunnel_id', 0)}")
            try:
                for mac_val in self._ipset.list_members(ipset_name):
                    out[mac_val.lower()] = p["id"]
            except Exception:
                pass

        # Non-VPN: local store
        for mac, pid in store_data.get("device_assignments", {}).items():
            if pid is None:
                continue
            for p in store_data.get("profiles", []):
                if p.get("id") == pid and p.get("type") != PROFILE_TYPE_VPN:
                    out[mac] = pid
                    break
        return out

    def build_devices_live(self) -> list:
        """Build the device list from live router data.

        Sources:
          - DHCP leases (router /tmp/dhcp.leases): mac, ip, hostname
          - GL.iNet client tracking (ubus call gl-clients list): online, speeds,
            signal, alias (= user-set label), device_class
          - Router from_mac lists: VPN profile assignment (via resolve_assignments)
          - Local store: non-VPN profile assignment + LAN access overrides

        Hostname / IP / online / class / label / speeds are NEVER cached on disk.
        Display name precedence: gl-client.alias > DHCP hostname > MAC.
        """
        router = self._router
        try:
            leases = router.devices.get_dhcp_leases()
        except Exception:
            leases = []
        try:
            client_details = router.devices.get_client_details()
        except Exception:
            client_details = {}

        store_data = ps.load()
        assignment_map = self.resolve_assignments(store_data)

        devices = {}
        for lease in leases:
            mac = lease["mac"].lower()
            d = default_device(mac, assignment_map.get(mac))
            d["ip"] = lease.get("ip", "")
            d["hostname"] = lease.get("hostname", "")
            devices[mac] = d

        for mac, details in client_details.items():
            mac = mac.lower()
            d = devices.setdefault(mac, default_device(mac, assignment_map.get(mac)))
            d["router_online"] = bool(details.get("online", False))
            d["device_class"] = details.get("device_class", "")
            d["label"] = details.get("alias", "")  # router-canonical custom label
            d["rx_speed"] = details.get("rx_speed", 0)
            d["tx_speed"] = details.get("tx_speed", 0)
            d["total_rx"] = details.get("total_rx", 0)
            d["total_tx"] = details.get("total_tx", 0)
            d["signal_dbm"] = details.get("signal_dbm")
            d["link_speed_mbps"] = details.get("link_speed_mbps")
            d["iface"] = details.get("iface", "")
            if details.get("ip") and not d.get("ip"):
                d["ip"] = details["ip"]
            # gl-clients exposes a 'name' field (mDNS/Bonjour discovered hostname)
            # for devices not currently in DHCP leases. Use it as a hostname fallback
            # so offline / recently-departed devices still display their name.
            if not d.get("hostname") and details.get("name"):
                d["hostname"] = details["name"]

        # Merge IPv6 addresses from NDP neighbor table
        try:
            ndp = router.devices.get_ndp_neighbors()
            for mac, ipv6_addrs in ndp.items():
                mac = mac.lower()
                d = devices.setdefault(mac, default_device(mac, assignment_map.get(mac)))
                d["ipv6_addresses"] = ipv6_addrs
        except Exception:
            pass

        # Router-only MACs (e.g. assigned via SSH but never seen via DHCP)
        for mac, pid in assignment_map.items():
            if mac not in devices:
                devices[mac] = default_device(mac, pid)

        # Resolve device IP → network name (reuse leases to avoid duplicate SSH call)
        network_map = build_ip_to_network_map(self._router, leases=leases)

        out = []
        for mac, d in sorted(devices.items()):
            d["display_name"] = d.get("label") or d.get("hostname") or mac
            d["last_seen"] = None  # legacy field, no longer tracked
            net_info = network_map.get(d.get("ip", ""), {})
            d["network"] = net_info.get("label", "")
            d["network_zone"] = net_info.get("zone", "")
            out.append(d)
        return out

    def get_devices_cached(self) -> list:
        """5-second TTL wrapper around build_devices_live to throttle SSH calls."""
        with self._cache_lock:
            now = time.time()
            if self._cache["data"] is not None and (now - self._cache["ts"]) < self._CACHE_TTL:
                return self._cache["data"]
        # Build outside the lock to avoid holding it during SSH calls
        data = self.build_devices_live()
        with self._cache_lock:
            self._cache["data"] = data
            self._cache["ts"] = time.time()
        return data

    def invalidate_cache(self):
        """Invalidate the in-memory device cache."""
        with self._cache_lock:
            self._cache["data"] = None
            self._cache["ts"] = 0.0

    def assign_device(self, mac, profile_id, sync_noint_fn=None, sync_adblock_fn=None):
        """Assign a device to a profile.

        VPN assignments are written ONLY to the router (source of truth).
        Non-VPN/NoInternet assignments are written to local profile_store.

        sync_noint_fn and sync_adblock_fn are callbacks from VPNService to
        trigger cross-system sync after assignment.

        Raises:
            ValueError: If the MAC address is invalid.
            NotFoundError: If the target profile is not found.
        """
        from services.vpn_service import NotFoundError

        mac = ps.validate_mac(mac)

        store_data = ps.load()

        # Always clear any router VPN rule containing this MAC (idempotent).
        # NoInternet membership is handled by the LAN sync at the end (single
        # ipset, derived from local assignments).
        try:
            self._router.devices.remove_device_from_all_vpn(mac)
        except Exception as e:
            log.warning(f"remove_device_from_all_vpn({mac}) failed: {e}")

        # Apply new assignment
        if profile_id:
            new_profile = ps.get_profile(profile_id)
            if not new_profile:
                raise NotFoundError("Profile not found")

            if new_profile["type"] == PROFILE_TYPE_VPN and new_profile.get("router_info"):
                ri = new_profile["router_info"]
                proto = ri.get("vpn_protocol", PROTO_WIREGUARD)
                # Router is the source for VPN assignments. Drop any local
                # entry so we don't double-track (and so a future unassign
                # can write a fresh sticky-None marker).
                if mac in store_data.get("device_assignments", {}):
                    del store_data["device_assignments"][mac]
                    ps.save(store_data)
                if proto.startswith("wireguard-"):
                    # proton-wg: add MAC to ipset directly (no route_policy rule).
                    # Also persist locally — ipsets are ephemeral and lost on
                    # firewall reload / app restart. Local store is the backup.
                    ipset_name = ri.get("ipset_name", f"src_mac_{ri.get('tunnel_id', 0)}")
                    self._ipset.ensure_and_add(ipset_name, mac)
                    ps.assign_device(mac, profile_id)
                else:
                    # Kernel WG / OpenVPN: use route_policy rule
                    self._router.devices.set_device_vpn(mac, ri["rule_name"])
            else:
                # no_vpn / no_internet -- local store; LAN sync below applies the
                # router-side execution (NoInternet ipset membership).
                ps.assign_device(mac, profile_id)
        else:
            # Explicit unassign. Write a sticky-None marker so the device tracker
            # won't auto-reassign this MAC to the guest group on the next unlock
            # or restart (the in-memory _known_macs set is wiped on every fresh
            # tracker instance, so the local store is the only durable signal).
            ps.assign_device(mac, None)

        target = ps.get_profile(profile_id)["name"] if profile_id and ps.get_profile(profile_id) else "Unassigned"
        log.info(f"Device {mac} assigned to '{target}'")

        # Single sync handles both LAN access (per-group ipsets) and NoInternet
        # (the global fvpn_noint_ips ipset).
        if sync_noint_fn:
            try:
                sync_noint_fn()
            except Exception as e:
                log.warning(f"LAN sync after assignment failed: {e}")

        if sync_adblock_fn:
            sync_adblock_fn()

        # Invalidate the device cache so the next /api/devices call sees the new assignment
        self.invalidate_cache()

    def set_device_label(self, mac, label, device_class=""):
        """Set a custom label and/or device class for a device.

        gl-client.alias and gl-client.class are router-canonical.
        No local cache write -- build_devices_live reads them from the router live.
        """
        mac_upper = mac.upper()
        existing = self._router.exec(
            f"uci show gl-client 2>/dev/null | grep -B1 \"mac='{mac_upper}'\" | "
            "grep '=client' | head -1 | cut -d. -f2 | cut -d= -f1"
        ).strip()
        if existing:
            section = existing
        else:
            self._router.uci.add("gl-client", "client")
            section = self._router.exec(
                "uci show gl-client 2>/dev/null | grep '=client' | tail -1 | "
                "cut -d. -f2 | cut -d= -f1"
            ).strip()
            self._router.uci.set(f"gl-client.{section}.mac", mac_upper)

        self._router.uci.set(f"gl-client.{section}.alias", label)
        if device_class:
            self._router.uci.set(f"gl-client.{section}.class", device_class)
        self._router.uci.commit("gl-client")

        # Invalidate cache so next device query picks up the change
        self.invalidate_cache()
