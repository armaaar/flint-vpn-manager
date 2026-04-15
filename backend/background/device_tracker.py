"""Device tracker — minimal background thread for new-device auto-assignment.

Stage 8: This thread no longer caches device data on disk. All device fields
(hostname, IP, online, class, label, speeds) are read live from the router via
`router.get_dhcp_leases()` + `router.get_client_details()` in `app._build_devices_live`.

The tracker's only remaining job is detecting NEW MACs that appear on the
network and auto-assigning them to the guest profile (if one exists). This
prevents random visitors from getting unrestricted internet by default.

The `noint_stale` flag is set when any device IP changes, so the SSE tick can
reconcile the NoInternet ipset membership.
"""

import threading
import time
from typing import Optional

import persistence.profile_store as profile_store
from consts import (
    PROFILE_TYPE_NO_INTERNET,
    PROFILE_TYPE_NO_VPN,
    PROFILE_TYPE_VPN,
)
from router.api import RouterAPI

# Global tracker instance
_tracker: Optional["DeviceTracker"] = None


class DeviceTracker:
    """Polls router every 30s, auto-assigns new MACs to the guest profile.

    Maintains in-memory state only — no JSON writes for device discovery.
    """

    def __init__(self, router: RouterAPI, poll_interval: int = 30):
        self.router = router
        self.poll_interval = poll_interval
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._known_macs: set[str] = set()

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _poll_loop(self):
        while not self._stop_event.is_set():
            try:
                self.poll_once()
            except Exception:
                pass
            self._stop_event.wait(self.poll_interval)

    def poll_once(self):
        """Detect new devices and auto-assign them to the guest profile.

        Reads DHCP leases from router (live). For each MAC not seen before:
          1. Check if it's already assigned anywhere (router VPN rule, local
             non-VPN store, OR has a sticky-None marker indicating an
             intentional unassignment) — if so, skip and just remember it.
          2. If a guest profile exists, assign the new MAC to it:
             - VPN guest → router.set_device_vpn() + ipset
             - NoVPN/NoInternet guest → local profile_store.device_assignments

        Sticky-None: when the user explicitly unassigns a device,
        api_assign_device writes `device_assignments[mac] = None` so the
        intent survives lock/unlock and app restarts (which clear the
        in-memory `_known_macs` set).
        """
        try:
            leases = self.router.devices.get_dhcp_leases()
        except Exception:
            return  # Router unreachable — try again next tick

        try:
            router_assignments = self.router.devices.get_device_assignments()
        except Exception:
            router_assignments = {}

        data = profile_store.load()
        guest = profile_store.get_guest_profile(data)
        local_assignments = data.get("device_assignments", {})

        new_macs_to_assign = []
        for lease in leases:
            mac = lease["mac"].lower()
            if mac in self._known_macs:
                continue
            self._known_macs.add(mac)

            if not guest:
                continue
            # Already assigned somewhere on the router?
            if mac in router_assignments:
                continue
            # KEY check (not value check): if the MAC has any local entry —
            # including a sticky-None from an intentional unassignment — leave
            # it alone. Only never-seen-before MACs get auto-assigned.
            if mac in local_assignments:
                continue
            new_macs_to_assign.append(mac)

        # Apply auto-assignments
        if new_macs_to_assign and guest:
            guest_type = guest.get("type")
            guest_rule_name = (guest.get("router_info") or {}).get("rule_name", "")
            for mac in new_macs_to_assign:
                if guest_type == PROFILE_TYPE_VPN and guest_rule_name:
                    try:
                        self.router.devices.set_device_vpn(mac, guest_rule_name)
                    except Exception:
                        pass
                else:
                    # NoVPN / NoInternet — write to local store
                    data["device_assignments"][mac] = guest["id"]
            # Persist non-VPN auto-assignments
            if guest_type in (PROFILE_TYPE_NO_VPN, PROFILE_TYPE_NO_INTERNET):
                profile_store.save(data)



def get_tracker() -> Optional[DeviceTracker]:
    return _tracker


def start_tracker(router: RouterAPI, poll_interval: int = 30) -> DeviceTracker:
    global _tracker
    if _tracker:
        _tracker.stop()
    _tracker = DeviceTracker(router, poll_interval)
    _tracker.start()
    return _tracker


def stop_tracker():
    global _tracker
    if _tracker:
        _tracker.stop()
        _tracker = None
