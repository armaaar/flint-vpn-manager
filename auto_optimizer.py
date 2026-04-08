"""Auto-optimizer — periodically switches VPN groups to better servers.

Stage 11: uses live router health and `build_profile_list()` rather than
cached `p["status"]`. The optimizer only switches profiles whose tunnel
is actually up (green/amber) on the router right now.

Runs as a background thread, checking once per minute. Within a 2-minute
window after the configured time of day, it evaluates all connected VPN
groups and switches any that have a significantly better server available
(based on server_scope).

Only groups with server_scope != "server" are candidates. Groups where
the user chose a specific server are never changed.
"""

import logging
import threading
from datetime import datetime
from typing import Callable, Optional

import profile_store as ps
import secrets_manager as sm
from server_optimizer import find_better_server, LOAD_THRESHOLD_SWITCH

log = logging.getLogger("flintvpn")

_optimizer: Optional["AutoOptimizer"] = None


class AutoOptimizer:
    """Background thread that auto-switches VPN groups to faster servers."""

    def __init__(
        self,
        get_proton: Callable,
        get_router: Callable,
        switch_fn: Callable,
        build_profile_list_fn: Callable,
        poll_interval: int = 60,
    ):
        self.get_proton = get_proton
        self.get_router = get_router
        self.switch_fn = switch_fn
        self.build_profile_list_fn = build_profile_list_fn
        self.poll_interval = poll_interval
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._last_run_date: Optional[str] = None

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
                self.check_and_optimize()
            except Exception:
                pass
            self._stop_event.wait(self.poll_interval)

    @staticmethod
    def _within_window(scheduled_hhmm: str, now: datetime, window_minutes: int = 2) -> bool:
        """Stage 11: tolerate a few minutes of clock drift / poll-loop jitter.

        Returns True if `now` is within `window_minutes` AFTER the scheduled
        time. This avoids the bug where an exact-minute match could be missed
        if the poll loop happened to sleep through the precise minute.
        """
        try:
            sched_h, sched_m = map(int, scheduled_hhmm.split(":"))
        except (ValueError, AttributeError):
            return False
        sched_total = sched_h * 60 + sched_m
        now_total = now.hour * 60 + now.minute
        diff = now_total - sched_total
        return 0 <= diff < window_minutes

    def check_and_optimize(self):
        """Check if it's time to auto-optimize and do it."""
        config = sm.get_config()
        ao = config.get("auto_optimize", {})
        if not ao.get("enabled", False):
            return

        scheduled_time = ao.get("time", "04:00")
        now = datetime.now()
        current_date = now.strftime("%Y-%m-%d")

        if not self._within_window(scheduled_time, now):
            return
        if self._last_run_date == current_date:
            return  # Already ran today

        self._last_run_date = current_date
        log.info("Auto-optimize: starting scheduled check")

        try:
            proton = self.get_proton()
            if not proton or not proton.is_logged_in:
                log.warning("Auto-optimize: ProtonVPN not logged in, skipping")
                return

            router = self.get_router()
            all_servers = proton.get_servers()
            # Stage 11: read the LIVE merged profile list — health, kill_switch,
            # and resolved server info come from the router and Proton API.
            data = ps.load()
            profiles = self.build_profile_list_fn(router, data, proton=proton)
            switched = 0

            for p in profiles:
                if p.get("type") != "vpn":
                    continue
                # Live router health, not cached status
                if p.get("health") not in ("green", "amber"):
                    continue
                scope = p.get("server_scope") or {}
                if scope.get("type") == "server":
                    continue

                better = find_better_server(p, all_servers, threshold=LOAD_THRESHOLD_SWITCH)
                if not better:
                    continue
                cur = p.get("server") or {}
                log.info(
                    f"Auto-optimize: switching '{p['name']}' from "
                    f"{cur.get('name', '?')} (load {cur.get('load', '?')}%) to "
                    f"{better['name']} (load {better['load']}%)"
                )
                try:
                    self.switch_fn(p["id"], better["id"])
                    switched += 1
                except Exception as e:
                    log.error(f"Auto-optimize: switch failed for '{p['name']}': {e}")

            log.info(f"Auto-optimize: completed, {switched} group(s) switched")

        except Exception as e:
            log.error(f"Auto-optimize: failed: {e}")


def get_optimizer() -> Optional[AutoOptimizer]:
    return _optimizer


def start_optimizer(
    get_proton: Callable,
    get_router: Callable,
    switch_fn: Callable,
    build_profile_list_fn: Callable,
) -> AutoOptimizer:
    global _optimizer
    if _optimizer:
        _optimizer.stop()
    _optimizer = AutoOptimizer(
        get_proton=get_proton,
        get_router=get_router,
        switch_fn=switch_fn,
        build_profile_list_fn=build_profile_list_fn,
    )
    _optimizer.start()
    return _optimizer


def stop_optimizer():
    global _optimizer
    if _optimizer:
        _optimizer.stop()
        _optimizer = None
