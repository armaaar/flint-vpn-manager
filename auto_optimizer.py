"""Auto-optimizer — periodically switches VPN groups to better servers
and renews expiring WireGuard persistent certificates.

Runs as a background thread, checking once per minute:
  - Server optimization: within a 2-minute window after the configured
    time of day, evaluates all connected VPN groups and switches any
    that have a significantly better server available (by Proton score).
  - Certificate renewal: once per day, checks all VPN profiles' cert_expiry
    and refreshes any within 30 days of expiry via the Proton API.
"""

import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Callable, Dict, Optional

import profile_store as ps
import secrets_manager as sm
from server_optimizer import find_better_server

log = logging.getLogger("flintvpn")

# Don't auto-switch the same profile more often than this. Cheap insurance
# against oscillation between two servers whose scores keep crossing each
# other. State is in-memory only — resets across app restarts, same as
# `_last_run_date`.
MIN_DWELL_HOURS = 6

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
        self._last_cert_check_date: Optional[str] = None
        # profile_id → datetime of last successful auto-switch.
        self._last_switch_at: Dict[str, datetime] = {}

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
            try:
                self.check_and_refresh_certs()
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
                # Skip profiles where the user pinned a specific server.
                # find_better_server enforces this too, but checking here
                # avoids unnecessary work and makes the intent explicit.
                scope = p.get("server_scope") or {}
                if scope.get("server_id"):
                    continue

                better = find_better_server(p, all_servers)
                if not better:
                    continue

                # Dwell-time gate: don't flap a profile that we already
                # switched recently. Even though the optimizer normally
                # runs at most once per day, this guards against config
                # changes that increase the cadence and against the
                # general "ping-pong between two near-equal servers"
                # failure mode.
                last_switch = self._last_switch_at.get(p["id"])
                if last_switch and (now - last_switch) < timedelta(hours=MIN_DWELL_HOURS):
                    log.info(
                        f"Auto-optimize: skipping '{p['name']}' — switched "
                        f"{(now - last_switch).total_seconds() / 3600:.1f}h ago "
                        f"(< {MIN_DWELL_HOURS}h dwell)"
                    )
                    continue

                cur = p.get("server") or {}
                log.info(
                    f"Auto-optimize: switching '{p['name']}' from "
                    f"{cur.get('name', '?')} (score {cur.get('score', '?')}) to "
                    f"{better['name']} (score {better['score']})"
                )
                try:
                    self.switch_fn(p["id"], better["id"])
                    self._last_switch_at[p["id"]] = now
                    switched += 1
                except Exception as e:
                    log.error(f"Auto-optimize: switch failed for '{p['name']}': {e}")

            log.info(f"Auto-optimize: completed, {switched} group(s) switched")

        except Exception as e:
            log.error(f"Auto-optimize: failed: {e}")

    # ── Persistent WireGuard certificate renewal ──────────────────────────

    CERT_REFRESH_THRESHOLD_DAYS = 30  # Refresh certs within 30 days of expiry

    def check_and_refresh_certs(self):
        """Once per day, refresh any WG persistent certs approaching expiry.

        Runs independently of the server optimization schedule — doesn't
        require auto_optimize to be enabled. Certificate renewal only
        needs the Proton API (no router interaction).
        """
        now = datetime.now()
        current_date = now.strftime("%Y-%m-%d")

        if self._last_cert_check_date == current_date:
            return  # Already checked today

        self._last_cert_check_date = current_date

        try:
            proton = self.get_proton()
            if not proton or not proton.is_logged_in:
                return

            data = ps.load()
            threshold = time.time() + (self.CERT_REFRESH_THRESHOLD_DAYS * 86400)
            refreshed = 0

            for p in data.get("profiles", []):
                if p.get("type") != "vpn":
                    continue
                wg_key = p.get("wg_key")
                cert_exp = p.get("cert_expiry", 0)
                if not wg_key or cert_exp > threshold:
                    continue  # No key (legacy/OVPN) or cert still fresh

                name = p.get("name", "Unnamed")
                opts = p.get("options", {})
                try:
                    new_expiry = proton.refresh_wireguard_cert(
                        wg_key_b64=wg_key,
                        profile_name=name,
                        netshield=opts.get("netshield", 0),
                        moderate_nat=opts.get("moderate_nat", False),
                        nat_pmp=opts.get("nat_pmp", False),
                        vpn_accelerator=opts.get("vpn_accelerator", True),
                    )
                    ps.update_profile(p["id"], cert_expiry=new_expiry)
                    refreshed += 1
                    log.info(
                        f"Cert renewal: refreshed '{name}' — new expiry in "
                        f"{(new_expiry - time.time()) / 86400:.0f} days"
                    )
                except Exception as e:
                    log.warning(f"Cert renewal: failed for '{name}': {e}")

            if refreshed:
                log.info(f"Cert renewal: refreshed {refreshed} cert(s)")

        except Exception as e:
            log.error(f"Cert renewal: failed: {e}")


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
