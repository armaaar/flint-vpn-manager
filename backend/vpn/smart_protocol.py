"""Smart Protocol — Automatic protocol fallback state machine.

Non-blocking protocol fallback. When a VPN tunnel doesn't connect within
CONNECT_TIMEOUT seconds, cycles through WireGuard → OpenVPN → WG TCP/TLS
until one works.

Extracted from VPNService to keep the state machine self-contained.
VPNService owns the callbacks (change_protocol, connect, get_health).
"""

import logging
import time
import threading

import persistence.profile_store as ps
from consts import (
    PROFILE_TYPE_VPN,
    PROTO_OPENVPN,
    PROTO_WIREGUARD,
    PROTO_WIREGUARD_TCP,
    PROTO_WIREGUARD_TLS,
)
from vpn.protocol_limits import check_protocol_slot
from vpn.tunnel_strategy import get_strategy

log = logging.getLogger("flintvpn")

# Fallback order: WireGuard variants first (faster, same cert/key,
# zero-flicker switch), then progressively harder-to-block protocols,
# ending with OpenVPN (requires full teardown + recreate).
PROTOCOL_CHAIN = [
    (PROTO_WIREGUARD, "udp"),
    (PROTO_WIREGUARD_TCP, "tcp"),
    (PROTO_WIREGUARD_TLS, "tls"),
    (PROTO_OPENVPN, "udp"),
    (PROTO_OPENVPN, "tcp"),
]

CONNECT_TIMEOUT = 45  # seconds before trying next protocol


class SmartProtocolManager:
    """Background state machine for protocol fallback.

    Callbacks (injected by VPNService):
        change_protocol_fn(profile_id, new_proto, ovpn_protocol=...) — tears down
            old tunnel, creates new one.
        get_switch_lock_fn(profile_id) -> threading.RLock — per-profile lock shared
            with VPNService to prevent concurrent switches.
    """

    def __init__(self, change_protocol_fn, get_switch_lock_fn):
        self._pending = {}      # {profile_id: state_dict}
        self._lock = threading.Lock()
        self._change_protocol = change_protocol_fn
        self._get_switch_lock = get_switch_lock_fn

    def register(self, profile_id, current_proto):
        """Register a profile for smart protocol monitoring."""
        chain = [
            (p, t) for p, t in PROTOCOL_CHAIN
            if p != current_proto
        ]
        # Tor and Secure Core servers are WireGuard-only on Proton —
        # exclude OpenVPN from the fallback chain for these profiles
        profile = ps.get_profile(profile_id)
        if profile:
            features = (profile.get("server_scope") or {}).get("features") or {}
            if features.get("tor") or features.get("secure_core"):
                chain = [(p, t) for p, t in chain if p != PROTO_OPENVPN]
        with self._lock:
            self._pending[profile_id] = {
                "started_at": time.time(),
                "chain": chain,
                "attempt_idx": -1,  # -1 = still on original protocol
                "original_proto": current_proto,
            }

    def cancel(self, profile_id):
        """Cancel smart protocol monitoring for a profile."""
        with self._lock:
            self._pending.pop(profile_id, None)

    def is_pending(self, profile_id):
        """Check if a profile is registered for smart protocol monitoring."""
        return profile_id in self._pending

    def tick(self, router):
        """Called every SSE tick (~10s). Check pending smart protocol retries.

        For each pending profile:
        - If connected (green/amber): done, remove from pending.
        - If still connecting and timeout not reached: wait.
        - If timeout reached: disconnect, switch to next protocol, connect.
        - If all protocols exhausted: remove from pending, log warning.
        """
        with self._lock:
            pending_ids = list(self._pending)
        if not pending_ids:
            return

        for profile_id in pending_ids:
            state = self._pending.get(profile_id)
            if state is None:
                continue  # Cancelled between snapshot and access
            profile = ps.get_profile(profile_id)
            if not profile or profile.get("type") != PROFILE_TYPE_VPN:
                self.cancel(profile_id)
                continue

            ri = profile.get("router_info", {})
            if not ri.get("rule_name"):
                self.cancel(profile_id)
                continue

            proto = ri.get("vpn_protocol", PROTO_WIREGUARD)
            try:
                strategy = get_strategy(proto)
                health = strategy.get_health(router, ri)
            except Exception:
                continue  # SSH error — retry next tick

            if health in ("green", "amber"):
                log.info(f"Smart Protocol: {profile_id} connected on {proto}")
                self.cancel(profile_id)
                continue

            elapsed = time.time() - state["started_at"]
            if elapsed < CONNECT_TIMEOUT:
                continue  # Still waiting for current protocol

            # Timeout — try next protocol. Use per-profile switch lock to
            # prevent concurrent SSE tabs from double-switching.
            lock = self._get_switch_lock(profile_id)
            if not lock.acquire(blocking=False):
                continue  # Another thread is switching this profile

            try:
                # Re-check under lock: user may have disconnected/deleted
                with self._lock:
                    if profile_id not in self._pending:
                        continue

                state["attempt_idx"] += 1
                idx = state["attempt_idx"]

                # Skip protocols without available slots
                while idx < len(state["chain"]):
                    next_proto, _ = state["chain"][idx]
                    if check_protocol_slot(next_proto, exclude_profile_id=profile_id):
                        break
                    idx += 1
                    state["attempt_idx"] = idx

                if idx >= len(state["chain"]):
                    log.warning(f"Smart Protocol: all protocols exhausted for {profile_id}")
                    self.cancel(profile_id)
                    continue

                next_proto, next_transport = state["chain"][idx]
                log.info(f"Smart Protocol: switching {profile_id} from {proto} to {next_proto}")

                # Clear port + custom_dns — ports differ per protocol, and
                # custom DNS only works with kernel WireGuard (UCI-managed)
                profile = ps.get_profile(profile_id)
                if not profile:
                    self.cancel(profile_id)
                    continue
                opts = dict(profile.get("options") or {})
                opts.pop("port", None)
                if next_proto != PROTO_WIREGUARD:
                    opts.pop("custom_dns", None)
                ps.update_profile(profile_id, options=opts)

                # change_protocol handles disconnect + teardown + recreate.
                # We hold _switch_locks[profile_id] (RLock), so change_protocol's
                # acquire will succeed (reentrant).
                self._change_protocol(
                    profile_id, next_proto,
                    ovpn_protocol=next_transport if next_proto == PROTO_OPENVPN else "udp",
                )

                # Connect with new protocol
                profile = ps.get_profile(profile_id)
                if not profile:
                    self.cancel(profile_id)
                    continue
                new_ri = profile.get("router_info", {})
                new_strategy = get_strategy(next_proto)
                new_strategy.connect(router, new_ri)

                # Reset timer for the new protocol attempt
                with self._lock:
                    if profile_id in self._pending:
                        self._pending[profile_id]["started_at"] = time.time()
            except Exception as e:
                log.warning(f"Smart Protocol: failed for {profile_id}: {e}")
                with self._lock:
                    if profile_id in self._pending:
                        self._pending[profile_id]["started_at"] = time.time()
            finally:
                lock.release()

    def get_status(self):
        """Return smart protocol retry status for SSE streaming.

        Returns:
            Dict of {profile_id: {attempting, attempt, total, elapsed}}.
        """
        with self._lock:
            snapshot = dict(self._pending)
        result = {}
        for pid, state in snapshot.items():
            idx = state["attempt_idx"]
            chain = state["chain"]
            if idx < 0:
                attempting = state["original_proto"]
            elif idx < len(chain):
                attempting = chain[idx][0]
            else:
                attempting = None
            result[pid] = {
                "attempting": attempting,
                "attempt": max(idx + 2, 1),  # +1 for original, +1 for 0-index
                "total": len(chain) + 1,
                "elapsed": int(time.time() - state["started_at"]),
            }
        return result
