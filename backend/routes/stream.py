"""SSE Stream blueprint — Server-Sent Events for live updates."""

import json
import time

from flask import Blueprint, Response

import persistence.profile_store as ps
from consts import PROFILE_TYPE_VPN
from service_registry import registry as _registry
from background.device_tracker import get_tracker
from routes._helpers import get_service, log

stream_bp = Blueprint("stream", __name__)


@stream_bp.route("/api/stream")
def api_stream():
    """Server-Sent Events stream for live tunnel health + device updates.

    Pushes updates every 10 seconds with:
    - Tunnel health per VPN profile (green/amber/red)
    - Device count changes
    """
    if not _registry.session_unlocked:
        return Response("data: {\"error\": \"locked\"}\n\n", mimetype="text/event-stream", status=401)

    def generate():
        while True:
            try:
                # Trigger a device tracker poll to refresh client details
                tracker = get_tracker()
                if tracker:
                    tracker.poll_once()

                service = get_service()

                # Build the canonical profile list once per tick
                data = ps.load()
                merged_profiles = service.build_profile_list(data)
                tunnel_health = {}
                kill_switch_state = {}
                profile_names = {}
                server_info = {}
                for p in merged_profiles:
                    if p.get("type") != PROFILE_TYPE_VPN:
                        continue
                    pid = p["id"]
                    if "health" in p:
                        tunnel_health[pid] = p["health"]
                    if "kill_switch" in p:
                        kill_switch_state[pid] = p["kill_switch"]
                    if p.get("name"):
                        profile_names[pid] = p["name"]
                    if p.get("server"):
                        server_info[pid] = p["server"]

                # Smart Protocol: check pending retries and switch protocols
                try:
                    service.tick_smart_protocol()
                except Exception:
                    pass

                # Sync LAN rules if device IPs changed
                if tracker and tracker.noint_stale:
                    try:
                        service.sync_noint_to_router()
                        tracker.noint_stale = False
                    except Exception:
                        pass

                # Device list: refresh on every SSE tick (10s)
                service.invalidate_device_cache()
                all_devices = service.get_devices_cached()

                # Smart Protocol retry status for the frontend
                smart_status = {}
                try:
                    smart_status = service.get_smart_protocol_status()
                except Exception:
                    pass

                event_data = {
                    "tunnel_health": tunnel_health,
                    "kill_switch": kill_switch_state,
                    "profile_names": profile_names,
                    "server_info": server_info,
                    "devices": all_devices,
                    "device_count": len(all_devices),
                    "smart_protocol_status": smart_status,
                    "timestamp": time.time(),
                }
                yield f"data: {json.dumps(event_data)}\n\n"
            except Exception as e:
                log.warning(f"SSE tick failed: {e}")
                yield f"data: {json.dumps({'error': 'update failed'})}\n\n"

            time.sleep(10)

    return Response(generate(), mimetype="text/event-stream")
