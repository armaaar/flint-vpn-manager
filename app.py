"""FlintVPN Manager — Flask REST API + SSE.

Main application server. Thin routing layer that delegates business logic
to VPNService (vpn_service.py). Each route: parse request, call service,
format response.

Run: python app.py (or flask run)
Access: http://localhost:5000 or http://<surface-ip>:5000 from LAN
"""

import functools
import json
import logging
import time
from pathlib import Path
from typing import Optional

from flask import Flask, request, jsonify, Response, send_from_directory

import secrets_manager as sm
import profile_store as ps
from consts import (
    LAN_ALLOWED,
    PROFILE_TYPE_VPN,
)
from proton_api import ProtonAPI
from router_api import RouterAPI
from device_tracker import start_tracker, stop_tracker, get_tracker
from auto_optimizer import start_optimizer, stop_optimizer
from vpn_service import (
    VPNService, NotFoundError, ConflictError, LimitExceededError,
    NotLoggedInError, backup_local_state_to_router, check_and_auto_restore,
    ROUTER_BACKUP_PATH, BACKUP_FORMAT_VERSION,
)

app = Flask(__name__, static_folder="static", static_url_path="")

# ── Logging ───────────────────────────────────────────────────────────────────

LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

# Separate log files by purpose
APP_LOG = LOG_DIR / "app.log"       # Actions: connect, disconnect, create, delete, assign
ERROR_LOG = LOG_DIR / "error.log"   # Errors and exceptions only
ACCESS_LOG = LOG_DIR / "access.log" # HTTP request log

# App logger (actions + errors)
log = logging.getLogger("flintvpn")
log.setLevel(logging.DEBUG)

app_handler = logging.FileHandler(APP_LOG)
app_handler.setLevel(logging.INFO)
app_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))

error_handler = logging.FileHandler(ERROR_LOG)
error_handler.setLevel(logging.ERROR)
error_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s\n%(exc_info)s"))

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))

log.addHandler(app_handler)
log.addHandler(error_handler)
log.addHandler(console_handler)

# Werkzeug access log → access.log
access_logger = logging.getLogger("werkzeug")
access_handler = logging.FileHandler(ACCESS_LOG)
access_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
access_logger.addHandler(access_handler)

# ── Global State ──────────────────────────────────────────────────────────────

_proton_api: Optional[ProtonAPI] = None
_router_api: Optional[RouterAPI] = None
_service: Optional[VPNService] = None
_session_unlocked = False

SSH_KEY_PATH = "/home/armaaar/.ssh/id_ed25519"


def _get_proton():
    global _proton_api
    if _proton_api is None:
        _proton_api = ProtonAPI()
    return _proton_api


def _get_router():
    global _router_api
    if _router_api is None:
        config = sm.get_config()
        _router_api = RouterAPI(
            host=config.get("router_ip", "192.168.8.1"),
            key_filename=SSH_KEY_PATH,
        )
    return _router_api


def _get_service() -> VPNService:
    """Return the VPNService instance. Raises if session is not unlocked."""
    if _service is None:
        raise RuntimeError("Service not initialized. Unlock first.")
    return _service


def require_unlocked(f):
    """Decorator that returns 401 if the session is locked."""
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if not _session_unlocked:
            return jsonify({"error": "Session locked. POST /api/unlock first."}), 401
        return f(*args, **kwargs)
    return wrapper


def _invalidate_device_cache():
    """Invalidate the in-memory device cache.

    Thin wrapper that delegates to the service. Kept as a module-level
    function for backward compatibility with tests that import it directly.
    """
    if _service is not None:
        _service.invalidate_device_cache()


# ── Status / Setup / Unlock ───────────────────────────────────────────────────

@app.route("/api/status")
def api_status():
    """App status: setup-needed, locked, or unlocked."""
    if not sm.is_setup():
        return jsonify({"status": "setup-needed"})
    if not _session_unlocked:
        return jsonify({"status": "locked"})
    return jsonify({
        "status": "unlocked",
        "proton_logged_in": _get_proton().is_logged_in,
    })


@app.route("/api/setup", methods=["POST"])
def api_setup():
    """First-time setup: store encrypted credentials."""
    data = request.json
    required = ["proton_user", "proton_pass", "router_pass", "master_password"]
    missing = [k for k in required if k not in data]
    if missing:
        return jsonify({"error": f"Missing fields: {missing}"}), 400

    sm.setup(
        proton_user=data["proton_user"],
        proton_pass=data["proton_pass"],
        router_pass=data["router_pass"],
        master_password=data["master_password"],
        router_ip=data.get("router_ip", "192.168.8.1"),
    )
    return jsonify({"success": True})


@app.route("/api/unlock", methods=["POST"])
def api_unlock():
    """Unlock session with master password."""
    global _session_unlocked, _service
    data = request.json
    if "master_password" not in data:
        return jsonify({"error": "master_password required"}), 400

    try:
        sm.unlock(data["master_password"])
        _session_unlocked = True

        # Create the VPN service
        router = _get_router()
        proton = _get_proton()
        _service = VPNService(router, proton)

        # Register backup callback so every save() pushes to router
        ps.register_save_callback(
            lambda path: backup_local_state_to_router(_service.router, path)
        )

        # Auto-restore local state from router backup if newer (silent disaster
        # recovery — must run BEFORE the device tracker / LAN sync since they
        # depend on the local store).
        try:
            check_and_auto_restore(router)
        except Exception as e:
            log.warning(f"Auto-restore check failed: {e}")

        # Start device tracker and poll immediately so devices are ready
        tracker = start_tracker(router)
        tracker.poll_once()

        # Reconcile router LAN execution layer (UCI ipsets + rules) with the
        # restored / local intent.
        try:
            _service.sync_lan_to_router()
        except Exception as e:
            log.warning(f"LAN sync on unlock failed: {e}")

        # Start auto-optimizer
        try:
            start_optimizer(
                get_proton=lambda: _service.proton,
                get_router=lambda: _service.router,
                switch_fn=_service.switch_server,
                build_profile_list_fn=lambda r, d, proton=None: _service.build_profile_list(d),
            )
        except Exception as e:
            log.warning(f"Auto-optimizer start failed: {e}")

        return jsonify({"success": True})
    except (ValueError, FileNotFoundError) as e:
        return jsonify({"error": str(e)}), 401


@app.route("/api/lock", methods=["POST"])
def api_lock():
    """Lock the session without restarting the app.

    Clears the in-memory unlocked flag, stops the device tracker, and stops
    the auto-optimizer. The next request that needs an unlocked session will
    return 401 until /api/unlock is called again.
    """
    global _session_unlocked, _service
    _session_unlocked = False
    _service = None
    try:
        stop_tracker()
    except Exception as e:
        log.warning(f"Failed to stop tracker on lock: {e}")
    try:
        stop_optimizer()
    except Exception as e:
        log.warning(f"Failed to stop optimizer on lock: {e}")
    log.info("Session locked")
    return jsonify({"success": True})


# ── Profiles ──────────────────────────────────────────────────────────────────

@app.route("/api/profiles")
@require_unlocked
def api_get_profiles():
    """Get all profiles. Built from router rules + local UI metadata."""
    profiles = _get_service().build_profile_list()
    return jsonify(profiles)


@app.route("/api/profiles", methods=["POST"])
@require_unlocked
def api_create_profile():
    """Create a new profile.

    Body: {name, type, color?, icon?, is_guest?, kill_switch?,
           server_id? (VPN), options? (VPN)}
    """
    data = request.json
    if "name" not in data or "type" not in data:
        return jsonify({"error": "name and type required"}), 400

    try:
        profile = _get_service().create_profile(
            name=data["name"],
            profile_type=data["type"],
            vpn_protocol=data.get("vpn_protocol", "wireguard"),
            server_id=data.get("server_id"),
            options=data.get("options"),
            color=data.get("color", "#3498db"),
            icon=data.get("icon", "\U0001f512"),
            is_guest=data.get("is_guest", False),
            kill_switch=data.get("kill_switch", True),
            server_scope=data.get("server_scope"),
            ovpn_protocol=data.get("ovpn_protocol", "udp"),
        )
        return jsonify(profile), 201
    except LimitExceededError as e:
        return jsonify({"error": str(e)}), 400
    except NotLoggedInError as e:
        return jsonify({"error": str(e)}), 400
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        log.error(f"Failed to create profile: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/profiles/reorder", methods=["PUT"])
@require_unlocked
def api_reorder_profiles():
    """Reorder profiles.

    Body: {profile_ids: ["id1", "id2", ...]}
    """
    body = request.json or {}
    ids = body.get("profile_ids", [])
    if not ids:
        return jsonify({"error": "profile_ids required"}), 400

    try:
        _get_service().reorder_profiles(ids)
        return jsonify({"success": True})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/profiles/<profile_id>", methods=["PUT"])
@require_unlocked
def api_update_profile(profile_id):
    """Update profile metadata (name, color, icon, options, kill_switch)."""
    data = dict(request.json or {})
    try:
        profile = _get_service().update_profile(profile_id, **data)
        return jsonify(profile)
    except NotFoundError:
        return jsonify({"error": "Profile not found"}), 404


@app.route("/api/profiles/<profile_id>", methods=["DELETE"])
@require_unlocked
def api_delete_profile(profile_id):
    """Delete a profile and tear down its tunnel if VPN."""
    try:
        _get_service().delete_profile(profile_id)
        return jsonify({"success": True})
    except NotFoundError:
        return jsonify({"error": "Profile not found"}), 404


# ── Server Selection ──────────────────────────────────────────────────────────

@app.route("/api/profiles/<profile_id>/servers")
@require_unlocked
def api_get_servers(profile_id):
    """Get ProtonVPN server list for a profile's server picker."""
    proton = _get_service().proton
    if not proton.is_logged_in:
        return jsonify({"error": "Not logged into ProtonVPN"}), 400

    country = request.args.get("country")
    city = request.args.get("city")
    feature = request.args.get("feature")

    servers = proton.get_servers(country=country, city=city, feature=feature)
    return jsonify(servers)


@app.route("/api/profiles/<profile_id>/server", methods=["PUT"])
@require_unlocked
def api_change_server(profile_id):
    """Change the server for a VPN profile.

    Body: {server_id, options?, server_scope?}
    """
    data = request.json
    if "server_id" not in data:
        return jsonify({"error": "server_id required"}), 400

    try:
        profile = _get_service().switch_server(
            profile_id, data["server_id"],
            options=data.get("options"),
            server_scope=data.get("server_scope"),
        )
        return jsonify(profile)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except (RuntimeError, ConflictError) as e:
        return jsonify({"error": str(e)}), 409
    except Exception as e:
        log.error(f"Failed to switch server: {e}", exc_info=True)
        return jsonify({"error": f"Failed to switch server: {e}"}), 500


@app.route("/api/profiles/<profile_id>/type", methods=["PUT"])
@require_unlocked
def api_change_type(profile_id):
    """Change the group type of a profile (VPN ↔ NoVPN ↔ NoInternet).

    Body: {type, vpn_protocol?, server_id?, options?, kill_switch?,
           server_scope?, ovpn_protocol?}
    """
    data = request.json or {}
    new_type = data.get("type")
    if not new_type:
        return jsonify({"error": "type required"}), 400

    try:
        profile = _get_service().change_type(
            profile_id, new_type,
            vpn_protocol=data.get("vpn_protocol", "wireguard"),
            server_id=data.get("server_id"),
            options=data.get("options"),
            kill_switch=data.get("kill_switch", True),
            server_scope=data.get("server_scope"),
            ovpn_protocol=data.get("ovpn_protocol", "udp"),
        )
        return jsonify(profile)
    except NotFoundError:
        return jsonify({"error": "Profile not found"}), 404
    except LimitExceededError as e:
        return jsonify({"error": str(e)}), 400
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except NotLoggedInError as e:
        return jsonify({"error": str(e)}), 400
    except (RuntimeError, ConflictError) as e:
        return jsonify({"error": str(e)}), 409
    except Exception as e:
        log.error(f"Failed to change type: {e}", exc_info=True)
        return jsonify({"error": f"Failed to change type: {e}"}), 500


@app.route("/api/profiles/<profile_id>/protocol", methods=["PUT"])
@require_unlocked
def api_change_protocol(profile_id):
    """Change the VPN protocol of a profile.

    Body: {vpn_protocol, server_id?, options?, server_scope?, ovpn_protocol?}
    """
    data = request.json or {}
    new_proto = data.get("vpn_protocol")
    if not new_proto:
        return jsonify({"error": "vpn_protocol required"}), 400

    try:
        profile = _get_service().change_protocol(
            profile_id, new_proto,
            server_id=data.get("server_id"),
            options=data.get("options"),
            server_scope=data.get("server_scope"),
            ovpn_protocol=data.get("ovpn_protocol", "udp"),
        )
        return jsonify(profile)
    except NotFoundError:
        return jsonify({"error": "Profile not found"}), 404
    except LimitExceededError as e:
        return jsonify({"error": str(e)}), 400
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except (RuntimeError, ConflictError) as e:
        return jsonify({"error": str(e)}), 409
    except NotLoggedInError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        log.error(f"Failed to change protocol: {e}", exc_info=True)
        return jsonify({"error": f"Failed to change protocol: {e}"}), 500


# ── Tunnel Control ────────────────────────────────────────────────────────────

@app.route("/api/profiles/<profile_id>/connect", methods=["POST"])
@require_unlocked
def api_connect(profile_id):
    """Bring a VPN profile's tunnel up."""
    try:
        result = _get_service().connect_profile(profile_id)
        return jsonify(result)
    except NotFoundError:
        return jsonify({"error": "VPN profile not found"}), 404
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        log.error(f"Failed to connect: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/profiles/<profile_id>/disconnect", methods=["POST"])
@require_unlocked
def api_disconnect(profile_id):
    """Bring a VPN profile's tunnel down."""
    try:
        result = _get_service().disconnect_profile(profile_id)
        return jsonify(result)
    except NotFoundError:
        return jsonify({"error": "VPN profile not found"}), 404
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        log.error(f"Failed to disconnect: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/profiles/<profile_id>/guest", methods=["PUT"])
@require_unlocked
def api_set_guest(profile_id):
    """Set this profile as the guest profile."""
    try:
        _get_service().set_guest_profile(profile_id)
        return jsonify({"success": True})
    except NotFoundError:
        return jsonify({"error": "Profile not found"}), 404


# ── Devices ───────────────────────────────────────────────────────────────────

@app.route("/api/devices/<mac>/label", methods=["PUT"])
@require_unlocked
def api_set_device_label(mac):
    """Set a custom label and/or device class for a device.

    Body: {label: "Living Room TV", device_class?: "computer"}
    """
    data = request.json or {}
    label = data.get("label", "").strip()
    device_class = data.get("device_class", "")

    try:
        _get_service().set_device_label(mac, label, device_class)
        return jsonify({"success": True, "label": label, "device_class": device_class})
    except Exception as e:
        log.error(f"Failed to set device label on router: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/devices")
@require_unlocked
def api_get_devices():
    """Get all devices, fetched live from router."""
    return jsonify(_get_service().get_devices_cached())


@app.route("/api/devices/<mac>/profile", methods=["PUT"])
@require_unlocked
def api_assign_device(mac):
    """Assign a device to a profile.

    Body: {profile_id: "uuid" or null}
    """
    try:
        mac = ps.validate_mac(mac)
    except ValueError:
        return jsonify({"error": f"Invalid MAC address: {mac}"}), 400

    data = request.json
    profile_id = data.get("profile_id")

    try:
        _get_service().assign_device(mac, profile_id)
        return jsonify({"success": True})
    except NotFoundError:
        return jsonify({"error": "Profile not found"}), 404
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


# ── LAN Access Control ────────────────────────────────────────────────────────

@app.route("/api/profiles/<profile_id>/lan-access", methods=["PUT"])
@require_unlocked
def api_set_profile_lan_access(profile_id):
    """Set LAN access rules for a profile.

    Body: {"outbound": "allowed"|"group_only"|"blocked",
           "inbound": "allowed"|"group_only"|"blocked"}
    """
    data = request.json
    outbound = data.get("outbound", LAN_ALLOWED)
    inbound = data.get("inbound", LAN_ALLOWED)
    outbound_allow = data.get("outbound_allow", [])
    inbound_allow = data.get("inbound_allow", [])

    try:
        result = _get_service().set_profile_lan_access(
            profile_id, outbound, inbound,
            outbound_allow=outbound_allow,
            inbound_allow=inbound_allow,
        )
        return jsonify({"success": True, "lan_access": result.get("lan_access")})
    except NotFoundError:
        return jsonify({"error": "Profile not found"}), 404
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/devices/<mac>/lan-access", methods=["PUT"])
@require_unlocked
def api_set_device_lan_access(mac):
    """Set per-device LAN access override.

    Body: {"outbound": "allowed"|"group_only"|"blocked"|null,
           "inbound": "allowed"|"group_only"|"blocked"|null}
    null values mean inherit from group.
    """
    data = request.json
    outbound = data.get("outbound")
    inbound = data.get("inbound")
    outbound_allow = data.get("outbound_allow", [])
    inbound_allow = data.get("inbound_allow", [])

    try:
        _get_service().set_device_lan_override(
            mac, outbound, inbound,
            outbound_allow=outbound_allow,
            inbound_allow=inbound_allow,
        )
        return jsonify({"success": True})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


# ── Refresh ───────────────────────────────────────────────────────────────────

@app.route("/api/refresh", methods=["POST"])
@require_unlocked
def api_refresh():
    """Refresh DHCP leases, tunnel handshakes, and server list."""
    tracker = get_tracker()
    if tracker:
        tracker.poll_once()

    return jsonify({"success": True})


# ── SSE Stream ────────────────────────────────────────────────────────────────

@app.route("/api/stream")
def api_stream():
    """Server-Sent Events stream for live tunnel health + device updates.

    Pushes updates every 10 seconds with:
    - Tunnel health per VPN profile (green/amber/red)
    - Device count changes
    """
    def generate():
        while True:
            try:
                # Trigger a device tracker poll to refresh client details
                tracker = get_tracker()
                if tracker:
                    tracker.poll_once()

                service = _get_service()

                # Build the canonical profile list once per tick
                data = ps.load()
                merged_profiles = service.build_profile_list(data)
                tunnel_health = {}
                kill_switch_state = {}
                profile_names = {}
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

                # Sync LAN rules if device IPs changed
                if tracker and tracker.lan_rules_stale:
                    try:
                        service.sync_lan_to_router()
                        tracker.lan_rules_stale = False
                    except Exception:
                        pass

                # Device list: refresh on every SSE tick (10s)
                service.invalidate_device_cache()
                all_devices = service.get_devices_cached()

                event_data = {
                    "tunnel_health": tunnel_health,
                    "kill_switch": kill_switch_state,
                    "profile_names": profile_names,
                    "devices": all_devices,
                    "device_count": len(all_devices),
                    "timestamp": time.time(),
                }
                yield f"data: {json.dumps(event_data)}\n\n"
            except Exception:
                yield f"data: {json.dumps({'error': 'update failed'})}\n\n"

            time.sleep(10)

    return Response(generate(), mimetype="text/event-stream")


# ── Logs ──────────────────────────────────────────────────────────────────────

@app.route("/api/logs")
@require_unlocked
def api_get_logs():
    """Get available log files."""
    logs = []
    for f in sorted(LOG_DIR.glob("*.log")):
        logs.append({
            "name": f.name,
            "size": f.stat().st_size,
            "modified": f.stat().st_mtime,
        })
    return jsonify(logs)


@app.route("/api/logs/<name>")
@require_unlocked
def api_get_log_content(name):
    """Get the last N lines of a log file.

    Query params: lines (default 100)
    """
    # Sanitize filename
    if "/" in name or ".." in name or not name.endswith(".log"):
        return jsonify({"error": "Invalid log name"}), 400

    log_file = LOG_DIR / name
    if not log_file.exists():
        return jsonify({"error": "Log not found"}), 404

    lines = int(request.args.get("lines", 200))
    try:
        all_lines = log_file.read_text().splitlines()
        tail = all_lines[-lines:] if len(all_lines) > lines else all_lines
        return jsonify({
            "name": name,
            "total_lines": len(all_lines),
            "lines": tail,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/logs/<name>", methods=["DELETE"])
@require_unlocked
def api_clear_log(name):
    """Clear a log file."""
    if "/" in name or ".." in name or not name.endswith(".log"):
        return jsonify({"error": "Invalid log name"}), 400

    log_file = LOG_DIR / name
    if log_file.exists():
        log_file.write_text("")
    return jsonify({"success": True})


# ── Settings ──────────────────────────────────────────────────────────────────

@app.route("/api/settings")
def api_get_settings():
    """Get non-sensitive config."""
    return jsonify(sm.get_config())


@app.route("/api/settings", methods=["PUT"])
def api_update_settings():
    """Update non-sensitive config (router_ip etc)."""
    data = request.json
    config = sm.update_config(**data)

    # Reset router API if IP changed
    global _router_api
    _router_api = None

    return jsonify(config)


@app.route("/api/settings/credentials", methods=["PUT"])
@require_unlocked
def api_update_credentials():
    """Update encrypted credentials."""
    data = request.json
    master_password = data.pop("master_password", None)
    if not master_password:
        return jsonify({"error": "master_password required"}), 400

    try:
        sm.update(master_password, **data)
        return jsonify({"success": True})
    except (ValueError, KeyError) as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/settings/master-password", methods=["PUT"])
@require_unlocked
def api_change_master_password():
    """Change the master password.

    Body: {old_password, new_password}
    """
    data = request.json
    old_password = data.get("old_password")
    new_password = data.get("new_password")

    if not old_password or not new_password:
        return jsonify({"error": "Both old_password and new_password required"}), 400

    if len(new_password) < 4:
        return jsonify({"error": "New password too short (minimum 4 characters)"}), 400

    try:
        sm.change_master_password(old_password, new_password)
        log.info("Master password changed")
        return jsonify({"success": True})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


# ── Static Files ──────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the main dashboard."""
    return send_from_directory("static", "index.html")


# ── Startup ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True, threaded=True)
