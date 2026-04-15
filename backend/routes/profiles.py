"""Profiles blueprint — Profile CRUD, server selection, tunnel control, refresh."""

import time

from flask import Blueprint, request, jsonify

import persistence.secrets_manager as sm
from services.vpn_service import (
    NotFoundError, ConflictError, LimitExceededError, NotLoggedInError,
)
from background.device_tracker import get_tracker
from routes._helpers import (
    require_unlocked, get_service, get_router,
    location_cache, LOCATION_CACHE_TTL, log,
)

profiles_bp = Blueprint("profiles", __name__)


# ── Profiles CRUD ────────────────────────────────────────────────────────────

@profiles_bp.route("/api/profiles")
@require_unlocked
def api_get_profiles():
    """Get all profiles. Built from router rules + local UI metadata."""
    profiles = get_service().build_profile_list()
    return jsonify(profiles)


@profiles_bp.route("/api/profiles", methods=["POST"])
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
        profile = get_service().create_profile(
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
            adblock=data.get("adblock", False),
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


@profiles_bp.route("/api/profiles/reorder", methods=["PUT"])
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
        get_service().reorder_profiles(ids)
        return jsonify({"success": True})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@profiles_bp.route("/api/profiles/<profile_id>", methods=["PUT"])
@require_unlocked
def api_update_profile(profile_id):
    """Update profile metadata (name, color, icon, options, kill_switch)."""
    data = dict(request.json or {})
    try:
        profile = get_service().update_profile(profile_id, **data)
        return jsonify(profile)
    except NotFoundError:
        return jsonify({"error": "Profile not found"}), 404


@profiles_bp.route("/api/profiles/<profile_id>", methods=["DELETE"])
@require_unlocked
def api_delete_profile(profile_id):
    """Delete a profile and tear down its tunnel if VPN."""
    try:
        get_service().delete_profile(profile_id)
        return jsonify({"success": True})
    except NotFoundError:
        return jsonify({"error": "Profile not found"}), 404


# ── Server Selection ─────────────────────────────────────────────────────────

@profiles_bp.route("/api/profiles/<profile_id>/servers")
@require_unlocked
def api_get_servers(profile_id):
    """Get ProtonVPN server list for a profile's server picker."""
    proton = get_service().proton
    if not proton.is_logged_in:
        return jsonify({"error": "Not logged into ProtonVPN"}), 400

    country = request.args.get("country")
    city = request.args.get("city")
    feature = request.args.get("feature")

    servers = proton.get_servers(country=country, city=city, feature=feature)

    # Tag servers with blacklist/favourite status for frontend display
    config = sm.get_config()
    blacklist_set = set(config.get("server_blacklist", []))
    favourites_set = set(config.get("server_favourites", []))
    for s in servers:
        s["blacklisted"] = s["id"] in blacklist_set
        s["favourite"] = s["id"] in favourites_set

    return jsonify(servers)


@profiles_bp.route("/api/server-countries")
@require_unlocked
def api_get_server_countries():
    """Get all available ProtonVPN countries with server counts and cities."""
    proton = get_service().proton
    if not proton.is_logged_in:
        return jsonify({"error": "Not logged into ProtonVPN"}), 400
    try:
        countries = proton.get_countries()
        return jsonify(countries)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 400


@profiles_bp.route("/api/vpn-status")
@require_unlocked
def api_get_vpn_status():
    """Get ProtonVPN account/session status: login state, tier, server list freshness."""
    proton = get_service().proton
    result = {"logged_in": proton.is_logged_in}
    if proton.is_logged_in:
        result["account_name"] = proton.account_name
        result["user_tier"] = proton.user_tier
        result["tier_name"] = "Plus" if proton.user_tier >= 2 else "Free"
        sl = proton.server_list
        if sl:
            result["server_count"] = len(sl)
            result["server_list_expired"] = sl.expired
            result["loads_expired"] = sl.loads_expired
    return jsonify(result)


@profiles_bp.route("/api/available-ports")
@require_unlocked
def api_available_ports():
    """Get available VPN ports per protocol."""
    from proton_vpn.api import ProtonAPI
    return jsonify(ProtonAPI.AVAILABLE_PORTS)


@profiles_bp.route("/api/location")
@require_unlocked
def api_get_location():
    """Get the current physical location as seen by ProtonVPN.

    Cached for 30 seconds to avoid excessive Proton API calls.
    Returns: {ip, country, isp, lat, lon}
    """
    now = time.time()
    if location_cache["data"] and (now - location_cache["ts"]) < LOCATION_CACHE_TTL:
        return jsonify(location_cache["data"])

    proton = get_service().proton
    if not proton or not proton.is_logged_in:
        return jsonify({"error": "Not logged into ProtonVPN"}), 400
    try:
        location = proton.get_location()
        location_cache["data"] = location
        location_cache["ts"] = now
        return jsonify(location)
    except Exception as e:
        log.warning(f"Location check failed: {e}")
        return jsonify({"error": str(e)}), 500



# ── Server / Type / Protocol Changes ─────────────────────────────────────────

@profiles_bp.route("/api/profiles/<profile_id>/server", methods=["PUT"])
@require_unlocked
def api_change_server(profile_id):
    """Change the server for a VPN profile.

    Body: {server_id, options?, server_scope?}
    """
    data = request.json
    if "server_id" not in data:
        return jsonify({"error": "server_id required"}), 400

    try:
        profile = get_service().switch_server(
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


@profiles_bp.route("/api/profiles/<profile_id>/type", methods=["PUT"])
@require_unlocked
def api_change_type(profile_id):
    """Change the group type of a profile (VPN <-> NoVPN <-> NoInternet).

    Body: {type, vpn_protocol?, server_id?, options?, kill_switch?,
           server_scope?, ovpn_protocol?}
    """
    data = request.json or {}
    new_type = data.get("type")
    if not new_type:
        return jsonify({"error": "type required"}), 400

    try:
        profile = get_service().change_type(
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


@profiles_bp.route("/api/profiles/<profile_id>/protocol", methods=["PUT"])
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
        profile = get_service().change_protocol(
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


# ── Tunnel Control ───────────────────────────────────────────────────────────

@profiles_bp.route("/api/profiles/<profile_id>/connect", methods=["POST"])
@require_unlocked
def api_connect(profile_id):
    """Bring a VPN profile's tunnel up.

    Smart Protocol retry (if enabled in profile options) is handled in the
    background by the SSE tick -- this endpoint always returns immediately.
    """
    try:
        result = get_service().connect_profile(profile_id)
        location_cache["data"] = None  # IP may have changed
        return jsonify(result)
    except NotFoundError:
        return jsonify({"error": "VPN profile not found"}), 404
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        log.error(f"Failed to connect: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@profiles_bp.route("/api/profiles/<profile_id>/disconnect", methods=["POST"])
@require_unlocked
def api_disconnect(profile_id):
    """Bring a VPN profile's tunnel down."""
    try:
        result = get_service().disconnect_profile(profile_id)
        location_cache["data"] = None  # IP may have changed
        return jsonify(result)
    except NotFoundError:
        return jsonify({"error": "VPN profile not found"}), 404
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        log.error(f"Failed to disconnect: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@profiles_bp.route("/api/profiles/<profile_id>/guest", methods=["PUT"])
@require_unlocked
def api_set_guest(profile_id):
    """Set this profile as the guest profile."""
    try:
        get_service().set_guest_profile(profile_id)
        return jsonify({"success": True})
    except NotFoundError:
        return jsonify({"error": "Profile not found"}), 404


# ── Refresh / Latency ────────────────────────────────────────────────────────

@profiles_bp.route("/api/refresh", methods=["POST"])
@require_unlocked
def api_refresh():
    """Refresh DHCP leases, tunnel handshakes, and server list."""
    tracker = get_tracker()
    if tracker:
        tracker.poll_once()

    # Refresh server scores if stale
    try:
        proton = get_service().proton
        if proton and proton.is_logged_in:
            if proton.server_list_expired:
                proton.refresh_server_list()
            elif proton.server_loads_expired:
                proton.refresh_server_loads()
    except Exception as e:
        log.warning(f"Server refresh on manual poll failed: {e}")

    # Re-sync adblock ipset (picks up device assignment changes)
    try:
        get_service().sync_adblock_to_router()
    except Exception as e:
        log.warning(f"Adblock sync on refresh failed: {e}")

    return jsonify({"success": True})


@profiles_bp.route("/api/probe-latency", methods=["POST"])
@require_unlocked
def api_probe_latency():
    """Probe TCP latency to a list of VPN servers (from the router).

    Body: {server_ids: ["id1", "id2", ...]}
    Returns: {latencies: {server_id: latency_ms_or_null}}
    """
    data = request.json or {}
    server_ids = data.get("server_ids", [])
    if not server_ids:
        return jsonify({"latencies": {}})

    proton = get_service().proton
    if not proton or not proton.is_logged_in:
        return jsonify({"error": "Not logged into ProtonVPN"}), 400

    to_probe = proton.get_server_entry_ips(server_ids)
    if not to_probe:
        return jsonify({"latencies": {}})

    from proton_vpn.latency_probe import probe_servers_via_router

    try:
        router = get_router()
        latencies = probe_servers_via_router(router, to_probe)
    except Exception as e:
        log.warning(f"Latency probe failed: {e}")
        latencies = {}

    return jsonify({"latencies": latencies})
