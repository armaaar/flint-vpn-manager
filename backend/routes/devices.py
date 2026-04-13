"""Devices blueprint — Device listing, labeling, and assignment."""

from flask import Blueprint, request, jsonify

import persistence.profile_store as ps
from services.vpn_service import NotFoundError
from routes._helpers import require_unlocked, get_service, log

devices_bp = Blueprint("devices", __name__)


@devices_bp.route("/api/devices/<mac>/label", methods=["PUT"])
@require_unlocked
def api_set_device_label(mac):
    """Set a custom label and/or device class for a device.

    Body: {label: "Living Room TV", device_class?: "computer"}
    """
    data = request.json or {}
    label = data.get("label", "").strip()
    device_class = data.get("device_class", "")

    try:
        get_service().set_device_label(mac, label, device_class)
        return jsonify({"success": True, "label": label, "device_class": device_class})
    except Exception as e:
        log.error(f"Failed to set device label on router: {e}")
        return jsonify({"error": str(e)}), 500


@devices_bp.route("/api/devices")
@require_unlocked
def api_get_devices():
    """Get all devices, fetched live from router."""
    return jsonify(get_service().get_devices_cached())


@devices_bp.route("/api/devices/<mac>/profile", methods=["PUT"])
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
        get_service().assign_device(mac, profile_id)
        return jsonify({"success": True})
    except NotFoundError:
        return jsonify({"error": "Profile not found"}), 404
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
