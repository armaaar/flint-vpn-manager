"""VPN Bypass blueprint — exception CRUD, presets, dnsmasq management."""

from flask import Blueprint, request, jsonify

from service_registry import registry as _registry
from routes._helpers import require_unlocked

bypass_bp = Blueprint("vpn_bypass", __name__)


def _get_bypass_service():
    return _registry.get_bypass_service()


@bypass_bp.route("/api/vpn-bypass", methods=["GET"])
@require_unlocked
def api_get_bypass_overview():
    return jsonify(_get_bypass_service().get_overview())


@bypass_bp.route("/api/vpn-bypass/exceptions", methods=["POST"])
@require_unlocked
def api_add_bypass_exception():
    try:
        return jsonify(_get_bypass_service().add_exception(request.json))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@bypass_bp.route("/api/vpn-bypass/exceptions/<exc_id>", methods=["PUT"])
@require_unlocked
def api_update_bypass_exception(exc_id):
    try:
        return jsonify(_get_bypass_service().update_exception(exc_id, request.json))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@bypass_bp.route("/api/vpn-bypass/exceptions/<exc_id>", methods=["DELETE"])
@require_unlocked
def api_delete_bypass_exception(exc_id):
    try:
        return jsonify(_get_bypass_service().remove_exception(exc_id))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@bypass_bp.route("/api/vpn-bypass/exceptions/<exc_id>/toggle", methods=["PUT"])
@require_unlocked
def api_toggle_bypass_exception(exc_id):
    data = request.json
    enabled = data.get("enabled", True)
    try:
        return jsonify(_get_bypass_service().toggle_exception(exc_id, enabled))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@bypass_bp.route("/api/vpn-bypass/presets", methods=["POST"])
@require_unlocked
def api_save_custom_preset():
    try:
        return jsonify(_get_bypass_service().save_custom_preset(request.json))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@bypass_bp.route("/api/vpn-bypass/presets/<preset_id>", methods=["PUT"])
@require_unlocked
def api_update_custom_preset(preset_id):
    data = request.json
    data["id"] = preset_id
    try:
        return jsonify(_get_bypass_service().save_custom_preset(data))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@bypass_bp.route("/api/vpn-bypass/presets/<preset_id>", methods=["DELETE"])
@require_unlocked
def api_delete_custom_preset(preset_id):
    try:
        return jsonify(_get_bypass_service().delete_custom_preset(preset_id))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@bypass_bp.route("/api/vpn-bypass/dnsmasq-install", methods=["POST"])
@require_unlocked
def api_install_dnsmasq_full():
    try:
        return jsonify(_get_bypass_service().install_dnsmasq_full())
    except Exception as e:
        return jsonify({"error": str(e)}), 500
