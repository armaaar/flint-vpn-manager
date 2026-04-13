"""LAN Access blueprint — Network CRUD, zone forwarding, isolation, exceptions."""

from flask import Blueprint, request, jsonify

from service_registry import registry as _registry
from routes._helpers import require_unlocked

lan_bp = Blueprint("lan_access", __name__)


def _get_lan_service():
    return _registry.get_lan_service()


@lan_bp.route("/api/lan-access/networks", methods=["GET"])
@require_unlocked
def api_get_lan_networks():
    return jsonify(_get_lan_service().get_lan_overview())


@lan_bp.route("/api/lan-access/networks", methods=["POST"])
@require_unlocked
def api_create_lan_network():
    try:
        return jsonify(_get_lan_service().create_network(request.json))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@lan_bp.route("/api/lan-access/networks/<zone_id>", methods=["PUT"])
@require_unlocked
def api_update_lan_network(zone_id):
    try:
        return jsonify(_get_lan_service().update_network(zone_id, request.json))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@lan_bp.route("/api/lan-access/networks/<zone_id>", methods=["DELETE"])
@require_unlocked
def api_delete_lan_network(zone_id):
    try:
        return jsonify(_get_lan_service().delete_network(zone_id))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@lan_bp.route("/api/lan-access/networks/<zone_id>/devices", methods=["GET"])
@require_unlocked
def api_get_lan_network_devices(zone_id):
    return jsonify({"devices": _get_lan_service().get_network_devices(zone_id)})


@lan_bp.route("/api/lan-access/rules", methods=["PUT"])
@require_unlocked
def api_update_lan_rules():
    data = request.json
    rules = data.get("rules", [])
    return jsonify(_get_lan_service().update_access_rules(rules))


@lan_bp.route("/api/lan-access/isolation/<zone_id>", methods=["PUT"])
@require_unlocked
def api_set_lan_isolation(zone_id):
    data = request.json
    enabled = data.get("enabled", False)
    try:
        return jsonify(_get_lan_service().set_isolation(zone_id, enabled))
    except ValueError as e:
        return jsonify({"error": str(e)}), 404


@lan_bp.route("/api/lan-access/exceptions", methods=["GET"])
@require_unlocked
def api_get_lan_exceptions():
    return jsonify({"exceptions": _get_lan_service().get_exceptions()})


@lan_bp.route("/api/lan-access/exceptions", methods=["POST"])
@require_unlocked
def api_add_lan_exception():
    try:
        return jsonify(_get_lan_service().add_exception(request.json))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@lan_bp.route("/api/lan-access/exceptions/<exc_id>", methods=["DELETE"])
@require_unlocked
def api_remove_lan_exception(exc_id):
    return jsonify(_get_lan_service().remove_exception(exc_id))
