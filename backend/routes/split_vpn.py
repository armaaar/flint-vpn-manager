"""Split VPN blueprint — third-party VPNs routed for selected groups/destinations."""

from flask import Blueprint, jsonify, request

from routes._helpers import require_unlocked
from service_registry import registry as _registry

split_vpn_bp = Blueprint("split_vpn", __name__)


def _svc():
    return _registry.get_split_vpn_service()


def _run(fn, *args):
    try:
        return jsonify(fn(*args))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 502


@split_vpn_bp.route("/api/split-vpns", methods=["GET"])
@require_unlocked
def api_list_split_vpns():
    live = request.args.get("live", "1") != "0"
    return _run(_svc().get_overview, live)


@split_vpn_bp.route("/api/split-vpns", methods=["POST"])
@require_unlocked
def api_create_split_vpn():
    return _run(_svc().create, request.json or {})


@split_vpn_bp.route("/api/split-vpns/<vpn_id>", methods=["PUT"])
@require_unlocked
def api_update_split_vpn(vpn_id):
    return _run(_svc().update, vpn_id, request.json or {})


@split_vpn_bp.route("/api/split-vpns/<vpn_id>", methods=["DELETE"])
@require_unlocked
def api_delete_split_vpn(vpn_id):
    return _run(_svc().delete, vpn_id)


@split_vpn_bp.route("/api/split-vpns/<vpn_id>/connect", methods=["POST"])
@require_unlocked
def api_connect_split_vpn(vpn_id):
    return _run(_svc().connect, vpn_id, (request.json or {}).get("otp", ""))


@split_vpn_bp.route("/api/split-vpns/<vpn_id>/disconnect", methods=["POST"])
@require_unlocked
def api_disconnect_split_vpn(vpn_id):
    return _run(_svc().disconnect, vpn_id)


@split_vpn_bp.route("/api/split-vpns/<vpn_id>/log", methods=["GET"])
@require_unlocked
def api_split_vpn_log(vpn_id):
    return _run(_svc().get_log, vpn_id)


@split_vpn_bp.route("/api/split-vpns/runtime", methods=["GET"])
@require_unlocked
def api_split_vpn_runtime():
    return _run(_svc().runtime_status)


@split_vpn_bp.route("/api/split-vpns/runtime/install", methods=["POST"])
@require_unlocked
def api_install_split_vpn_runtime():
    return _run(_svc().install_runtime)
