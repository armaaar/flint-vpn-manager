"""Logs blueprint — Log file listing, reading, and clearing."""

from pathlib import Path

from flask import Blueprint, request, jsonify

from routes._helpers import require_unlocked

logs_bp = Blueprint("logs", __name__)

# Log directory — same location as app.py's LOG_DIR
LOG_DIR = Path(__file__).resolve().parent.parent.parent / "logs"


@logs_bp.route("/api/logs")
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


@logs_bp.route("/api/logs/<name>")
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


@logs_bp.route("/api/logs/<name>", methods=["DELETE"])
@require_unlocked
def api_clear_log(name):
    """Clear a log file."""
    if "/" in name or ".." in name or not name.endswith(".log"):
        return jsonify({"error": "Invalid log name"}), 400

    log_file = LOG_DIR / name
    if log_file.exists():
        log_file.write_text("")
    return jsonify({"success": True})
