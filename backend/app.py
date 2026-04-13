"""FlintVPN Manager — Flask REST API + SSE.

Main application server. Registers route blueprints and configures logging.

Run: python app.py (or flask run)
Access: http://localhost:5000 or http://<surface-ip>:5000 from LAN
"""

import logging
from pathlib import Path

from flask import Flask, send_from_directory

import pathlib as _pathlib
_PROJECT_ROOT = _pathlib.Path(__file__).resolve().parent.parent
app = Flask(__name__, static_folder=str(_PROJECT_ROOT / "static"), static_url_path="")

# ── Logging ───────────────────────────────────────────────────────────────────

LOG_DIR = Path(__file__).parent.parent / "logs"
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

# ── Register Blueprints ──────────────────────────────────────────────────────

from routes.auth import auth_bp          # noqa: E402
from routes.profiles import profiles_bp  # noqa: E402
from routes.devices import devices_bp    # noqa: E402
from routes.lan_access import lan_bp     # noqa: E402
from routes.settings import settings_bp  # noqa: E402
from routes.stream import stream_bp      # noqa: E402
from routes.logs import logs_bp          # noqa: E402

app.register_blueprint(auth_bp)
app.register_blueprint(profiles_bp)
app.register_blueprint(devices_bp)
app.register_blueprint(lan_bp)
app.register_blueprint(settings_bp)
app.register_blueprint(stream_bp)
app.register_blueprint(logs_bp)


# ── Static Files ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the main dashboard."""
    return send_from_directory(str(_PROJECT_ROOT / "static"), "index.html")


# ── Startup ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
