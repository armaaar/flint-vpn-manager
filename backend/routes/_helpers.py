"""Shared helpers for Flask route blueprints.

Provides the require_unlocked decorator, service getters, and shared
mutable state (location cache) used across multiple blueprint modules.
"""

import functools
import logging
import time

from flask import jsonify

from service_registry import registry as _registry

log = logging.getLogger("flintvpn")


def require_unlocked(f):
    """Decorator that returns 401 if the session is locked."""
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if not _registry.session_unlocked:
            return jsonify({"error": "Session locked. POST /api/unlock first."}), 401
        return f(*args, **kwargs)
    return wrapper


def get_service():
    """Return the VPNService instance (raises if not initialized)."""
    return _registry.get_service()


def get_proton():
    """Lazy-init and return the ProtonAPI instance."""
    return _registry.get_proton()


def get_router():
    """Lazy-init and return the RouterAPI instance."""
    return _registry.get_router()


def invalidate_device_cache():
    """Invalidate the in-memory device cache."""
    if _registry.service is not None:
        _registry.service.invalidate_device_cache()


# ── Location cache ──────────────────────────────────────────────────────────
# Shared mutable state used by profiles blueprint (connect/disconnect clear
# it) and the location endpoint (reads/writes it).

location_cache = {"data": None, "ts": 0.0}
LOCATION_CACHE_TTL = 30  # seconds
