"""Auth blueprint — Status, setup, unlock, and lock endpoints."""

import logging
import time

from flask import Blueprint, request, jsonify

import persistence.secrets_manager as sm
import persistence.profile_store as ps
from service_registry import registry as _registry
from services.vpn_service import VPNService
from services.backup_service import backup_local_state_to_router, check_and_auto_restore
from background.device_tracker import start_tracker, stop_tracker
from background.auto_optimizer import start_optimizer, stop_optimizer
from routes._helpers import get_proton, get_router, log

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/api/status")
def api_status():
    """App status: setup-needed, locked, or unlocked."""
    if not sm.is_setup():
        return jsonify({"status": "setup-needed"})
    if not _registry.session_unlocked:
        return jsonify({"status": "locked"})
    return jsonify({
        "status": "unlocked",
        "proton_logged_in": get_proton().is_logged_in,
    })


@auth_bp.route("/api/setup", methods=["POST"])
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


@auth_bp.route("/api/unlock", methods=["POST"])
def api_unlock():
    """Unlock session with master password."""
    data = request.json
    if "master_password" not in data:
        return jsonify({"error": "master_password required"}), 400

    try:
        t_total = time.time()

        t = time.time()
        sm.unlock(data["master_password"])
        _registry.session_unlocked = True
        log.info(f"Unlock timing: decrypt={time.time()-t:.2f}s")

        # Create the VPN service
        t = time.time()
        router = get_router()
        proton = get_proton()
        _registry.service = VPNService(router, proton)
        log.info(f"Unlock timing: service_init={time.time()-t:.2f}s")

        # Register backup callback so every save() pushes to router
        ps.register_save_callback(
            lambda path: backup_local_state_to_router(_registry.service.router, path)
        )

        # Auto-restore local state from router backup if newer (silent disaster
        # recovery — must run BEFORE the device tracker / LAN sync since they
        # depend on the local store).
        t = time.time()
        try:
            check_and_auto_restore(router)
        except Exception as e:
            log.warning(f"Auto-restore check failed: {e}")
        log.info(f"Unlock timing: auto_restore={time.time()-t:.2f}s")

        # Apply alternative routing setting
        config = sm.get_config()
        if config.get("alternative_routing") is False:
            proton.set_alternative_routing(False)

        # Start device tracker and poll immediately so devices are ready
        t = time.time()
        tracker = start_tracker(router)
        tracker.poll_once()
        log.info(f"Unlock timing: tracker={time.time()-t:.2f}s")

        # Apply global IPv6 setting — enable router IPv6 if user opted in,
        # otherwise ensure leak protection blocks all IPv6 forwarding.
        t = time.time()
        config = sm.get_config()
        if config.get("global_ipv6_enabled"):
            try:
                router.firewall.ensure_ipv6_router_enabled()
            except Exception as e:
                log.warning(f"IPv6 router enablement failed: {e}")
        try:
            router.firewall.ensure_ipv6_leak_protection()
        except Exception as e:
            log.warning(f"IPv6 leak protection setup failed: {e}")
        log.info(f"Unlock timing: ipv6={time.time()-t:.2f}s")

        # Reconcile router LAN execution layer (UCI ipsets + rules) with the
        # restored / local intent.
        t = time.time()
        try:
            _registry.service.sync_noint_to_router()
        except Exception as e:
            log.warning(f"NoInternet sync on unlock failed: {e}")
        log.info(f"Unlock timing: noint_sync={time.time()-t:.2f}s")

        # Reconcile proton-wg ipsets (ephemeral, lost on restart/reload)
        t = time.time()
        try:
            _registry.service.reconcile_proton_wg_ipsets()
        except Exception as e:
            log.warning(f"proton-wg ipset reconciliation failed: {e}")
        log.info(f"Unlock timing: pwg_ipsets={time.time()-t:.2f}s")

        # Reapply LAN access exceptions from config
        t = time.time()
        try:
            _registry.get_lan_service().reapply_all()
        except Exception as e:
            log.warning(f"LAN access reapply on unlock failed: {e}")
        log.info(f"Unlock timing: lan_access={time.time()-t:.2f}s")

        # Reapply VPN bypass exceptions from config
        t = time.time()
        try:
            _registry.get_bypass_service().reapply_all()
        except Exception as e:
            log.warning(f"VPN bypass reapply on unlock failed: {e}")
        log.info(f"Unlock timing: vpn_bypass={time.time()-t:.2f}s")

        # Start auto-optimizer
        t = time.time()
        try:
            start_optimizer(
                get_proton=lambda: _registry.service.proton,
                get_router=lambda: _registry.service.router,
                switch_fn=_registry.service.switch_server,
                build_profile_list_fn=lambda r, d, proton=None: _registry.service.build_profile_list(d),
            )
        except Exception as e:
            log.warning(f"Auto-optimizer start failed: {e}")
        log.info(f"Unlock timing: optimizer={time.time()-t:.2f}s")

        log.info(f"Unlock timing: TOTAL={time.time()-t_total:.2f}s")
        return jsonify({"success": True})
    except (ValueError, FileNotFoundError) as e:
        return jsonify({"error": str(e)}), 401


@auth_bp.route("/api/lock", methods=["POST"])
def api_lock():
    """Lock the session without restarting the app.

    Clears the in-memory unlocked flag, stops the device tracker, and stops
    the auto-optimizer. The next request that needs an unlocked session will
    return 401 until /api/unlock is called again.
    """
    _registry.reset()
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
