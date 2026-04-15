"""Backup Service — Push/restore profile_store.json to/from the router.

The router backup is the source of truth for the profile store.  On
every unlock the app pulls the backup from the router and overwrites
the local file — no timestamp comparison, no fingerprint gating.  A
new router (no backup) means a genuinely clean slate (empty store).

During normal operation every ``ps.save()`` pushes the updated store
back to the router via the registered save callback.

Standalone functions with no VPNService dependency.  Called from the
unlock handler (auth.py) and registered as a save callback.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import persistence.profile_store as ps

log = logging.getLogger("flintvpn")

# ── Constants ───────────────────────────────────────────────────────────────

ROUTER_BACKUP_PATH = "/etc/fvpn/profile_store.bak.json"


# ── Backup / Restore ───────────────────────────────────────────────────────


def backup_local_state_to_router(router, store_path: Path):
    """Push profile_store.json to the router as a static backup file.

    Wraps the JSON in a small ``_meta`` envelope (timestamp, router
    fingerprint) for debug logging.

    Best-effort: SSH failures log a warning and never propagate.
    """
    try:
        if not store_path.exists():
            return
        try:
            content = store_path.read_text()
            data = json.loads(content)
        except Exception as e:
            log.warning(f"Backup skipped (local store unreadable): {e}")
            return

        try:
            fingerprint = router.get_router_fingerprint()
        except Exception:
            fingerprint = ""

        wrapped = {
            "_meta": {
                "saved_at": datetime.now(timezone.utc).isoformat(),
                "router_fingerprint": fingerprint,
            },
            "data": data,
        }

        # Make sure /etc/fvpn/ exists (idempotent)
        try:
            router.exec("mkdir -p /etc/fvpn 2>/dev/null || true")
        except Exception:
            pass

        router.write_file(ROUTER_BACKUP_PATH, json.dumps(wrapped, indent=2))
    except Exception as e:
        log.warning(f"Backup to router failed: {e}")


def check_and_auto_restore(router):
    """On unlock, restore profile_store.json from the router backup.

    The router is the source of truth.  Rules:
      - Backup exists and is valid JSON → **always restore** (overwrite local).
      - Backup exists but unparseable → log warning, leave local alone.
      - No backup file on the router → **reset to empty store** (new router).
      - SSH read failure → log warning, leave local alone (transient error).

    Silent operation — no UX, no toasts, no banners.
    """
    try:
        try:
            raw = router.read_file(ROUTER_BACKUP_PATH)
        except Exception as e:
            log.warning(f"Auto-restore: SSH read failed, leaving local store: {e}")
            return
        if not raw:
            # New router — no backup file.  Start with a clean slate.
            log.info("Auto-restore: no backup on router, resetting to empty store")
            ps.save(ps._EMPTY_STORE.copy())
            return
        try:
            wrapped = json.loads(raw)
        except json.JSONDecodeError as e:
            log.warning(f"Auto-restore: backup unparseable, leaving local store: {e}")
            return

        backup_data = wrapped.get("data") or {}

        # Log metadata for debugging (not used for decision-making)
        meta = wrapped.get("_meta") or {}
        log.info(
            "Auto-restore: restoring from router backup (saved_at=%s, fingerprint=%s)",
            meta.get("saved_at", "unknown"),
            meta.get("router_fingerprint", "unknown"),
        )

        ps.save(backup_data)
    except Exception as e:
        log.warning(f"Auto-restore check failed: {e}")
