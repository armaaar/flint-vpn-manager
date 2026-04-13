"""Backup Service — Push/restore profile_store.json to/from the router.

Standalone functions with no VPNService dependency. Called from the
unlock handler (app.py) and registered as a save callback.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import persistence.profile_store as ps

log = logging.getLogger("flintvpn")

# ── Constants ───────────────────────────────────────────────────────────────

ROUTER_BACKUP_PATH = "/etc/fvpn/profile_store.bak.json"
BACKUP_FORMAT_VERSION = 1


# ── Backup / Restore ───────────────────────────────────────────────────────


def backup_local_state_to_router(router, store_path: Path):
    """Push profile_store.json to the router as a static backup file.

    Wraps the JSON in a small ``_meta`` envelope (timestamp, router
    fingerprint, format version) so the auto-restore path on unlock can
    verify it before overwriting local state.

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
                "version": BACKUP_FORMAT_VERSION,
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
    """On unlock, restore profile_store.json from the router backup if newer.

    Comparison rules:
      - If no backup file on the router -> no-op.
      - If backup ``_meta.version`` doesn't match current -> log warning, no-op.
      - If router fingerprint mismatches the live router -> log warning, no-op
        (the backup belongs to a different router).
      - If local profile_store.json is missing/unparseable -> restore.
      - Else compare backup ``_meta.saved_at`` with local file mtime:
          backup newer  -> restore
          local newer   -> push local back to router (self-heal stale backup)
          equal         -> no-op

    Both timestamps are sourced from the same machine's clock (this Surface
    Go), so there's no clock-skew issue.

    Silent operation per user instruction -- no UX, no toasts, no banners.
    """
    try:
        try:
            raw = router.read_file(ROUTER_BACKUP_PATH)
        except Exception as e:
            log.warning(f"Auto-restore: read failed: {e}")
            return
        if not raw:
            return  # No backup to restore from
        try:
            wrapped = json.loads(raw)
        except json.JSONDecodeError as e:
            log.warning(f"Auto-restore: backup file is unparseable: {e}")
            return

        meta = wrapped.get("_meta") or {}
        if meta.get("version") != BACKUP_FORMAT_VERSION:
            log.warning(
                f"Auto-restore: backup version {meta.get('version')} != "
                f"{BACKUP_FORMAT_VERSION}, skipping"
            )
            return

        # Fingerprint check -- if it doesn't match, the backup is from a
        # different router and we should NOT silently overwrite.
        try:
            current_fingerprint = router.get_router_fingerprint()
        except Exception:
            current_fingerprint = ""
        backup_fp = meta.get("router_fingerprint", "")
        if current_fingerprint and backup_fp and current_fingerprint != backup_fp:
            log.warning(
                f"Auto-restore: router fingerprint mismatch "
                f"(backup={backup_fp}, current={current_fingerprint}), skipping"
            )
            return

        backup_data = wrapped.get("data") or {}
        backup_saved_at = meta.get("saved_at", "")
        try:
            backup_dt = datetime.fromisoformat(backup_saved_at)
        except (ValueError, TypeError):
            log.warning(f"Auto-restore: invalid saved_at {backup_saved_at!r}")
            return

        # Compare to local file mtime
        if not ps.STORE_FILE.exists():
            local_dt = datetime.fromtimestamp(0, tz=timezone.utc)
            local_state = "missing"
        else:
            try:
                # Verify local is parseable; if not, treat as missing
                _ = json.loads(ps.STORE_FILE.read_text())
                local_dt = datetime.fromtimestamp(
                    ps.STORE_FILE.stat().st_mtime, tz=timezone.utc
                )
                local_state = "valid"
            except Exception:
                local_dt = datetime.fromtimestamp(0, tz=timezone.utc)
                local_state = "unparseable"

        if backup_dt > local_dt:
            log.info(
                f"Auto-restore: backup ({backup_saved_at}) is newer than "
                f"local ({local_state}), restoring"
            )
            ps.save(backup_data)
            # The save() call would normally fire the backup callback; but
            # because the data is identical to the backup, the next backup
            # push is essentially a no-op (idempotent).
        elif backup_dt < local_dt:
            log.info(
                "Auto-restore: local is newer than backup, self-healing by "
                "pushing local state to router"
            )
            try:
                backup_local_state_to_router(router, ps.STORE_FILE)
            except Exception as e:
                log.warning(f"Auto-restore self-heal failed: {e}")
        # else: equal -- no-op
    except Exception as e:
        log.warning(f"Auto-restore check failed: {e}")
