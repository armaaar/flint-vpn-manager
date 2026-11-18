"""Read-only access to the SOPS-encrypted secrets file.

The file (default ``secrets/flint.enc.yaml``, override with the
``sops_secrets_file`` config key or ``FLINT_SOPS_FILE``) is encrypted with
the owner's age key and edited by the owner with ``sops <file>`` — the app
only ever decrypts it, in memory, when a value is needed. Decryption uses the
standard SOPS key lookup (``~/.config/sops/age/keys.txt`` or
``SOPS_AGE_KEY_FILE``).

Schema (see ``secrets/flint.example.yaml``)::

    flint:
      master_password: ...          # enables auto-unlock on startup
    split_vpns:
      <ref>:                        # a split VPN's ``secret_ref``
        username: ...               # optional
        password: ...
        totp_secret: ...            # base32 or otpauth://totp/... URI
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_FILE = "secrets/flint.enc.yaml"
_CACHE_TTL = 30  # seconds; also invalidated when the file changes
_PLACEHOLDER = "CHANGE_ME"

_lock = threading.Lock()
_cache: dict = {"key": None, "at": 0.0, "data": None}


class SopsError(Exception):
    """The secrets file is missing, undecryptable, or sops isn't installed."""


def secrets_path() -> Path:
    raw = os.environ.get("FLINT_SOPS_FILE")
    if not raw:
        try:
            import persistence.secrets_manager as sm
            raw = sm.get_config().get("sops_secrets_file")
        except Exception:
            raw = None
    p = Path(raw or DEFAULT_FILE).expanduser()
    return p if p.is_absolute() else _PROJECT_ROOT / p


def sops_binary() -> str:
    found = shutil.which("sops")
    if found:
        return found
    # systemd services don't have ~/.local/bin on PATH
    for cand in (Path.home() / ".local/bin/sops", Path("/usr/local/bin/sops")):
        if cand.is_file() and os.access(cand, os.X_OK):
            return str(cand)
    raise SopsError("sops binary not found")


def load(force: bool = False) -> dict:
    """Decrypt and return the whole secrets document (cached briefly)."""
    path = secrets_path()
    if not path.exists():
        raise SopsError(f"SOPS secrets file not found: {path}")
    stat = path.stat()
    key = (str(path), stat.st_mtime_ns, stat.st_size)
    with _lock:
        if not force and _cache["key"] == key and time.time() - _cache["at"] < _CACHE_TTL:
            return _cache["data"]
        try:
            proc = subprocess.run(
                [sops_binary(), "--decrypt", "--output-type", "json", str(path)],
                capture_output=True, timeout=30, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as e:
            raise SopsError(f"sops failed to run: {e}") from e
        if proc.returncode != 0:
            # stderr never contains plaintext values, only key/format errors
            msg = proc.stderr.decode(errors="replace").strip().splitlines()
            raise SopsError(f"sops could not decrypt {path.name}: {msg[-1] if msg else proc.returncode}")
        try:
            data = json.loads(proc.stdout or b"{}")
        except json.JSONDecodeError as e:
            raise SopsError(f"sops returned invalid JSON: {e}") from e
        if not isinstance(data, dict):
            raise SopsError("SOPS secrets file must be a mapping")
        _cache.update(key=key, at=time.time(), data=data)
        return data


def get(*keys: str, default=None):
    """Nested lookup, e.g. ``get("flint", "master_password")``. Placeholder
    values (``CHANGE_ME``) and empty strings count as missing."""
    node = load()
    for k in keys:
        if not isinstance(node, dict) or k not in node:
            return default
        node = node[k]
    if node is None or (isinstance(node, str) and node.strip() in ("", _PLACEHOLDER)):
        return default
    return node


def split_vpn_credentials(ref: str) -> dict:
    """Credentials for a split VPN ``secret_ref`` → {username?, password?, totp_secret?}."""
    entry = get("split_vpns", ref, default=None)
    if not isinstance(entry, dict):
        raise SopsError(f"No 'split_vpns.{ref}' entry in the SOPS secrets file")
    out = {}
    for field in ("username", "password", "totp_secret"):
        val = entry.get(field)
        if isinstance(val, str) and val.strip() and val.strip() != _PLACEHOLDER:
            out[field] = val.strip()
    return out


def clear_cache() -> None:
    with _lock:
        _cache.update(key=None, at=0.0, data=None)
