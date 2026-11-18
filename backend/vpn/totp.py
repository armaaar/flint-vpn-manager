"""RFC 6238 TOTP (standard library only) for split VPN logins.

Accepts a bare base32 secret or an ``otpauth://totp/...`` URI (as exported
by authenticator apps / QR codes) and produces the current code.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import struct
import time
from urllib.parse import parse_qs, unquote, urlparse

_ALGORITHMS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


def parse_totp(value: str) -> dict:
    """Normalise user input into ``{secret, digits, period, algorithm}``.

    Raises ValueError if the secret isn't valid base32 or parameters are
    out of range.
    """
    value = (value or "").strip()
    if not value:
        raise ValueError("TOTP secret is empty")
    params = {"digits": 6, "period": 30, "algorithm": "SHA1"}
    if value.lower().startswith("otpauth://"):
        u = urlparse(value)
        if u.netloc.lower() != "totp":
            raise ValueError("Only otpauth://totp URIs are supported")
        q = {k.lower(): v[0] for k, v in parse_qs(u.query).items()}
        secret = q.get("secret", "")
        if "digits" in q:
            params["digits"] = int(q["digits"])
        if "period" in q:
            params["period"] = int(q["period"])
        if "algorithm" in q:
            params["algorithm"] = q["algorithm"].upper()
        label = unquote(u.path.lstrip("/"))
        if label:
            params["label"] = label[:128]
    else:
        secret = value
    secret = secret.replace(" ", "").replace("-", "").upper().rstrip("=")
    if params["algorithm"] not in _ALGORITHMS:
        raise ValueError(f"Unsupported TOTP algorithm: {params['algorithm']}")
    if not 6 <= params["digits"] <= 10:
        raise ValueError("TOTP digits must be 6-10")
    if not 10 <= params["period"] <= 300:
        raise ValueError("TOTP period must be 10-300 seconds")
    _decode(secret)  # validate
    return {"secret": secret, **params}


def _decode(secret: str) -> bytes:
    try:
        key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    except (binascii.Error, ValueError) as e:
        raise ValueError("TOTP secret is not valid base32") from e
    if len(key) < 10:
        raise ValueError("TOTP secret is too short")
    return key


def totp_code(cfg: dict, at: float | None = None) -> str:
    """Current code for a config from ``parse_totp``."""
    key = _decode(cfg["secret"])
    period = int(cfg.get("period", 30))
    digits = int(cfg.get("digits", 6))
    counter = int((time.time() if at is None else at) // period)
    digest = hmac.new(key, struct.pack(">Q", counter), _ALGORITHMS[cfg.get("algorithm", "SHA1")]).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10 ** digits)).zfill(digits)


def seconds_left(cfg: dict, at: float | None = None) -> float:
    period = int(cfg.get("period", 30))
    now = time.time() if at is None else at
    return period - (now % period)
