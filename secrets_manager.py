"""Encrypted credential storage using Fernet (AES-128-CBC + HMAC-SHA256).

Secrets are encrypted with a key derived from the master password via
PBKDF2-HMAC-SHA256. The salt is stored alongside the ciphertext in
secrets.enc. Secrets are only held in memory after unlock — never
written to disk in plain text.
"""

import base64
import json
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

DATA_DIR = Path(__file__).parent
SECRETS_FILE = DATA_DIR / "secrets.enc"
CONFIG_FILE = DATA_DIR / "config.json"

PBKDF2_ITERATIONS = 600_000


def _derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode("utf-8")))


def is_setup() -> bool:
    return SECRETS_FILE.exists()


def setup(
    proton_user: str,
    proton_pass: str,
    router_pass: str,
    master_password: str,
    router_ip: str = "192.168.8.1",
) -> dict:
    """First-time setup: encrypt credentials and write config.

    Returns the secrets dict (same as unlock would return).
    """
    secrets = {
        "proton_user": proton_user,
        "proton_pass": proton_pass,
        "router_pass": router_pass,
    }

    salt = os.urandom(16)
    key = _derive_key(master_password, salt)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(json.dumps(secrets).encode("utf-8"))

    # Write salt (16 bytes) + encrypted blob
    SECRETS_FILE.write_bytes(salt + encrypted)

    # Write non-sensitive config
    config = {"router_ip": router_ip}
    CONFIG_FILE.write_text(json.dumps(config, indent=2))

    return secrets


def unlock(master_password: str) -> dict:
    """Decrypt secrets into memory using master password.

    Raises ValueError if the password is wrong or file is corrupt.
    """
    if not is_setup():
        raise FileNotFoundError("No secrets.enc found. Run setup first.")

    raw = SECRETS_FILE.read_bytes()
    salt = raw[:16]
    encrypted = raw[16:]

    key = _derive_key(master_password, salt)
    fernet = Fernet(key)
    try:
        decrypted = fernet.decrypt(encrypted)
    except InvalidToken:
        raise ValueError("Wrong master password or corrupted secrets file.")

    return json.loads(decrypted)


def update(master_password: str, **updates: str) -> dict:
    """Update one or more credentials. Re-encrypts with a new salt.

    Valid keys: proton_user, proton_pass, router_pass.
    Returns the updated secrets dict.
    """
    valid_keys = {"proton_user", "proton_pass", "router_pass"}
    invalid = set(updates.keys()) - valid_keys
    if invalid:
        raise KeyError(f"Invalid secret keys: {invalid}")

    secrets = unlock(master_password)
    secrets.update(updates)

    # Re-encrypt with fresh salt
    salt = os.urandom(16)
    key = _derive_key(master_password, salt)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(json.dumps(secrets).encode("utf-8"))
    SECRETS_FILE.write_bytes(salt + encrypted)

    return secrets


def change_master_password(old_password: str, new_password: str) -> dict:
    """Change the master password. Decrypts with old, re-encrypts with new."""
    secrets = unlock(old_password)

    salt = os.urandom(16)
    key = _derive_key(new_password, salt)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(json.dumps(secrets).encode("utf-8"))
    SECRETS_FILE.write_bytes(salt + encrypted)

    return secrets


def get_config() -> dict:
    """Read non-sensitive config (router_ip etc)."""
    if not CONFIG_FILE.exists():
        return {"router_ip": "192.168.8.1"}
    return json.loads(CONFIG_FILE.read_text())


def update_config(**updates) -> dict:
    """Update non-sensitive config values."""
    config = get_config()
    config.update(updates)
    CONFIG_FILE.write_text(json.dumps(config, indent=2))
    return config
