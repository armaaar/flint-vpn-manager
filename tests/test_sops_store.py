"""Tests for persistence.sops_store and SOPS auto-unlock."""

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

import persistence.sops_store as sops


@pytest.fixture(autouse=True)
def _fresh(tmp_path, monkeypatch):
    f = tmp_path / "flint.enc.yaml"
    f.write_text("encrypted")
    monkeypatch.setenv("FLINT_SOPS_FILE", str(f))
    monkeypatch.setattr(sops, "sops_binary", lambda: "/usr/bin/sops")
    sops.clear_cache()
    yield f
    sops.clear_cache()


def _decrypted(doc):
    return MagicMock(returncode=0, stdout=json.dumps(doc).encode(), stderr=b"")


DOC = {"flint": {"master_password": "mp"},
       "split_vpns": {"work": {"username": "bob", "password": "pw",
                                   "totp_secret": "CHANGE_ME"}}}


def test_get_and_placeholders():
    with patch.object(subprocess, "run", return_value=_decrypted(DOC)) as run:
        assert sops.get("flint", "master_password") == "mp"
        assert sops.get("flint", "missing") is None
        creds = sops.split_vpn_credentials("work")
    assert creds == {"username": "bob", "password": "pw"}     # CHANGE_ME dropped
    assert run.call_count == 1                                # cached
    assert run.call_args.args[0][:4] == ["/usr/bin/sops", "--decrypt", "--output-type", "json"]


def test_missing_entry_and_file(_fresh):
    with patch.object(subprocess, "run", return_value=_decrypted(DOC)):
        with pytest.raises(sops.SopsError, match="split_vpns.nope"):
            sops.split_vpn_credentials("nope")
    _fresh.unlink()
    sops.clear_cache()
    with pytest.raises(sops.SopsError, match="not found"):
        sops.load()


def test_decrypt_failure():
    bad = MagicMock(returncode=128, stdout=b"", stderr=b"Failed to get the data key")
    with patch.object(subprocess, "run", return_value=bad):
        with pytest.raises(sops.SopsError, match="data key"):
            sops.load()


class TestAutoUnlock:
    def test_unlocks_with_sops_master_password(self):
        import routes.auth as auth
        with patch.object(auth.sm, "is_setup", return_value=True), \
             patch.object(auth._registry, "session_unlocked", False), \
             patch.object(sops, "get", return_value="mp"), \
             patch.object(auth, "perform_unlock") as unlock:
            assert auth.auto_unlock_from_sops() is True
        unlock.assert_called_once_with("mp")

    def test_skips_without_password_or_on_error(self):
        import routes.auth as auth
        with patch.object(auth.sm, "is_setup", return_value=True), \
             patch.object(auth._registry, "session_unlocked", False), \
             patch.object(auth, "perform_unlock") as unlock:
            with patch.object(sops, "get", return_value=None):
                assert auth.auto_unlock_from_sops() is False
            with patch.object(sops, "get", side_effect=sops.SopsError("no file")):
                assert auth.auto_unlock_from_sops() is False
            with patch.object(sops, "get", return_value="wrong"):
                unlock.side_effect = ValueError("Wrong master password")
                assert auth.auto_unlock_from_sops() is False
