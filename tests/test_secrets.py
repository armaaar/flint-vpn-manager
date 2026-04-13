"""Tests for secrets_manager.py — encrypted credential storage."""

import json
import os

import pytest

import persistence.secrets_manager as sm


class TestIsSetup:
    def test_false_when_no_file(self, tmp_data_dir):
        assert sm.is_setup() is False

    def test_true_after_setup(self, tmp_data_dir):
        sm.setup("user", "pass", "rpass", "master")
        assert sm.is_setup() is True


class TestSetup:
    def test_returns_secrets_dict(self, tmp_data_dir):
        result = sm.setup("user", "pass", "rpass", "master")
        assert result == {
            "proton_user": "user",
            "proton_pass": "pass",
            "router_pass": "rpass",
        }

    def test_creates_secrets_file(self, tmp_data_dir):
        sm.setup("user", "pass", "rpass", "master")
        assert sm.SECRETS_FILE.exists()

    def test_creates_config_file(self, tmp_data_dir):
        sm.setup("user", "pass", "rpass", "master")
        assert sm.CONFIG_FILE.exists()

    def test_secrets_file_is_encrypted(self, tmp_data_dir):
        sm.setup("user", "pass", "rpass", "master")
        raw = sm.SECRETS_FILE.read_bytes()
        assert b"user" not in raw
        assert b"pass" not in raw
        assert b"rpass" not in raw

    def test_config_has_default_router_ip(self, tmp_data_dir):
        sm.setup("user", "pass", "rpass", "master")
        config = json.loads(sm.CONFIG_FILE.read_text())
        assert config["router_ip"] == "192.168.8.1"

    def test_config_has_custom_router_ip(self, tmp_data_dir):
        sm.setup("user", "pass", "rpass", "master", router_ip="10.0.0.1")
        config = json.loads(sm.CONFIG_FILE.read_text())
        assert config["router_ip"] == "10.0.0.1"

    def test_salt_is_unique_per_setup(self, tmp_data_dir):
        sm.setup("user", "pass", "rpass", "master")
        salt1 = sm.SECRETS_FILE.read_bytes()[:16]
        sm.setup("user", "pass", "rpass", "master")
        salt2 = sm.SECRETS_FILE.read_bytes()[:16]
        assert salt1 != salt2


class TestUnlock:
    def test_correct_password(self, tmp_data_dir):
        sm.setup("user", "pass", "rpass", "master")
        result = sm.unlock("master")
        assert result == {
            "proton_user": "user",
            "proton_pass": "pass",
            "router_pass": "rpass",
        }

    def test_wrong_password_raises(self, tmp_data_dir):
        sm.setup("user", "pass", "rpass", "master")
        with pytest.raises(ValueError, match="Wrong master password"):
            sm.unlock("wrong")

    def test_no_file_raises(self, tmp_data_dir):
        with pytest.raises(FileNotFoundError):
            sm.unlock("master")

    def test_survives_simulated_restart(self, tmp_data_dir):
        """Secrets persist across 'process restarts' (re-reading from disk)."""
        sm.setup("user", "pass", "rpass", "master")
        # Simulate restart: just unlock fresh from disk
        result = sm.unlock("master")
        assert result["proton_user"] == "user"


class TestUpdate:
    def test_update_single_key(self, tmp_data_dir):
        sm.setup("user", "pass", "rpass", "master")
        result = sm.update("master", proton_user="newuser")
        assert result["proton_user"] == "newuser"
        assert result["proton_pass"] == "pass"  # unchanged

    def test_update_multiple_keys(self, tmp_data_dir):
        sm.setup("user", "pass", "rpass", "master")
        result = sm.update("master", proton_user="u2", proton_pass="p2")
        assert result["proton_user"] == "u2"
        assert result["proton_pass"] == "p2"
        assert result["router_pass"] == "rpass"

    def test_update_persists(self, tmp_data_dir):
        sm.setup("user", "pass", "rpass", "master")
        sm.update("master", proton_user="newuser")
        result = sm.unlock("master")
        assert result["proton_user"] == "newuser"

    def test_invalid_key_raises(self, tmp_data_dir):
        sm.setup("user", "pass", "rpass", "master")
        with pytest.raises(KeyError):
            sm.update("master", bad_key="value")

    def test_wrong_password_raises(self, tmp_data_dir):
        sm.setup("user", "pass", "rpass", "master")
        with pytest.raises(ValueError):
            sm.update("wrong", proton_user="x")

    def test_update_uses_new_salt(self, tmp_data_dir):
        sm.setup("user", "pass", "rpass", "master")
        salt1 = sm.SECRETS_FILE.read_bytes()[:16]
        sm.update("master", proton_user="newuser")
        salt2 = sm.SECRETS_FILE.read_bytes()[:16]
        assert salt1 != salt2


class TestChangeMasterPassword:
    def test_new_password_works(self, tmp_data_dir):
        sm.setup("user", "pass", "rpass", "master")
        sm.change_master_password("master", "newmaster")
        result = sm.unlock("newmaster")
        assert result["proton_user"] == "user"

    def test_old_password_rejected(self, tmp_data_dir):
        sm.setup("user", "pass", "rpass", "master")
        sm.change_master_password("master", "newmaster")
        with pytest.raises(ValueError):
            sm.unlock("master")

    def test_wrong_old_password_raises(self, tmp_data_dir):
        sm.setup("user", "pass", "rpass", "master")
        with pytest.raises(ValueError):
            sm.change_master_password("wrong", "newmaster")


class TestConfig:
    def test_default_config(self, tmp_data_dir):
        config = sm.get_config()
        assert config["router_ip"] == "192.168.8.1"

    def test_update_config(self, tmp_data_dir):
        sm.setup("user", "pass", "rpass", "master")
        sm.update_config(router_ip="10.0.0.1")
        config = sm.get_config()
        assert config["router_ip"] == "10.0.0.1"

    def test_update_config_adds_new_keys(self, tmp_data_dir):
        sm.setup("user", "pass", "rpass", "master")
        sm.update_config(custom_key="custom_value")
        config = sm.get_config()
        assert config["custom_key"] == "custom_value"
        assert config["router_ip"] == "192.168.8.1"  # preserved
