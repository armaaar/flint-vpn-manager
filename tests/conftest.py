"""Shared test fixtures for FlintVPN Manager tests."""

import os
import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest


@pytest.fixture
def tmp_data_dir(tmp_path):
    """Provide a temporary directory and patch secrets_manager to use it."""
    import persistence.secrets_manager as secrets_manager

    orig_data_dir = secrets_manager.DATA_DIR
    orig_secrets = secrets_manager.SECRETS_FILE
    orig_config = secrets_manager.CONFIG_FILE

    secrets_manager.DATA_DIR = tmp_path
    secrets_manager.SECRETS_FILE = tmp_path / "secrets.enc"
    secrets_manager.CONFIG_FILE = tmp_path / "config.json"

    yield tmp_path

    secrets_manager.DATA_DIR = orig_data_dir
    secrets_manager.SECRETS_FILE = orig_secrets
    secrets_manager.CONFIG_FILE = orig_config
