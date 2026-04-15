"""Shared test fixtures for FlintVPN Manager tests."""

import logging
import os
import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest


def _strip_file_handlers(logger):
    """Remove all FileHandlers from a logger, return the removed handlers."""
    removed = []
    for h in list(logger.handlers):
        if isinstance(h, logging.FileHandler):
            logger.removeHandler(h)
            removed.append(h)
    return removed


@pytest.fixture(autouse=True)
def _no_production_logging():
    """Prevent tests from writing to production log files.

    Strips FileHandlers from all flintvpn loggers before each test and
    restores them after.  This catches handlers added by late imports
    (e.g., ``import app`` inside a fixture) that a session-scoped
    fixture would miss.
    """
    loggers = [logging.getLogger(name) for name in
               ("flintvpn", "flintvpn.profile_store", "werkzeug")]

    saved = {lg.name: _strip_file_handlers(lg) for lg in loggers}
    for lg in loggers:
        if not lg.handlers:
            lg.addHandler(logging.NullHandler())

    yield

    # Restore — strip again first (in case test added handlers), then
    # re-add the originals so the next test's strip finds them.
    for lg in loggers:
        for h in list(lg.handlers):
            if isinstance(h, logging.NullHandler):
                lg.removeHandler(h)
    for lg in loggers:
        for h in saved[lg.name]:
            if h not in lg.handlers:
                lg.addHandler(h)


@pytest.fixture(autouse=True)
def _clear_profile_store_callback():
    """Clear the profile_store save callback after every test.

    The callback is a module-level global that leaks between tests,
    causing 'MagicMock is not JSON serializable' warnings when a
    stale mock router is used by a subsequent test's ps.save() call.
    """
    yield
    import persistence.profile_store as ps
    ps.register_save_callback(None)


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
