"""Shared fixtures for Flask route tests.

Creates a Flask test client with mocked service registry so routes can
be tested without SSH, ProtonVPN, or router access.
"""

from unittest.mock import MagicMock, patch

import pytest

from flask import Flask


def _create_test_app():
    """Build a minimal Flask app with all route blueprints registered."""
    app = Flask(__name__)
    app.config["TESTING"] = True

    from routes.auth import auth_bp
    from routes.profiles import profiles_bp
    from routes.devices import devices_bp
    from routes.lan_access import lan_bp
    from routes.settings import settings_bp
    from routes.logs import logs_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(profiles_bp)
    app.register_blueprint(devices_bp)
    app.register_blueprint(lan_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(logs_bp)

    return app


@pytest.fixture
def mock_registry():
    """A MagicMock service registry with session_unlocked=True."""
    reg = MagicMock()
    reg.session_unlocked = True
    reg.service = MagicMock()
    reg.proton = MagicMock()
    reg.router = MagicMock()
    reg.get_service.return_value = reg.service
    reg.get_proton.return_value = reg.proton
    reg.get_router.return_value = reg.router
    reg.get_lan_service.return_value = MagicMock()
    return reg


@pytest.fixture
def client(mock_registry):
    """Flask test client with mocked registry for all routes."""
    app = _create_test_app()

    with patch("routes._helpers._registry", mock_registry), \
         patch("routes.auth._registry", mock_registry), \
         patch("routes.settings._registry", mock_registry), \
         patch("routes.lan_access._registry", mock_registry):
        with app.test_client() as c:
            yield c


@pytest.fixture
def locked_client(mock_registry):
    """Flask test client with session locked."""
    mock_registry.session_unlocked = False
    app = _create_test_app()

    with patch("routes._helpers._registry", mock_registry), \
         patch("routes.auth._registry", mock_registry), \
         patch("routes.settings._registry", mock_registry), \
         patch("routes.lan_access._registry", mock_registry):
        with app.test_client() as c:
            yield c
