"""Service Registry — Holds runtime service instances.

Replaces the module-level globals in app.py (_proton_api, _router_api,
_service, _session_unlocked) with a single object. Tests can patch
fields on the registry object instead of patching module-level globals.
"""

import os
from typing import Optional

from proton_vpn.api import ProtonAPI
from router.api import RouterAPI
from services.vpn_service import VPNService


DEFAULT_SSH_KEY_PATH = "~/.ssh/id_ed25519"


def _resolve_ssh_key_path(config: dict) -> str:
    """SSH key path resolution: env var → config.json → default."""
    path = os.environ.get("FLINT_SSH_KEY") or config.get("ssh_key_path") or DEFAULT_SSH_KEY_PATH
    return os.path.expanduser(path)


class ServiceRegistry:
    """Holds runtime service instances. One per app lifetime."""

    def __init__(self):
        self.proton: Optional[ProtonAPI] = None
        self.router: Optional[RouterAPI] = None
        self.service: Optional[VPNService] = None
        self.session_unlocked: bool = False
        self._lan_service = None
        self._bypass_service = None

    def get_proton(self) -> ProtonAPI:
        """Lazy-init ProtonAPI."""
        if self.proton is None:
            self.proton = ProtonAPI()
        return self.proton

    def get_router(self) -> RouterAPI:
        """Lazy-init RouterAPI from config."""
        if self.router is None:
            import persistence.secrets_manager as sm
            config = sm.get_config()
            self.router = RouterAPI(
                host=config.get("router_ip", "192.168.8.1"),
                key_filename=_resolve_ssh_key_path(config),
            )
        return self.router

    def get_service(self) -> VPNService:
        """Return the VPNService instance. Raises if not initialized."""
        if self.service is None:
            raise RuntimeError("Service not initialized. Unlock first.")
        return self.service

    def get_lan_service(self):
        """Lazy-init and return the LanAccessService instance."""
        if self._lan_service is None:
            from services.lan_access_service import LanAccessService
            self._lan_service = LanAccessService(self.get_router())
        return self._lan_service

    def get_bypass_service(self):
        """Lazy-init and return the VpnBypassService instance."""
        if self._bypass_service is None:
            from services.vpn_bypass_service import VpnBypassService
            self._bypass_service = VpnBypassService(self.get_router())
        return self._bypass_service

    def reset(self):
        """Called on lock — clears service but keeps router/proton for re-unlock."""
        self.session_unlocked = False
        self.service = None
        self._lan_service = None
        self._bypass_service = None


# Module-level singleton (one per process).
registry = ServiceRegistry()
