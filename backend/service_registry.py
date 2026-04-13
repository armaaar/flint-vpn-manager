"""Service Registry — Holds runtime service instances.

Replaces the module-level globals in app.py (_proton_api, _router_api,
_service, _session_unlocked) with a single object. Tests can patch
fields on the registry object instead of patching module-level globals.
"""

from typing import Optional

from proton_api import ProtonAPI
from router_api import RouterAPI
from vpn_service import VPNService


SSH_KEY_PATH = "/home/armaaar/.ssh/id_ed25519"


class ServiceRegistry:
    """Holds runtime service instances. One per app lifetime."""

    def __init__(self):
        self.proton: Optional[ProtonAPI] = None
        self.router: Optional[RouterAPI] = None
        self.service: Optional[VPNService] = None
        self.session_unlocked: bool = False

    def get_proton(self) -> ProtonAPI:
        """Lazy-init ProtonAPI."""
        if self.proton is None:
            self.proton = ProtonAPI()
        return self.proton

    def get_router(self) -> RouterAPI:
        """Lazy-init RouterAPI from config."""
        if self.router is None:
            import secrets_manager as sm
            config = sm.get_config()
            self.router = RouterAPI(
                host=config.get("router_ip", "192.168.8.1"),
                key_filename=SSH_KEY_PATH,
            )
        return self.router

    def get_service(self) -> VPNService:
        """Return the VPNService instance. Raises if not initialized."""
        if self.service is None:
            raise RuntimeError("Service not initialized. Unlock first.")
        return self.service

    def reset(self):
        """Called on lock — clears service but keeps router/proton for re-unlock."""
        self.session_unlocked = False
        self.service = None


# Module-level singleton (one per process).
registry = ServiceRegistry()
