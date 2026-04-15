"""VPN Bypass Service — business logic for VPN exception rules.

Manages CRUD for bypass exceptions and custom presets, persists to
``config.json``, and delegates router-side application to the
``RouterVpnBypass`` facade.

Each exception contains **rule blocks**.  Rules within a block are ANDed
(one iptables rule).  Blocks within an exception are ORed (separate rules).
"""

from __future__ import annotations

import logging
import uuid
from typing import TYPE_CHECKING

import persistence.secrets_manager as sm
from consts import VPN_BYPASS_PRESETS

if TYPE_CHECKING:
    from router.api import RouterAPI

log = logging.getLogger(__name__)


class VpnBypassService:
    """Orchestrates VPN bypass exception CRUD and router application."""

    def __init__(self, router: RouterAPI):
        self.router = router

    # ── Read ───────────────────────────────────────────────────────────

    def get_overview(self) -> dict:
        """Return all exceptions, presets, and dnsmasq status."""
        config = sm.get_config()
        vb = config.get("vpn_bypass", {})
        dnsmasq_full = vb.get("dnsmasq_full_installed", False)

        if not dnsmasq_full:
            try:
                dnsmasq_full = self.router.vpn_bypass.check_dnsmasq_full()
                if dnsmasq_full:
                    vb["dnsmasq_full_installed"] = True
                    sm.update_config(vpn_bypass=vb)
            except Exception:
                pass

        presets = {}
        for pid, p in VPN_BYPASS_PRESETS.items():
            presets[pid] = {**p, "id": pid, "builtin": True}
        for pid, p in vb.get("custom_presets", {}).items():
            presets[pid] = {**p, "id": pid, "builtin": False}

        return {
            "exceptions": vb.get("exceptions", []),
            "presets": presets,
            "dnsmasq_full_installed": dnsmasq_full,
        }

    # ── Exception CRUD ─────────────────────────────────────────────────

    def add_exception(self, data: dict) -> dict:
        """Create a bypass exception, persist, and apply to router."""
        rule_blocks = data.get("rule_blocks", [])

        # If preset_id given, copy rule_blocks from preset
        preset_id = data.get("preset_id")
        if preset_id and not rule_blocks:
            preset = self._resolve_preset(preset_id)
            if preset:
                rule_blocks = [
                    {"label": b.get("label", ""), "rules": list(b.get("rules", []))}
                    for b in preset.get("rule_blocks", [])
                ]

        if not rule_blocks or not any(b.get("rules") for b in rule_blocks):
            raise ValueError("At least one rule block with rules is required")

        exc = {
            "id": f"byp_{uuid.uuid4().hex[:8]}",
            "name": data.get("name", "Untitled"),
            "preset_id": preset_id,
            "enabled": data.get("enabled", True),
            "scope": data.get("scope", "global"),
            "scope_target": data.get("scope_target"),
            "rule_blocks": rule_blocks,
        }

        self._validate_scope(exc)

        config = sm.get_config()
        vb = config.setdefault("vpn_bypass", {})
        exceptions = vb.setdefault("exceptions", [])
        exceptions.append(exc)
        sm.update_config(vpn_bypass=vb)

        self._apply(vb.get("exceptions", []))
        return {"success": True, "exception": exc}

    def update_exception(self, exc_id: str, data: dict) -> dict:
        """Update fields of an existing exception."""
        config = sm.get_config()
        vb = config.get("vpn_bypass", {})
        exceptions = vb.get("exceptions", [])

        exc = self._find_exception(exceptions, exc_id)
        if not exc:
            raise ValueError(f"Exception {exc_id} not found")

        for key in ("name", "enabled", "scope", "scope_target", "rule_blocks"):
            if key in data:
                exc[key] = data[key]

        self._validate_scope(exc)

        sm.update_config(vpn_bypass=vb)
        self._apply(exceptions)
        return {"success": True, "exception": exc}

    def remove_exception(self, exc_id: str) -> dict:
        """Delete a bypass exception."""
        config = sm.get_config()
        vb = config.get("vpn_bypass", {})
        exceptions = vb.get("exceptions", [])
        vb["exceptions"] = [e for e in exceptions if e.get("id") != exc_id]
        sm.update_config(vpn_bypass=vb)

        self._apply(vb["exceptions"])
        return {"success": True}

    def toggle_exception(self, exc_id: str, enabled: bool) -> dict:
        """Enable or disable a bypass exception."""
        return self.update_exception(exc_id, {"enabled": enabled})

    # ── Preset CRUD ────────────────────────────────────────────────────

    def save_custom_preset(self, data: dict) -> dict:
        """Create or update a custom preset."""
        preset_id = data.get("id")
        if not preset_id:
            preset_id = f"custom_{uuid.uuid4().hex[:8]}"

        if preset_id in VPN_BYPASS_PRESETS:
            raise ValueError("Cannot overwrite a built-in preset")

        preset = {
            "name": data.get("name", "Custom Preset"),
            "rule_blocks": data.get("rule_blocks", []),
        }

        config = sm.get_config()
        vb = config.setdefault("vpn_bypass", {})
        custom = vb.setdefault("custom_presets", {})
        custom[preset_id] = preset
        sm.update_config(vpn_bypass=vb)

        return {"success": True, "preset_id": preset_id, "preset": preset}

    def delete_custom_preset(self, preset_id: str) -> dict:
        """Delete a custom preset."""
        if preset_id in VPN_BYPASS_PRESETS:
            raise ValueError("Cannot delete a built-in preset")

        config = sm.get_config()
        vb = config.get("vpn_bypass", {})
        custom = vb.get("custom_presets", {})
        custom.pop(preset_id, None)
        sm.update_config(vpn_bypass=vb)
        return {"success": True}

    # ── dnsmasq ────────────────────────────────────────────────────────

    def check_dnsmasq_full(self) -> dict:
        """Check dnsmasq-full installation status."""
        installed = self.router.vpn_bypass.check_dnsmasq_full()
        return {"installed": installed}

    def install_dnsmasq_full(self) -> dict:
        """Install dnsmasq-full on the router."""
        result = self.router.vpn_bypass.install_dnsmasq_full()

        config = sm.get_config()
        vb = config.setdefault("vpn_bypass", {})
        vb["dnsmasq_full_installed"] = True
        sm.update_config(vpn_bypass=vb)

        return {"success": True, "output": result}

    # ── Integration hooks ──────────────────────────────────────────────

    def reapply_all(self) -> None:
        """Reapply all bypass rules to router. Called on unlock."""
        config = sm.get_config()
        vb = config.get("vpn_bypass", {})
        self._apply(vb.get("exceptions", []))

    def on_group_deleted(self, profile_id: str) -> None:
        """Handle VPN group deletion — disable affected exceptions."""
        config = sm.get_config()
        vb = config.get("vpn_bypass", {})
        exceptions = vb.get("exceptions", [])

        changed = False
        for exc in exceptions:
            if exc.get("scope") == "group" and exc.get("scope_target") == profile_id:
                exc["enabled"] = False
                changed = True
                log.warning(
                    "Disabled bypass exception '%s' — group %s was deleted",
                    exc.get("name"), profile_id,
                )

        if changed:
            sm.update_config(vpn_bypass=vb)
            self._apply(exceptions)

    # ── Internal ───────────────────────────────────────────────────────

    def _apply(self, exceptions: list[dict]) -> None:
        """Build group ipset map and delegate to router facade."""
        group_map = self._build_group_ipset_map()
        self.router.vpn_bypass.apply_all(exceptions, group_map)

    def _build_group_ipset_map(self) -> dict[str, str]:
        """Map profile_id → MAC ipset name for group-scoped exceptions."""
        import persistence.profile_store as ps

        result: dict[str, str] = {}
        store = ps.load()
        profiles = store.get("profiles", [])

        for p in profiles:
            if p.get("type") != "vpn":
                continue
            pid = p.get("id", "")
            ri = p.get("router_info", {})
            vpn_proto = ri.get("vpn_protocol", "")
            rule_name = ri.get("rule_name", "")

            if vpn_proto in ("wireguard-tcp", "wireguard-tls"):
                tunnel_id = ri.get("tunnel_id")
                if tunnel_id:
                    result[pid] = f"pwg_mac_{tunnel_id}"
            elif rule_name:
                try:
                    tid = self.router.exec(
                        f"uci -q get route_policy.{rule_name}.tunnel_id 2>/dev/null || true"
                    ).strip()
                    if tid:
                        result[pid] = f"src_mac_{tid}"
                except Exception:
                    pass

        return result

    def _resolve_preset(self, preset_id: str) -> dict | None:
        """Look up a preset by ID (built-in or custom)."""
        if preset_id in VPN_BYPASS_PRESETS:
            return VPN_BYPASS_PRESETS[preset_id]
        config = sm.get_config()
        vb = config.get("vpn_bypass", {})
        return vb.get("custom_presets", {}).get(preset_id)

    @staticmethod
    def _find_exception(exceptions: list[dict], exc_id: str) -> dict | None:
        for e in exceptions:
            if e.get("id") == exc_id:
                return e
        return None

    @staticmethod
    def _validate_scope(exc: dict) -> None:
        scope = exc.get("scope", "global")
        target = exc.get("scope_target")
        if scope == "global":
            exc["scope_target"] = None
        elif scope == "group":
            if not target:
                raise ValueError("scope_target (profile_id) required for group scope")
        elif scope == "device":
            if not target:
                raise ValueError("scope_target (MAC address) required for device scope")
        else:
            raise ValueError(f"Invalid scope: {scope}")
