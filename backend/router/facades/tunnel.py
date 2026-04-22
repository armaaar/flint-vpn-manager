"""Router tunnel facade — tunnel lifecycle and health.

Delegates to tool-layer objects (Uci, ServiceCtl) via explicit tool
injection.
"""

from typing import Optional

from consts import (
    HEALTH_AMBER,
    HEALTH_CONNECTING,
    HEALTH_GREEN,
    HEALTH_RED,
)


class RouterTunnel:
    """Facade for VPN tunnel control on the GL.iNet Flint 2."""

    def __init__(self, uci, service_ctl, ssh, ipv6_mangle_rebuild=None):
        self._uci = uci
        self._service_ctl = service_ctl
        self._ssh = ssh  # raw exec for ifstatus, wg show, etc.
        self._ipv6_mangle_rebuild = ipv6_mangle_rebuild

    # ── Tunnel Control ───────────────────────────────────────────────────

    def bring_tunnel_up(self, rule_name: str, **_kwargs):
        """Bring a VPN tunnel up by enabling its route policy rule.

        The vpn-client service will create the network interface and
        start the WireGuard tunnel automatically.
        """
        rule_exists = self._uci.get(
            f"route_policy.{rule_name}.tunnel_id", "MISSING"
        ).strip()
        if rule_exists == "MISSING":
            raise RuntimeError(f"Route policy rule {rule_name} does not exist.")

        self._uci.set(f"route_policy.{rule_name}.enabled", "1")
        self._uci.commit("route_policy")

        self._service_ctl.restart("vpn-client")

        # Rebuild IPv6 mangle rules after vpn-client restart.
        # vpn-client only sets up IPv4 mangle/routing — Flint VPN Manager manages IPv6.
        if self._ipv6_mangle_rebuild:
            try:
                self._ipv6_mangle_rebuild()
            except Exception:
                pass

    def bring_tunnel_down(self, rule_name: str, **_kwargs):
        """Bring a VPN tunnel down by disabling its route policy rule.

        Disables kill switch before disabling the rule to prevent devices
        from losing internet when the tunnel goes down.
        """
        self._uci.multi([
            f"uci set route_policy.{rule_name}.killswitch='0'",
            f"uci set route_policy.{rule_name}.enabled='0'",
            "uci commit route_policy",
        ])

        self._service_ctl.restart("vpn-client")

        # Rebuild IPv6 mangle rules after vpn-client restart
        if self._ipv6_mangle_rebuild:
            try:
                self._ipv6_mangle_rebuild()
            except Exception:
                pass

        self._uci.multi([
            f"uci set route_policy.{rule_name}.killswitch='1'",
            "uci commit route_policy",
        ])

    def get_rule_interface(self, rule_name: str) -> Optional[str]:
        """Get the network interface name assigned to a rule by vpn-client.

        Returns the interface name (e.g. 'wgclient1') or None if not assigned.
        """
        via = self._uci.get(f"route_policy.{rule_name}.via").strip()
        return via if via and (via.startswith("wgclient") or via.startswith("ovpnclient")) else None

    def get_tunnel_status(self, rule_name: str) -> dict:
        """Get tunnel status by rule name.

        Returns dict with: up, connecting, interface, handshake_seconds_ago, rx_bytes, tx_bytes
        """
        result = {"up": False, "connecting": False, "interface": None, "handshake_seconds_ago": None, "rx_bytes": 0, "tx_bytes": 0}

        enabled = self._uci.get(
            f"route_policy.{rule_name}.enabled", "0"
        ).strip()
        if enabled != "1":
            return result

        iface = self.get_rule_interface(rule_name)
        if not iface:
            result["connecting"] = True
            return result

        result["interface"] = iface

        up_check = self._ssh.exec(
            f"ifstatus {iface} 2>/dev/null | "
            "jsonfilter -e '@.up' 2>/dev/null || echo 'false'"
        )
        result["up"] = up_check.strip().lower() == "true"

        if not result["up"]:
            if iface.startswith("wgclient"):
                state = self._ssh.exec(f"cat /tmp/wireguard/{iface}_state 2>/dev/null || echo ''").strip()
                if state == "connecting":
                    result["connecting"] = True
            elif iface.startswith("ovpnclient"):
                proc = self._ssh.exec(f"ps | grep 'openvpn.*{iface}' | grep -v grep | head -1").strip()
                if proc:
                    result["connecting"] = True
            return result

        if iface.startswith("wgclient"):
            from router.tools.wg_show import parse_handshake_age, parse_transfer
            result["handshake_seconds_ago"] = parse_handshake_age(self._ssh, iface)
            result["rx_bytes"], result["tx_bytes"] = parse_transfer(self._ssh, iface)
        elif iface.startswith("ovpnclient"):
            result["handshake_seconds_ago"] = 0

        return result

    def get_tunnel_health(self, rule_name: str) -> str:
        """Get tunnel health as a color/status: green, amber, red, connecting.

        green: handshake within 3 minutes (or OVPN interface up)
        amber: handshake 3-10 minutes ago
        red: no handshake in 10+ minutes or tunnel down
        connecting: tunnel is being established
        """
        status = self.get_tunnel_status(rule_name)
        if status.get("connecting"):
            return HEALTH_CONNECTING
        if not status["up"]:
            return HEALTH_RED
        if status["handshake_seconds_ago"] is None:
            return HEALTH_RED
        if status["handshake_seconds_ago"] <= 180:
            return HEALTH_GREEN
        if status["handshake_seconds_ago"] <= 600:
            return HEALTH_AMBER
        return HEALTH_RED
