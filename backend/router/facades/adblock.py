"""Router adblock facade — second dnsmasq instance + ipset + iptables REDIRECT.

Manages a blocking dnsmasq on port 5354 with community blocklists.
Devices in adblock-enabled groups have their DNS redirected via iptables
from port 53 to 5354. The blocking dnsmasq forwards non-blocked queries
to the main dnsmasq on 127.0.0.1:53.

Safety invariant: iptables REDIRECT rules are ONLY active when BOTH:
  1. The blocking dnsmasq is confirmed listening on the port
  2. The blocklist file is non-empty
If either condition fails, REDIRECT rules are removed to prevent DNS
blackholing (which kills internet for affected devices).

Tool-layer objects (Uci, Ipset, Iptables, ServiceCtl) are injected directly.
The raw ``ssh`` handle is kept only for netstat, grep, chmod, kill, and
write_file calls.
"""

import logging

from consts import (
    ADBLOCK_CHAIN,
    ADBLOCK_CONF_PATH,
    ADBLOCK_HOSTS_PATH,
    ADBLOCK_INIT_SCRIPT,
    ADBLOCK_IPSET,
    ADBLOCK_MACS_FILE,
    ADBLOCK_PORT,
    ADBLOCK_RULES_SCRIPT,
)

log = logging.getLogger("flintvpn")


DNSMASQ_ADBLOCK_CONF = """\
# FlintVPN — blocking dnsmasq for DNS ad filtering
port={port}
listen-address={listen}
bind-interfaces
no-resolv
no-hosts
addn-hosts={hosts}
server={listen}#53
cache-size=1000
user=root
log-facility=/dev/null
"""

INIT_SCRIPT = f"""\
#!/bin/sh /etc/rc.common
START=99
STOP=10
USE_PROCD=1

start_service() {{
    # Only start if blocklist has content — empty blocklist = no point running
    [ -s "{ADBLOCK_HOSTS_PATH}" ] || return
    [ -f "{ADBLOCK_CONF_PATH}" ] || return
    procd_open_instance "dnsmasq-adblock"
    procd_set_param command /usr/sbin/dnsmasq -C "{ADBLOCK_CONF_PATH}" -k
    procd_set_param stdout 0
    procd_set_param stderr 0
    procd_set_param respawn
    procd_close_instance
}}
"""


class RouterAdblock:
    """Facade for DNS ad-blocking infrastructure on the GL.iNet Flint 2."""

    def __init__(self, uci, ipset, iptables, service_ctl, ssh):
        self._uci = uci
        self._ipset = ipset
        self._iptables = iptables
        self._service_ctl = service_ctl
        self._ssh = ssh  # raw exec for netstat, grep, chmod, kill; write_file for configs

    # ── Health checks ──────────────────────────────────────────────────

    def _blocklist_has_content(self) -> bool:
        """Check if the blocklist file exists and has entries."""
        result = self._ssh.exec(
            f"[ -s {ADBLOCK_HOSTS_PATH} ] && "
            f"grep -c '^0\\.0\\.0\\.0 ' {ADBLOCK_HOSTS_PATH} 2>/dev/null || echo 0"
        ).strip()
        try:
            return int(result) > 0
        except ValueError:
            return False

    def _dnsmasq_is_healthy(self) -> bool:
        """Check if the blocking dnsmasq is listening on the correct port."""
        result = self._ssh.exec(
            f"netstat -tlnup 2>/dev/null | grep ':{ADBLOCK_PORT} .*dnsmasq' || true"
        ).strip()
        return bool(result)

    def _redirect_is_safe(self) -> bool:
        """Return True only if it's safe to redirect DNS to the blocking dnsmasq."""
        return self._dnsmasq_is_healthy() and self._blocklist_has_content()

    # ── Blocking dnsmasq lifecycle ──────────────────────────────────────

    def ensure_adblock_dnsmasq(self) -> bool:
        """Ensure the blocking dnsmasq instance is running with a valid blocklist.

        Always writes config and init script. Only starts the process if
        the blocklist has content. Returns True if dnsmasq is healthy and
        ready to receive redirected DNS.
        """
        router_ip = self._uci.get(
            "network.lan.ipaddr", "192.168.8.1"
        ).strip() or "192.168.8.1"
        conf = DNSMASQ_ADBLOCK_CONF.format(
            port=ADBLOCK_PORT, listen=router_ip, hosts=ADBLOCK_HOSTS_PATH,
        )
        self._ssh.write_file(ADBLOCK_CONF_PATH, conf)
        self._ssh.write_file(ADBLOCK_INIT_SCRIPT, INIT_SCRIPT)
        self._ssh.exec(f"chmod +x {ADBLOCK_INIT_SCRIPT}")
        self._service_ctl.enable("fvpn-adblock")

        if not self._blocklist_has_content():
            log.warning("Blocklist empty — not starting blocking dnsmasq")
            self.stop_adblock_dnsmasq()
            return False

        if self._dnsmasq_is_healthy():
            return True

        log.info("Starting blocking dnsmasq on port %d", ADBLOCK_PORT)

        self._service_ctl.stop("fvpn-adblock")
        self._service_ctl.start("fvpn-adblock")

        import time
        for _ in range(3):
            time.sleep(1)
            if self._dnsmasq_is_healthy():
                log.info("Blocking dnsmasq healthy on port %d", ADBLOCK_PORT)
                return True

        log.warning("Blocking dnsmasq failed to start on port %d", ADBLOCK_PORT)
        return False

    def stop_adblock_dnsmasq(self) -> None:
        """Stop the blocking dnsmasq. Idempotent."""
        self._service_ctl.stop("fvpn-adblock")
        self._service_ctl.disable("fvpn-adblock")

    # ── Ipset + iptables rules ──────────────────────────────────────────

    def sync_adblock_rules(self, macs: set) -> None:
        """Rebuild the adblock ipset and iptables REDIRECT rules.

        Safety: only adds REDIRECT rules if the blocking dnsmasq is
        confirmed healthy and the blocklist has content. Otherwise
        removes all REDIRECT rules to prevent DNS blackholing.
        """
        if not macs:
            self.cleanup_adblock()
            return

        dnsmasq_ready = self.ensure_adblock_dnsmasq()

        mac_content = "\n".join(sorted(macs)) + "\n"
        self._ssh.write_file(ADBLOCK_MACS_FILE, mac_content)

        # Create and populate ipset
        self._ipset.create(ADBLOCK_IPSET, "hash:mac")
        self._ipset.flush(ADBLOCK_IPSET)
        for mac in sorted(macs):
            self._ipset.add(ADBLOCK_IPSET, mac)

        if dnsmasq_ready:
            self._apply_redirect_rules()
            self._write_firewall_include(with_redirect=True)
            log.info("Adblock rules synced: %d MACs, redirect ACTIVE", len(macs))
        else:
            self._remove_redirect_rules()
            self._write_firewall_include(with_redirect=False)
            log.warning(
                "Adblock rules synced: %d MACs in ipset, redirect DISABLED "
                "(blocklist empty or dnsmasq not ready)", len(macs)
            )

    def _apply_redirect_rules(self) -> None:
        """Create the iptables REDIRECT chain and wire it into policy_redirect."""
        chain = ADBLOCK_CHAIN
        ipt = self._iptables
        ipt.ensure_chain("nat", chain)
        ipt.flush_chain("nat", chain)
        ipt.append(
            "nat", chain,
            f"-m set --match-set {ADBLOCK_IPSET} src",
            f"-p udp --dport 53 -j REDIRECT --to-ports {ADBLOCK_PORT}",
        )
        ipt.append(
            "nat", chain,
            f"-m set --match-set {ADBLOCK_IPSET} src",
            f"-p tcp --dport 53 -j REDIRECT --to-ports {ADBLOCK_PORT}",
        )
        ipt.insert_if_absent("nat", "policy_redirect", f"-j {chain}")

    def _remove_redirect_rules(self) -> None:
        """Remove REDIRECT rules from iptables. Idempotent."""
        self._iptables.delete_chain("nat", "policy_redirect", ADBLOCK_CHAIN)

    def _build_rule_commands(self) -> list:
        """Build iptables commands for the firewall include script."""
        chain = ADBLOCK_CHAIN
        return [
            f"iptables -t nat -N {chain} 2>/dev/null || true",
            f"iptables -t nat -F {chain}",
            f"iptables -t nat -A {chain} "
            f"-m set --match-set {ADBLOCK_IPSET} src "
            f"-p udp --dport 53 -j REDIRECT --to-ports {ADBLOCK_PORT}",
            f"iptables -t nat -A {chain} "
            f"-m set --match-set {ADBLOCK_IPSET} src "
            f"-p tcp --dport 53 -j REDIRECT --to-ports {ADBLOCK_PORT}",
            f"iptables -t nat -C policy_redirect -j {chain} 2>/dev/null || "
            f"iptables -t nat -I policy_redirect 1 -j {chain}",
        ]

    def _write_firewall_include(self, with_redirect: bool) -> None:
        """Write the firewall include script for reboot persistence."""
        script = (
            "#!/bin/sh\n"
            "# Auto-generated by FlintVPN — DNS ad-block rules\n"
            "# Re-applied on every firewall reload\n\n"
            f"ipset create {ADBLOCK_IPSET} hash:mac -exist\n"
            f"ipset flush {ADBLOCK_IPSET}\n"
            f"if [ -f {ADBLOCK_MACS_FILE} ]; then\n"
            f"  while read mac; do\n"
            f'    [ -n "$mac" ] && ipset add {ADBLOCK_IPSET} "$mac" -exist 2>/dev/null\n'
            f"  done < {ADBLOCK_MACS_FILE}\n"
            f"fi\n\n"
        )
        if with_redirect:
            script += (
                f"# Only redirect if blocklist has content and dnsmasq is running\n"
                f"if [ -s {ADBLOCK_HOSTS_PATH} ] && "
                f"netstat -tlnup 2>/dev/null | grep -q ':{ADBLOCK_PORT} '; then\n"
            )
            for cmd in self._build_rule_commands():
                script += f"  {cmd}\n"
            script += "fi\n"

        self._ssh.write_file(ADBLOCK_RULES_SCRIPT, script)
        self._ssh.exec(f"chmod +x {ADBLOCK_RULES_SCRIPT}")

        # Register as firewall include (idempotent)
        self._uci.ensure_firewall_include("fvpn_adblock", ADBLOCK_RULES_SCRIPT)

    # ── Blocklist upload ────────────────────────────────────────────────

    def upload_blocklist(self, content: str) -> None:
        """Write blocklist to router and reload the blocking dnsmasq."""
        self._ssh.write_file(ADBLOCK_HOSTS_PATH, content)
        log.info("Blocklist uploaded (%d bytes)", len(content))

        if self._dnsmasq_is_healthy():
            self._ssh.exec(
                f"kill -HUP $(pgrep -f 'dnsmasq.*dnsmasq-adblock') 2>/dev/null || true"
            )
        else:
            self.ensure_adblock_dnsmasq()

    # ── Full teardown ───────────────────────────────────────────────────

    def cleanup_adblock(self) -> None:
        """Remove all adblock infrastructure from the router. Idempotent."""
        self._remove_redirect_rules()
        self._ipset.destroy(ADBLOCK_IPSET)
        self.stop_adblock_dnsmasq()
        self._uci.delete("firewall.fvpn_adblock")
        self._uci.commit("firewall")
        self._ssh.exec(
            f"rm -f {ADBLOCK_RULES_SCRIPT} {ADBLOCK_MACS_FILE} "
            f"{ADBLOCK_CONF_PATH} {ADBLOCK_INIT_SCRIPT}; true"
        )
        log.info("Adblock infrastructure cleaned up")
