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

Delegates SSH execution to the RouterAPI instance passed as ``ssh``.
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

    def __init__(self, ssh):
        self._ssh = ssh

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
        """Return True only if it's safe to redirect DNS to the blocking dnsmasq.

        Both conditions must hold:
          1. Blocking dnsmasq is listening
          2. Blocklist file has content
        """
        return self._dnsmasq_is_healthy() and self._blocklist_has_content()

    # ── Blocking dnsmasq lifecycle ──────────────────────────────────────

    def ensure_adblock_dnsmasq(self) -> bool:
        """Ensure the blocking dnsmasq instance is running with a valid blocklist.

        Always writes config and init script. Only starts the process if
        the blocklist has content. Returns True if dnsmasq is healthy and
        ready to receive redirected DNS.
        """
        # Always write config + init script (idempotent, ensures correct port)
        # Get router LAN IP for listen-address and upstream
        router_ip = self._ssh.exec(
            "uci get network.lan.ipaddr 2>/dev/null || echo 192.168.8.1"
        ).strip() or "192.168.8.1"
        conf = DNSMASQ_ADBLOCK_CONF.format(
            port=ADBLOCK_PORT, listen=router_ip, hosts=ADBLOCK_HOSTS_PATH,
        )
        self._ssh.write_file(ADBLOCK_CONF_PATH, conf)
        self._ssh.write_file(ADBLOCK_INIT_SCRIPT, INIT_SCRIPT)
        self._ssh.exec(
            f"chmod +x {ADBLOCK_INIT_SCRIPT} && "
            f"{ADBLOCK_INIT_SCRIPT} enable 2>/dev/null; true"
        )

        # Don't start if blocklist is empty — no point, and avoid risk
        if not self._blocklist_has_content():
            log.warning("Blocklist empty — not starting blocking dnsmasq")
            self.stop_adblock_dnsmasq()
            return False

        # Ensure empty file exists for touch safety
        # (blocklist already has content if we got here)

        # Check if already listening on the correct port
        if self._dnsmasq_is_healthy():
            return True

        log.info("Starting blocking dnsmasq on port %d", ADBLOCK_PORT)

        # Stop any stale instance, then start fresh
        self._ssh.exec(f"{ADBLOCK_INIT_SCRIPT} stop 2>/dev/null; true")
        self._ssh.exec(f"{ADBLOCK_INIT_SCRIPT} start 2>/dev/null; true")

        # Wait briefly for startup (large blocklists take a moment)
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
        self._ssh.exec(
            f"{ADBLOCK_INIT_SCRIPT} stop 2>/dev/null; "
            f"{ADBLOCK_INIT_SCRIPT} disable 2>/dev/null; true"
        )

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

        # 1. Ensure dnsmasq is running (returns False if blocklist empty)
        dnsmasq_ready = self.ensure_adblock_dnsmasq()

        # 2. Write MAC list (for reboot recovery)
        mac_content = "\n".join(sorted(macs)) + "\n"
        self._ssh.write_file(ADBLOCK_MACS_FILE, mac_content)

        # 3. Create and populate ipset (always — needed for firewall include)
        ipset_cmds = [f"ipset create {ADBLOCK_IPSET} hash:mac -exist"]
        ipset_cmds.append(f"ipset flush {ADBLOCK_IPSET}")
        for mac in sorted(macs):
            ipset_cmds.append(
                f"ipset add {ADBLOCK_IPSET} {mac} -exist 2>/dev/null || true"
            )
        self._ssh.exec(" ; ".join(ipset_cmds))

        if dnsmasq_ready:
            # 4a. Safe to redirect — add iptables rules
            cmds = self._build_rule_commands()
            self._ssh.exec("; ".join(cmds))
            self._write_firewall_include(with_redirect=True)
            log.info("Adblock rules synced: %d MACs, redirect ACTIVE", len(macs))
        else:
            # 4b. NOT safe to redirect — remove rules to prevent blackholing
            self._remove_redirect_rules()
            self._write_firewall_include(with_redirect=False)
            log.warning(
                "Adblock rules synced: %d MACs in ipset, redirect DISABLED "
                "(blocklist empty or dnsmasq not ready)", len(macs)
            )

    def _build_rule_commands(self) -> list:
        """Build iptables commands for the adblock REDIRECT chain."""
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

    def _remove_redirect_rules(self) -> None:
        """Remove REDIRECT rules from iptables. Idempotent."""
        chain = ADBLOCK_CHAIN
        self._ssh.exec(
            f"iptables -t nat -D policy_redirect -j {chain} 2>/dev/null; "
            f"iptables -t nat -F {chain} 2>/dev/null; "
            f"iptables -t nat -X {chain} 2>/dev/null; true"
        )

    def _write_firewall_include(self, with_redirect: bool) -> None:
        """Write the firewall include script for reboot persistence.

        The script always recreates the ipset from the MAC file.
        REDIRECT rules are only included if ``with_redirect`` is True
        AND the blocklist file has content (checked at script runtime).
        """
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
            # Runtime safety check: only add REDIRECT if blocklist has content
            # AND dnsmasq is actually listening
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
        self._ssh.exec(
            f"uci -q get firewall.fvpn_adblock >/dev/null 2>&1 || ("
            f"uci set firewall.fvpn_adblock=include && "
            f"uci set firewall.fvpn_adblock.type='script' && "
            f"uci set firewall.fvpn_adblock.path='{ADBLOCK_RULES_SCRIPT}' && "
            f"uci set firewall.fvpn_adblock.reload='1' && "
            f"uci commit firewall)"
        )

    # ── Blocklist upload ────────────────────────────────────────────────

    def upload_blocklist(self, content: str) -> None:
        """Write blocklist to router and reload the blocking dnsmasq.

        After uploading, SIGHUP the dnsmasq to re-read the hosts file.
        If dnsmasq isn't running, start it (now that we have content).
        """
        self._ssh.write_file(ADBLOCK_HOSTS_PATH, content)
        log.info("Blocklist uploaded (%d bytes)", len(content))

        if self._dnsmasq_is_healthy():
            # SIGHUP tells dnsmasq to re-read hosts files
            self._ssh.exec(
                f"kill -HUP $(pgrep -f 'dnsmasq.*dnsmasq-adblock') 2>/dev/null || true"
            )
        else:
            # dnsmasq wasn't running (maybe blocklist was empty before)
            # Now we have content, so start it
            self.ensure_adblock_dnsmasq()

    # ── Full teardown ───────────────────────────────────────────────────

    def cleanup_adblock(self) -> None:
        """Remove all adblock infrastructure from the router. Idempotent.

        Removes REDIRECT rules first (safety), then stops dnsmasq,
        destroys ipset, removes firewall include. Keeps blocklist file
        (expensive to re-download).
        """
        # Remove REDIRECT rules FIRST (safety — restore normal DNS immediately)
        self._remove_redirect_rules()

        # Destroy ipset
        self._ssh.exec(f"ipset destroy {ADBLOCK_IPSET} 2>/dev/null; true")

        # Stop dnsmasq
        self.stop_adblock_dnsmasq()

        # Remove firewall include
        self._ssh.exec(
            f"uci delete firewall.fvpn_adblock 2>/dev/null; "
            f"uci commit firewall 2>/dev/null; true"
        )

        # Clean up files (keep blocklist — it's expensive to re-download)
        self._ssh.exec(
            f"rm -f {ADBLOCK_RULES_SCRIPT} {ADBLOCK_MACS_FILE} "
            f"{ADBLOCK_CONF_PATH} {ADBLOCK_INIT_SCRIPT}; true"
        )

        log.info("Adblock infrastructure cleaned up")
