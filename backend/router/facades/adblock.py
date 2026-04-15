"""Router adblock facade — blocklist injection into per-tunnel dnsmasq instances.

Instead of running a separate blocking dnsmasq with iptables REDIRECT (which
breaks GL.iNet's per-tunnel conntrack zones and kills DNS for VPN-marked
devices), we inject ``addn-hosts`` directives directly into the per-tunnel
dnsmasq conf-dirs.  Each VPN profile's tunnel has its own dnsmasq instance
with a ``conf-dir`` at ``/tmp/dnsmasq.d.<iface>/``.  For no-VPN profiles,
the main dnsmasq uses ``/tmp/dnsmasq.d/``.

This keeps DNS on the normal per-tunnel path with correct conntrack zones,
while still providing ad-blocking via the shared blocklist file.

Safety invariant: addn-hosts snippets are ONLY injected when the blocklist
file on the router is non-empty.  If the blocklist is empty, all snippets
are removed to prevent stale blocking after a failed update.

Tool-layer objects (Uci, Ipset, Iptables, ServiceCtl) are injected directly.
The raw ``ssh`` handle is kept for file operations and process signaling.
"""

import logging

from consts import ADBLOCK_HOSTS_PATH, ADBLOCK_RULES_SCRIPT

log = logging.getLogger("flintvpn")

# Config snippet injected into each target dnsmasq conf-dir
_SNIPPET_NAME = "fvpn-adblock"

# Persistence file: which interfaces currently have adblock active
_IFACES_FILE = "/etc/fvpn/adblock_ifaces.txt"

# Dnsmasq conf-dir paths
_MAIN_CONF_DIR = "/tmp/dnsmasq.d"
_TUNNEL_CONF_DIR_TPL = "/tmp/dnsmasq.d.{iface}"

# Legacy infrastructure constants (for one-time cleanup only)
_OLD_IPSET = "fvpn_adblock_macs"
_OLD_CHAIN = "fvpn_adblock"
_OLD_CONF_PATH = "/etc/fvpn/dnsmasq-adblock.conf"
_OLD_INIT_SCRIPT = "/etc/init.d/fvpn-adblock"
_OLD_MACS_FILE = "/etc/fvpn/adblock_macs.txt"


class RouterAdblock:
    """Facade for DNS ad-blocking infrastructure on the GL.iNet Flint 2."""

    def __init__(self, uci, ipset, iptables, service_ctl, ssh, ip6tables=None):
        self._uci = uci
        self._ipset = ipset
        self._iptables = iptables
        self._ip6tables = ip6tables
        self._service_ctl = service_ctl
        self._ssh = ssh

    # ── Path helpers ───────────────────────────────────────────────────

    @staticmethod
    def _conf_dir(iface: str) -> str:
        if iface == "main":
            return _MAIN_CONF_DIR
        return _TUNNEL_CONF_DIR_TPL.format(iface=iface)

    @classmethod
    def _snippet_path(cls, iface: str) -> str:
        return f"{cls._conf_dir(iface)}/{_SNIPPET_NAME}"

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

    # ── Core sync ──────────────────────────────────────────────────────

    def sync_adblock(self, ifaces: set) -> None:
        """Inject or remove the blocklist from per-tunnel dnsmasq instances.

        Args:
            ifaces: Set of interface names (e.g. ``{"wgclient1", "main"}``)
                that should have ad-blocking active.  Pass empty set to
                disable adblock everywhere.
        """
        # One-time cleanup of legacy REDIRECT-based infrastructure
        if not hasattr(self, "_legacy_cleaned"):
            self._cleanup_old_redirect_infra()
            self._legacy_cleaned = True

        if not ifaces or not self._blocklist_has_content():
            self._remove_all_snippets()
            self._write_firewall_include(set())
            log.info("Adblock disabled: %s",
                     "no interfaces" if not ifaces else "blocklist empty")
            return

        # Inject snippet into target conf-dirs
        for iface in ifaces:
            conf_dir = self._conf_dir(iface)
            self._ssh.exec(
                f"[ -d {conf_dir} ] && "
                f"echo 'addn-hosts={ADBLOCK_HOSTS_PATH}' > {conf_dir}/{_SNIPPET_NAME} "
                f"|| true"
            )

        # Remove stale snippets from interfaces that no longer need adblock
        old_ifaces = self._read_ifaces_file()
        removed_ifaces = old_ifaces - ifaces
        for stale in removed_ifaces:
            self._ssh.exec(f"rm -f {self._snippet_path(stale)}")

        # Persist interface list for firewall-reload recovery
        self._ssh.write_file(_IFACES_FILE, "\n".join(sorted(ifaces)) + "\n")
        self._write_firewall_include(ifaces)

        # Restart dnsmasq instances that lost their snippet (SIGHUP won't
        # unload addn-hosts from a deleted conf-dir file). Instances that
        # gained or kept a snippet only need SIGHUP to re-read hosts files.
        self._restart_dnsmasq(removed_ifaces)
        self._sighup_dnsmasq()
        log.info("Adblock synced: blocklist injected into %s",
                 ", ".join(sorted(ifaces)))

    # ── Blocklist upload ───────────────────────────────────────────────

    def upload_blocklist(self, content: str) -> None:
        """Write blocklist to router and reload affected dnsmasq instances."""
        self._ssh.write_file(ADBLOCK_HOSTS_PATH, content)
        log.info("Blocklist uploaded (%d bytes)", len(content))
        if self._read_ifaces_file():
            self._sighup_dnsmasq()

    # ── Full teardown ──────────────────────────────────────────────────

    def cleanup_adblock(self) -> None:
        """Remove all adblock infrastructure from the router. Idempotent."""
        self._remove_all_snippets()
        self._cleanup_old_redirect_infra()
        self._uci.delete("firewall.fvpn_adblock")
        self._uci.commit("firewall")
        self._ssh.exec(
            f"rm -f {ADBLOCK_RULES_SCRIPT} {_IFACES_FILE}; true"
        )
        log.info("Adblock infrastructure cleaned up")

    # ── Private helpers ────────────────────────────────────────────────

    def _read_ifaces_file(self) -> set:
        result = self._ssh.exec(
            f"cat {_IFACES_FILE} 2>/dev/null || true"
        ).strip()
        if not result:
            return set()
        return {line.strip() for line in result.splitlines() if line.strip()}

    def _remove_all_snippets(self) -> None:
        """Remove addn-hosts snippets from all known conf-dirs."""
        old_ifaces = self._read_ifaces_file()
        all_ifaces = set(old_ifaces)
        paths = [self._snippet_path(iface) for iface in old_ifaces]
        # Also clean all known tunnel dirs in case ifaces file was stale
        for extra in ("main", "wgclient1", "wgclient2", "wgclient3", "wgclient4",
                       "protonwg0", "protonwg1", "protonwg2", "protonwg3"):
            p = self._snippet_path(extra)
            if p not in paths:
                paths.append(p)
            all_ifaces.add(extra)
        if paths:
            self._ssh.exec(f"rm -f {' '.join(paths)}; true")
        self._ssh.write_file(_IFACES_FILE, "")
        self._restart_dnsmasq(all_ifaces)

    def _sighup_dnsmasq(self) -> None:
        """Send SIGHUP to all dnsmasq processes to re-read hosts files."""
        self._ssh.exec("killall -HUP dnsmasq 2>/dev/null || true")

    def _restart_dnsmasq(self, ifaces: set) -> None:
        """Restart dnsmasq instances for the given interfaces.

        Needed when removing addn-hosts snippets: SIGHUP won't unload
        an addn-hosts directive that was loaded from a conf-dir file
        that has since been deleted.  A full restart forces dnsmasq to
        re-read its conf-dir, picking up the removal.
        """
        if not ifaces:
            return
        cmds = []
        for iface in ifaces:
            conf = ("dnsmasq.conf.cfg01411c" if iface == "main"
                    else f"dnsmasq.conf.{iface}")
            cmds.append(
                f"pgrep -f 'dnsmasq.*{conf}' | xargs kill 2>/dev/null; "
                f"sleep 0.5; "
                f"pgrep -f 'dnsmasq.*{conf}' || "
                f"/usr/sbin/dnsmasq -C /var/etc/{conf} 2>/dev/null"
            )
        self._ssh.exec("; ".join(cmds) + "; true")

    def _write_firewall_include(self, ifaces: set) -> None:
        """Write firewall include script for reboot/reload persistence."""
        script = (
            "#!/bin/sh\n"
            "# Auto-generated by FlintVPN — DNS ad-block injection\n"
            "# Re-applied on every firewall reload\n\n"
        )
        if ifaces:
            script += (
                f"if [ -s {ADBLOCK_HOSTS_PATH} ] && "
                f"[ -f {_IFACES_FILE} ]; then\n"
                f"  while IFS= read -r iface; do\n"
                f"    [ -z \"$iface\" ] && continue\n"
                f"    if [ \"$iface\" = \"main\" ]; then\n"
                f"      conf_dir=\"{_MAIN_CONF_DIR}\"\n"
                f"    else\n"
                f"      conf_dir=\"/tmp/dnsmasq.d.$iface\"\n"
                f"    fi\n"
                f"    [ -d \"$conf_dir\" ] && "
                f"echo 'addn-hosts={ADBLOCK_HOSTS_PATH}' "
                f"> \"$conf_dir/{_SNIPPET_NAME}\"\n"
                f"  done < {_IFACES_FILE}\n"
                f"  killall -HUP dnsmasq 2>/dev/null || true\n"
                f"fi\n"
            )
        self._ssh.write_file(ADBLOCK_RULES_SCRIPT, script)
        self._ssh.exec(f"chmod +x {ADBLOCK_RULES_SCRIPT}")
        self._uci.ensure_firewall_include("fvpn_adblock", ADBLOCK_RULES_SCRIPT)

    def _cleanup_old_redirect_infra(self) -> None:
        """Remove legacy REDIRECT-based adblock infrastructure (one-time migration)."""
        for ipt in self._all_iptables():
            ipt.delete_chain("nat", "policy_redirect", _OLD_CHAIN)
        self._ipset.destroy(_OLD_IPSET)
        self._service_ctl.stop("fvpn-adblock")
        self._service_ctl.disable("fvpn-adblock")
        self._ssh.exec(
            f"rm -f {_OLD_CONF_PATH} {_OLD_INIT_SCRIPT} {_OLD_MACS_FILE}; true"
        )

    def _all_iptables(self):
        """Yield iptables tool, and ip6tables if available."""
        yield self._iptables
        if self._ip6tables:
            yield self._ip6tables
