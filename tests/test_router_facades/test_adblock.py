"""Tests for RouterAdblock facade — blocklist injection into per-tunnel dnsmasq."""

from unittest.mock import MagicMock, patch, call

import pytest

from consts import ADBLOCK_HOSTS_PATH
from router.facades.adblock import RouterAdblock, _IFACES_FILE, _SNIPPET_NAME


@pytest.fixture
def adblock(uci, ipset, iptables, service_ctl, ssh):
    return RouterAdblock(uci, ipset, iptables, service_ctl, ssh)


class TestBlocklistCheck:
    def test_blocklist_has_content_true(self, adblock, ssh):
        ssh.exec.return_value = "5000"
        assert adblock._blocklist_has_content() is True

    def test_blocklist_has_content_false(self, adblock, ssh):
        ssh.exec.return_value = "0"
        assert adblock._blocklist_has_content() is False

    def test_blocklist_has_content_error(self, adblock, ssh):
        ssh.exec.return_value = "not a number"
        assert adblock._blocklist_has_content() is False


class TestSyncAdblock:
    def test_empty_ifaces_removes_all(self, adblock, ssh):
        with patch.object(adblock, "_remove_all_snippets") as mock_remove, \
             patch.object(adblock, "_write_firewall_include") as mock_fw:
            adblock.sync_adblock(set())
        mock_remove.assert_called_once()
        mock_fw.assert_called_once_with(set())

    def test_blocklist_empty_removes_all(self, adblock, ssh):
        with patch.object(adblock, "_blocklist_has_content", return_value=False), \
             patch.object(adblock, "_remove_all_snippets") as mock_remove, \
             patch.object(adblock, "_write_firewall_include") as mock_fw:
            adblock.sync_adblock({"wgclient1"})
        mock_remove.assert_called_once()
        mock_fw.assert_called_once_with(set())

    def test_injects_snippets_and_sighup(self, adblock, ssh):
        ifaces = {"wgclient1", "wgclient2"}
        with patch.object(adblock, "_blocklist_has_content", return_value=True), \
             patch.object(adblock, "_read_ifaces_file", return_value=set()), \
             patch.object(adblock, "_sighup_dnsmasq") as mock_hup:
            adblock.sync_adblock(ifaces)
        # Should write snippet to each conf-dir
        exec_calls = [str(c) for c in ssh.exec.call_args_list]
        assert any("dnsmasq.d.wgclient1" in c for c in exec_calls)
        assert any("dnsmasq.d.wgclient2" in c for c in exec_calls)
        # Should write ifaces file
        ssh.write_file.assert_any_call(
            _IFACES_FILE, "wgclient1\nwgclient2\n"
        )
        mock_hup.assert_called_once()

    def test_removes_stale_snippets(self, adblock, ssh):
        """When a tunnel loses adblock, its snippet should be removed."""
        with patch.object(adblock, "_blocklist_has_content", return_value=True), \
             patch.object(adblock, "_read_ifaces_file",
                          return_value={"wgclient1", "wgclient2"}), \
             patch.object(adblock, "_sighup_dnsmasq"):
            adblock.sync_adblock({"wgclient1"})  # wgclient2 no longer needs it
        # Should rm the stale wgclient2 snippet
        exec_calls = [str(c) for c in ssh.exec.call_args_list]
        assert any("rm -f" in c and "wgclient2" in c for c in exec_calls)

    def test_main_dnsmasq_injection(self, adblock, ssh):
        """No-VPN profiles inject into /tmp/dnsmasq.d/ (main)."""
        with patch.object(adblock, "_blocklist_has_content", return_value=True), \
             patch.object(adblock, "_read_ifaces_file", return_value=set()), \
             patch.object(adblock, "_sighup_dnsmasq"):
            adblock.sync_adblock({"main"})
        exec_calls = [str(c) for c in ssh.exec.call_args_list]
        assert any("/tmp/dnsmasq.d/" + _SNIPPET_NAME in c
                    or "dnsmasq.d/fvpn-adblock" in c for c in exec_calls)


class TestUploadBlocklist:
    def test_writes_and_sighups_when_active(self, adblock, ssh):
        with patch.object(adblock, "_read_ifaces_file",
                          return_value={"wgclient1"}), \
             patch.object(adblock, "_sighup_dnsmasq") as mock_hup:
            adblock.upload_blocklist("0.0.0.0 example.com\n")
        ssh.write_file.assert_called_once_with(
            ADBLOCK_HOSTS_PATH, "0.0.0.0 example.com\n"
        )
        mock_hup.assert_called_once()

    def test_no_sighup_when_no_active_ifaces(self, adblock, ssh):
        with patch.object(adblock, "_read_ifaces_file", return_value=set()), \
             patch.object(adblock, "_sighup_dnsmasq") as mock_hup:
            adblock.upload_blocklist("0.0.0.0 example.com\n")
        mock_hup.assert_not_called()


class TestCleanupAdblock:
    def test_full_cleanup(self, adblock, iptables, ipset, uci, ssh, service_ctl):
        with patch.object(adblock, "_remove_all_snippets") as mock_remove, \
             patch.object(adblock, "_cleanup_old_redirect_infra") as mock_old:
            adblock.cleanup_adblock()
        mock_remove.assert_called_once()
        mock_old.assert_called_once()
        uci.delete.assert_called_once_with("firewall.fvpn_adblock")
        uci.commit.assert_called_once_with("firewall")


class TestCleanupOldRedirectInfra:
    def test_removes_legacy_infrastructure(self, adblock, iptables, ipset,
                                           service_ctl, ssh):
        adblock._cleanup_old_redirect_infra()
        iptables.delete_chain.assert_called_once_with(
            "nat", "policy_redirect", "fvpn_adblock"
        )
        ipset.destroy.assert_called_once_with("fvpn_adblock_macs")
        service_ctl.stop.assert_called_with("fvpn-adblock")
        service_ctl.disable.assert_called_with("fvpn-adblock")


class TestRemoveAllSnippets:
    def test_removes_known_dirs_and_sighup(self, adblock, ssh):
        with patch.object(adblock, "_read_ifaces_file",
                          return_value={"wgclient1"}), \
             patch.object(adblock, "_restart_dnsmasq") as mock_restart:
            adblock._remove_all_snippets()
        # Should rm snippets from all known dirs
        rm_calls = [str(c) for c in ssh.exec.call_args_list if "rm -f" in str(c)]
        assert len(rm_calls) >= 1
        # Should write empty ifaces file
        ssh.write_file.assert_called_with(_IFACES_FILE, "")
        mock_restart.assert_called_once()


class TestFirewallInclude:
    def test_writes_script_with_ifaces(self, adblock, ssh, uci):
        adblock._write_firewall_include({"wgclient1", "main"})
        # Should write a shell script
        content = ssh.write_file.call_args_list[0][0][1]
        assert "#!/bin/sh" in content
        assert ADBLOCK_HOSTS_PATH in content
        assert _IFACES_FILE in content
        assert "killall -HUP dnsmasq" in content
        # Should register firewall include
        uci.ensure_firewall_include.assert_called_once()

    def test_writes_empty_script_when_no_ifaces(self, adblock, ssh, uci):
        adblock._write_firewall_include(set())
        content = ssh.write_file.call_args_list[0][0][1]
        assert "#!/bin/sh" in content
        # Should NOT contain injection logic
        assert "killall" not in content


# ── IPv6 Tests ───────────────────────────────────────────────────────────

@pytest.fixture
def ip6tables():
    m = MagicMock()
    m.delete_chain.return_value = None
    return m


@pytest.fixture
def adblock_v6(uci, ipset, iptables, service_ctl, ssh, ip6tables):
    return RouterAdblock(uci, ipset, iptables, service_ctl, ssh, ip6tables=ip6tables)


class TestRestartDnsmasq:
    """Test _restart_dnsmasq() — kills and restarts dnsmasq for given interfaces."""

    def test_restarts_main_dnsmasq(self, adblock, ssh):
        adblock._restart_dnsmasq({"main"})
        exec_calls = [str(c) for c in ssh.exec.call_args_list]
        # main dnsmasq uses dnsmasq.conf.cfg01411c
        assert any("dnsmasq.conf.cfg01411c" in c for c in exec_calls)
        assert any("pgrep" in c and "kill" in c for c in exec_calls)

    def test_restarts_tunnel_dnsmasq(self, adblock, ssh):
        adblock._restart_dnsmasq({"wgclient1"})
        exec_calls = [str(c) for c in ssh.exec.call_args_list]
        # Tunnel dnsmasq uses dnsmasq.conf.wgclient1
        assert any("dnsmasq.conf.wgclient1" in c for c in exec_calls)

    def test_restarts_multiple(self, adblock, ssh):
        adblock._restart_dnsmasq({"main", "wgclient2"})
        exec_calls = [str(c) for c in ssh.exec.call_args_list]
        assert any("cfg01411c" in c for c in exec_calls)
        assert any("wgclient2" in c for c in exec_calls)

    def test_empty_set_does_nothing(self, adblock, ssh):
        adblock._restart_dnsmasq(set())
        ssh.exec.assert_not_called()


class TestCleanupOldRedirectIPv6:
    def test_cleans_both_stacks(self, adblock_v6, iptables, ip6tables,
                                ipset, service_ctl, ssh):
        adblock_v6._cleanup_old_redirect_infra()
        iptables.delete_chain.assert_called_once()
        ip6tables.delete_chain.assert_called_once()
