"""Tests for RouterAdblock facade."""

from unittest.mock import MagicMock, patch, call

import pytest

from consts import ADBLOCK_CHAIN, ADBLOCK_IPSET, ADBLOCK_PORT
from router.facades.adblock import RouterAdblock


@pytest.fixture
def adblock(uci, ipset, iptables, service_ctl, ssh):
    return RouterAdblock(uci, ipset, iptables, service_ctl, ssh)


class TestHealthChecks:
    def test_blocklist_has_content_true(self, adblock, ssh):
        ssh.exec.return_value = "5000"
        assert adblock._blocklist_has_content() is True

    def test_blocklist_has_content_false(self, adblock, ssh):
        ssh.exec.return_value = "0"
        assert adblock._blocklist_has_content() is False

    def test_blocklist_has_content_error(self, adblock, ssh):
        ssh.exec.return_value = "not a number"
        assert adblock._blocklist_has_content() is False

    def test_dnsmasq_is_healthy(self, adblock, ssh):
        ssh.exec.return_value = f"udp  0  0 0.0.0.0:{ADBLOCK_PORT}  dnsmasq"
        assert adblock._dnsmasq_is_healthy() is True

    def test_dnsmasq_not_healthy(self, adblock, ssh):
        ssh.exec.return_value = ""
        assert adblock._dnsmasq_is_healthy() is False

    def test_redirect_is_safe_both_true(self, adblock):
        with patch.object(adblock, "_dnsmasq_is_healthy", return_value=True), \
             patch.object(adblock, "_blocklist_has_content", return_value=True):
            assert adblock._redirect_is_safe() is True

    def test_redirect_is_safe_dnsmasq_down(self, adblock):
        with patch.object(adblock, "_dnsmasq_is_healthy", return_value=False), \
             patch.object(adblock, "_blocklist_has_content", return_value=True):
            assert adblock._redirect_is_safe() is False

    def test_redirect_is_safe_blocklist_empty(self, adblock):
        with patch.object(adblock, "_dnsmasq_is_healthy", return_value=True), \
             patch.object(adblock, "_blocklist_has_content", return_value=False):
            assert adblock._redirect_is_safe() is False


class TestEnsureAdblockDnsmasq:
    def test_already_healthy(self, adblock, uci, ssh, service_ctl):
        uci.get.return_value = "192.168.8.1"
        with patch.object(adblock, "_blocklist_has_content", return_value=True), \
             patch.object(adblock, "_dnsmasq_is_healthy", return_value=True):
            result = adblock.ensure_adblock_dnsmasq()
        assert result is True
        # Should write config but NOT restart
        assert ssh.write_file.call_count >= 2
        service_ctl.stop.assert_not_called()

    def test_empty_blocklist_stops_dnsmasq(self, adblock, uci, ssh, service_ctl):
        uci.get.return_value = "192.168.8.1"
        with patch.object(adblock, "_blocklist_has_content", return_value=False):
            result = adblock.ensure_adblock_dnsmasq()
        assert result is False
        service_ctl.stop.assert_called_with("fvpn-adblock")

    def test_starts_and_retries(self, adblock, uci, ssh, service_ctl):
        uci.get.return_value = "192.168.8.1"
        health_results = [False, False, True]  # healthy on 3rd check
        with patch.object(adblock, "_blocklist_has_content", return_value=True), \
             patch.object(adblock, "_dnsmasq_is_healthy", side_effect=[False] + health_results), \
             patch("time.sleep"):
            result = adblock.ensure_adblock_dnsmasq()
        assert result is True
        service_ctl.start.assert_called_once_with("fvpn-adblock")

    def test_start_failure(self, adblock, uci, ssh, service_ctl):
        uci.get.return_value = "192.168.8.1"
        with patch.object(adblock, "_blocklist_has_content", return_value=True), \
             patch.object(adblock, "_dnsmasq_is_healthy", return_value=False), \
             patch("time.sleep"):
            result = adblock.ensure_adblock_dnsmasq()
        assert result is False


class TestSyncAdblockRules:
    def test_empty_macs_cleans_up(self, adblock):
        with patch.object(adblock, "cleanup_adblock") as mock_cleanup:
            adblock.sync_adblock_rules(set())
        mock_cleanup.assert_called_once()

    def test_with_macs_dnsmasq_ready(self, adblock, ssh, ipset, iptables):
        macs = {"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"}
        with patch.object(adblock, "ensure_adblock_dnsmasq", return_value=True), \
             patch.object(adblock, "_apply_redirect_rules") as mock_apply, \
             patch.object(adblock, "_write_firewall_include") as mock_write:
            adblock.sync_adblock_rules(macs)
        # Ipset populated
        ipset.create.assert_called_once_with(ADBLOCK_IPSET, "hash:mac")
        ipset.flush.assert_called_once_with(ADBLOCK_IPSET)
        assert ipset.add.call_count == 2
        # Redirect applied
        mock_apply.assert_called_once()
        mock_write.assert_called_once_with(with_redirect=True)

    def test_with_macs_dnsmasq_not_ready(self, adblock, ssh, ipset):
        macs = {"aa:bb:cc:dd:ee:ff"}
        with patch.object(adblock, "ensure_adblock_dnsmasq", return_value=False), \
             patch.object(adblock, "_remove_redirect_rules") as mock_remove, \
             patch.object(adblock, "_write_firewall_include") as mock_write:
            adblock.sync_adblock_rules(macs)
        mock_remove.assert_called_once()
        mock_write.assert_called_once_with(with_redirect=False)


class TestApplyRedirectRules:
    def test_creates_chain_and_rules(self, adblock, iptables):
        adblock._apply_redirect_rules()
        iptables.ensure_chain.assert_called_once_with("nat", ADBLOCK_CHAIN)
        iptables.flush_chain.assert_called_once_with("nat", ADBLOCK_CHAIN)
        assert iptables.append.call_count == 2  # UDP + TCP
        iptables.insert_if_absent.assert_called_once()


class TestRemoveRedirectRules:
    def test_deletes_chain(self, adblock, iptables):
        adblock._remove_redirect_rules()
        iptables.delete_chain.assert_called_once_with(
            "nat", "policy_redirect", ADBLOCK_CHAIN
        )


class TestCleanupAdblock:
    def test_full_cleanup(self, adblock, iptables, ipset, uci, ssh, service_ctl):
        with patch.object(adblock, "_remove_redirect_rules") as mock_remove:
            adblock.cleanup_adblock()
        mock_remove.assert_called_once()
        ipset.destroy.assert_called_once_with(ADBLOCK_IPSET)
        service_ctl.stop.assert_called_with("fvpn-adblock")
        service_ctl.disable.assert_called_with("fvpn-adblock")
        uci.delete.assert_called_once_with("firewall.fvpn_adblock")
        uci.commit.assert_called_once_with("firewall")


class TestUploadBlocklist:
    def test_writes_and_reloads_healthy(self, adblock, ssh):
        with patch.object(adblock, "_dnsmasq_is_healthy", return_value=True):
            adblock.upload_blocklist("0.0.0.0 example.com\n")
        ssh.write_file.assert_called_once()
        # Should HUP the running dnsmasq
        hup_call = [c for c in ssh.exec.call_args_list if "HUP" in str(c)]
        assert len(hup_call) == 1

    def test_starts_dnsmasq_if_not_running(self, adblock, ssh):
        with patch.object(adblock, "_dnsmasq_is_healthy", return_value=False), \
             patch.object(adblock, "ensure_adblock_dnsmasq") as mock_ensure:
            adblock.upload_blocklist("0.0.0.0 example.com\n")
        mock_ensure.assert_called_once()
