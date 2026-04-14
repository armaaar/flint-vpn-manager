"""Tests for RouterFirewall facade."""

import pytest

from router.facades.firewall import RouterFirewall


@pytest.fixture
def fw(uci, ipset, service_ctl, ssh):
    return RouterFirewall(uci, ipset, service_ctl, ssh)


class TestFvpnUciApply:
    def test_applies_batch_and_reloads(self, fw, uci, service_ctl):
        fw.fvpn_uci_apply("set firewall.rule=x", reload=True)
        uci.batch.assert_called_once_with("set firewall.rule=x", "firewall")
        service_ctl.reload.assert_called_once_with("firewall")

    def test_applies_batch_without_reload(self, fw, uci, service_ctl):
        fw.fvpn_uci_apply("set firewall.rule=x", reload=False)
        uci.batch.assert_called_once()
        service_ctl.reload.assert_not_called()

    def test_empty_batch_with_reload(self, fw, uci, service_ctl):
        fw.fvpn_uci_apply("  ", reload=True)
        uci.batch.assert_not_called()
        service_ctl.reload.assert_called_once_with("firewall")

    def test_empty_batch_no_reload_is_noop(self, fw, uci, service_ctl):
        fw.fvpn_uci_apply("  ", reload=False)
        uci.batch.assert_not_called()
        service_ctl.reload.assert_not_called()


class TestFvpnIpsetMembership:
    def test_delegates_to_membership_batch(self, fw, ipset):
        fw.fvpn_ipset_membership("myset", add=["a"], remove=["b"])
        ipset.membership_batch.assert_called_once_with("myset", add=["a"], remove=["b"])

    def test_empty_add_and_remove_is_noop(self, fw, ipset):
        fw.fvpn_ipset_membership("myset", add=[], remove=[])
        ipset.membership_batch.assert_not_called()


class TestFvpnIpsetCreateDestroy:
    def test_create(self, fw, ipset):
        fw.fvpn_ipset_create("myset", "hash:mac")
        ipset.create.assert_called_once_with("myset", "hash:mac")

    def test_destroy(self, fw, ipset):
        fw.fvpn_ipset_destroy("myset")
        ipset.destroy.assert_called_once_with("myset")


class TestSetupMdnsReflection:
    def test_enables_avahi_reflection(self, fw, ssh, service_ctl):
        ssh.exec.side_effect = lambda cmd, **kw: (
            "/usr/sbin/avahi-daemon" if "which" in cmd
            else "wgclient1" if "ifstatus" in cmd
            else ""
        )
        fw.setup_mdns_reflection("wgclient1")
        service_ctl.restart.assert_called_once_with("avahi-daemon", background=True)

    def test_skips_when_avahi_not_installed(self, fw, ssh, service_ctl):
        ssh.exec.return_value = ""
        fw.setup_mdns_reflection("wgclient1")
        service_ctl.restart.assert_not_called()

    def test_skips_when_no_l3_device(self, fw, ssh, service_ctl):
        ssh.exec.side_effect = lambda cmd, **kw: (
            "/usr/sbin/avahi-daemon" if "which" in cmd
            else ""
        )
        fw.setup_mdns_reflection("wgclient1")
        service_ctl.restart.assert_not_called()
