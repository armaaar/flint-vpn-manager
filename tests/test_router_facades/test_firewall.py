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


class TestEnsureIpv6LeakProtection:
    def test_writes_script_and_registers_include(self, fw, ssh, uci):
        fw.ensure_ipv6_leak_protection()

        # Verify script was written
        write_call = ssh.write_file.call_args
        path = write_call[0][0]
        content = write_call[0][1]
        assert path == "/etc/fvpn/ipv6_forward.sh"
        assert "ip6tables -P FORWARD DROP" in content
        assert "ESTABLISHED,RELATED" in content

        # Verify chmod
        chmod_calls = [c for c in ssh.exec.call_args_list if "chmod" in str(c)]
        assert len(chmod_calls) == 1

        # Verify firewall include registered
        uci.ensure_firewall_include.assert_called_once_with(
            "fvpn_ipv6_fwd", "/etc/fvpn/ipv6_forward.sh"
        )

    def test_is_idempotent(self, fw, ssh, uci):
        fw.ensure_ipv6_leak_protection()
        fw.ensure_ipv6_leak_protection()
        assert ssh.write_file.call_count == 2  # Overwrites each time (safe)
        assert uci.ensure_firewall_include.call_count == 2  # Idempotent helper


class TestRemoveIpv6LeakProtection:
    def test_removes_uci_and_script(self, fw, ssh, uci):
        fw.remove_ipv6_leak_protection()
        uci.delete.assert_called_once_with("firewall.fvpn_ipv6_fwd")
        uci.commit.assert_called_once_with("firewall")
        rm_calls = [c for c in ssh.exec.call_args_list if "rm -f" in str(c)]
        assert len(rm_calls) == 1


class TestEnsureIpv6RouterEnabled:
    def test_enables_kernel_and_wan6(self, fw, ssh, uci, service_ctl):
        # Kernel IPv6 currently disabled
        ssh.exec.side_effect = lambda cmd, **kw: (
            "1" if "sysctl -n" in cmd else ""
        )
        fw.ensure_ipv6_router_enabled()

        # Verify sysctl written
        sysctl_calls = [c for c in ssh.exec.call_args_list if "sysctl -w" in str(c)]
        assert len(sysctl_calls) >= 1

        # Verify sysctl file persisted
        write_calls = [c for c in ssh.write_file.call_args_list if "sysctl" in str(c[0][0])]
        assert len(write_calls) == 1
        assert "disable_ipv6=0" in write_calls[0][0][1]

        # Verify UCI settings
        uci.set.assert_any_call("network.wan6.disabled", "0")
        uci.set.assert_any_call("network.wan6.proto", "dhcpv6")
        uci.set.assert_any_call("network.wan.ipv6", "1")
        uci.commit.assert_called_with("network")

        # Verify WAN6 brought up
        ubus_calls = [c for c in ssh.exec.call_args_list if "wan6 up" in str(c)]
        assert len(ubus_calls) == 1

    def test_idempotent_when_already_enabled(self, fw, ssh, uci):
        # Kernel already enabled + WAN6 not disabled
        ssh.exec.side_effect = lambda cmd, **kw: "0"
        uci.get.return_value = "0"
        fw.ensure_ipv6_router_enabled()

        # Should not set any UCI fields (early return)
        uci.set.assert_not_called()


class TestDisableIpv6Router:
    def test_disables_kernel_and_wan6(self, fw, ssh, uci, service_ctl):
        fw.disable_ipv6_router()

        sysctl_calls = [c for c in ssh.exec.call_args_list if "disable_ipv6=1" in str(c)]
        assert len(sysctl_calls) >= 1

        uci.set.assert_any_call("network.wan6.disabled", "1")
        uci.commit.assert_called_with("network")
        service_ctl.reload.assert_called_with("firewall")
