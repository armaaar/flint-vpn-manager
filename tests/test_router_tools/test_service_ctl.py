"""Tests for router_tools.service_ctl — service control wrapper."""

from unittest.mock import MagicMock

import pytest

from router.tools.service_ctl import ServiceCtl


@pytest.fixture
def ssh():
    return MagicMock()


@pytest.fixture
def svc(ssh):
    return ServiceCtl(ssh)


class TestReload:
    def test_foreground(self, svc, ssh):
        svc.reload("firewall")
        ssh.exec.assert_called_once_with(
            "/etc/init.d/firewall reload >/dev/null 2>&1; true"
        )

    def test_background(self, svc, ssh):
        svc.reload("dnsmasq", background=True)
        ssh.exec.assert_called_once_with(
            "/etc/init.d/dnsmasq reload >/dev/null 2>&1; true &"
        )


class TestRestart:
    def test_restart(self, svc, ssh):
        svc.restart("vpn-client")
        ssh.exec.assert_called_once_with(
            "/etc/init.d/vpn-client restart >/dev/null 2>&1; true"
        )


class TestStart:
    def test_start(self, svc, ssh):
        svc.start("fvpn-adblock")
        ssh.exec.assert_called_once_with(
            "/etc/init.d/fvpn-adblock start >/dev/null 2>&1; true"
        )


class TestStop:
    def test_stop(self, svc, ssh):
        svc.stop("fvpn-adblock")
        ssh.exec.assert_called_once_with(
            "/etc/init.d/fvpn-adblock stop >/dev/null 2>&1; true"
        )


class TestEnable:
    def test_enable(self, svc, ssh):
        svc.enable("fvpn-protonwg")
        ssh.exec.assert_called_once_with(
            "/etc/init.d/fvpn-protonwg enable 2>/dev/null; true"
        )


class TestDisable:
    def test_disable(self, svc, ssh):
        svc.disable("fvpn-protonwg")
        ssh.exec.assert_called_once_with(
            "/etc/init.d/fvpn-protonwg disable 2>/dev/null; true"
        )


class TestWifi:
    def test_wifi_reload(self, svc, ssh):
        svc.wifi_reload()
        ssh.exec.assert_called_once_with("wifi reload 2>/dev/null; true")

    def test_wifi_up(self, svc, ssh):
        svc.wifi_up()
        ssh.exec.assert_called_once_with("wifi up 2>/dev/null; true")

    def test_wifi_down(self, svc, ssh):
        svc.wifi_down()
        ssh.exec.assert_called_once_with("wifi down 2>/dev/null; true")
