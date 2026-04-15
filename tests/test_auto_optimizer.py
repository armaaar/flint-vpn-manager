"""Tests for auto_optimizer.py — scheduled server optimization and cert renewal."""

import time

import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta

from background.auto_optimizer import AutoOptimizer, MIN_DWELL_HOURS


@pytest.fixture
def optimizer():
    get_proton = MagicMock()
    get_router = MagicMock()
    switch_fn = MagicMock()
    build_fn = MagicMock(return_value=[])
    opt = AutoOptimizer(
        get_proton=get_proton,
        get_router=get_router,
        switch_fn=switch_fn,
        build_profile_list_fn=build_fn,
        poll_interval=1,
    )
    return opt, get_proton, get_router, switch_fn, build_fn


class TestAutoOptimizer:
    def test_skips_when_disabled(self, optimizer):
        opt, *_, switch_fn, _ = optimizer
        with patch("background.auto_optimizer.sm") as mock_sm:
            mock_sm.get_config.return_value = {"auto_optimize": {"enabled": False}}
            opt.check_and_optimize()
        switch_fn.assert_not_called()

    def test_skips_when_outside_window(self, optimizer):
        opt, *_, switch_fn, _ = optimizer
        with patch("background.auto_optimizer.sm") as mock_sm, \
             patch("background.auto_optimizer.datetime") as mock_dt:
            mock_sm.get_config.return_value = {
                "auto_optimize": {"enabled": True, "time": "04:00"}
            }
            mock_dt.now.return_value = datetime(2026, 4, 6, 15, 30)
            opt.check_and_optimize()
        switch_fn.assert_not_called()

    def test_runs_within_2_minute_window(self, optimizer):
        """Stage 11: tolerates up to 2 minutes of poll-loop jitter after the scheduled time."""
        opt, get_proton, _, switch_fn, build_fn = optimizer
        mock_proton = MagicMock()
        mock_proton.is_logged_in = True
        mock_proton.get_servers.return_value = []
        get_proton.return_value = mock_proton
        build_fn.return_value = []  # nothing to optimize

        with patch("background.auto_optimizer.sm") as mock_sm, \
             patch("background.auto_optimizer.ps") as mock_ps, \
             patch("background.auto_optimizer.datetime") as mock_dt:
            mock_sm.get_config.return_value = {
                "auto_optimize": {"enabled": True, "time": "04:00"}
            }
            mock_ps.load.return_value = {"profiles": []}
            # 04:01 — within 2-minute window
            mock_dt.now.return_value = datetime(2026, 4, 6, 4, 1)
            opt.check_and_optimize()

        assert opt._last_run_date == "2026-04-06"

    def test_skips_if_already_ran_today(self, optimizer):
        opt, *_, switch_fn, _ = optimizer
        opt._last_run_date = "2026-04-06"
        with patch("background.auto_optimizer.sm") as mock_sm, \
             patch("background.auto_optimizer.datetime") as mock_dt:
            mock_sm.get_config.return_value = {
                "auto_optimize": {"enabled": True, "time": "04:00"}
            }
            mock_dt.now.return_value = datetime(2026, 4, 6, 4, 0)
            opt.check_and_optimize()
        switch_fn.assert_not_called()

    def _server(self, id, country_code="DE", city="Frankfurt", load=50,
                streaming=False, p2p=False, secure_core=False):
        return {
            "id": id, "name": f"{country_code}#{id}",
            "country_code": country_code, "country": "Germany",
            "city": city, "load": load, "score": load,
            "secure_core": secure_core, "streaming": streaming, "p2p": p2p,
            "entry_country_code": "", "features": [],
            "enabled": True, "tier": 2,
        }

    def _scope(self, country_code=None, city=None, server_id=None,
               streaming=False, p2p=False, secure_core=False):
        return {
            "country_code": country_code, "city": city,
            "entry_country_code": None, "server_id": server_id,
            "features": {
                "streaming": streaming, "p2p": p2p, "secure_core": secure_core,
            },
        }

    def test_switches_when_better_server_found(self, optimizer):
        opt, get_proton, get_router, switch_fn, build_fn = optimizer
        mock_proton = MagicMock()
        mock_proton.is_logged_in = True
        mock_proton.get_servers.return_value = [
            self._server("s1", load=90),
            self._server("s2", load=10),
        ]
        get_proton.return_value = mock_proton
        build_fn.return_value = [{
            "id": "p1", "type": "vpn", "name": "Test",
            "health": "green",  # live router health
            "server": {"id": "s1", "load": 90, "score": 90, "name": "DE#1"},
            "server_scope": self._scope(country_code="DE"),
            "options": {},
        }]

        with patch("background.auto_optimizer.sm") as mock_sm, \
             patch("background.auto_optimizer.ps") as mock_ps, \
             patch("background.auto_optimizer.datetime") as mock_dt:
            mock_sm.get_config.return_value = {
                "auto_optimize": {"enabled": True, "time": "04:00"}
            }
            mock_dt.now.return_value = datetime(2026, 4, 6, 4, 0)
            mock_ps.load.return_value = {"profiles": []}
            opt.check_and_optimize()

        switch_fn.assert_called_once_with("p1", "s2")
        assert opt._last_run_date == "2026-04-06"

    def test_skips_disconnected_tunnel(self, optimizer):
        """Stage 11: skip profiles whose live router health isn't green/amber."""
        opt, get_proton, _, switch_fn, build_fn = optimizer
        mock_proton = MagicMock()
        mock_proton.is_logged_in = True
        mock_proton.get_servers.return_value = [self._server("s2", load=5)]
        get_proton.return_value = mock_proton
        build_fn.return_value = [{
            "id": "p1", "type": "vpn", "name": "Test",
            "health": "red",  # disconnected — should be skipped
            "server": {"id": "s1", "load": 90, "score": 90, "name": "DE#1"},
            "server_scope": self._scope(country_code="DE"),
            "options": {},
        }]

        with patch("background.auto_optimizer.sm") as mock_sm, \
             patch("background.auto_optimizer.ps") as mock_ps, \
             patch("background.auto_optimizer.datetime") as mock_dt:
            mock_sm.get_config.return_value = {
                "auto_optimize": {"enabled": True, "time": "04:00"}
            }
            mock_dt.now.return_value = datetime(2026, 4, 6, 4, 0)
            mock_ps.load.return_value = {"profiles": []}
            opt.check_and_optimize()

        switch_fn.assert_not_called()

    def test_skips_pinned_server(self, optimizer):
        """A profile with scope.server_id pinned should never be auto-switched."""
        opt, get_proton, _, switch_fn, build_fn = optimizer
        mock_proton = MagicMock()
        mock_proton.is_logged_in = True
        mock_proton.get_servers.return_value = [self._server("s2", load=5)]
        get_proton.return_value = mock_proton
        build_fn.return_value = [{
            "id": "p1", "type": "vpn", "name": "Test",
            "health": "green",
            "server": {"id": "s1", "load": 90, "score": 90, "name": "DE#1"},
            "server_scope": self._scope(country_code="DE", city="Frankfurt", server_id="s1"),
            "options": {},
        }]

        with patch("background.auto_optimizer.sm") as mock_sm, \
             patch("background.auto_optimizer.ps") as mock_ps, \
             patch("background.auto_optimizer.datetime") as mock_dt:
            mock_sm.get_config.return_value = {
                "auto_optimize": {"enabled": True, "time": "04:00"}
            }
            mock_dt.now.return_value = datetime(2026, 4, 6, 4, 0)
            mock_ps.load.return_value = {"profiles": []}
            opt.check_and_optimize()

        switch_fn.assert_not_called()

    def test_dwell_time_blocks_recent_reswitch(self, optimizer):
        """A profile that was switched recently must not be switched again
        until MIN_DWELL_HOURS has elapsed, even if a clearly better server
        exists. This is the anti-flapping guardrail."""
        opt, get_proton, _, switch_fn, build_fn = optimizer
        mock_proton = MagicMock()
        mock_proton.is_logged_in = True
        mock_proton.get_servers.return_value = [
            self._server("s1", load=90),
            self._server("s2", load=10),
        ]
        get_proton.return_value = mock_proton
        build_fn.return_value = [{
            "id": "p1", "type": "vpn", "name": "Test",
            "health": "green",
            "server": {"id": "s1", "load": 90, "score": 90, "name": "DE#1"},
            "server_scope": self._scope(country_code="DE"),
            "options": {},
        }]

        now = datetime(2026, 4, 6, 4, 0)
        # Pretend we switched this profile 1 hour ago — well within the dwell window.
        opt._last_switch_at["p1"] = now - timedelta(hours=1)

        with patch("background.auto_optimizer.sm") as mock_sm, \
             patch("background.auto_optimizer.ps") as mock_ps, \
             patch("background.auto_optimizer.datetime") as mock_dt:
            mock_sm.get_config.return_value = {
                "auto_optimize": {"enabled": True, "time": "04:00"}
            }
            mock_dt.now.return_value = now
            mock_ps.load.return_value = {"profiles": []}
            opt.check_and_optimize()

        switch_fn.assert_not_called()

    def test_dwell_time_allows_switch_after_window(self, optimizer):
        """After MIN_DWELL_HOURS has elapsed, a better server should
        trigger a switch normally."""
        opt, get_proton, _, switch_fn, build_fn = optimizer
        mock_proton = MagicMock()
        mock_proton.is_logged_in = True
        mock_proton.get_servers.return_value = [
            self._server("s1", load=90),
            self._server("s2", load=10),
        ]
        get_proton.return_value = mock_proton
        build_fn.return_value = [{
            "id": "p1", "type": "vpn", "name": "Test",
            "health": "green",
            "server": {"id": "s1", "load": 90, "score": 90, "name": "DE#1"},
            "server_scope": self._scope(country_code="DE"),
            "options": {},
        }]

        now = datetime(2026, 4, 6, 4, 0)
        # Last switch was just outside the dwell window.
        opt._last_switch_at["p1"] = now - timedelta(hours=MIN_DWELL_HOURS + 1)

        with patch("background.auto_optimizer.sm") as mock_sm, \
             patch("background.auto_optimizer.ps") as mock_ps, \
             patch("background.auto_optimizer.datetime") as mock_dt:
            mock_sm.get_config.return_value = {
                "auto_optimize": {"enabled": True, "time": "04:00"}
            }
            mock_dt.now.return_value = now
            mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
            mock_ps.load.return_value = {"profiles": []}
            opt.check_and_optimize()

        switch_fn.assert_called_once_with("p1", "s2")
        # Successful switch should refresh the dwell timestamp.
        assert opt._last_switch_at["p1"] == now

    def test_respects_streaming_feature(self, optimizer):
        """Profile scope says 'fastest streaming server in US' — only swap to
        another US streaming server, never to a non-streaming or non-US one."""
        opt, get_proton, _, switch_fn, build_fn = optimizer
        mock_proton = MagicMock()
        mock_proton.is_logged_in = True
        mock_proton.get_servers.return_value = [
            self._server("s1", country_code="US", load=90, streaming=True),
            # Better load but NOT streaming → must be skipped
            self._server("s2", country_code="US", load=5, streaming=False),
            # Better load AND streaming but DE → must be skipped
            self._server("s3", country_code="DE", load=5, streaming=True),
            # US streaming with much better load → should be picked
            self._server("s4", country_code="US", load=20, streaming=True),
        ]
        get_proton.return_value = mock_proton
        build_fn.return_value = [{
            "id": "p1", "type": "vpn", "name": "Streaming US",
            "health": "green",
            "server": {"id": "s1", "load": 90, "score": 90, "name": "US#1"},
            "server_scope": self._scope(country_code="US", streaming=True),
            "options": {},
        }]

        with patch("background.auto_optimizer.sm") as mock_sm, \
             patch("background.auto_optimizer.ps") as mock_ps, \
             patch("background.auto_optimizer.datetime") as mock_dt:
            mock_sm.get_config.return_value = {
                "auto_optimize": {"enabled": True, "time": "04:00"}
            }
            mock_dt.now.return_value = datetime(2026, 4, 6, 4, 0)
            mock_ps.load.return_value = {"profiles": []}
            opt.check_and_optimize()

        # Must pick s4 — the only candidate that's both US AND streaming
        switch_fn.assert_called_once_with("p1", "s4")


class TestServerRefresh:
    """Tests for _maybe_refresh_server_data in the poll loop."""

    def test_refreshes_loads_when_expired(self, optimizer):
        opt, get_proton, *_ = optimizer
        mock_proton = MagicMock()
        mock_proton.is_logged_in = True
        mock_proton.server_list_expired = False
        mock_proton.server_loads_expired = True
        get_proton.return_value = mock_proton

        opt._maybe_refresh_server_data()

        mock_proton.refresh_server_loads.assert_called_once()
        mock_proton.refresh_server_list.assert_not_called()

    def test_refreshes_full_list_when_expired(self, optimizer):
        opt, get_proton, *_ = optimizer
        mock_proton = MagicMock()
        mock_proton.is_logged_in = True
        mock_proton.server_list_expired = True
        mock_proton.server_loads_expired = True  # both expired
        get_proton.return_value = mock_proton

        opt._maybe_refresh_server_data()

        # Full list refresh takes priority
        mock_proton.refresh_server_list.assert_called_once()
        mock_proton.refresh_server_loads.assert_not_called()

    def test_skips_when_fresh(self, optimizer):
        opt, get_proton, *_ = optimizer
        mock_proton = MagicMock()
        mock_proton.is_logged_in = True
        mock_proton.server_list_expired = False
        mock_proton.server_loads_expired = False
        get_proton.return_value = mock_proton

        opt._maybe_refresh_server_data()

        mock_proton.refresh_server_list.assert_not_called()
        mock_proton.refresh_server_loads.assert_not_called()

    def test_skips_when_not_logged_in(self, optimizer):
        opt, get_proton, *_ = optimizer
        mock_proton = MagicMock()
        mock_proton.is_logged_in = False
        get_proton.return_value = mock_proton

        opt._maybe_refresh_server_data()

        mock_proton.refresh_server_list.assert_not_called()
        mock_proton.refresh_server_loads.assert_not_called()

    def test_refresh_failure_does_not_propagate(self, optimizer):
        opt, get_proton, *_ = optimizer
        mock_proton = MagicMock()
        mock_proton.is_logged_in = True
        mock_proton.server_list_expired = True
        mock_proton.refresh_server_list.side_effect = RuntimeError("network error")
        get_proton.return_value = mock_proton

        # Should not raise
        opt._maybe_refresh_server_data()


class TestCertRenewal:
    """Tests for the background WireGuard persistent cert renewal."""

    def test_skips_when_already_checked_today(self, optimizer):
        opt, *_ = optimizer
        opt._last_cert_check_date = datetime.now().strftime("%Y-%m-%d")
        with patch("background.auto_optimizer.ps") as mock_ps:
            opt.check_and_refresh_certs()
        mock_ps.load.assert_not_called()  # Didn't even load profiles

    def test_skips_when_not_logged_in(self, optimizer):
        opt, get_proton, *_ = optimizer
        mock_proton = MagicMock()
        mock_proton.is_logged_in = False
        get_proton.return_value = mock_proton

        with patch("background.auto_optimizer.ps") as mock_ps, \
             patch("background.auto_optimizer.datetime") as mock_dt:
            mock_dt.now.return_value = datetime(2026, 4, 9, 12, 0)
            opt.check_and_refresh_certs()
        mock_ps.load.assert_not_called()

    def test_refreshes_expiring_cert(self, optimizer):
        """A cert expiring in < 30 days should be refreshed."""
        opt, get_proton, *_ = optimizer
        mock_proton = MagicMock()
        mock_proton.is_logged_in = True
        mock_proton.refresh_wireguard_cert.return_value = int(time.time()) + 365 * 86400
        get_proton.return_value = mock_proton

        # Profile with cert expiring in 10 days
        expiring_profile = {
            "id": "p1", "type": "vpn", "name": "Trusted",
            "wg_key": "dGVzdGtleQ==",  # base64 "testkey"
            "cert_expiry": int(time.time()) + 10 * 86400,  # 10 days from now
            "options": {"netshield": 2, "moderate_nat": False,
                        "nat_pmp": False, "vpn_accelerator": True},
        }

        with patch("background.auto_optimizer.ps") as mock_ps, \
             patch("background.auto_optimizer.datetime") as mock_dt:
            mock_dt.now.return_value = datetime(2026, 4, 9, 12, 0)
            mock_ps.load.return_value = {"profiles": [expiring_profile]}
            opt.check_and_refresh_certs()

        mock_proton.refresh_wireguard_cert.assert_called_once_with(
            wg_key_b64="dGVzdGtleQ==",
            profile_name="Trusted",
            netshield=2,
            moderate_nat=False,
            nat_pmp=False,
            vpn_accelerator=True,
        )
        mock_ps.update_profile.assert_called_once()

    def test_skips_fresh_cert(self, optimizer):
        """A cert with > 30 days remaining should NOT be refreshed."""
        opt, get_proton, *_ = optimizer
        mock_proton = MagicMock()
        mock_proton.is_logged_in = True
        get_proton.return_value = mock_proton

        fresh_profile = {
            "id": "p1", "type": "vpn", "name": "Trusted",
            "wg_key": "dGVzdGtleQ==",
            "cert_expiry": int(time.time()) + 300 * 86400,  # 300 days left
            "options": {},
        }

        with patch("background.auto_optimizer.ps") as mock_ps, \
             patch("background.auto_optimizer.datetime") as mock_dt:
            mock_dt.now.return_value = datetime(2026, 4, 9, 12, 0)
            mock_ps.load.return_value = {"profiles": [fresh_profile]}
            opt.check_and_refresh_certs()

        mock_proton.refresh_wireguard_cert.assert_not_called()

    def test_skips_profiles_without_wg_key(self, optimizer):
        """Legacy profiles and OVPN profiles (no wg_key) should be skipped."""
        opt, get_proton, *_ = optimizer
        mock_proton = MagicMock()
        mock_proton.is_logged_in = True
        get_proton.return_value = mock_proton

        legacy_profile = {
            "id": "p1", "type": "vpn", "name": "Legacy",
            "cert_expiry": 0,  # No cert
            "options": {},
        }

        with patch("background.auto_optimizer.ps") as mock_ps, \
             patch("background.auto_optimizer.datetime") as mock_dt:
            mock_dt.now.return_value = datetime(2026, 4, 9, 12, 0)
            mock_ps.load.return_value = {"profiles": [legacy_profile]}
            opt.check_and_refresh_certs()

        mock_proton.refresh_wireguard_cert.assert_not_called()


class TestBlocklistUpdate:
    """Tests for check_and_update_blocklist() — daily blocklist auto-update."""

    def test_skips_when_already_checked_today(self, optimizer):
        opt, *_ = optimizer
        opt._last_blocklist_check_date = datetime.now().strftime("%Y-%m-%d")
        with patch("background.auto_optimizer.sm") as mock_sm:
            opt.check_and_update_blocklist()
        mock_sm.get_config.assert_not_called()

    def test_skips_when_no_sources_configured(self, optimizer):
        opt, *_ = optimizer
        with patch("background.auto_optimizer.sm") as mock_sm, \
             patch("background.auto_optimizer.datetime") as mock_dt:
            mock_dt.now.return_value = datetime(2026, 4, 9, 12, 0)
            mock_sm.get_config.return_value = {"adblock": {"blocklist_sources": []}}
            opt.check_and_update_blocklist()

        assert opt._last_blocklist_check_date == "2026-04-09"

    def test_calls_download_and_merge_blocklists(self, optimizer):
        """Should use download_and_merge_blocklists() instead of duplicating logic."""
        opt, _, get_router, *_ = optimizer
        mock_router = MagicMock()
        get_router.return_value = mock_router

        with patch("background.auto_optimizer.sm") as mock_sm, \
             patch("background.auto_optimizer.datetime") as mock_dt, \
             patch("services.adblock_service.download_and_merge_blocklists") as mock_dl:
            mock_dt.now.return_value = datetime(2026, 4, 9, 12, 0)
            mock_sm.get_config.return_value = {
                "adblock": {"blocklist_sources": ["hagezi-light"]}
            }
            mock_dl.return_value = ("0.0.0.0 ads.test\n:: ads.test\n", 1, [])
            opt.check_and_update_blocklist()

        mock_dl.assert_called_once()
        mock_router.adblock.upload_blocklist.assert_called_once()

    def test_uploads_content_to_router(self, optimizer):
        opt, _, get_router, *_ = optimizer
        mock_router = MagicMock()
        get_router.return_value = mock_router
        content = "0.0.0.0 test.com\n:: test.com\n"

        with patch("background.auto_optimizer.sm") as mock_sm, \
             patch("background.auto_optimizer.datetime") as mock_dt, \
             patch("services.adblock_service.download_and_merge_blocklists") as mock_dl:
            mock_dt.now.return_value = datetime(2026, 4, 9, 12, 0)
            mock_sm.get_config.return_value = {
                "adblock": {"blocklist_sources": ["hagezi-light"]}
            }
            mock_dl.return_value = (content, 1, [])
            opt.check_and_update_blocklist()

        mock_router.adblock.upload_blocklist.assert_called_once_with(content)

    def test_skips_when_download_returns_none(self, optimizer):
        opt, _, get_router, *_ = optimizer
        mock_router = MagicMock()
        get_router.return_value = mock_router

        with patch("background.auto_optimizer.sm") as mock_sm, \
             patch("background.auto_optimizer.datetime") as mock_dt, \
             patch("services.adblock_service.download_and_merge_blocklists") as mock_dl:
            mock_dt.now.return_value = datetime(2026, 4, 9, 12, 0)
            mock_sm.get_config.return_value = {
                "adblock": {"blocklist_sources": ["hagezi-light"]}
            }
            mock_dl.return_value = (None, 0, ["hagezi-light"])
            opt.check_and_update_blocklist()

        mock_router.adblock.upload_blocklist.assert_not_called()
