"""Tests for auto_optimizer.py — scheduled server optimization (Stage 11)."""

import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime

from auto_optimizer import AutoOptimizer


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
        with patch("auto_optimizer.sm") as mock_sm:
            mock_sm.get_config.return_value = {"auto_optimize": {"enabled": False}}
            opt.check_and_optimize()
        switch_fn.assert_not_called()

    def test_skips_when_outside_window(self, optimizer):
        opt, *_, switch_fn, _ = optimizer
        with patch("auto_optimizer.sm") as mock_sm, \
             patch("auto_optimizer.datetime") as mock_dt:
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

        with patch("auto_optimizer.sm") as mock_sm, \
             patch("auto_optimizer.ps") as mock_ps, \
             patch("auto_optimizer.datetime") as mock_dt:
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
        with patch("auto_optimizer.sm") as mock_sm, \
             patch("auto_optimizer.datetime") as mock_dt:
            mock_sm.get_config.return_value = {
                "auto_optimize": {"enabled": True, "time": "04:00"}
            }
            mock_dt.now.return_value = datetime(2026, 4, 6, 4, 0)
            opt.check_and_optimize()
        switch_fn.assert_not_called()

    def test_switches_when_better_server_found(self, optimizer):
        opt, get_proton, get_router, switch_fn, build_fn = optimizer
        mock_proton = MagicMock()
        mock_proton.is_logged_in = True
        mock_proton.get_servers.return_value = [
            {"id": "s1", "name": "DE#1", "country_code": "DE", "city": "Frankfurt",
             "load": 90, "score": 90, "secure_core": False, "features": [],
             "country": "Germany", "enabled": True, "tier": 2},
            {"id": "s2", "name": "DE#2", "country_code": "DE", "city": "Frankfurt",
             "load": 10, "score": 10, "secure_core": False, "features": [],
             "country": "Germany", "enabled": True, "tier": 2},
        ]
        get_proton.return_value = mock_proton
        # Stage 11: optimizer reads profiles from build_profile_list (live data)
        build_fn.return_value = [{
            "id": "p1", "type": "vpn", "name": "Test",
            "health": "green",  # live router health
            "server": {"id": "s1", "load": 90, "name": "DE#1"},
            "server_scope": {"type": "country", "country_code": "DE"},
            "options": {"secure_core": False},
        }]

        with patch("auto_optimizer.sm") as mock_sm, \
             patch("auto_optimizer.ps") as mock_ps, \
             patch("auto_optimizer.datetime") as mock_dt:
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
        mock_proton.get_servers.return_value = [
            {"id": "s2", "name": "DE#2", "country_code": "DE", "city": "Frankfurt",
             "load": 5, "score": 5, "secure_core": False, "features": [],
             "country": "Germany", "enabled": True, "tier": 2},
        ]
        get_proton.return_value = mock_proton
        build_fn.return_value = [{
            "id": "p1", "type": "vpn", "name": "Test",
            "health": "red",  # disconnected — should be skipped
            "server": {"id": "s1", "load": 90, "name": "DE#1"},
            "server_scope": {"type": "country", "country_code": "DE"},
            "options": {},
        }]

        with patch("auto_optimizer.sm") as mock_sm, \
             patch("auto_optimizer.ps") as mock_ps, \
             patch("auto_optimizer.datetime") as mock_dt:
            mock_sm.get_config.return_value = {
                "auto_optimize": {"enabled": True, "time": "04:00"}
            }
            mock_dt.now.return_value = datetime(2026, 4, 6, 4, 0)
            mock_ps.load.return_value = {"profiles": []}
            opt.check_and_optimize()

        switch_fn.assert_not_called()

    def test_skips_server_scope_server(self, optimizer):
        opt, get_proton, _, switch_fn, build_fn = optimizer
        mock_proton = MagicMock()
        mock_proton.is_logged_in = True
        mock_proton.get_servers.return_value = [
            {"id": "s2", "load": 5, "score": 5, "secure_core": False,
             "country_code": "DE", "city": "Frankfurt", "features": [],
             "name": "DE#2", "country": "Germany", "enabled": True, "tier": 2},
        ]
        get_proton.return_value = mock_proton
        build_fn.return_value = [{
            "id": "p1", "type": "vpn", "name": "Test",
            "health": "green",
            "server": {"id": "s1", "load": 90, "name": "DE#1"},
            "server_scope": {"type": "server"},
            "options": {},
        }]

        with patch("auto_optimizer.sm") as mock_sm, \
             patch("auto_optimizer.ps") as mock_ps, \
             patch("auto_optimizer.datetime") as mock_dt:
            mock_sm.get_config.return_value = {
                "auto_optimize": {"enabled": True, "time": "04:00"}
            }
            mock_dt.now.return_value = datetime(2026, 4, 6, 4, 0)
            mock_ps.load.return_value = {"profiles": []}
            opt.check_and_optimize()

        switch_fn.assert_not_called()
