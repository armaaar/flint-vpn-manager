"""Tests for server_optimizer.py — scope-based server filtering and selection.

The new scope shape (see profile_store.normalize_server_scope):

    {
      "country_code": "AU" | None,
      "city": "Sydney" | None,
      "entry_country_code": "CH" | None,    # secure_core only
      "server_id": "abc..." | None,
      "features": {"streaming": bool, "p2p": bool, "secure_core": bool},
    }
"""

import pytest

from server_optimizer import (
    filter_servers_by_scope,
    resolve_scope_to_server,
    find_better_server,
)


def _server(
    id, country_code="DE", city="Frankfurt", load=50, score=None,
    secure_core=False, streaming=False, p2p=False,
    entry_country_code="",
):
    # Default score to load so older tests that only set load still
    # produce a sensible "lower is better" ordering. Tests that need
    # to verify score/load divergence pass `score` explicitly.
    return {
        "id": id, "name": f"{country_code}#{id}",
        "country_code": country_code, "country": "Germany",
        "city": city, "load": load, "score": load if score is None else score,
        "secure_core": secure_core, "streaming": streaming, "p2p": p2p,
        "entry_country_code": entry_country_code,
        "features": [], "enabled": True, "tier": 2,
    }


def _scope(country_code=None, city=None, entry_country_code=None,
           server_id=None, streaming=False, p2p=False, secure_core=False):
    return {
        "country_code": country_code,
        "city": city,
        "entry_country_code": entry_country_code,
        "server_id": server_id,
        "features": {
            "streaming": streaming, "p2p": p2p, "secure_core": secure_core,
        },
    }


def _profile(server_id="s1", load=50, score=None, **scope_kwargs):
    return {
        "type": "vpn",
        "server": {
            "id": server_id, "load": load,
            "score": load if score is None else score,
            "name": f"DE#{server_id}",
        },
        "server_scope": _scope(**scope_kwargs),
    }


class TestFilterServersByScope:
    def test_no_filters_returns_all(self):
        servers = [_server("s1"), _server("s2", "US")]
        assert len(filter_servers_by_scope(_scope(), servers)) == 2

    def test_country_filter(self):
        servers = [
            _server("s1", "DE"), _server("s2", "DE"), _server("s3", "US"),
        ]
        result = filter_servers_by_scope(_scope(country_code="DE"), servers)
        assert {s["id"] for s in result} == {"s1", "s2"}

    def test_city_filter(self):
        servers = [
            _server("s1", "DE", "Frankfurt"),
            _server("s2", "DE", "Berlin"),
        ]
        scope = _scope(country_code="DE", city="Berlin")
        result = filter_servers_by_scope(scope, servers)
        assert [s["id"] for s in result] == ["s2"]

    def test_streaming_filter(self):
        servers = [
            _server("s1", streaming=True),
            _server("s2", streaming=False),
            _server("s3", streaming=True),
        ]
        result = filter_servers_by_scope(_scope(streaming=True), servers)
        assert {s["id"] for s in result} == {"s1", "s3"}

    def test_p2p_filter(self):
        servers = [
            _server("s1", p2p=True),
            _server("s2", p2p=False),
        ]
        result = filter_servers_by_scope(_scope(p2p=True), servers)
        assert [s["id"] for s in result] == ["s1"]

    def test_streaming_and_p2p_combined(self):
        servers = [
            _server("s1", streaming=True, p2p=True),
            _server("s2", streaming=True, p2p=False),
            _server("s3", streaming=False, p2p=True),
        ]
        result = filter_servers_by_scope(
            _scope(streaming=True, p2p=True), servers
        )
        assert [s["id"] for s in result] == ["s1"]

    def test_secure_core_excludes_non_sc(self):
        servers = [
            _server("s1", secure_core=True),
            _server("s2", secure_core=False),
        ]
        result = filter_servers_by_scope(_scope(secure_core=True), servers)
        assert [s["id"] for s in result] == ["s1"]

    def test_no_secure_core_excludes_sc(self):
        """When secure_core feature is OFF, SC servers should NOT appear."""
        servers = [
            _server("s1", secure_core=True),
            _server("s2", secure_core=False),
        ]
        result = filter_servers_by_scope(_scope(secure_core=False), servers)
        assert [s["id"] for s in result] == ["s2"]

    def test_entry_country_filter_for_sc(self):
        servers = [
            _server("s1", "AU", "Sydney", secure_core=True, entry_country_code="CH"),
            _server("s2", "AU", "Sydney", secure_core=True, entry_country_code="SE"),
        ]
        scope = _scope(country_code="AU", city="Sydney",
                       entry_country_code="CH", secure_core=True)
        result = filter_servers_by_scope(scope, servers)
        assert [s["id"] for s in result] == ["s1"]


class TestResolveScopeToServer:
    def test_pinned_server_returned(self):
        servers = [_server("s1", load=80), _server("s2", load=10)]
        scope = _scope(country_code="DE", server_id="s1")
        assert resolve_scope_to_server(scope, servers)["id"] == "s1"

    def test_pinned_server_falls_back_when_missing(self):
        servers = [_server("s2", "DE", load=10), _server("s3", "DE", load=40)]
        scope = _scope(country_code="DE", server_id="vanished")
        # Falls back to fastest in country
        assert resolve_scope_to_server(scope, servers)["id"] == "s2"

    def test_picks_lowest_score(self):
        servers = [
            _server("s1", load=80),
            _server("s2", load=30),
            _server("s3", load=10),
        ]
        assert resolve_scope_to_server(_scope(), servers)["id"] == "s3"

    def test_picks_lowest_score_when_score_diverges_from_load(self):
        """`score` is the source of truth, not `load`. A server with higher
        load but a better Proton score must win."""
        servers = [
            _server("s1", load=10, score=2.5),  # low load, mediocre score
            _server("s2", load=80, score=0.5),  # high load, excellent score
        ]
        assert resolve_scope_to_server(_scope(), servers)["id"] == "s2"

    def test_returns_none_when_no_match(self):
        servers = [_server("s1", "DE")]
        assert resolve_scope_to_server(_scope(country_code="US"), servers) is None


class TestFindBetterServer:
    def test_switches_when_relative_improvement_met(self):
        """Default 20% threshold: best=10 vs current=60 → 83% better → switch."""
        profile = _profile(server_id="s1", load=60)
        servers = [_server("s1", load=60), _server("s2", load=10)]
        result = find_better_server(profile, servers)
        assert result is not None
        assert result["id"] == "s2"

    def test_skips_when_below_relative_threshold(self):
        """current=10, best=9 → only ~10% improvement → below default 20%."""
        profile = _profile(server_id="s1", load=10)
        servers = [_server("s1", load=10), _server("s2", load=9)]
        result = find_better_server(profile, servers)
        assert result is None

    def test_threshold_is_relative_not_absolute(self):
        """A 30-point absolute delta is huge at low scores, tiny at high.
        Verify the relative threshold treats both correctly."""
        # Low end: 30→0 is a 100% improvement → must switch
        low = _profile(server_id="s1", load=30)
        low_servers = [_server("s1", load=30), _server("s2", load=0)]
        assert find_better_server(low, low_servers)["id"] == "s2"

        # High end: 530→500 is a 5.7% improvement → must NOT switch
        high = _profile(server_id="s1", load=530)
        high_servers = [_server("s1", load=530), _server("s2", load=500)]
        assert find_better_server(high, high_servers) is None

    def test_custom_relative_improvement(self):
        """The threshold is configurable via min_relative_improvement."""
        profile = _profile(server_id="s1", load=10)
        servers = [_server("s1", load=10), _server("s2", load=9)]
        # ~10% improvement: blocked at default 20%, allowed at 5%
        assert find_better_server(profile, servers) is None
        result = find_better_server(profile, servers, min_relative_improvement=0.05)
        assert result is not None and result["id"] == "s2"

    def test_uses_score_not_load(self):
        """find_better_server must rank by score, ignoring load entirely."""
        profile = _profile(server_id="s1", load=10, score=2.0)
        servers = [
            _server("s1", load=10, score=2.0),
            # Higher load but a much better score → should be picked.
            _server("s2", load=90, score=0.5),
        ]
        result = find_better_server(profile, servers)
        assert result is not None
        assert result["id"] == "s2"

    def test_returns_none_for_pinned_server(self):
        """If scope.server_id is set, the user pinned a specific server."""
        profile = _profile(server_id="s1", load=90)
        profile["server_scope"]["server_id"] = "s1"
        servers = [_server("s2", load=5)]
        assert find_better_server(profile, servers) is None

    def test_returns_lowest_score_candidate(self):
        profile = _profile(server_id="s1", load=80)
        servers = [
            _server("s1", load=80),
            _server("s2", load=30),
            _server("s3", load=15),
            _server("s4", load=50),
        ]
        result = find_better_server(profile, servers)
        assert result["id"] == "s3"

    def test_respects_country_constraint(self):
        """Auto-optimizer should only swap within the user's chosen country."""
        profile = _profile(server_id="s1", load=80, country_code="DE")
        servers = [
            _server("s1", "DE", load=80),
            _server("s2", "DE", load=70),  # only 12.5% better → below threshold
            _server("s3", "US", load=5),   # would win but wrong country
        ]
        assert find_better_server(profile, servers) is None

    def test_respects_streaming_constraint(self):
        """Auto-optimizer should only swap to streaming servers when scope wants streaming."""
        profile = _profile(server_id="s1", load=80, streaming=True)
        profile["server"]["streaming"] = True
        servers = [
            _server("s1", load=80, streaming=True),
            _server("s2", load=5, streaming=False),  # better but not streaming
            _server("s3", load=40, streaming=True),  # streaming, 50% better
        ]
        result = find_better_server(profile, servers)
        assert result is not None
        assert result["id"] == "s3"

    def test_respects_country_plus_streaming(self):
        """User picked 'fastest streaming server in US' — only US streaming candidates."""
        profile = _profile(server_id="s1", load=80,
                           country_code="US", streaming=True)
        servers = [
            _server("s1", "US", load=80, streaming=True),
            _server("s2", "DE", load=5, streaming=True),   # streaming but DE
            _server("s3", "US", load=10, streaming=False), # US but not streaming
            _server("s4", "US", load=30, streaming=True),  # US streaming
        ]
        result = find_better_server(profile, servers)
        assert result["id"] == "s4"

    def test_handles_missing_server_score(self):
        profile = _profile()
        profile["server"] = {"id": "s1"}  # no score
        assert find_better_server(profile, [_server("s2", load=5)]) is None
