"""Tests for server_optimizer.py — better server detection logic."""

import pytest
from server_optimizer import find_better_server, get_candidate_servers


def _server(id, country_code="DE", city="Frankfurt", load=50, secure_core=False):
    return {
        "id": id, "name": f"{country_code}#{id}", "country_code": country_code,
        "city": city, "load": load, "score": load, "secure_core": secure_core,
        "country": "Germany", "features": [], "enabled": True, "tier": 2,
    }


def _profile(server_id="s1", load=50, scope_type="global", country_code="DE",
             city="Frankfurt", secure_core=False):
    scope = {"type": scope_type}
    if scope_type == "country":
        scope["country_code"] = country_code
    elif scope_type == "city":
        scope["country_code"] = country_code
        scope["city"] = city
    return {
        "type": "vpn",
        "server": {"id": server_id, "load": load, "name": f"DE#{server_id}"},
        "server_scope": scope,
        "options": {"secure_core": secure_core},
        "status": "connected",
    }


class TestGetCandidateServers:
    def test_server_scope_returns_empty(self):
        profile = _profile(scope_type="server")
        assert get_candidate_servers(profile, [_server("s2")]) == []

    def test_missing_scope_returns_empty(self):
        profile = _profile()
        del profile["server_scope"]
        assert get_candidate_servers(profile, [_server("s2")]) == []

    def test_global_returns_all_except_current(self):
        profile = _profile(server_id="s1")
        servers = [_server("s1"), _server("s2"), _server("s3")]
        result = get_candidate_servers(profile, servers)
        assert len(result) == 2
        assert all(s["id"] != "s1" for s in result)

    def test_country_filters_by_country(self):
        profile = _profile(scope_type="country", country_code="DE")
        servers = [_server("s1", "DE"), _server("s2", "DE"), _server("s3", "US")]
        result = get_candidate_servers(profile, servers)
        assert len(result) == 1
        assert result[0]["country_code"] == "DE"

    def test_city_filters_by_city(self):
        profile = _profile(scope_type="city", country_code="DE", city="Frankfurt")
        servers = [
            _server("s1", "DE", "Frankfurt"),
            _server("s2", "DE", "Frankfurt"),
            _server("s3", "DE", "Berlin"),
        ]
        result = get_candidate_servers(profile, servers)
        assert len(result) == 1
        assert result[0]["city"] == "Frankfurt"

    def test_secure_core_filtering(self):
        profile = _profile(secure_core=True)
        servers = [
            _server("s2", secure_core=True, load=10),
            _server("s3", secure_core=False, load=5),
        ]
        result = get_candidate_servers(profile, servers)
        assert len(result) == 1
        assert result[0]["secure_core"] is True


class TestFindBetterServer:
    def test_returns_better_when_threshold_met(self):
        profile = _profile(server_id="s1", load=60)
        servers = [_server("s1", load=60), _server("s2", load=10)]
        result = find_better_server(profile, servers, threshold=20)
        assert result is not None
        assert result["id"] == "s2"

    def test_returns_none_when_below_threshold(self):
        profile = _profile(server_id="s1", load=30)
        servers = [_server("s1", load=30), _server("s2", load=20)]
        result = find_better_server(profile, servers, threshold=20)
        assert result is None

    def test_returns_none_for_server_scope(self):
        profile = _profile(scope_type="server", load=90)
        servers = [_server("s2", load=5)]
        assert find_better_server(profile, servers) is None

    def test_returns_none_when_no_candidates(self):
        profile = _profile(server_id="s1", load=90, scope_type="country", country_code="DE")
        servers = [_server("s1", "DE", load=90)]  # only current server in country
        assert find_better_server(profile, servers) is None

    def test_returns_lowest_load_candidate(self):
        profile = _profile(server_id="s1", load=80)
        servers = [
            _server("s1", load=80),
            _server("s2", load=30),
            _server("s3", load=15),
            _server("s4", load=50),
        ]
        result = find_better_server(profile, servers, threshold=20)
        assert result["id"] == "s3"

    def test_handles_missing_server_load(self):
        profile = _profile()
        profile["server"] = {"id": "s1"}  # no load
        assert find_better_server(profile, [_server("s2", load=5)]) is None
