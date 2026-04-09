"""Server optimizer — finds candidate servers matching a profile's scope.

Used by:
  - The auto-optimizer: periodically picks a better-scored server within
    the profile's scope constraints.
  - The frontend ServerPicker: same filter logic, mirrored in JS for the
    live preview.

"Fastest" definition: lowest Proton `score`. This matches the upstream
`proton-vpn-api-core` behavior — `ServerList.get_fastest_server` is
literally `min(servers, key=lambda s: s.score)`. Per the library:
"The lower the number is the better is for establishing a connection."
The library also adds +1000 to the score of non-auto-connectable
servers, so sorting by score automatically excludes servers Proton's
own client wouldn't pick.

Scope filtering rules (see profile_store.normalize_server_scope):
  - features.streaming, features.p2p, features.secure_core: each must
    match (AND-combined) — a server qualifies only if it has every
    enabled feature.
  - country_code: filter by exit country (None = any country).
  - city: filter by exit city (None = any city in the chosen country).
  - entry_country_code: only meaningful with secure_core; filters by
    the SC entry country (None = any entry).
  - server_id: if set, the optimizer never switches (the user pinned a
    specific server).
"""

import math
from typing import Optional


# Auto-switch when the best candidate's score is at least this fraction
# lower than the current server's score. Replaces the legacy absolute
# load-points threshold — relative is more meaningful across the wide
# dynamic range of Proton scores (a 30-point delta means very different
# things at score 5 vs. score 500).
MIN_RELATIVE_IMPROVEMENT = 0.20


def _server_score(s: dict) -> float:
    """Return a server's score, or +inf if missing (sorts last)."""
    score = s.get("score")
    return score if score is not None else math.inf


def filter_servers_by_scope(scope: dict, servers: list) -> list:
    """Return the list of servers matching the scope's filter constraints.

    Does NOT consider scope.server_id — that's handled by the caller (it's
    a "pin" indicator, not a filter).

    Args:
        scope: normalized server_scope dict (see profile_store.normalize_server_scope)
        servers: full server list (each a dict with id, country_code, city,
                 entry_country_code, secure_core, streaming, p2p, load, score)

    Returns:
        Filtered list. Empty if nothing matches.
    """
    if not scope or not isinstance(scope, dict):
        return list(servers)

    features = scope.get("features") or {}
    want_streaming = bool(features.get("streaming"))
    want_p2p = bool(features.get("p2p"))
    want_secure_core = bool(features.get("secure_core"))

    out = []
    for s in servers:
        if want_streaming and not s.get("streaming"):
            continue
        if want_p2p and not s.get("p2p"):
            continue
        # secure_core is binary: enabled = SC servers only, disabled = non-SC only
        if want_secure_core != bool(s.get("secure_core")):
            continue

        cc = scope.get("country_code")
        if cc and s.get("country_code") != cc:
            continue

        city = scope.get("city")
        if city and s.get("city") != city:
            continue

        ecc = scope.get("entry_country_code")
        if ecc and s.get("entry_country_code") != ecc:
            continue

        out.append(s)
    return out


def resolve_scope_to_server(scope: dict, servers: list) -> Optional[dict]:
    """Pick the specific server that scope currently resolves to.

    If scope.server_id is set and that server still exists in `servers`,
    return it. Otherwise, return the lowest-score server matching the
    scope's filter constraints.

    Returns None if no server matches the constraints.
    """
    if scope and scope.get("server_id"):
        sid = scope["server_id"]
        for s in servers:
            if s.get("id") == sid:
                return s
        # Pinned server vanished from the list — fall through to fastest

    candidates = filter_servers_by_scope(scope, servers)
    if not candidates:
        return None
    return min(candidates, key=_server_score)


def find_better_server(
    profile: dict,
    servers: list,
    min_relative_improvement: float = MIN_RELATIVE_IMPROVEMENT,
) -> Optional[dict]:
    """Find a significantly better server within the profile's scope.

    Skips profiles with a pinned server_id (the user explicitly chose
    that exact server). For all others, finds the lowest-score server
    matching the scope filters and returns it only if its score is at
    least `min_relative_improvement` fraction lower than the current
    server's score.

    Example: with the default 0.20, switching happens when
    best_score <= current_score * 0.80 (i.e. best is at least 20% lower).

    Args:
        profile: VPN profile dict with 'server' and 'server_scope'.
        servers: Full server list from proton_api.get_servers().
        min_relative_improvement: Minimum fractional improvement (0..1).

    Returns:
        Server dict if a strictly better one exists, None otherwise.
    """
    scope = profile.get("server_scope") or {}
    if scope.get("server_id"):
        return None  # User pinned a specific server — never auto-switch

    current_server = profile.get("server") or {}
    current_id = current_server.get("id")
    current_score = current_server.get("score")
    if current_score is None:
        return None

    candidates = filter_servers_by_scope(scope, servers)
    # Don't suggest the current server as a "better" alternative
    candidates = [s for s in candidates if s.get("id") != current_id]
    if not candidates:
        return None

    best = min(candidates, key=_server_score)
    best_score = _server_score(best)

    if best_score <= current_score * (1 - min_relative_improvement):
        return best
    return None
