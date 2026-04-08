"""Server optimizer — finds better servers for VPN profiles.

Used by both the passive SSE hint (threshold=20) and the active
auto-optimize background thread (threshold=30).
"""

from typing import Optional


LOAD_THRESHOLD_HINT = 20     # Show hint when current > best + 20
LOAD_THRESHOLD_SWITCH = 30   # Auto-switch when current > best + 30


def get_candidate_servers(profile: dict, servers: list[dict]) -> list[dict]:
    """Filter servers matching the profile's selection scope.

    Returns an empty list if scope is "server" (explicit choice, no optimization)
    or if scope is missing.
    """
    scope = profile.get("server_scope", {})
    scope_type = scope.get("type", "server")

    if scope_type == "server":
        return []

    current_id = profile.get("server", {}).get("id")
    is_secure_core = profile.get("options", {}).get("secure_core", False)

    candidates = [s for s in servers if s["id"] != current_id]

    # Match secure_core setting
    if is_secure_core:
        candidates = [s for s in candidates if s.get("secure_core")]
    else:
        candidates = [s for s in candidates if not s.get("secure_core")]

    if scope_type == "country":
        code = scope.get("country_code", "")
        candidates = [s for s in candidates if s.get("country_code") == code]
    elif scope_type == "city":
        code = scope.get("country_code", "")
        city = scope.get("city", "")
        candidates = [
            s for s in candidates
            if s.get("country_code") == code and s.get("city") == city
        ]
    # "global" — no further filtering

    return candidates


def find_better_server(
    profile: dict,
    servers: list[dict],
    threshold: int = LOAD_THRESHOLD_HINT,
) -> Optional[dict]:
    """Find a significantly better server for a profile.

    Args:
        profile: VPN profile dict with 'server', 'server_scope', 'options'.
        servers: Full server list from proton_api.get_servers().
        threshold: Minimum load difference to qualify as "better".

    Returns:
        Server dict if a better one exists, None otherwise.
    """
    current_server = profile.get("server", {})
    current_load = current_server.get("load")
    if current_load is None:
        return None

    candidates = get_candidate_servers(profile, servers)
    if not candidates:
        return None

    # Find the lowest-load candidate
    best = min(candidates, key=lambda s: s.get("load", 100))
    best_load = best.get("load", 100)

    if current_load > best_load + threshold:
        return best

    return None
