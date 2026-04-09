"""Profile store — JSON persistence with atomic writes.

Manages profiles (VPN, No VPN, No Internet), device assignments,
device hostnames, and last-seen timestamps. All writes use atomic
temp-file-then-rename to prevent corruption.

Data model (profile_store.json):
    profiles: list of profile dicts
    device_assignments: {mac: profile_id or null}
    device_last_seen: {mac: ISO timestamp}
    device_hostnames: {mac: hostname}
"""

import json
import logging
import os
import re
import tempfile
import uuid
from pathlib import Path
from typing import Callable, Optional

DATA_DIR = Path(__file__).parent
STORE_FILE = DATA_DIR / "profile_store.json"

VALID_TYPES = {"vpn", "no_vpn", "no_internet"}
VALID_LAN_ACCESS = {"allowed", "group_only", "blocked"}
_MAC_RE = re.compile(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$', re.IGNORECASE)


# ── Server scope normalization ────────────────────────────────────────────
#
# New server_scope shape:
# {
#   "country_code": "AU" | None,           # None = "Fastest country"
#   "city": "Sydney" | None,               # None = "Fastest city"
#   "entry_country_code": "CH" | None,     # only for secure_core; None = fastest entry
#   "server_id": "abc123" | None,          # None = "Fastest server"
#   "features": {
#       "streaming": bool, "p2p": bool, "secure_core": bool
#   }
# }
#
# Cascade rule (enforced by normalize_server_scope and the UI):
#   If country_code is None → city, entry_country_code, server_id all None.
#   If city is None → entry_country_code, server_id all None.
#   If features.secure_core is False → entry_country_code is None.
#
# normalize_server_scope() also accepts the legacy shape (type='server'|
# 'country'|'city'|'global') and converts it.

DEFAULT_SCOPE_FEATURES = {"streaming": False, "p2p": False, "secure_core": False}


def normalize_server_scope(scope) -> dict:
    """Normalize server_scope to the canonical shape.

    Accepts the new shape (returns it unchanged after validation) OR the
    legacy `{type: 'server'|'country'|'city'|'global'}` shape (translates).
    Always returns a dict with all five fields present and the cascade
    invariant enforced.
    """
    if not isinstance(scope, dict):
        scope = {}
    features_in = scope.get("features") or {}
    if not isinstance(features_in, dict):
        features_in = {}
    features = {
        "streaming": bool(features_in.get("streaming", False)),
        "p2p": bool(features_in.get("p2p", False)),
        "secure_core": bool(features_in.get("secure_core", False)),
    }

    # Check whether this is the new shape (has any of the new top-level fields)
    is_new_shape = (
        "country_code" in scope or "city" in scope or "server_id" in scope
        or "entry_country_code" in scope or "features" in scope
    )

    if is_new_shape:
        country_code = scope.get("country_code") or None
        city = scope.get("city") or None
        entry_country_code = scope.get("entry_country_code") or None
        server_id = scope.get("server_id") or None
    else:
        # Legacy shape
        typ = scope.get("type", "server")
        country_code = scope.get("country_code") if typ in ("country", "city") else None
        city = scope.get("city") if typ == "city" else None
        entry_country_code = None
        server_id = None
        # In the old design, "server" type meant a specific server was
        # picked but the id wasn't stored in the scope (it lived on
        # profile.server.id). We can't recover it here, so leave it None
        # and let the caller handle it.

    # Enforce cascade
    if country_code is None:
        city = None
        entry_country_code = None
        server_id = None
    elif city is None:
        entry_country_code = None
        server_id = None
    if not features["secure_core"]:
        entry_country_code = None

    return {
        "country_code": country_code,
        "city": city,
        "entry_country_code": entry_country_code,
        "server_id": server_id,
        "features": features,
    }


def empty_server_scope() -> dict:
    """Return a fresh, fully-fastest scope with no features enabled."""
    return {
        "country_code": None,
        "city": None,
        "entry_country_code": None,
        "server_id": None,
        "features": dict(DEFAULT_SCOPE_FEATURES),
    }

# Optional callback fired after every successful save() — used by app.py to
# push a copy of profile_store.json to the router as a disaster-recovery
# backup. Best-effort: failures are logged but never propagate.
_save_callback: Optional[Callable[[Path], None]] = None
_log = logging.getLogger("flintvpn.profile_store")


def register_save_callback(fn: Optional[Callable[[Path], None]]):
    """Register (or clear) a callback to fire after every successful save().

    The callback receives the absolute path to the freshly-written
    profile_store.json. Exceptions raised by the callback are caught and
    logged but do not propagate (the local save is the source of truth).
    """
    global _save_callback
    _save_callback = fn


def _validate_mac(mac: str) -> str:
    """Validate and normalize a MAC address. Raises ValueError if invalid."""
    mac = mac.strip().lower()
    if not _MAC_RE.match(mac):
        raise ValueError(f"Invalid MAC address: {mac!r}")
    return mac

_EMPTY_STORE = {
    "profiles": [],
    # device_assignments is for non-VPN profiles only (Stage 5+).
    # VPN assignments come from router.from_mac (canonical).
    "device_assignments": {},
    # LAN access overrides per device (iptables can't be parsed back to a 3-state policy).
    "device_lan_overrides": {},
}


def load() -> dict:
    """Load the profile store from disk. Returns empty store if file missing.

    Also normalizes any legacy server_scope shapes on every load so the rest
    of the codebase only ever sees the canonical scope shape.
    """
    if not STORE_FILE.exists():
        return json.loads(json.dumps(_EMPTY_STORE))  # deep copy
    data = json.loads(STORE_FILE.read_text())
    # Normalize server_scope on every load (handles legacy shapes transparently)
    for p in data.get("profiles", []):
        if p.get("type") == "vpn":
            p["server_scope"] = normalize_server_scope(p.get("server_scope"))
    return data


def save(data: dict):
    """Atomically write the profile store to disk.

    After a successful write, fires the registered save callback (if any)
    so the caller can push the new content to the router as a backup.
    Callback failures are caught and logged but never propagate.
    """
    _sanitize_mac_keys(data)
    fd, tmp_path = tempfile.mkstemp(dir=DATA_DIR, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_path, STORE_FILE)
    except Exception:
        os.unlink(tmp_path)
        raise

    if _save_callback is not None:
        try:
            _save_callback(STORE_FILE)
        except Exception as e:
            _log.warning(f"profile_store save callback failed: {e}")


def _sanitize_mac_keys(data: dict):
    """Fix any corrupted MAC keys (e.g. two MACs concatenated with a space).

    Also drops legacy device-tracking fields (Stage 8 made them obsolete) so
    they don't grow forever in profile_store.json.
    """
    profile_ids = {p["id"] for p in data.get("profiles", [])}

    # Drop legacy fields no longer maintained as of Stage 8.
    for legacy_key in ("device_last_seen", "device_hostnames", "device_ips",
                       "device_client_info", "device_labels"):
        data.pop(legacy_key, None)

    for section in ("device_assignments", "device_lan_overrides"):
        mapping = data.get(section)
        if not mapping or not isinstance(mapping, dict):
            continue
        bad_keys = [k for k in mapping if not _MAC_RE.match(k)]
        for k in bad_keys:
            val = mapping.pop(k)
            # For assignments, drop values pointing to deleted profiles
            if section == "device_assignments" and val and val not in profile_ids:
                val = None
            for part in k.split():
                if _MAC_RE.match(part):
                    if part not in mapping or mapping[part] is None:
                        mapping[part] = val


# ── Profile CRUD ──────────────────────────────────────────────────────────────

def get_profiles(data: Optional[dict] = None) -> list[dict]:
    """Get all profiles."""
    if data is None:
        data = load()
    return data["profiles"]


def reorder_profiles(profile_ids: list[str]) -> bool:
    """Reorder profiles by the given list of IDs.

    Any profiles not in the list are appended at the end in their current order.
    Returns True if the order changed.
    """
    data = load()
    id_to_profile = {p["id"]: p for p in data["profiles"]}

    ordered = []
    for pid in profile_ids:
        if pid in id_to_profile:
            ordered.append(id_to_profile.pop(pid))

    # Append any remaining profiles not in the list
    for p in data["profiles"]:
        if p["id"] in id_to_profile:
            ordered.append(p)

    if [p["id"] for p in ordered] != [p["id"] for p in data["profiles"]]:
        data["profiles"] = ordered
        save(data)
        return True
    return False


def get_profile(profile_id: str, data: Optional[dict] = None) -> Optional[dict]:
    """Get a single profile by ID."""
    if data is None:
        data = load()
    for p in data["profiles"]:
        if p["id"] == profile_id:
            return p
    return None


def create_profile(
    name: str,
    profile_type: str,
    color: str = "#3498db",
    icon: str = "🔒",
    is_guest: bool = False,
    kill_switch: bool = True,
    server: Optional[dict] = None,
    options: Optional[dict] = None,
    router_info: Optional[dict] = None,
    server_scope: Optional[dict] = None,
    **kwargs,
) -> dict:
    """Create a new profile and save.

    Args:
        name: Profile display name
        profile_type: "vpn", "no_vpn", or "no_internet"
        color: Hex color for UI card
        icon: Emoji icon
        is_guest: Whether this is the guest profile
        kill_switch: Kill switch enabled (VPN only)
        server: Server info dict (VPN only)
        options: VPN options dict (VPN only)
        router_info: Dict from router_api.upload_wireguard_config (VPN only)
        **kwargs: Additional fields stored on VPN profiles (e.g. wg_key, cert_expiry)

    Returns:
        The created profile dict.
    """
    if profile_type not in VALID_TYPES:
        raise ValueError(f"Invalid profile type: {profile_type}. Must be one of {VALID_TYPES}")

    data = load()

    profile = {
        "id": str(uuid.uuid4()),
        "name": name,
        "type": profile_type,
        "color": color,
        "icon": icon,
        "is_guest": False,  # Set via set_guest_profile after creation
    }

    if profile_type == "vpn":
        # Stage 3: kill_switch is router-canonical (read live from
        # route_policy.{rule}.killswitch). The kill_switch arg is still
        # accepted because the upload_wireguard_config / upload_openvpn_config
        # path uses it to write the initial UCI value.
        # Stage 7: store only the server_id reference; live name/country/load
        # are resolved from Proton on every read. We also keep a minimal
        # cache of fields that DON'T come from the Proton logical server
        # (endpoint, physical domain, protocol) since they're picked at
        # config-generation time and used by _switch_server.
        if server:
            profile["server_id"] = server.get("id", "")
            cache = {}
            for k in ("id", "endpoint", "physical_server_domain", "protocol"):
                if server.get(k):
                    cache[k] = server[k]
            profile["server"] = cache
        else:
            profile["server_id"] = ""
            profile["server"] = {}
        profile["options"] = options or {
            "netshield": 0,
            "moderate_nat": False,
            "nat_pmp": False,
            "vpn_accelerator": True,
            "secure_core": False,
        }
        profile["router_info"] = router_info or {}
        profile["server_scope"] = normalize_server_scope(server_scope)

        # Additional VPN fields (wg_key, cert_expiry for persistent WG certs)
        for k, v in kwargs.items():
            if v is not None:
                profile[k] = v

    data["profiles"].append(profile)

    if is_guest:
        _clear_guest_flag(data)
        profile["is_guest"] = True

    save(data)
    return profile


def update_profile(profile_id: str, **updates) -> Optional[dict]:
    """Update a profile's fields. Returns updated profile or None if not found."""
    data = load()
    for p in data["profiles"]:
        if p["id"] == profile_id:
            for key, value in updates.items():
                if key != "id":  # Never change ID
                    p[key] = value
            save(data)
            return p
    return None


def delete_profile(profile_id: str) -> bool:
    """Delete a profile and unassign all its devices. Returns True if found."""
    data = load()
    original_len = len(data["profiles"])
    data["profiles"] = [p for p in data["profiles"] if p["id"] != profile_id]

    if len(data["profiles"]) == original_len:
        return False

    # Cascade: drop devices that were assigned to the deleted profile entirely
    # (NOT a sticky-None — the device tracker should auto-reassign these to
    # the guest group on the next poll, since the user didn't explicitly
    # unassign them; the group just disappeared from under them).
    lan_overrides = data.get("device_lan_overrides", {})
    for mac, pid in list(data["device_assignments"].items()):
        if pid == profile_id:
            del data["device_assignments"][mac]
            lan_overrides.pop(mac, None)

    # Strip the deleted profile's ID from any *_allow lists on remaining
    # profiles' lan_access and on every device override (entries can be MAC
    # strings OR profile IDs — only the latter need cleanup here).
    for p in data["profiles"]:
        lan = p.get("lan_access")
        if not lan:
            continue
        for key in ("outbound_allow", "inbound_allow"):
            lst = lan.get(key)
            if lst:
                lan[key] = [e for e in lst if e != profile_id]
    for mac, ovr in lan_overrides.items():
        for key in ("outbound_allow", "inbound_allow"):
            lst = ovr.get(key)
            if lst:
                ovr[key] = [e for e in lst if e != profile_id]

    save(data)
    return True


# ── Guest Profile ─────────────────────────────────────────────────────────────

def get_guest_profile(data: Optional[dict] = None) -> Optional[dict]:
    """Get the profile with is_guest=True, or None."""
    if data is None:
        data = load()
    for p in data["profiles"]:
        if p.get("is_guest"):
            return p
    return None


def set_guest_profile(profile_id: str) -> bool:
    """Set a profile as the guest profile. Clears flag from all others."""
    data = load()
    found = False
    for p in data["profiles"]:
        if p["id"] == profile_id:
            p["is_guest"] = True
            found = True
        else:
            p["is_guest"] = False
    if found:
        save(data)
    return found


def _clear_guest_flag(data: dict):
    """Clear is_guest from all profiles (in-memory, doesn't save)."""
    for p in data["profiles"]:
        p["is_guest"] = False


# ── Device Assignment ─────────────────────────────────────────────────────────

def assign_device(mac: str, profile_id: Optional[str]) -> bool:
    """Assign a device to a profile (or None to unassign).

    Returns True if the profile exists (or profile_id is None).
    Raises ValueError if mac is not a valid single MAC address.
    """
    mac = _validate_mac(mac)
    data = load()

    if profile_id is not None:
        if not any(p["id"] == profile_id for p in data["profiles"]):
            return False

    data["device_assignments"][mac] = profile_id
    save(data)
    return True


def get_device_assignment(mac: str, data: Optional[dict] = None) -> Optional[str]:
    """Get the profile ID a device is assigned to (or None)."""
    if data is None:
        data = load()
    return data["device_assignments"].get(mac.lower())


def get_devices_for_profile(profile_id: str, data: Optional[dict] = None) -> list[str]:
    """Get all MACs assigned to a profile."""
    if data is None:
        data = load()
    return [
        mac for mac, pid in data["device_assignments"].items()
        if pid == profile_id
    ]


def get_unassigned_devices(data: Optional[dict] = None) -> list[str]:
    """Get MACs with no profile assignment (None)."""
    if data is None:
        data = load()
    return [
        mac for mac, pid in data["device_assignments"].items()
        if pid is None
    ]


# ── Device Tracking ───────────────────────────────────────────────────────────
#
# Stage 8: device hostnames, IPs, last-seen, online status, classes, labels,
# and client info are NOT cached locally. They are read live from the router
# (DHCP leases + ubus gl-clients) by app._build_devices_live(). The label is
# the router's gl-client.{section}.alias (canonical).
#
# Only device_assignments (for non-VPN profiles) and device_lan_overrides
# remain in profile_store — both are local-only metadata with no router source.


# ── LAN Access Control ───────────────────────────────────────────────────────

_DEFAULT_LAN = {
    "outbound": "allowed",
    "inbound": "allowed",
    "outbound_allow": [],
    "inbound_allow": [],
}


def _validate_allow_list(lst, profile_ids: set) -> list:
    """Validate an allow list. Each entry is a MAC string or a profile ID.

    Returns a normalized copy (MACs lowercased). Raises ValueError on invalid
    entries (bad MAC, or unknown profile ID).
    """
    if lst is None:
        return []
    if not isinstance(lst, (list, tuple)):
        raise ValueError(f"allow list must be a list, got {type(lst).__name__}")
    out = []
    for entry in lst:
        if not isinstance(entry, str):
            raise ValueError(f"allow list entry must be a string, got {entry!r}")
        if _MAC_RE.match(entry):
            out.append(entry.lower())
        elif entry in profile_ids:
            out.append(entry)
        else:
            raise ValueError(f"Invalid allow list entry: {entry!r} (not a MAC or known profile ID)")
    # de-dup preserving order
    seen = set()
    deduped = []
    for e in out:
        if e not in seen:
            seen.add(e)
            deduped.append(e)
    return deduped


def set_profile_lan_access(
    profile_id: str,
    outbound: str,
    inbound: str,
    outbound_allow: Optional[list] = None,
    inbound_allow: Optional[list] = None,
) -> Optional[dict]:
    """Set LAN access rules for a profile. Returns the profile or None."""
    if outbound not in VALID_LAN_ACCESS:
        raise ValueError(f"Invalid outbound: {outbound}")
    if inbound not in VALID_LAN_ACCESS:
        raise ValueError(f"Invalid inbound: {inbound}")

    data = load()
    profile_ids = {p["id"] for p in data["profiles"]}
    out_allow = _validate_allow_list(outbound_allow, profile_ids - {profile_id})
    in_allow = _validate_allow_list(inbound_allow, profile_ids - {profile_id})

    for p in data["profiles"]:
        if p["id"] == profile_id:
            p["lan_access"] = {
                "outbound": outbound,
                "inbound": inbound,
                "outbound_allow": out_allow,
                "inbound_allow": in_allow,
            }
            save(data)
            return p
    return None


def get_profile_lan_access(profile_id: str, data: Optional[dict] = None) -> dict:
    """Get LAN access for a profile. Returns default if not set.

    Always returns a dict with all four keys present (state + allow lists).
    """
    if data is None:
        data = load()
    for p in data["profiles"]:
        if p["id"] == profile_id:
            lan = p.get("lan_access") or {}
            return {
                "outbound": lan.get("outbound", "allowed"),
                "inbound": lan.get("inbound", "allowed"),
                "outbound_allow": list(lan.get("outbound_allow", [])),
                "inbound_allow": list(lan.get("inbound_allow", [])),
            }
    return {**_DEFAULT_LAN, "outbound_allow": [], "inbound_allow": []}


def set_device_lan_override(
    mac: str,
    outbound=None,
    inbound=None,
    outbound_allow: Optional[list] = None,
    inbound_allow: Optional[list] = None,
):
    """Set per-device LAN overrides. None state values mean inherit from group.

    If state and allow lists are all empty, removes the override entirely.
    """
    mac = mac.lower()
    if outbound is not None and outbound not in VALID_LAN_ACCESS:
        raise ValueError(f"Invalid outbound: {outbound}")
    if inbound is not None and inbound not in VALID_LAN_ACCESS:
        raise ValueError(f"Invalid inbound: {inbound}")

    data = load()
    profile_ids = {p["id"] for p in data["profiles"]}
    out_allow = _validate_allow_list(outbound_allow, profile_ids)
    in_allow = _validate_allow_list(inbound_allow, profile_ids)

    overrides = data.setdefault("device_lan_overrides", {})

    if outbound is None and inbound is None and not out_allow and not in_allow:
        overrides.pop(mac, None)
    else:
        overrides[mac] = {
            "outbound": outbound,
            "inbound": inbound,
            "outbound_allow": out_allow,
            "inbound_allow": in_allow,
        }

    save(data)


def get_device_lan_override(mac: str, data: Optional[dict] = None) -> Optional[dict]:
    """Get per-device LAN override, or None if inheriting."""
    if data is None:
        data = load()
    return data.get("device_lan_overrides", {}).get(mac.lower())


def get_effective_lan_access(mac: str, data: Optional[dict] = None) -> dict:
    """Resolve effective LAN access: device override → group → default.

    State fields (outbound/inbound): device override REPLACES group when set.
    Allow lists: group + device override merged additively (union, dedup).

    Returns {
        "outbound": str, "inbound": str,
        "outbound_allow": [{"value", "type", "source"}],
        "inbound_allow": [...],
        "inherited": bool,  # True iff state fields fully inherited from group
    }
    Each allow-list entry carries a `source` of "group" or "device" so the UI
    can grey out inherited entries.
    """
    if data is None:
        data = load()

    mac = mac.lower()
    override = data.get("device_lan_overrides", {}).get(mac)

    # Get group setting
    profile_id = data["device_assignments"].get(mac)
    group_lan = None
    if profile_id:
        for p in data["profiles"]:
            if p["id"] == profile_id:
                group_lan = p.get("lan_access")
                break
    if not group_lan:
        group_lan = {}

    group_out = group_lan.get("outbound", "allowed")
    group_in = group_lan.get("inbound", "allowed")
    group_out_allow = group_lan.get("outbound_allow", []) or []
    group_in_allow = group_lan.get("inbound_allow", []) or []

    if override:
        ov_out = override.get("outbound")
        ov_in = override.get("inbound")
        outbound = ov_out if ov_out is not None else group_out
        inbound = ov_in if ov_in is not None else group_in
        inherited = ov_out is None and ov_in is None
        ov_out_allow = override.get("outbound_allow", []) or []
        ov_in_allow = override.get("inbound_allow", []) or []
    else:
        outbound = group_out
        inbound = group_in
        inherited = True
        ov_out_allow = []
        ov_in_allow = []

    def _tag_entries(group_lst, device_lst):
        seen = set()
        result = []
        for e in group_lst:
            if e in seen:
                continue
            seen.add(e)
            result.append({
                "value": e,
                "type": "mac" if _MAC_RE.match(e) else "profile",
                "source": "group",
            })
        for e in device_lst:
            if e in seen:
                continue
            seen.add(e)
            result.append({
                "value": e,
                "type": "mac" if _MAC_RE.match(e) else "profile",
                "source": "device",
            })
        return result

    return {
        "outbound": outbound,
        "inbound": inbound,
        "outbound_allow": _tag_entries(group_out_allow, ov_out_allow),
        "inbound_allow": _tag_entries(group_in_allow, ov_in_allow),
        "inherited": inherited,
    }
