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
import os
import re
import tempfile
import uuid
from pathlib import Path
from typing import Optional

DATA_DIR = Path(__file__).parent
STORE_FILE = DATA_DIR / "profile_store.json"

VALID_TYPES = {"vpn", "no_vpn", "no_internet"}
VALID_LAN_ACCESS = {"allowed", "group_only", "blocked"}
_MAC_RE = re.compile(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$', re.IGNORECASE)


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
    """Load the profile store from disk. Returns empty store if file missing."""
    if not STORE_FILE.exists():
        return json.loads(json.dumps(_EMPTY_STORE))  # deep copy
    return json.loads(STORE_FILE.read_text())


def save(data: dict):
    """Atomically write the profile store to disk."""
    _sanitize_mac_keys(data)
    fd, tmp_path = tempfile.mkstemp(dir=DATA_DIR, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_path, STORE_FILE)
    except Exception:
        os.unlink(tmp_path)
        raise


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
        profile["server_scope"] = server_scope or {"type": "server"}

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

    # Unassign devices from this profile and clean up their LAN overrides
    lan_overrides = data.get("device_lan_overrides", {})
    for mac, pid in list(data["device_assignments"].items()):
        if pid == profile_id:
            data["device_assignments"][mac] = None
            lan_overrides.pop(mac, None)

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

_DEFAULT_LAN = {"outbound": "allowed", "inbound": "allowed"}


def set_profile_lan_access(profile_id: str, outbound: str, inbound: str) -> Optional[dict]:
    """Set LAN access rules for a profile. Returns the profile or None."""
    if outbound not in VALID_LAN_ACCESS:
        raise ValueError(f"Invalid outbound: {outbound}")
    if inbound not in VALID_LAN_ACCESS:
        raise ValueError(f"Invalid inbound: {inbound}")

    data = load()
    for p in data["profiles"]:
        if p["id"] == profile_id:
            p["lan_access"] = {"outbound": outbound, "inbound": inbound}
            save(data)
            return p
    return None


def get_profile_lan_access(profile_id: str, data: Optional[dict] = None) -> dict:
    """Get LAN access for a profile. Returns default if not set."""
    if data is None:
        data = load()
    for p in data["profiles"]:
        if p["id"] == profile_id:
            return p.get("lan_access", {**_DEFAULT_LAN})
    return {**_DEFAULT_LAN}


def set_device_lan_override(mac: str, outbound=None, inbound=None):
    """Set per-device LAN overrides. None values mean inherit from group.

    If both are None, removes the override entirely.
    """
    mac = mac.lower()
    if outbound is not None and outbound not in VALID_LAN_ACCESS:
        raise ValueError(f"Invalid outbound: {outbound}")
    if inbound is not None and inbound not in VALID_LAN_ACCESS:
        raise ValueError(f"Invalid inbound: {inbound}")

    data = load()
    overrides = data.setdefault("device_lan_overrides", {})

    if outbound is None and inbound is None:
        overrides.pop(mac, None)
    else:
        overrides[mac] = {"outbound": outbound, "inbound": inbound}

    save(data)


def get_device_lan_override(mac: str, data: Optional[dict] = None) -> Optional[dict]:
    """Get per-device LAN override, or None if inheriting."""
    if data is None:
        data = load()
    return data.get("device_lan_overrides", {}).get(mac.lower())


def get_effective_lan_access(mac: str, data: Optional[dict] = None) -> dict:
    """Resolve effective LAN access: device override → group → default.

    Returns {"outbound": str, "inbound": str, "inherited": bool}.
    """
    if data is None:
        data = load()

    mac = mac.lower()
    override = data.get("device_lan_overrides", {}).get(mac)

    # Get group setting
    profile_id = data["device_assignments"].get(mac)
    group_lan = {**_DEFAULT_LAN}
    if profile_id:
        for p in data["profiles"]:
            if p["id"] == profile_id:
                group_lan = p.get("lan_access", {**_DEFAULT_LAN})
                break

    if override:
        outbound = override.get("outbound") or group_lan["outbound"]
        inbound = override.get("inbound") or group_lan["inbound"]
        inherited = override.get("outbound") is None and override.get("inbound") is None
    else:
        outbound = group_lan["outbound"]
        inbound = group_lan["inbound"]
        inherited = True

    return {"outbound": outbound, "inbound": inbound, "inherited": inherited}
