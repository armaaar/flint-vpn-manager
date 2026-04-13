"""Protocol Limits — Centralized VPN protocol slot counting and enforcement.

Deduplicates the limit-checking logic previously copy-pasted across
create_profile, change_type, change_protocol, and _smart_has_slot in
vpn_service.py.
"""

import persistence.profile_store as ps
from consts import (
    PROFILE_TYPE_VPN,
    PROTO_OPENVPN,
    PROTO_WIREGUARD,
    PROTO_WIREGUARD_TCP,
    PROTO_WIREGUARD_TLS,
)

# Router limits (fwmark address space)
MAX_WG_GROUPS = 5       # kernel WireGuard UDP tunnels (wgclient1-5)
MAX_OVPN_GROUPS = 5     # OpenVPN tunnels (ovpnclient1-5)
MAX_PWG_GROUPS = 4      # proton-wg TCP/TLS tunnels (protonwg0-3)


def _count_protocol_slots(vpn_protocol, exclude_profile_id=None):
    """Count existing VPN profiles using the given protocol family.

    Args:
        vpn_protocol: One of PROTO_WIREGUARD, PROTO_WIREGUARD_TCP,
            PROTO_WIREGUARD_TLS, or PROTO_OPENVPN.
        exclude_profile_id: Profile ID to exclude from the count (used
            when checking limits for protocol changes where the profile
            itself will be migrated).

    Returns:
        (count, max_allowed) tuple.
    """
    existing = ps.get_profiles()
    is_proton_wg = vpn_protocol in (PROTO_WIREGUARD_TCP, PROTO_WIREGUARD_TLS)

    if is_proton_wg:
        count = len([
            p for p in existing
            if p.get("type") == PROFILE_TYPE_VPN
            and (p.get("router_info", {}).get("vpn_protocol") or "").startswith("wireguard-")
            and p.get("id") != exclude_profile_id
        ])
        return count, MAX_PWG_GROUPS
    elif vpn_protocol == PROTO_WIREGUARD:
        count = len([
            p for p in existing
            if p.get("type") == PROFILE_TYPE_VPN
            and p.get("router_info", {}).get("vpn_protocol") == PROTO_WIREGUARD
            and p.get("id") != exclude_profile_id
        ])
        return count, MAX_WG_GROUPS
    elif vpn_protocol == PROTO_OPENVPN:
        count = len([
            p for p in existing
            if p.get("router_info", {}).get("vpn_protocol") == PROTO_OPENVPN
            and p.get("id") != exclude_profile_id
        ])
        return count, MAX_OVPN_GROUPS
    else:
        return 0, 0


def check_protocol_slot(vpn_protocol, exclude_profile_id=None):
    """Return True if a slot is available for the given protocol.

    Used by smart protocol to check before attempting a fallback.
    """
    count, max_allowed = _count_protocol_slots(vpn_protocol, exclude_profile_id)
    return count < max_allowed


# Protocol-specific error messages for user-facing limit errors.
_LIMIT_MESSAGES = {
    "proton_wg": (
        "Cannot create more than {max} WireGuard TCP/TLS groups "
        "(limited by router fwmark address space)."
    ),
    PROTO_WIREGUARD: (
        "Cannot create more than {max} WireGuard UDP groups. "
        "Try WireGuard TCP/TLS or OpenVPN instead."
    ),
    PROTO_OPENVPN: (
        "Cannot create more than {max} OpenVPN groups. "
        "Try WireGuard instead, or delete an existing OpenVPN group."
    ),
}


def require_protocol_slot(vpn_protocol, exclude_profile_id=None):
    """Raise LimitExceededError if no slot is available for the given protocol.

    Used by create_profile, change_type, and change_protocol.

    Raises:
        LimitExceededError: If the protocol's group limit is reached.
    """
    # Import here to avoid circular import (LimitExceededError is in vpn_service)
    from services.vpn_service import LimitExceededError

    count, max_allowed = _count_protocol_slots(vpn_protocol, exclude_profile_id)
    if count >= max_allowed:
        is_proton_wg = vpn_protocol in (PROTO_WIREGUARD_TCP, PROTO_WIREGUARD_TLS)
        key = "proton_wg" if is_proton_wg else vpn_protocol
        msg = _LIMIT_MESSAGES.get(key, f"Protocol limit reached ({max_allowed})")
        raise LimitExceededError(msg.format(max=max_allowed))
