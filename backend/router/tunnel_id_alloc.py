"""Shared tunnel ID allocator — scans route_policy, ipsets, and proton-wg
env files to find the next unused tunnel ID across all protocol types.
"""

PROTON_WG_DIR = "/etc/fvpn/protonwg"


def next_tunnel_id(ssh) -> int:
    """Find the next available tunnel ID (300-399).

    Scans three sources to avoid collisions:
    - route_policy tunnel_id fields (kernel WG + OpenVPN)
    - ipset names ``src_mac_<id>`` (proton-wg runtime)
    - proton-wg .env files ``FVPN_TUNNEL_ID=<id>`` (proton-wg persistent)

    Args:
        ssh: Object with ``exec()`` method (RouterAPI or SshExecutor).
    """
    # IDs used by route_policy (kernel WG + OVPN)
    existing = ssh.exec(
        "uci show route_policy 2>/dev/null | grep 'tunnel_id=' | "
        "sed \"s/.*='\\([^']*\\)'/\\1/\""
    )
    used = set()
    for line in existing.strip().splitlines():
        try:
            used.add(int(line.strip()))
        except ValueError:
            pass
    # IDs used by proton-wg (ipset names are src_mac_<tunnel_id>)
    ipsets = ssh.exec(
        "ipset list -n 2>/dev/null | grep '^src_mac_'"
    )
    for line in ipsets.strip().splitlines():
        line = line.strip()
        if line.startswith("src_mac_"):
            try:
                used.add(int(line.split("_")[-1]))
            except ValueError:
                pass
    # IDs claimed by proton-wg .env files (persist across reboots)
    env_ids = ssh.exec(
        f"grep -h '^FVPN_TUNNEL_ID=' {PROTON_WG_DIR}/*.env 2>/dev/null || true"
    )
    for line in env_ids.strip().splitlines():
        try:
            used.add(int(line.split("=", 1)[1].strip()))
        except (ValueError, IndexError):
            pass
    # Start from 300 to avoid conflicts with built-in IDs
    for tid in range(300, 400):
        if tid not in used:
            return tid
    raise RuntimeError("No available tunnel IDs")
