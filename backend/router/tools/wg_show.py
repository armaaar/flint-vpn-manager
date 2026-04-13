"""WireGuard show helper — shared handshake and transfer parsing.

Used by both RouterTunnel (kernel WG) and RouterProtonWG (userspace WG)
to avoid duplicating the handshake-age and transfer-bytes parsing logic.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from router.tools import SshExecutor


def parse_handshake_age(ssh: SshExecutor, iface: str) -> Optional[int]:
    """Read the latest WG handshake and return age in seconds.

    Returns None if no handshake data is available or the handshake
    timestamp is zero (not yet established).
    """
    try:
        raw = ssh.exec(
            f"wg show {iface} latest-handshakes 2>/dev/null || echo ''"
        ).strip()
    except Exception:
        return None

    for line in raw.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            try:
                hs_time = int(parts[1])
                if hs_time > 0:
                    return int(time.time()) - hs_time
            except ValueError:
                pass
    return None


def parse_transfer(ssh: SshExecutor, iface: str) -> tuple[int, int]:
    """Read WG transfer stats. Returns (rx_bytes, tx_bytes)."""
    try:
        raw = ssh.exec(
            f"wg show {iface} transfer 2>/dev/null || echo ''"
        ).strip()
    except Exception:
        return 0, 0

    for line in raw.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            try:
                return int(parts[1]), int(parts[2])
            except ValueError:
                pass
    return 0, 0
