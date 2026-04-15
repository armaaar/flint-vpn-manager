"""Latency probe — measure TCP connect time to VPN server IPs.

Probes run FROM THE ROUTER (via SSH) so the measured latency reflects
the actual WAN path, not the Surface Go's potentially-VPN'd path.
Falls back to local probing if the router is unreachable.

Used by:
  - Auto-optimizer: tiebreaker when multiple servers have similar scores.
  - ServerPicker API: on-demand latency test for the frontend.
"""

import logging
import re
import socket
import time
import concurrent.futures
from typing import Optional

log = logging.getLogger("flintvpn")


def probe_servers_via_router(
    router,
    servers: list[dict],
    port: int = 443,
    timeout: int = 2,
) -> dict[str, Optional[float]]:
    """Probe TCP latency to servers from the router via a single SSH command.

    Args:
        router: RouterAPI instance with an `exec()` method.
        servers: List of dicts with 'id' and 'entry_ip' keys.
        port: TCP port to probe (443 works for all protocol types).
        timeout: Per-probe timeout in seconds.

    Returns:
        {server_id: latency_ms} — None for unreachable servers.
    """
    if not servers:
        return {}

    # Build IP → server_id mapping
    ip_to_ids = {}
    for s in servers:
        ip = s.get("entry_ip")
        if ip:
            ip_to_ids.setdefault(ip, []).append(s["id"])

    if not ip_to_ids:
        return {}

    ips = list(ip_to_ids.keys())

    # Build a shell script that probes each IP using curl's connect-time
    # measurement. BusyBox nc on OpenWrt doesn't support -z/-w flags, and
    # BusyBox date doesn't support nanoseconds. curl is available on the
    # GL.iNet Flint 2 and gives precise connect time via %{time_connect}.
    # Output: "IP LATENCY_MS" or "IP FAIL" per line.
    # IPv6 addresses need bracket notation in URLs: https://[::1]:443
    ip_list = " ".join(ips)
    cmd = (
        f'for ip in {ip_list}; do '
        f'case "$ip" in *:*) url="https://[$ip]:{port}";; *) url="https://$ip:{port}";; esac; '
        f'T=$(curl -so /dev/null -w "%{{time_connect}}" '
        f'--connect-timeout {timeout} "$url" 2>/dev/null); '
        f'if [ -n "$T" ] && [ "$T" != "0.000000" ]; then '
        f'MS=$(awk "BEGIN{{printf \\"%d\\", $T * 1000}}"); '
        f'echo "$ip $MS"; '
        f'else echo "$ip FAIL"; fi; '
        f'done'
    )

    try:
        # Give enough time: (timeout_per_probe * num_ips) + overhead
        ssh_timeout = (timeout * len(ips)) + 10
        output = router.exec(cmd, timeout=ssh_timeout)
    except Exception as e:
        log.warning(f"Router latency probe failed: {e}")
        return {}

    return _parse_probe_output(output, ip_to_ids)


def _parse_probe_output(
    output: str, ip_to_ids: dict[str, list[str]]
) -> dict[str, Optional[float]]:
    """Parse router probe output into {server_id: latency_ms}."""
    results = {}
    for line in output.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        ip = parts[0]
        val = parts[1]
        ids = ip_to_ids.get(ip, [])
        if val == "FAIL":
            for sid in ids:
                results[sid] = None
        else:
            try:
                ms = float(val)
                for sid in ids:
                    results[sid] = ms
            except ValueError:
                for sid in ids:
                    results[sid] = None
    return results


def probe_servers_local(
    servers: list[dict],
    port: int = 443,
    timeout: float = 2.0,
    max_workers: int = 10,
) -> dict[str, Optional[float]]:
    """Probe TCP latency locally (fallback when router is unreachable).

    Note: If the Surface Go is behind a VPN tunnel, these latencies
    will reflect the tunneled path, not the direct ISP path.

    Args:
        servers: List of dicts with 'id' and 'entry_ip' keys.
        port: TCP port to probe.
        timeout: Per-probe timeout in seconds.
        max_workers: Max parallel probes.

    Returns:
        {server_id: latency_ms} — None for unreachable servers.
    """
    if not servers:
        return {}

    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {}
        for s in servers:
            ip = s.get("entry_ip")
            if not ip:
                continue
            futures[pool.submit(_tcp_connect_ms, ip, port, timeout)] = s["id"]
        for future in concurrent.futures.as_completed(futures):
            sid = futures[future]
            try:
                results[sid] = future.result()
            except Exception:
                results[sid] = None
    return results


def _tcp_connect_ms(ip: str, port: int, timeout: float) -> Optional[float]:
    """Measure TCP connect time in milliseconds. None on failure."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        start = time.monotonic()
        sock.connect((ip, port))
        elapsed_ms = (time.monotonic() - start) * 1000
        sock.close()
        return round(elapsed_ms, 1)
    except (socket.timeout, OSError):
        return None
