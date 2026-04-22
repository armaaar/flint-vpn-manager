# Smart Protocol Implementation Notes

Non-obvious design decisions in the Smart Protocol subsystem.

## Non-blocking SSE-tick design

Smart Protocol does NOT block the HTTP request. Instead:
1. `connect_profile(smart_protocol=True)` starts the tunnel normally and registers a `_smart_pending` entry
2. Every SSE tick (10s), `tick_smart_protocol()` is called
3. If 45 seconds have passed without the tunnel reaching `green`/`amber`, it calls `change_protocol()` to try the next protocol
4. The cycle is: WG UDP → OVPN UDP → OVPN TCP → WG TCP → WG TLS
5. Each attempt checks slot availability before proceeding

## Threading: RLock, not Lock

`_switch_locks` uses `threading.RLock()` (reentrant), NOT `threading.Lock()`. This is required because `tick_smart_protocol()` acquires the lock and then calls `change_protocol()`, which also acquires the same lock (same thread). A plain `Lock` would deadlock here.

**Do not change RLock to Lock** — the call chain `tick_smart_protocol → change_protocol` requires reentrancy.

## Cancel semantics

`_smart_cancel(profile_id)` is called by:
- `disconnect_profile` — user explicitly disconnects
- `delete_profile` — group deleted
- `change_type` — group type changed away from VPN

This prevents stale retries from firing after the profile no longer needs a tunnel.

## Protocol restrictions

Smart Protocol skips Tor and Secure Core profiles. These server types must not fall back to OpenVPN (Tor routing and SC entry routing are WireGuard-specific features).

## SSE status field

`smart_protocol_status` is pushed via SSE with `{profile_id: {attempting, attempt, total, elapsed}}`. The frontend shows "Trying wireguard-tcp (3/5)" during retries.
