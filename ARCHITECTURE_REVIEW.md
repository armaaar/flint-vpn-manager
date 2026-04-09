# FlintVPN Manager — Architecture

**Codebase size:** ~8,200 lines Python, ~3,700 lines Svelte/JS, ~6,100 lines tests

---

## Module Map

```
app.py (739)              ← Thin Flask routes + SSE stream
vpn_service.py (1,233)    ← Business logic orchestration
tunnel_strategy.py (568)  ← Protocol-agnostic tunnel lifecycle (Strategy pattern)
router_api.py (1,222)     ← SSH transport + protocol config + facade delegates
router_policy.py (182)    ← Route policy, kill switch, reorder
router_devices.py (242)   ← DHCP, gl-clients, device assignments
router_firewall.py (195)  ← UCI apply, ipset ops, LAN full state
router_tunnel.py (155)    ← Tunnel up/down, health checks
profile_store.py (726)    ← Atomic JSON persistence
lan_sync.py (785)         ← UCI-native LAN access execution
proton_api.py (502)       ← ProtonVPN API wrapper
auto_optimizer.py (271)   ← Background server switch + cert renewal
server_optimizer.py (162) ← Pure scope filtering + score comparison
device_tracker.py (166)   ← Background new-device auto-assigner
secrets_manager.py (142)  ← Encrypted credential storage
consts.py (29)            ← Shared constants (profile types, protocols, health states)
cli.py (858)              ← Click CLI, delegates to VPNService
```

## Layering

```
            app.py (Flask routes)    cli.py (Click commands)
                         │                │
                         ▼                ▼
                    VPNService (orchestration)
                    ┌────┼────────────────┐
                    │    │                │
                    ▼    ▼                ▼
            ProfileStore  TunnelStrategy   RouterAPI (SSH transport)
                          ┌─────┼─────┐    ┌────┼──────────┐
                          │     │     │    │    │          │
                          ▼     ▼     ▼    ▼    ▼          ▼
                         WG   OVPN  PWG  Devices Policy  Firewall
```

## Key Patterns

### Strategy Pattern — `tunnel_strategy.py`

`TunnelStrategy` ABC with three concrete implementations:

- `WireGuardStrategy` — kernel WG UDP via vpn-client
- `OpenVPNStrategy` — OVPN via vpn-client (delete+recreate server switch)
- `ProtonWGStrategy` — userspace WG TCP/TLS via proton-wg binary

Factory: `get_strategy(vpn_protocol: str) -> TunnelStrategy`

Each strategy implements: `create`, `delete`, `connect`, `disconnect`, `switch_server`, `get_health`. Strategies receive `RouterAPI` as a parameter — they don't hold references.

### Service Layer — `vpn_service.py`

`VPNService` owns all business logic. Constructor takes `router`, `proton`, `strategies`. Holds per-instance state: `_switch_locks` (per-profile threading.Lock), `_device_cache` (5s TTL).

Flask routes are 5–15 lines: parse request → call service → format response. The service raises `NotFoundError`, `ConflictError`, `LimitExceededError`, `NotLoggedInError` instead of returning HTTP responses.

### Router Facades — `router_{policy,devices,firewall,tunnel}.py`

Each facade takes a `RouterAPI` instance and owns one domain of router interaction. `RouterDevices` additionally takes `RouterPolicy` (for cross-facade calls like `remove_device_from_all_vpn` needing `get_flint_vpn_rules`).

`RouterAPI` exposes lazy `@property` accessors (`router.policy`, `router.devices`, etc.) and thin delegate methods for backward compatibility.

### Constants — `consts.py`

Centralizes magic strings: `PROFILE_TYPE_VPN`, `PROTO_WIREGUARD`, `LAN_ALLOWED`, `HEALTH_GREEN`, etc. All source files import from here.

## Frontend

```
frontend/src/lib/
  api.js (50)           ← fetch wrapper, throws on !res.ok
  stores/app.js (69)    ← Svelte stores + SSE handler
  format.js (42)        ← timeAgo, formatBytes, formatSpeed
  device-utils.js (66)  ← isOnline, isRandomMac, deviceIcon, DEVICE_TYPES
  country.js (35)       ← countryFlag, countryName
  emojiData.js (109)    ← EMOJI_CATEGORIES (static data)
  utils.js (10)         ← Barrel re-export of format + device-utils + country
  components/
    Dashboard.svelte (272)       ← Sidebar + group cards + unassigned drop zone
    ServerPicker.svelte (652)    ← 3-level Country → City → Server browser
    GroupCard.svelte (401)       ← Profile card with gradient, DnD devices
    CreateGroupModal.svelte (362)
    EditGroupModal.svelte (335)
    DeviceModal.svelte (216)
    ...
```

## Remaining Opportunities

- **TypedDicts** for `RouterInfo`, `ServerScope`, `LanAccess` — the profile dict (~15 keys) still passes as raw `dict` across 6 modules
- **Temporal coupling in `api_unlock`** — 5 post-unlock steps must execute in order; enforced only by comments
- **ServerPicker.svelte** (652 lines) — the reactive filtering pipeline could be extracted
- **Remove RouterAPI delegates** — callers can be migrated to `router.policy.method()` style; the one-liner delegates on RouterAPI can then be deleted
