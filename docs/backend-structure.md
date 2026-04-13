# Backend Package Structure

The backend is organized into 8 packages, each with a single responsibility. This document explains what each package owns, how packages depend on each other, and how to find the right place for new code.

## Directory Layout

```
backend/
├── app.py                          # Flask entry point (~84 lines: logging + blueprint registration)
├── cli.py                          # Click CLI entry point
├── consts.py                       # Shared constants (protocols, profile types, health states)
├── service_registry.py             # Runtime singleton lifecycle (RouterAPI, ProtonAPI, VPNService, LanAccessService)
│
├── routes/                         # Flask route blueprints (no business logic)
│   ├── __init__.py
│   ├── _helpers.py                 # Shared: require_unlocked decorator, service getters, location cache
│   ├── auth.py                     # /api/status, /api/setup, /api/unlock, /api/lock
│   ├── profiles.py                 # Profile CRUD, server selection, tunnel control, refresh, latency
│   ├── devices.py                  # /api/devices — listing, labeling, assignment
│   ├── lan_access.py               # /api/lan-access/* — network CRUD, rules, exceptions
│   ├── settings.py                 # /api/settings/*, server prefs, adblock, credentials
│   ├── stream.py                   # /api/stream — SSE live updates (10s tick)
│   └── logs.py                     # /api/logs — log file listing, reading, clearing
│
├── router/                         # Everything that talks to the router via SSH
│   ├── api.py                      # SSH transport + lazy facade/tool hub (~270 lines)
│   ├── types.py                    # TypedDicts (WgRouterInfo, TunnelStatus, etc.)
│   ├── tunnel_id_alloc.py          # Shared tunnel ID allocator (300–399 range)
│   ├── ipset_ops.py                # Proton-wg MAC-based ipset operations
│   ├── noint_sync.py               # NoInternet WAN block enforcement
│   ├── tools/                      # Low-level CLI tool wrappers
│   │   ├── __init__.py             # SshExecutor protocol + re-exports
│   │   ├── uci.py                  # UCI config management
│   │   ├── ipset.py                # Kernel ipset operations
│   │   ├── iptables.py             # iptables chain/rule management
│   │   ├── iproute.py              # iproute2 interface/routing management
│   │   ├── service_ctl.py          # init.d + WiFi service control
│   │   └── wg_show.py              # WireGuard handshake/transfer parsing
│   └── facades/                    # Feature facades (one per router subsystem)
│       ├── policy.py               # Route policy rules, kill switch, naming
│       ├── tunnel.py               # Tunnel up/down, health monitoring
│       ├── firewall.py             # UCI batch apply, ipset CRUD, mDNS
│       ├── devices.py              # DHCP leases, device assignments, static leases
│       ├── wireguard.py            # Kernel WG peer CRUD + live hot-swap
│       ├── openvpn.py              # OpenVPN client CRUD
│       ├── proton_wg.py            # Userspace WG TCP/TLS full lifecycle
│       ├── adblock.py              # DNS blocking dnsmasq + ipset + iptables REDIRECT
│       └── lan_access.py           # Network CRUD, zone forwarding, device exceptions
│
├── services/                       # Business logic orchestrators (no SSH, no Flask)
│   ├── vpn_service.py              # Top-level facade: composes ProfileService + DeviceService + sync
│   ├── profile_service.py          # Profile CRUD + mutations (create, delete, change_type, switch_server, change_protocol)
│   ├── profile_list_builder.py     # Read-only profile list query (merges router + local + Proton)
│   ├── backup_service.py           # Profile store backup/restore to router
│   ├── adblock_service.py          # Blocklist download and merge
│   ├── device_service.py           # Device discovery, assignment, labeling, caching
│   └── lan_access_service.py       # LAN network management + config.json persistence
│
├── proton_vpn/                     # ProtonVPN API integration
│   ├── api.py                      # Login, server list, WG/OVPN config generation
│   ├── server_optimizer.py         # Server scoring, filtering, selection
│   └── latency_probe.py            # TCP latency measurement from router
│
├── vpn/                            # VPN protocol logic (no SSH, no Flask)
│   ├── tunnel_strategy.py          # Strategy pattern: WG/OVPN/ProtonWG operations
│   ├── smart_protocol.py           # Automatic protocol fallback state machine
│   ├── protocol_limits.py          # Protocol slot counting and enforcement
│   ├── profile_healer.py           # Startup self-healing for tunnel ID collisions
│   └── profile_keys.py             # Profile ↔ router key-matching helpers
│
├── persistence/                    # Local data storage (no network, no SSH)
│   ├── profile_store.py            # Atomic JSON read/write for profile_store.json
│   └── secrets_manager.py          # Fernet-encrypted credentials (secrets.enc)
│
└── background/                     # Daemon threads
    ├── auto_optimizer.py            # Server switch + cert renewal + score refresh + blocklist
    └── device_tracker.py            # New-device auto-assignment (polls DHCP every 30s)
```

## Package Dependency Graph

```
                    ┌──────────┐
                    │  app.py  │  cli.py  service_registry.py
                    └────┬─────┘
                         │ uses
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
    ┌──────────┐  ┌───────────┐  ┌────────────┐
    │ services │  │ background│  │ proton_vpn │
    └────┬─────┘  └─────┬─────┘  └────────────┘
         │              │
         │   uses       │ uses
         ▼              ▼
    ┌──────────┐  ┌──────────┐
    │   vpn    │  │  router  │
    └────┬─────┘  └──────────┘
         │              │
         │   uses       │ uses
         ▼              ▼
    ┌─────────────┐
    │ persistence │
    └─────────────┘
```

**Rules:**
- Arrows point downward — a package may only import from packages below it
- `consts.py` is importable by all packages (it has no dependencies)
- `router` never imports from `services`, `vpn`, or `proton_vpn`
- `persistence` never imports from any other package (except `consts`)
- `services` orchestrates `router`, `vpn`, `proton_vpn`, and `persistence`
- `background` threads access `router`, `persistence`, and `proton_vpn` directly

## Package Details

### `router/` — Router Communication

Everything that sends SSH commands to the GL.iNet Flint 2. Organized in three layers:

| Layer | Location | Purpose |
|-------|----------|---------|
| **SSH Transport** | `router/api.py` | Paramiko SSH connection, `exec()`, `write_file()`, `read_file()` |
| **Tool Layer** | `router/tools/` | Typed wrappers for UCI, ipset, iptables, iproute2, service control |
| **Feature Facades** | `router/facades/` | Domain-specific operations (one facade per router subsystem) |

`RouterAPI` in `router/api.py` is the hub — it exposes lazy-loaded properties for both layers. Callers access facades via `router.policy.*`, `router.tunnel.*`, `router.wireguard.*`, etc.

Each facade declares its tool dependencies in its constructor:

```python
class RouterPolicy:
    def __init__(self, uci: Uci, ssh: SshExecutor):
        self._uci = uci
        self._ssh = ssh  # raw exec for grep/pipe queries
```

See [router-layer-internals.md](router-layer-internals.md) for the full design, testing patterns, and conventions.

### `routes/` — Flask Blueprints

Seven blueprints, one per route domain. Each imports shared helpers from `routes/_helpers.py` (the `require_unlocked` decorator, service getters, location cache). No business logic — routes parse requests, delegate to services, and format responses.

| Blueprint | Routes | Purpose |
|-----------|--------|---------|
| `auth.py` | 4 | Status, setup, unlock (bootstraps all services), lock |
| `profiles.py` | 17 | Profile CRUD, server selection, tunnel control, refresh, latency |
| `devices.py` | 3 | Device listing, labeling, assignment |
| `lan_access.py` | 9 | LAN network CRUD, zone forwarding, isolation, exceptions |
| `settings.py` | 12 | App settings, server prefs, adblock, credentials |
| `stream.py` | 1 | SSE live updates (10s tick: health, devices, smart protocol) |
| `logs.py` | 3 | Log file listing, reading, clearing |

### `services/` — Business Logic

Orchestrators that combine router operations, Proton API calls, and local persistence into user-facing workflows. No Flask dependency — testable without HTTP.

| Module | Responsibility |
|--------|---------------|
| `vpn_service.py` | Top-level facade (~276 lines). Composes `ProfileService`, `DeviceService`, `SmartProtocolManager`. Owns tunnel control (connect/disconnect), sync operations, device delegation. |
| `profile_service.py` | Profile CRUD + mutations (~680 lines). `create`, `update`, `delete`, `change_type`, `switch_server`, `change_protocol`, `reorder`, `set_guest`. Uses callbacks for cross-cutting sync. |
| `profile_list_builder.py` | Read-only profile list query (~244 lines). Merges router rules + local store + Proton server data. |
| `backup_service.py` | Profile store backup/restore to router. Silent disaster recovery on unlock. |
| `adblock_service.py` | Blocklist download, merge, and deduplication. |
| `device_service.py` | Device discovery (`build_devices_live`), assignment (`assign_device`), labeling, TTL-based caching. Branches by protocol: kernel WG/OVPN → router, proton-wg → ipset, non-VPN → local store. |
| `lan_access_service.py` | LAN network CRUD, zone forwarding rules, AP isolation, device exceptions. Persists to `config.json`. Orthogonal to VPN routing. |

### `proton_vpn/` — ProtonVPN Integration

Talks to ProtonVPN's API. No router dependency — these modules produce configs that the router layer consumes.

| Module | Responsibility |
|--------|---------------|
| `api.py` | Login (with 2FA), server list, WG/OVPN config generation, cert management, sessions, alternative routing. |
| `server_optimizer.py` | Pure scoring functions: Proton score → blacklist filter → favourite boost → latency tiebreaker. |
| `latency_probe.py` | TCP connect-time measurement **from the router** via SSH. Never locally (Surface Go is behind VPN). |

### `vpn/` — Protocol Logic

Protocol-specific logic that doesn't touch SSH directly. These modules know about VPN protocols but delegate router operations to the router package.

| Module | Responsibility |
|--------|---------------|
| `tunnel_strategy.py` | Strategy pattern: `WireGuardStrategy`, `OpenVPNStrategy`, `ProtonWGStrategy`. Uniform interface for create/delete/connect/disconnect/switch/health. |
| `smart_protocol.py` | Automatic protocol fallback: WG UDP → WG TCP → WG TLS → OVPN UDP → OVPN TCP (45s timeout per attempt). |
| `protocol_limits.py` | Slot enforcement: max 5 WG, 4 proton-wg, 5 OVPN. |
| `profile_healer.py` | Startup self-healing for duplicate tunnel IDs (proton-wg ipset collisions). |
| `profile_keys.py` | Stable `(protocol, peer_id)` tuples for matching local profiles to router rules. |

See [tunnel-strategy-internals.md](tunnel-strategy-internals.md) for the strategy pattern design.

### `persistence/` — Local Storage

Pure data access — no network, no SSH, no business logic.

| Module | Responsibility |
|--------|---------------|
| `profile_store.py` | Atomic JSON read/write for `profile_store.json`. Stores UI metadata, non-VPN assignments, WG keys, cert expiry. |
| `secrets_manager.py` | Fernet encryption (AES-128-CBC + HMAC-SHA256, PBKDF2) for `secrets.enc`. |

### `background/` — Daemon Threads

Long-running background tasks that poll for changes.

| Module | Responsibility |
|--------|---------------|
| `auto_optimizer.py` | Polls every 60s. Four jobs: server data refresh (~15min), server optimization (daily), cert renewal (daily), blocklist update (daily). |
| `device_tracker.py` | Polls DHCP every 30s. Auto-assigns new MACs to guest profile. |

## Import Conventions

```python
# Router package
from router.api import RouterAPI
from router.tools.uci import Uci
from router.facades.policy import RouterPolicy

# Services
from services.vpn_service import VPNService

# ProtonVPN
from proton_vpn.api import ProtonAPI

# VPN protocol logic
from vpn.tunnel_strategy import get_strategy

# Persistence
import persistence.profile_store as ps
import persistence.secrets_manager as sm

# Background
from background.device_tracker import DeviceTracker

# Shared constants (importable from anywhere)
from consts import PROTO_WIREGUARD, HEALTH_GREEN
```

## Where to Put New Code

| You're adding... | Put it in... | Why |
|-----------------|-------------|-----|
| A new router CLI tool wrapper | `router/tools/` | Tool layer — consistent quoting/idempotency |
| A new router feature (e.g. QoS) | `router/facades/` | One facade per router subsystem |
| A new VPN protocol | `vpn/tunnel_strategy.py` + `router/facades/` | Strategy subclass + router facade |
| Business logic that combines router + Proton | `services/` | Orchestration layer |
| A new background polling job | `background/` | Daemon threads |
| A new ProtonVPN API feature | `proton_vpn/` | Proton integration |
| Local data storage | `persistence/` | No network deps |
| A shared constant | `consts.py` | Cross-package constants |

## Testing Structure

Tests mirror the source structure:

```
tests/
├── conftest.py                     # Shared fixtures
├── test_app.py                     # Flask endpoint tests
├── test_router_api.py              # RouterAPI + facade integration tests
├── test_vpn_service.py             # VPN service tests
├── test_tunnel_strategy.py         # Strategy pattern tests
├── test_device_tracker.py          # Device tracker tests
├── test_auto_optimizer.py          # Auto optimizer tests
├── test_ipset_ops.py               # IpsetOps tests
├── test_noint_sync.py              # NoInternet sync tests
├── test_lan_access.py              # LAN access service tests
├── test_protocol_limits.py         # Protocol limits tests
├── test_latency_probe.py           # Latency probe tests
├── test_proton_api.py              # ProtonVPN API tests
├── test_server_optimizer.py        # Server optimizer tests
├── test_profile_store.py           # Profile store tests
├── test_secrets.py                 # Secrets manager tests
└── test_router_tools/              # Tool layer unit tests
    ├── test_uci.py
    ├── test_ipset.py
    ├── test_iptables.py
    ├── test_iproute.py
    ├── test_service_ctl.py
    ├── test_wg_show.py
    └── test_integration.py         # Live router integration tests
```

Tests marked `@pytest.mark.integration` require a live router connection and are excluded from normal runs.
