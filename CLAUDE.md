# FlintVPN Manager

A local web dashboard for managing ProtonVPN WireGuard and OpenVPN profiles on a GL.iNet Flint 2 (GL-MT6000) router. Runs on a small always-on Linux host on the LAN, serves a Svelte frontend to any device on the LAN.

## Documentation

All project documentation lives in `docs/`:

- [docs/project-overview.md](docs/project-overview.md) — Features, architecture, environment, dependencies
- [docs/terminology.md](docs/terminology.md) — Domain glossary (Group, Device, Rule, Peer, Server Scope, etc.)
- [docs/backend-structure.md](docs/backend-structure.md) — Package layout, dependency graph, import conventions, where to put new code
- [docs/backend-modules.md](docs/backend-modules.md) — Detailed module descriptions per package
- [docs/frontend.md](docs/frontend.md) — Svelte components, stores, API client
- [docs/rest-api.md](docs/rest-api.md) — All REST API endpoints
- [docs/router-reference.md](docs/router-reference.md) — Config naming, limits, tunnel lifecycle, proton-wg, MediaTek constraints
- [docs/design-system.md](docs/design-system.md) — Sentry-inspired design reference
- [docs/design-tokens.md](docs/design-tokens.md) — CSS variable token catalog
- [docs/FEATURES_AND_SPECS.md](docs/FEATURES_AND_SPECS.md) — Detailed user-facing feature specs

### Implementation Internals

**MUST READ before modifying these subsystems** — contains non-obvious constraints, real bugs that were hit, and design decisions that look wrong but are intentional:

- [docs/proton-wg-internals.md](docs/proton-wg-internals.md) — process targeting, mangle ordering, tunnel ID allocation, firewall reload safety
- [docs/smart-protocol.md](docs/smart-protocol.md) — SSE-tick design, RLock threading, cancel semantics, protocol restrictions
- [docs/server-switch-internals.md](docs/server-switch-internals.md) — WG hot-swap vs OVPN teardown, cert handling, latency probe constraints
- [docs/tunnel-strategy-internals.md](docs/tunnel-strategy-internals.md) — Strategy pattern design, protocol behaviour matrix, how to add a new protocol
- [docs/router-layer-internals.md](docs/router-layer-internals.md) — Three-layer router architecture (SSH + tools + facades), constructor injection, testing patterns
- [docs/proton-api-gotchas.md](docs/proton-api-gotchas.md) — persistent vs session certs, cert deletion limitation, library attribute renames, OVPN username suffixes
- [docs/source-of-truth.md](docs/source-of-truth.md) — full field tables, JSON schema, sync mechanisms, ipset naming

## Quick Start

```bash
# Backend
source venv/bin/activate
python backend/app.py            # Flask on http://localhost:5000

# Frontend dev (hot reload on :5173, proxies API to :5000)
cd frontend && npm run dev

# Frontend build (outputs to static/)
cd frontend && npm run build

# Tests
source venv/bin/activate && python -m pytest tests/     # Backend tests
cd frontend && npx vitest run                           # Frontend unit tests
cd frontend && npx playwright test                      # Frontend E2E tests (needs backend running)
cd frontend && npx playwright test --ui                 # E2E with interactive UI
```

## Source-of-Truth Rules

**Every piece of state lives at exactly one source. The router is always the source of truth.** Read [docs/source-of-truth.md](docs/source-of-truth.md) for full details.

- **Router-canonical**: tunnel health, kill switch, profile name, device→VPN assignments (kernel WG + OpenVPN), device info — always read live, never cached locally
- **Router backup is source of truth for profile_store.json**: On every unlock, the app pulls `profile_store.bak.json` from the router and overwrites local. No timestamp comparison. New router (no backup) = clean slate (empty store). Swapping back to old router restores its backup.
- **Proton-canonical**: server name/country/city/load/score — refreshed every ~15min (loads) / ~3h (full list)
- **Local+Router** (`profile_store.json` + ipset): proton-wg device assignments — persisted locally in `device_assignments` for recovery after ipset flush, and applied to router ipsets. Local store is source of truth; router ipsets are derived.
- **Local-only** (`profile_store.json`): color, icon, server_scope, options, wg_key, cert_expiry, non-VPN assignments
- VPN profiles have **no** `name`, `status`, or `kill_switch` field locally
- `display_order` is local (unified across all profile types); router section order is synced for routing priority only

## Router Interaction Safety Rules

**CRITICAL — violating these rules can kill internet for all devices on the network.**

### SAFE commands (OK to run via SSH):
- `uci show/get/set/add_list/del_list/delete/commit/reorder/rename` — config reads/writes
- `/etc/init.d/vpn-client restart` — only when no tunnels are stuck connecting. **Side effect**: flushes ALL `src_mac_*` ipsets (kernel WG/OVPN). Proton-wg ipsets use `pwg_mac_*` prefix and are **immune** to vpn-client restart. Device assignments are also persisted in `.macs` files on the router — the firewall include script (`mangle_rules.sh`) repopulates ipsets from these files on every firewall reload.
- `ipset add/del` — MAC-assignment ipsets
- `/etc/init.d/firewall reload` — safe (~0.22s, WG survives). **NOT** `firewall restart` (re-runs rtp2.sh). See [docs/proton-wg-internals.md](docs/proton-wg-internals.md).
- `wg show`, `ifstatus`, `ipset list`, `iptables -L -n`, `ubus call gl-clients list/status`, `cat`, `grep`, `ls`, `ps` — read-only

### NEVER run these:
- `/etc/init.d/network reload` or `restart` — bricks all routing
- `/etc/init.d/firewall restart` — re-runs `rtp2.sh`, takes locks, deletes our interfaces, corrupts route policy rules
- `rtp2.sh` directly — same reason
- `ifup` / `ifdown` — bypasses vpn-client, creates catch-all routes
- `conntrack -D` — breaks active connections

## Design System Rules

See [docs/design-system.md](docs/design-system.md) for the full Sentry-inspired reference and [docs/design-tokens.md](docs/design-tokens.md) for the token catalog.

- **Always consult design-system.md before creating or modifying UI components**
- **Never hardcode colors, fonts, shadows, or radii in component `<style>` blocks** — use `var(--token-name)` from `frontend/src/app.css` `:root`
- Buttons use uppercase text with `letter-spacing: 0.2px`

## Testing a Change

```bash
# Backend
source venv/bin/activate && python -m pytest tests/ --tb=short

# Frontend unit tests
cd frontend && export NVM_DIR="$HOME/.nvm" && . "$NVM_DIR/nvm.sh" && npx vitest run

# Frontend E2E tests (requires backend running on :5000)
cd frontend && export NVM_DIR="$HOME/.nvm" && . "$NVM_DIR/nvm.sh" && npx playwright test

# Frontend build (must be rebuilt before user tests in browser — Flask serves static/)
cd frontend && export NVM_DIR="$HOME/.nvm" && . "$NVM_DIR/nvm.sh" && npm run build

# Restart server (KEEP secrets.enc and config.json — never delete them)
pkill -f "python backend/app.py"; sleep 1
source venv/bin/activate && nohup python backend/app.py > /tmp/flintvpn.log 2>&1 &
```

## Debugging

### Logs
- `logs/app.log` — actions: connect/disconnect/create/delete/assign
- `logs/error.log` — errors and exceptions with stack traces
- `logs/access.log` — HTTP request log
- Also viewable from Dashboard → Sidebar → Logs

### Common Issues
- **Status out of sync**: check `uci show route_policy.fvpn_rule_XXXX.enabled` and `wg show wgclientN`
- **Device not in expected group**: `uci show route_policy | grep from_mac`, check `_resolve_device_assignments`
- **Orphan `@rule[N]`**: open dashboard to trigger self-heal, or `uci rename` manually
- **VPN slow**: try different server. Filogic 880 does 200–400 Mbps WG (CPU-bound, no HW offload)
- **Connecting forever**: `wg show` (latest handshake), `logread | grep openvpn`

### SSH to Router
```bash
ssh root@192.168.8.1    # Key auth via ~/.ssh/id_ed25519
```

## Environment

- **Python**: 3.14 with `--system-site-packages` venv (for Proton libs from GTK app)
- **Node**: v24 via nvm (`export NVM_DIR="$HOME/.nvm" && . "$NVM_DIR/nvm.sh"`)
- **Router**: GL.iNet Flint 2 (GL-MT6000), firmware 4.8.4, OpenWrt
- **SSH**: Key auth (`~/.ssh/id_ed25519` → router root)
- **ProtonVPN**: Session from GTK app via system keyring. User has 2FA enabled.
