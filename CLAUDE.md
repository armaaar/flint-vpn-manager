# FlintVPN Manager

A local web dashboard for managing ProtonVPN WireGuard and OpenVPN profiles on a GL.iNet Flint 2 (GL-MT6000) router. Runs on a Surface Go 2 (Ultramarine Linux), serves a Svelte frontend to any device on the LAN.

## Quick Start

```bash
# Backend
source venv/bin/activate
python app.py                    # Flask on http://localhost:5000

# Frontend dev (hot reload on :5173, proxies API to :5000)
cd frontend && npm run dev

# Frontend build (outputs to static/)
cd frontend && npm run build

# Tests
source venv/bin/activate && python -m pytest tests/     # Backend tests
cd frontend && npx vitest run                           # Frontend tests
```

## Architecture

```
Surface Go 2 (this machine)          GL.iNet Flint 2 Router
┌──────────────────────────┐         ┌─────────────────────────┐
│  Flask (app.py :5000)    │──SSH──▶│  OpenWrt + GL.iNet FW   │
│  Svelte (static/)        │         │  WireGuard / OpenVPN    │
│  ProtonVPN API (keyring) │         │  route_policy + ipset   │
│  profile_store.json      │         │  vpn-client service     │
│  secrets.enc, config.json│         │  fvpn_lan iptables      │
└──────────────────────────┘         └─────────────────────────┘
```

## Source-of-Truth Rules

The hardest design constraint in this project. Every piece of state lives at exactly one source. Local JSON only holds fields that have **no** native router or Proton API source.

### Router-canonical (read live, never cached)

| State | UCI / runtime location |
|-------|------------------------|
| VPN tunnel rule existence + name | `route_policy.fvpn_rule_*` (named) or `@rule[N]` (anonymized by GL.iNet UI) |
| Tunnel health (green/amber/red/connecting) | `wg show`, `ifstatus`, `route_policy.{rule}.enabled` |
| Kill switch | `route_policy.{rule}.killswitch` |
| Profile name | `route_policy.{rule}.name` + `wireguard.{peer}.name` + `ovpnclient.{client}.name` (atomic 3-write) |
| WG endpoint | `wireguard.{peer_id}.end_point` |
| **Device → VPN profile** | `route_policy.{rule}.from_mac` (+ `src_mac{tunnel_id}` ipset) |
| Display order (VPN profiles) | Section order in `/etc/config/route_policy` |
| Device hostname / IP | `/tmp/dhcp.leases` |
| Device label / device class | `gl-client.{section}.alias` / `.class` |
| Device online / speeds / signal | `ubus call gl-clients list` |
| NoInternet firewall rules | `firewall.fvpn_noinet_<mac>_lan` + `_drop` |

### Proton-canonical (resolved on demand by `server_id`)

Server name, country, city, load, features, score → resolved via `proton.get_server_by_id()` (which the `proton-vpn-api-core` lib caches in memory). The local store keeps **only** `server_id` + a tiny cache of fields that come from physical-server selection at config-gen time (`endpoint`, `physical_server_domain`, `protocol`).

### Local-only (`profile_store.json`)

Fields with no router or Proton native source:

```json
{
  "profiles": [
    {
      "id": "<uuid>",
      "type": "vpn|no_vpn|no_internet",
      "color": "#3498db",
      "icon": "🔒",
      "is_guest": false,
      "router_info": { "rule_name": "fvpn_rule_9001", "peer_id": "9001", "vpn_protocol": "wireguard" },
      "server_id": "<proton id>",
      "server": { "id": "...", "endpoint": "...", "physical_server_domain": "...", "protocol": "openvpn-tcp" },
      "server_scope": { "type": "country", "country_code": "DE" },
      "options": { "netshield": 2, "moderate_nat": false, "nat_pmp": false, "vpn_accelerator": true, "secure_core": false },
      "lan_access": { "outbound": "allowed", "inbound": "allowed" }
    },
    {
      "id": "<uuid>",
      "type": "no_vpn",
      "name": "Direct",
      "color": "#888",
      "icon": "🌐",
      "is_guest": false,
      "lan_access": { "outbound": "allowed", "inbound": "allowed" },
      "display_order": 1
    }
  ],
  "device_assignments": { "aa:bb:cc:dd:ee:ff": "<non-vpn profile uuid>" },
  "device_lan_overrides": { "aa:bb:cc:dd:ee:ff": { "outbound": "blocked", "inbound": "allowed" } }
}
```

Notes:
- VPN profiles have **no** `name` field (read live from router) and **no** `display_order` (router section order).
- VPN profiles have **no** `status` or `kill_switch` fields (read live).
- `device_assignments` only contains non-VPN assignments. VPN device→profile lookup goes through `router.get_device_assignments()` which parses `from_mac` lists.
- Display name precedence for devices: `gl-client.alias` (router-canonical custom label) → DHCP hostname → MAC.
- Non-VPN profiles always render after VPN profiles in the dashboard, sorted among themselves by `display_order`.

### Why some things stay local

- **Color, icon, is_guest, server_scope, options, lan_access**: pure UI/intent metadata, no router-native concept
- **`server_id`**: the link from a local profile to a Proton server (no way to derive it from the router config alone)
- **`lan_access` 3-state policy** (`allowed`/`group_only`/`blocked`): iptables rules can't be parsed back to that semantic, even though they're applied on the router
- **`device_lan_overrides`**: same — local source, iptables is the execution layer
- **NoVPN/NoInternet group identity**: multiple no-internet groups can coexist with identical router-side firewall rules; only the local store can distinguish them
- **Non-VPN device assignments**: derived from local store (router has no concept)

## Source-of-Truth Sync Mechanisms

### `build_profile_list(router, store_data, proton)` — `app.py`
Single function that produces the canonical profile list. Iterates `router.get_flint_vpn_rules()` first, merges in local UI metadata by stable `(vpn_protocol, peer_id|client_id)` key (so renamed sections still match), resolves server info live via `_resolve_server_live(proton, ...)`. Returns VPN profiles in router section order followed by non-VPN sorted by `display_order`. Detects:
- **Ghost profiles**: local profile whose router rule was deleted out from under us → `_ghost: true`, `health: red`
- **Orphan profiles**: router rule with no matching local metadata → `_orphan: true`
- **Anonymous-section healing**: when GL.iNet UI replaces `fvpn_rule_9001` with `@rule[N]`, the matcher finds it by `peer_id`/`client_id` and `router.heal_anonymous_rule_section()` issues `uci rename` to restore the canonical name on the next read

### `_build_devices_live(router)` — `app.py`
Live device list builder. Queries `router.get_dhcp_leases()` + `router.get_client_details()` + `_resolve_device_assignments()`. Wrapped by `_get_devices_cached()` with a 5-second TTL to throttle SSH calls during rapid SSE ticks. Cache is invalidated on every SSE tick (10s), on `api_set_device_label`, and on `api_assign_device`. Hostname fallback chain: DHCP → gl-clients `name` → MAC.

### `_resolve_device_assignments(router, store_data)` — `app.py`
Returns `{mac: profile_id}` merging router VPN assignments (canonical via `from_mac`) with local non-VPN assignments. Matching VPN rules to local profiles uses the stable `(protocol, peer_id|client_id)` key.

### `_reconcile_no_internet_rules()` — `app.py`
NoInternet firewall rules (`firewall.fvpn_noinet_<mac>_*`) are the **execution layer**; local `device_assignments` is the source. This helper makes the router state match the local source by adding/removing firewall rules. Triggered on session unlock, `api_assign_device` (when old or new profile is no_internet), and `api_delete_profile` (when a no_internet profile is removed). Self-healing after router reboot.

### `_rebuild_lan_rules()` — `app.py`
Rebuilds the entire `fvpn_lan` iptables chain from local LAN settings. Triggered on session unlock, profile create/delete, device assignment change, LAN setting change, and SSE tick when `tracker.lan_rules_stale` is set (an IP for a restricted device changed). Device IPs come live from `router.get_dhcp_leases()`, not from any local cache.

### SSE stream — `api_stream()` in `app.py`
Every 10 seconds, builds the merged profile list and pushes:
- `tunnel_health[profile_id]` — live router health
- `kill_switch[profile_id]` — live router kill_switch
- `profile_names[profile_id]` — live router name (so SSH-side renames propagate)
- `better_servers[profile_id]` — passive auto-optimize hint (every 3rd tick)
- `devices[]` — full live device list

The frontend's Svelte stores are mutated in place from each event. No local persistence of any of these fields.

### Auto-optimizer — `auto_optimizer.py`
Background thread. At a configured time of day (within a 2-minute window to tolerate clock drift), it reads the live merged profile list via `build_profile_list_fn(router, data, proton)` and calls `find_better_server` for each VPN profile whose **live `health`** (not cached status) is `green`/`amber`. Uses `_switch_server` to apply changes.

## Terminology

| Term | Meaning |
|------|---------|
| **Group** | A profile devices are assigned to. Three types: VPN, NoVPN (direct), NoInternet (LAN-only). |
| **Device** | A network client identified by MAC. Discovered live from DHCP + `ubus gl-clients`. |
| **Rule** | A `route_policy` UCI entry mapping device MACs (via `src_mac{tunnel_id}` ipset + `from_mac` list) to a tunnel via fwmark routing. |
| **Peer** | A WireGuard peer in `/etc/config/wireguard` (`peer_9001`–`peer_9050`). |
| **Client** | An OpenVPN client in `/etc/config/ovpnclient` (`28216_9051`–`28216_9099`) + `.ovpn` file in `/etc/openvpn/profiles/`. |
| **Kill Switch** | Route policy flag. When the tunnel drops, assigned devices' packets are blackholed instead of leaking. Live from `route_policy.{rule}.killswitch`. |
| **Private MAC** | Randomized MAC (2nd hex char ∈ `{2,6,A,E}`). VPN routing by MAC won't persist across reconnects. |
| **Server Scope** | How a group selects its server: `country` (best in country), `city` (best in city), or `server` (specific, never auto-switched). |
| **Auto-Optimizer** | Background thread that periodically switches VPN groups to better-loaded servers. Only profiles with scope ≠ `server`. |
| **LAN Access** | Per-group or per-device firewall rules controlling LAN-to-LAN traffic. Three states: `allowed`, `group_only`, `blocked`. Inbound and outbound independent. |
| **NetShield** | ProtonVPN DNS-level ad/malware blocking. Level 0=off, 1=malware, 2=malware+ads+trackers. Baked into the WG/OVPN config at generation time. |
| **Guest Group** | The group new (previously unseen) MACs are auto-assigned to by the device tracker. Any group type (VPN/NoVPN/NoInternet) can be the guest group. |
| **Anonymous section** | A `@rule[N]` route_policy section (positional reference) created when the GL.iNet UI edits one of our rules. We self-heal these back to `fvpn_rule_*` named sections by matching on `peer_id`/`client_id`. |

## Backend Modules

### `app.py` — Flask REST API + SSE
Main server. All API endpoints, SSE stream, profile-list builder, device-list builder, NoInternet reconciler, LAN rule rebuilder.

### `proton_api.py` — ProtonVPN wrapper
Thin synchronous wrapper around `proton-vpn-api-core`. Login (with 2FA), server list, WG/OVPN config generation. Exposes `server_to_dict()` for live server resolution by `build_profile_list`.

### `router_api.py` — Router SSH management
SSH-based API (Paramiko + key auth) for the Flint 2. Manages WG/OVPN configs via UCI, route policy rules, ipset membership, firewall rules, DHCP leases, gl-clients metadata. Helpers: `get_flint_vpn_rules`, `get_device_assignments`, `get_tunnel_health`, `get_kill_switch`, `get_profile_name`, `rename_profile`, `reorder_vpn_rules`, `heal_anonymous_rule_section`, `_from_mac_tokens` (for case-preserving del_list).

### `profile_store.py` — Local JSON persistence
Atomic JSON read/write for the slim local store (UI metadata + non-VPN assignments + LAN overrides). `_sanitize_mac_keys()` strips legacy fields on every save so post-refactor data is automatically cleaned up.

### `device_tracker.py` — Background new-device auto-assigner
Minimal background thread. Polls DHCP leases every 30s. The **only** thing it persists is auto-assigning newly-discovered MACs to the guest profile (writes to router for VPN guest, local store for non-VPN guest). Maintains an in-memory `_known_macs` set and `lan_rules_stale` flag for IP-change detection.

### `secrets_manager.py` — Encrypted credentials
Fernet (AES-128-CBC + HMAC-SHA256) with PBKDF2 key derivation. Stores ProtonVPN and router credentials in `secrets.enc`.

### `server_optimizer.py` — Server load comparison
Pure function `find_better_server(profile, servers, threshold)`. Used by SSE passive hints (threshold=20) and auto-optimizer (threshold=30).

### `auto_optimizer.py` — Background server switcher
Daemon thread; uses live router health via `build_profile_list`. Within a 2-minute window after the scheduled time, switches each eligible VPN profile to a better server.

### `cli.py` — Click-based terminal interface
Wraps the same backend. Commands: setup, unlock, status, server browse, router status/devices/tunnels, profile CRUD, device assignment, settings.

## Frontend (Svelte + Vite)

Built with Svelte 5 + Vite. Source in `frontend/src/`, builds to `static/`.

### Components
| Component | Purpose |
|-----------|---------|
| `Dashboard.svelte` | Sidebar + group cards (DnD reorderable) + unassigned devices section |
| `GroupCard.svelte` | Aircove-style card: gradient header, server info, connect/disconnect button, collapsible VPN options panel, device list (DnD) |
| `DeviceRow.svelte` | Device in a group: icon, name, online dot, IP, speed, signal, private-MAC badge |
| `DeviceModal.svelte` | Device settings: custom name, device type (synced to router gl-client), group assignment |
| `CreateGroupModal.svelte` | New group: type selector, protocol cards (WG/OVPN UDP/OVPN TCP), server picker trigger |
| `EditGroupModal.svelte` | Edit existing group: name, icon, color, guest toggle, **VPN Options section** (kill switch, NetShield, accelerator, NAT options), LAN access, delete |
| `ServerPicker.svelte` | 3-level server browser: Country → City → Server. Filters, scope selector. **No VPN options** — those live in EditGroupModal |
| `EmojiPicker.svelte` | Categorized emoji grid with search |
| `ColorPicker.svelte` | Color selection for card accent |
| `SettingsModal.svelte` | Router IP, credentials, master password change |
| `LogsModal.svelte` | Live log viewer (app.log, error.log, access.log) with tabs |
| `SetupScreen.svelte` | First-time credential setup |
| `UnlockScreen.svelte` | Master password entry |
| `Toast.svelte` | Notification toasts |

### Stores (`frontend/src/lib/stores/app.js`)
Writable: `profiles`, `devices`, `appStatus`, `protonLoggedIn`, `toastMessage`, `movingDevices`, `betterServers`. Derived: `unassignedDevices`. SSE handler mutates `p.health`, `p.kill_switch`, `p.name` from each event.

### API Client (`frontend/src/lib/api.js`)
One function per Flask endpoint via `fetch()`.

## REST API

```
GET  /api/status                        → setup-needed | locked | unlocked
POST /api/setup                         → first-time credential setup
POST /api/unlock                        → unlock with master password

GET  /api/profiles                      → live merged profile list (router + local + Proton)
POST /api/profiles                      → create group (VPN/NoVPN/NoInternet)
PUT  /api/profiles/reorder              → split: VPN → uci reorder, non-VPN → local display_order
PUT  /api/profiles/:id                  → update metadata (name, color, icon, kill_switch)
DELETE /api/profiles/:id                → delete group + router cleanup + LAN rebuild + NoInternet reconcile

GET  /api/profiles/:id/servers          → ProtonVPN server list (filtered)
PUT  /api/profiles/:id/server           → switch server (regenerate tunnel, carry over devices)
POST /api/profiles/:id/connect          → bring tunnel up; returns live health
POST /api/profiles/:id/disconnect       → bring tunnel down; returns live health
PUT  /api/profiles/:id/guest            → set as guest group

GET  /api/devices                       → live device list (5s in-memory TTL)
PUT  /api/devices/:mac/profile          → assign device (router for VPN, local for non-VPN)
PUT  /api/devices/:mac/label            → write to gl-client.alias and .class on router
PUT  /api/profiles/:id/lan-access       → set group LAN policy
PUT  /api/devices/:mac/lan-access       → set per-device LAN override

POST /api/refresh                       → trigger device tracker poll
GET  /api/stream                        → SSE: tunnel_health + kill_switch + profile_names + devices (10s)

GET  /api/logs                          → list log files
GET  /api/logs/:name                    → tail log content
DELETE /api/logs/:name                  → clear a log

GET  /api/settings                      → non-sensitive config
PUT  /api/settings                      → update router IP etc
PUT  /api/settings/credentials          → update encrypted creds
PUT  /api/settings/master-password      → change master password

GET  /                                  → serve Svelte frontend (static/index.html)
```

## Router Interaction Safety Rules

**CRITICAL — violating these rules can kill internet for all devices on the network.**

### SAFE commands (OK to run via SSH):
- `uci show/get/set/add_list/del_list/delete/commit/reorder/rename` — config reads/writes
- `/etc/init.d/vpn-client restart` — only when no tunnels are stuck connecting
- `ipset add/del` — for `src_mac{tunnel_id}` ipsets (the safe MAC-assignment path)
- `wg show`, `ifstatus`, `ipset list`, `iptables -L -n` — read-only
- `ubus call gl-clients list/status` — read-only
- `cat`, `grep`, `ls`, `ps` — read-only

### NEVER run these:
- `/etc/init.d/network reload` or `restart` — bricks all routing
- `/etc/init.d/firewall reload` — can break active connections
- `rtp2.sh` — takes locks, deletes our interfaces, corrupts route policy rules
- `ifup` / `ifdown` — bypasses vpn-client, creates catch-all routes
- `conntrack -D` — breaks active connections

### Device assignment uses `ipset`, never `rtp2.sh`
`router.set_device_vpn`, `remove_device_from_vpn`, `remove_device_from_all_vpn`, and `set_kill_switch` use `ipset add/del` for immediate effect plus `uci commit` for persistence. The `src_mac{tunnel_id}` ipset is referenced by an existing iptables MARK rule (set up at tunnel creation by vpn-client). Adding a MAC to the ipset takes effect on the next packet — no daemon restart needed.

**Case sensitivity gotcha**: UCI's `del_list` requires an EXACT-match value. `_from_mac_tokens()` reads existing MACs preserving their case so `del_list` uses the stored case (uppercase from GL.iNet UI vs. lowercase from us).

### Tunnel lifecycle
1. Create WG peer (`/etc/config/wireguard`) or OVPN client (`/etc/config/ovpnclient` + `.ovpn` file under `/etc/openvpn/profiles/`)
2. Create a route_policy rule: `via_type='wireguard'|'openvpn'`, `peer_id`/`client_id`, `group_id`, `from='src_mac{tunnel_id}'`, `from_type='ipset'`
3. Connect: `uci set route_policy.{rule}.enabled='1'` + `uci commit` + `/etc/init.d/vpn-client restart`. vpn-client's `setup_instance_via.lua` reads our rule, creates the network interface, starts the tunnel, and sets up the iptables MARK rule.
4. Disconnect: disable kill switch, disable the rule, `vpn-client restart`, restore kill switch.

### Server switch (`_switch_server`)
1. **Capture devices currently in the OLD rule's `from_mac` BEFORE deleting it** (Stage 5 fix — VPN device assignments are router-canonical, so we must read them from the router before tearing down)
2. Delete old WG peer / OVPN client + route_policy rule
3. Generate new config from Proton (with same options)
4. Upload and create the new rule
5. Re-add captured MACs to the new rule's `from_mac` + ipset
6. `bring_tunnel_up`

### Router limits
- **5 WireGuard tunnels** (`wgclient1`–`wgclient5`, marks `0x1000`–`0x5000`)
- **5 OpenVPN tunnels** (`ovpnclient1`–`ovpnclient5`, marks `0xa000`–`0xe000`)
- **10 total simultaneous VPN tunnels**
- **150 DHCP devices** (pool `.100`–`.249`)
- **65,536 MACs per ipset** (per-group device limit)

## File Transfer to Router

The router runs Dropbear (no SFTP). Use `write_file()` in `router_api.py` which pipes content through SSH stdin:

```python
router.write_file("/path/on/router", content_string)
# Uses: cat > /path via stdin pipe — no escaping issues
```

Never use heredocs or base64 — they corrupt certificates and keys.

## GL.iNet-Compatible Config Naming

| Protocol | UCI Section | ID Range | `group_id` |
|----------|-------------|----------|-----------|
| WireGuard | `wireguard.peer_NNNN` | 9001–9050 | `1957` (FromApp) |
| OpenVPN | `ovpnclient.28216_NNNN` | 9051–9099 | `28216` (FromApp) |
| Route Policy (WG) | `route_policy.fvpn_rule_NNNN` | — | — |
| Route Policy (OVPN) | `route_policy.fvpn_rule_ovpn_NNNN` | — | — |

These names make our configs visible in the GL.iNet router dashboard (http://192.168.8.1) as a fallback.

## Debugging

### Logs
- `logs/app.log` — actions: connect/disconnect/create/delete/assign
- `logs/error.log` — errors and exceptions with stack traces
- `logs/access.log` — HTTP request log
- Also viewable from Dashboard → Sidebar → Logs

### Common issues
- **Status out of sync**: shouldn't happen — every read goes to the router. Check: `uci show route_policy.fvpn_rule_XXXX.enabled` and `wg show wgclientN`.
- **Device not in expected group**: read live with `router.get_device_assignments()` (in CLI) or `uci show route_policy | grep from_mac`. Check `_resolve_device_assignments` mapping by `(protocol, peer_id|client_id)`.
- **Anonymous `@rule[N]` showing in dashboard as orphan**: open the dashboard to trigger `build_profile_list` self-heal, OR `uci rename route_policy.@rule[N]=fvpn_rule_NNNN && uci commit route_policy`.
- **VPN connects but very slow**: try a different Proton server. Filogic 880 typically does 200–400 Mbps WG; pure software path with no `flow_offloading`. The `flow_offloading` toggle helps the LAN-side path but doesn't accelerate WG encryption (which is always CPU-bound).
- **Connecting forever**: check `wg show` (latest handshake) and `logread | grep openvpn`.

### Testing a change
```bash
# Backend
source venv/bin/activate && python -m pytest tests/ --tb=short

# Frontend (must be rebuilt before user tests in browser — Flask serves static/)
cd frontend && export NVM_DIR="$HOME/.nvm" && . "$NVM_DIR/nvm.sh" && npm run build

# Restart server (KEEP secrets.enc and config.json — never delete them)
pkill -f "python app.py"; sleep 1
source venv/bin/activate && nohup python app.py > /tmp/flintvpn.log 2>&1 &
```

### SSH to router
```bash
ssh root@192.168.8.1    # Key auth via ~/.ssh/id_ed25519
```

## Environment

- **Python**: 3.14 with `--system-site-packages` venv (for Proton libs from GTK app)
- **Node**: v24 via nvm (`export NVM_DIR="$HOME/.nvm" && . "$NVM_DIR/nvm.sh"`)
- **Router**: GL.iNet Flint 2 (GL-MT6000), firmware 4.8.4, OpenWrt
- **SSH**: Key auth (`~/.ssh/id_ed25519` → router root)
- **ProtonVPN**: Session from GTK app via system keyring. User has 2FA enabled.

## Key Dependencies

### Backend (requirements.txt)
- `flask` — REST API server
- `paramiko` — SSH client for router management
- `cryptography` — Fernet encryption for secrets
- `click` — CLI framework
- `proton-vpn-api-core` — ProtonVPN official library (system-wide)
- `pytest` — test framework

### Frontend (frontend/package.json)
- `svelte` — UI framework
- `vite` — build tool + dev server
- `svelte-dnd-action` — drag and drop for groups and devices
- `vitest` — test framework
- `happy-dom` — test environment

## Device Type Mapping (GL.iNet ↔ Dashboard)

Both the dashboard and the router use the same UCI `gl-client.{section}.class` device class strings. Changes sync bidirectionally via `api_set_device_label` writing to `gl-client.{section}.alias` and `.class`:

`computer`, `phone`, `pad`, `camera`, `watch`, `laptop`, `printer`, `sound`, `television`, `smartappliances`, `games`, `gateway`, `nas`, `server`, `switch`
