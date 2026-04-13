# FlintVPN Manager

A local web dashboard for managing ProtonVPN WireGuard and OpenVPN profiles on a GL.iNet Flint 2 (GL-MT6000) router. Runs on a Surface Go 2 (Ultramarine Linux), serves a Svelte frontend to any device on the LAN.

## Features

- **3 VPN protocols**: WireGuard UDP (fastest), WireGuard TCP/TLS (bypasses firewalls), OpenVPN UDP/TCP (most compatible)
- **Up to 14 simultaneous tunnels**: 5 WG UDP + 4 WG TCP/TLS + 5 OpenVPN
- **Per-device VPN routing**: assign any device to any VPN group via MAC-based ipset rules
- **Persistent WireGuard certificates**: 365-day certs, router works standalone without the Surface Go
- **Auto-optimizer**: daily background task switches VPN groups to faster servers (by Proton score + latency tiebreaker)
- **Server score refresh**: background thread keeps Proton server scores fresh (~15min loads, ~3h full list)
- **Server blacklist & favourites**: exclude bad servers, prefer known-good ones — persisted in `config.json`
- **Latency probing**: TCP connect-time measurement from the router's direct WAN to VPN server IPs
- **Auto cert renewal**: background daily check refreshes WG certs within 30 days of expiry
- **Server picker**: 3-level browser (Country → City → Server) with star/ban toggles and latency test
- **Kill switch**: per-group packet blackholing when tunnel drops (kernel WG via UCI, proton-wg via blackhole route)
- **WireGuard Stealth/TLS**: traffic looks like normal HTTPS — hardest to detect and block
- **Tor server routing**: filter and connect through ProtonVPN's Tor exit nodes for .onion access
- **Port selection**: choose alternate ports per protocol (WG: 443/88/1224/51820/500/4500, OVPN UDP: 80/51820/4569/1194/5060, OVPN TCP: 443/7770/8443) when ISPs block defaults
- **Smart Protocol**: automatic protocol fallback — if a tunnel doesn't connect within 45s, cycles through WireGuard → OpenVPN → WG TCP/TLS until one works
- **Custom DNS**: per-profile DNS override (e.g. Pi-hole, AdGuard) instead of Proton's default resolver
- **Alternative routing**: DNS-over-HTTPS transport fallback for API calls when Proton servers are blocked (censored networks)
- **DNS Ad Blocker**: per-group DNS-level ad/tracker/malware blocking via second dnsmasq instance with community blocklists (OISD). Stacks with NetShield.
- **LAN access control**: create/delete networks, per-network isolation, cross-network access rules with device exceptions, enforced via separate subnets and fw3 zone forwarding
- **NetShield status**: prominent protection-level display on group cards (active indicator when connected)
- **Location/IP check**: sidebar widget showing current public IP, country, and ISP as seen by ProtonVPN
- **Active sessions**: view all connected VPN sessions on the Proton account with exit IP and protocol
- **Live dashboard**: SSE-powered real-time tunnel health, device status, speeds
- **Disaster recovery**: local state backed up to router, auto-restored on unlock
- **GL.iNet compatible**: configs visible in the router's native dashboard as fallback

## Implementation Notes

**MUST READ before modifying these subsystems** — contains non-obvious constraints, real bugs that were hit, and design decisions that look wrong but are intentional:

- [docs/proton-wg-internals.md](docs/proton-wg-internals.md) — process targeting, mangle ordering, tunnel ID allocation, firewall reload safety
- [docs/smart-protocol.md](docs/smart-protocol.md) — SSE-tick design, RLock threading, cancel semantics, protocol restrictions
- [docs/server-switch-internals.md](docs/server-switch-internals.md) — WG hot-swap vs OVPN teardown, cert handling, latency probe constraints
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
cd frontend && npx vitest run                           # Frontend tests
```

## Architecture

```
Surface Go 2 (this machine)          GL.iNet Flint 2 Router
┌──────────────────────────┐         ┌─────────────────────────┐
│  Flask (backend/ :5000)  │──SSH──▶│  OpenWrt + GL.iNet FW   │
│  Svelte (static/)        │         │  WireGuard / OpenVPN    │
│  ProtonVPN API (keyring) │         │  route_policy + ipset   │
│  profile_store.json      │         │  vpn-client service     │
│  secrets.enc, config.json│         │  proton-wg (TCP/TLS)    │
│                          │         │  fvpn_noint ipset       │
└──────────────────────────┘         └─────────────────────────┘
```

## Source-of-Truth Rules

**Every piece of state lives at exactly one source.** Read [docs/source-of-truth.md](docs/source-of-truth.md) for the full schema, field tables, and sync mechanisms.

Key rules:
- **Router-canonical**: tunnel health, kill switch, profile name, device→VPN assignments, device info — always read live, never cached locally
- **Proton-canonical**: server name/country/city/load/score — refreshed every ~15min (loads) / ~3h (full list)
- **Local-only** (`profile_store.json`): color, icon, server_scope, options, wg_key, cert_expiry, non-VPN assignments
- VPN profiles have **no** `name`, `status`, or `kill_switch` field locally
- `display_order` is local (unified across all profile types); router section order is synced for routing priority only

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
| **Server Scope** | How a group selects its server. Three levels (`country_code`, `city`, `server_id`) + `features` filter. Cascade: null forces narrower levels to null. `entry_country_code` only for `secure_core=true`. See `profile_store.normalize_server_scope`. |
| **Auto-Optimizer** | Background thread switching VPN groups to better servers within scope. Applies blacklist/favourites/latency. Skipped for pinned `server_id`. |
| **Server Blacklist** | IDs excluded from auto-selection. `config.json`. Mutually exclusive with favourites. |
| **Server Favourites** | IDs preferred when scores are close (30% tolerance). `config.json`. |
| **Latency Probe** | TCP connect-time to port 443. **Always from router** (never local). `curl -w "%{time_connect}"`. Tiebreaker within 15% score. |
| **NetShield** | DNS ad/malware blocking. 0=off, 1=malware, 2=malware+ads+trackers. |
| **Guest Group** | Auto-assign target for new MACs. Any group type. |
| **DNS Ad Blocker** | Per-group DNS-level blocking via second dnsmasq on port 5353. `fvpn_adblock_macs` hash:mac ipset + iptables REDIRECT in `policy_redirect` chain. Profile field `adblock: true/false`. VPN + NoVPN groups only. |
| **Anonymous section** | `@rule[N]` from GL.iNet UI edits. Self-healed to `fvpn_rule_*` by `heal_anonymous_rule_section`. |
| **proton-wg** | Userspace WG (TCP/TLS). ARM64 binary at `/usr/bin/proton-wg`. FlintVPN-managed. |
| **Persistent cert** | 365-day WG cert, `Mode: "persistent"`. Per-profile Ed25519 key. No local agent needed. |
| **Smart Protocol** | Auto protocol fallback: 45s timeout → cycles WG UDP → OVPN UDP → OVPN TCP → WG TCP → WG TLS. See [docs/smart-protocol.md](docs/smart-protocol.md). |
| **Custom DNS** | Per-profile DNS override (**kernel WG UDP only**). Single IPv4 (`ipaddress.IPv4Address`). Disables NetShield DNS. |
| **Port Override** | Alternate ports per protocol from Proton's `clientconfig`. |
| **Alternative Routing** | DoH fallback for API calls via `proton-vpn-api-core`'s `AutoTransport`. |
| **Tor Server** | Tor exit node routing via `tor` feature flag in `server_scope.features`. |
| **Network (LAN Access)** | A zone on the router with its own bridge, subnet, and (optionally) SSIDs. Discovered from UCI `wireless`/`network`/`firewall`. Identified by zone name (e.g. `lan`, `guest`). |
| **Zone Forwarding** | A `firewall.forwarding` UCI entry allowing traffic between two fw3 zones. Presence = allowed, absence = blocked. Managed by `router_lan_access.set_zone_forwarding()`. |
| **AP Isolation** | Per-SSID `wireless.*.isolate` flag. When enabled, WiFi clients on the same SSID cannot communicate directly (packets go through the router). Toggled via `router_lan_access.set_wifi_isolation()`. |
| **Device Exception** | An iptables ACCEPT rule in `forwarding_rule` chain allowing a specific device (by IP) to communicate across blocked networks. Persisted in `config.json` under `lan_access.exceptions`, re-applied on unlock. |

## Backend Modules (`backend/`)

### `app.py` — Flask REST API + SSE
Main server. Thin routing layer that delegates to `VPNService`. All API endpoints, SSE stream. Backup-to-router and auto-restore-on-unlock helpers.

### `vpn_service.py` — Business logic
Core orchestrator. `VPNService` owns `build_profile_list`, profile CRUD, `switch_server`, `change_protocol`, `change_type`, `connect_profile`, `disconnect_profile`, `reorder_profiles`, device assignment. Adds `network_zone` (zone ID like `"fvpn_iot"`) alongside `network` (display label) to each device for SSE-reactive network device lists. No Flask dependency.

### `noint_sync.py` — NoInternet WAN block enforcement
Manages the `fvpn_noint_ips` ipset + firewall rule that blocks WAN access for NoInternet groups. Extracted from the old `lan_sync.py`. Key functions: `sync_noint_to_router()`, `wipe_noint()`.

### `proton_api.py` — ProtonVPN wrapper
Thin synchronous wrapper around `proton-vpn-api-core`. Login (with 2FA), server list, WG/OVPN config generation. WireGuard configs use **persistent-mode certificates** (365-day validity, `Mode: "persistent"`). Each VPN profile gets its own Ed25519 key pair registered as a named device in Proton's dashboard. Key methods: `generate_wireguard_config()`, `refresh_wireguard_cert()`, `get_wireguard_x25519_key()`, `refresh_server_loads()` / `refresh_server_list()`, `get_server_entry_ips()`, `get_location()`, `get_sessions()`, `set_alternative_routing()`. All VPN options (NetShield, Moderate NAT, NAT-PMP, VPN Accelerator) work with both WireGuard (certificate features) and OpenVPN (username suffixes: `+f{level}`, `+nr`, `+pmp`, `+nst`). See [docs/proton-api-gotchas.md](docs/proton-api-gotchas.md) for cert modes, deletion limitations, and library quirks.

### `router_api.py` — Router SSH management
SSH-based API (Paramiko + key auth) for the Flint 2. Manages WG/OVPN configs via UCI, route policy rules, ipset membership, firewall rules, DHCP leases, gl-clients metadata. Helpers: `get_flint_vpn_rules`, `get_device_assignments`, `get_tunnel_health`, `get_kill_switch`, `get_profile_name`, `rename_profile`, `reorder_vpn_rules`, `heal_anonymous_rule_section`, `from_mac_tokens` (for case-preserving del_list). FlintVPN UCI helpers: `fvpn_uci_apply`, `fvpn_ipset_membership`. Also `read_file`/`write_file` for disaster-recovery backup, `get_router_fingerprint` for restore fingerprint check.

### `profile_store.py` — Local JSON persistence
Atomic JSON read/write for the slim local store (UI metadata + non-VPN assignments). `_sanitize_mac_keys()` strips legacy fields on every save so post-refactor data is automatically cleaned up. WireGuard VPN profiles additionally store `wg_key` (base64 Ed25519 private key for persistent cert management) and `cert_expiry` (Unix timestamp).

### `device_tracker.py` — Background new-device auto-assigner
Minimal background thread. Polls DHCP leases every 30s. The **only** thing it persists is auto-assigning newly-discovered MACs to the guest profile (writes to router for VPN guest, local store for non-VPN guest). Maintains an in-memory `_known_macs` set and `noint_stale` flag for IP-change detection.

### `secrets_manager.py` — Encrypted credentials
Fernet (AES-128-CBC + HMAC-SHA256) with PBKDF2 key derivation. Stores ProtonVPN and router credentials in `secrets.enc`.

### `server_optimizer.py` — Server scoring, filtering, and selection
Pure functions. Ranking: Proton `score` (lower = better) → blacklist filter → favourite boost (30% tolerance) → latency tiebreaker (15% similarity). Key functions: `resolve_scope_to_server()` (profile creation, ServerPicker), `find_better_server()` (auto-optimizer, 20% minimum improvement threshold).

### `latency_probe.py` — TCP latency measurement from router
**Probes always run from the router via SSH** (never locally — Surface Go is behind VPN). Uses `curl -w "%{time_connect}"` because BusyBox `nc` lacks `-z`/`-w`. `probe_servers_local` exists for testing only — never use in production.

### `auto_optimizer.py` — Background server switcher + cert renewal + score refresh + blocklist update
Daemon thread, `_poll_loop` every 60s. Four jobs: (1) server data refresh (~15min loads, ~3h full list), (2) server optimization (daily window, `MIN_DWELL_HOURS=6` cooldown), (3) cert renewal (daily, within 30 days of expiry, independent of auto-optimize), (4) blocklist update (daily, downloads community blocklist and uploads to router).

### `router_lan_access.py` — Router facade for cross-network access control
Discovers networks from UCI `wireless`/`network`/`firewall` config, builds a list of zones with SSIDs, subnets, device counts, and isolation state. Manages fw3 zone `forwarding` entries for cross-network traffic rules, toggles per-SSID AP isolation via `wireless.*.isolate`, and applies per-device iptables ACCEPT rules in the `forwarding_rule` chain (with a firewall include script at `/etc/fvpn/lan_access_rules.sh` for reboot persistence). Network creation/deletion uses `_reload_wifi_driver()` which unloads and reloads the `mt_wifi` kernel module — required because MediaTek's driver reads `BssidNum` from `.dat` files only at module load time (see [MediaTek WiFi Driver Constraints](#mediatek-wifi-driver-constraints)). Key methods: `get_networks()`, `get_zone_forwardings()`, `set_zone_forwarding()`, `set_wifi_isolation()`, `create_network()`, `delete_network()`, `apply_device_exceptions()`, `cleanup_exceptions()`.

### `lan_access_service.py` — LAN access business logic
Orchestrates `RouterLanAccess` (SSH/UCI) with `config.json` persistence. Separate from `VPNService` because LAN access and VPN routing are orthogonal concerns. Zone IDs are truncated to 6 characters (fw3 zone name limit is 11 chars; `fvpn_` prefix takes 5) with collision handling. Methods: `get_lan_overview()` (networks + access rules + exceptions), `get_network_devices()` (devices by zone/subnet), `create_network()` / `delete_network()` (full network lifecycle with WiFi driver reload), `update_access_rules()` (zone forwarding changes), `set_isolation()` (AP isolation toggle), `add_exception()` / `remove_exception()` (device-level iptables rules), `reapply_all()` (boot recovery). Exceptions are persisted in `config.json` under `lan_access.exceptions` and re-applied on unlock.

### `router_adblock.py` — DNS ad-block infrastructure on the router
Manages a second dnsmasq instance (port 5353) with community blocklists. Devices in adblock-enabled groups have their DNS redirected via iptables REDIRECT from port 53 to 5353. The blocking dnsmasq forwards non-blocked queries to the main dnsmasq on 127.0.0.1:53. Uses `fvpn_adblock_macs` hash:mac ipset for per-group MAC matching. Self-healing: checks and provisions on demand. Firewall include script ensures rules survive router reboot.

### `consts.py` — Shared constants
`PROFILE_TYPES`, `LAN_STATES`, `PROTOCOLS`, `ADBLOCK_*` — used across modules to avoid magic strings.

### `tunnel_strategy.py` — Protocol-specific tunnel operations
Strategy pattern for tunnel create/delete/connect/disconnect/switch across the three protocol families (kernel WG, proton-wg, OpenVPN). Encapsulates the differences so `vpn_service.py` doesn't need protocol-specific branches.

### `cli.py` — Click-based terminal interface
Wraps the same backend. Commands: setup, unlock, status, server browse, router status/devices/tunnels, profile CRUD, device assignment, settings.

## Design System

See [DESIGN.md](DESIGN.md) for the Sentry-inspired reference and [docs/design-tokens.md](docs/design-tokens.md) for the full token catalog. Rules:

- **Always consult DESIGN.md before creating or modifying UI components**
- **Never hardcode colors, fonts, shadows, or radii in component `<style>` blocks** — use `var(--token-name)` from `frontend/src/app.css` `:root`
- Buttons use uppercase text with `letter-spacing: 0.2px`

## Frontend (Svelte + Vite)

Built with Svelte 5 + Vite. Source in `frontend/src/`, builds to `static/`.

### Components
| Component | Purpose |
|-----------|---------|
| `Dashboard.svelte` | Sidebar + group cards (DnD reorderable) + unassigned devices section |
| `GroupCard.svelte` | Aircove-style card: gradient header, server info, connect/disconnect button, collapsible VPN options panel, device list (DnD) |
| `DeviceRow.svelte` | Device in a group: icon, name, online dot, IP, speed, signal, private-MAC badge |
| `DeviceModal.svelte` | Device settings: custom name, device type (synced to router gl-client), group assignment |
| `GroupModal.svelte` | Unified create/edit group modal. Same field order in both modes: type → protocol → VPN options → name → icon/color → guest. Create mode opens ServerPicker for VPN groups. Edit mode handles protocol change, type change (VPN ↔ NoVPN ↔ NoInternet), and VPN option regeneration on Save. |
| `ServerPicker.svelte` | 3-level server browser: Country → City → Server. Filters, scope selector. Per-server star (favourite) and ban (blacklist) toggles. "Test latency" button probes from router and shows color-coded ms badges (green <50ms, yellow <150ms, red >=150ms). Blacklisted servers dimmed + strikethrough + sorted last. Favourites sorted first. |
| `LanAccessPage.svelte` | Top-level page (`#lan-access`): network cards (collapsible) with isolation toggle, create/delete network, cross-network access rules table (inbound/outbound per zone pair), SSE-reactive device list per network (derived from global `$devices` store via `network_zone` field), exceptions section. Shows WiFi restart warning modals before disruptive actions (driver reload for create/delete, `wifi reload` for enable/disable/isolation/SSID changes). |
| `ExceptionModal.svelte` | Modal for adding device exceptions: From/To pickers (device or entire network), direction selector (both/outbound/inbound) |
| `EmojiPicker.svelte` | Categorized emoji grid with search |
| `ColorPicker.svelte` | Color selection for card accent |
| `SettingsModal.svelte` | Router IP, auto-optimize schedule, server preferences (blacklist/favourites counts + clear all), credentials, master password change |
| `LogsModal.svelte` | Live log viewer (app.log, error.log, access.log) with tabs |
| `SetupScreen.svelte` | First-time credential setup |
| `UnlockScreen.svelte` | Master password entry |
| `Toast.svelte` | Notification toasts |

### Stores (`frontend/src/lib/stores/app.js`)
Writable: `profiles`, `devices`, `appStatus`, `protonLoggedIn`, `toastMessage`, `movingDevices`, `smartProtocolStatus`. Derived: `unassignedDevices`. SSE handler mutates `p.health`, `p.kill_switch`, `p.name`, `p.server` from each event.

### API Client (`frontend/src/lib/api.js`)
One function per Flask endpoint via `fetch()`.

## REST API

```
GET/POST /api/status|setup|unlock       → auth lifecycle
GET/POST/PUT/DELETE /api/profiles[/:id] → CRUD, reorder
PUT  /api/profiles/:id/server|protocol|type|guest → server switch, protocol change, type change, guest
POST /api/profiles/:id/connect|disconnect → tunnel up/down (connect accepts {smart_protocol?: true})
GET/PUT /api/devices[/:mac/profile|label] → device list, assign, label
POST /api/refresh                       → trigger device poll + score refresh
POST /api/probe-latency                 → {server_ids:[]} → {latencies:{id:ms}}
GET  /api/stream                        → SSE (10s): health, kill_switch, names, server_info, smart_protocol, devices
GET  /api/location|sessions|available-ports → IP check, VPN sessions, port list
GET/PUT /api/settings[/server-preferences|credentials|master-password|adblock] → config CRUD
POST /api/settings/adblock/update-now                                → immediate blocklist download + upload
POST/DELETE /api/settings/server-preferences/blacklist|favourites/:id → toggle
GET/DELETE /api/logs[/:name]            → log viewer
GET  /api/lan-access/networks          → discovered networks (zones, SSIDs, subnets, device counts)
GET  /api/lan-access/networks/:zone/devices → devices in a specific network
POST /api/lan-access/networks          → create a new network (zone, bridge, SSID, subnet, firewall)
DELETE /api/lan-access/networks/:zone  → delete a network and all its resources
PUT  /api/lan-access/rules             → update cross-network zone forwarding rules
PUT  /api/lan-access/isolation/:zone   → toggle WiFi AP isolation for a network
GET/POST /api/lan-access/exceptions    → list / add device exceptions
DELETE /api/lan-access/exceptions/:id  → remove a device exception
```

## Router Interaction Safety Rules

**CRITICAL — violating these rules can kill internet for all devices on the network.**

### SAFE commands (OK to run via SSH):
- `uci show/get/set/add_list/del_list/delete/commit/reorder/rename` — config reads/writes
- `/etc/init.d/vpn-client restart` — only when no tunnels are stuck connecting
- `ipset add/del` — MAC-assignment ipsets
- `/etc/init.d/firewall reload` — safe (~0.22s, WG survives). **NOT** `firewall restart` (re-runs rtp2.sh). See [docs/proton-wg-internals.md](docs/proton-wg-internals.md).
- `wg show`, `ifstatus`, `ipset list`, `iptables -L -n`, `ubus call gl-clients list/status`, `cat`, `grep`, `ls`, `ps` — read-only

### NEVER run these:
- `/etc/init.d/network reload` or `restart` — bricks all routing
- `/etc/init.d/firewall restart` — re-runs the `firewall.vpnclient=include` script (`/usr/bin/rtp2.sh`) on the start cycle, which takes locks, deletes our interfaces, and corrupts route policy rules
- `rtp2.sh` directly — same reason as above
- `ifup` / `ifdown` — bypasses vpn-client, creates catch-all routes
- `conntrack -D` — breaks active connections

### Device assignment uses `ipset`, never `rtp2.sh`
`router.set_device_vpn`, `remove_device_from_vpn`, `remove_device_from_all_vpn`, and `set_kill_switch` use `ipset add/del` for immediate effect plus `uci commit` for persistence. The `src_mac{tunnel_id}` ipset is referenced by an existing iptables MARK rule (set up at tunnel creation by vpn-client). Adding a MAC to the ipset takes effect on the next packet — no daemon restart needed.

**Case sensitivity gotcha**: UCI's `del_list` requires an EXACT-match value. `from_mac_tokens()` reads existing MACs preserving their case so `del_list` uses the stored case (uppercase from GL.iNet UI vs. lowercase from us).

### Tunnel lifecycle (kernel WG + OpenVPN, via vpn-client)
1. Create WG peer (`/etc/config/wireguard`) or OVPN client (`/etc/config/ovpnclient` + `.ovpn` file under `/etc/openvpn/profiles/`)
2. Create a route_policy rule: `via_type='wireguard'|'openvpn'`, `peer_id`/`client_id`, `group_id`, `from='src_mac{tunnel_id}'`, `from_type='ipset'`
3. Connect: `uci set route_policy.{rule}.enabled='1'` + `uci commit` + `/etc/init.d/vpn-client restart`. vpn-client's `setup_instance_via.lua` reads our rule, creates the network interface, starts the tunnel, and sets up the iptables MARK rule.
4. Disconnect: disable kill switch, disable the rule, `vpn-client restart`, restore kill switch.

**proton-wg (TCP/TLS) tunnels have a completely different lifecycle** — see [proton-wg section](#proton-wg-wireguard-tcptls) below.

### Server switch
- **Kernel WG**: in-place hot-swap via `wg set` (update UCI peer endpoint + `wg set` to add new peer / remove old peer on live interface). Zero-flicker — no tunnel teardown.
- **OpenVPN**: full delete + recreate (OVPN cannot hot-swap peers). Brief flicker during restart.
- **proton-wg**: `wg setconf` on the live interface.

All protocols: capture devices from the OLD rule's `from_mac` BEFORE any teardown (VPN device assignments are router-canonical), then re-add them to the new rule after switch.

### MediaTek WiFi driver constraints

**Critical**: MediaTek's `mt_wifi` kernel module reads `BssidNum` from `.dat` files ONLY at module load time. `wifi reload` and `wifi down/up` do NOT reload the module, so new wireless interfaces (e.g. `ra2`, `rax2`) are never created by those commands alone.

**Solution**: `router_lan_access.py`'s `_reload_wifi_driver()` performs a full driver reload:
`wifi down` → `rmmod mtk_warp_proxy` → `rmmod mt_wifi` → `insmod mt_wifi` → `insmod mtk_warp_proxy` → `wifi up` → firewall/dnsmasq reload

- Runs detached (`&`) via SSH so it survives the SSH disconnect (WiFi drop kills the SSH session)
- Causes **~15s WiFi outage for ALL clients on ALL bands** — unavoidable on MediaTek hardware
- Required only for network creation/deletion; other WiFi operations (enable/disable, SSID settings, isolation toggle) only need `wifi reload` which briefly reconnects the affected band(s)

**`.dat` file paths** (active on Flint 2 / MT7986):
- `/etc/wireless/mediatek/mt7986-ax6000.dbdc.b0.dat` (2.4G radio)
- `/etc/wireless/mediatek/mt7986-ax6000.dbdc.b1.dat` (5G radio)
- Referenced by `/etc/wireless/l1profile.dat`. Other `.dat` files in that directory are for different models and are NOT used.
- Max `BssidNum` is typically 4 per radio (`ra0`–`ra3`, `rax0`–`rax3`) on MT7986.

### fw3 zone name limit (11 characters)

**Critical**: fw3 silently ignores zones with names longer than 11 characters. No error, no warning — just no firewall rules, no NAT, no internet for that zone.

FlintVPN zone name format: `fvpn_` (5 chars) + `zone_id` → `zone_id` max 6 chars. `lan_access_service.py` truncates zone_id to 6 chars and handles collisions.

### VPN routing across bridges

VPN `route_policy` mangle chain matches `br-+` (bridge wildcard), so MAC-based ipset routing works for devices on ANY network bridge (`br-lan`, `br-guest`, `br-fvpn_*`). No special handling needed when creating new networks.

### Router limits
- **5 WireGuard UDP tunnels** (`wgclient1`–`wgclient5`, marks `0x1000`–`0x5000`, vpn-client)
- **4 WireGuard TCP/TLS tunnels** (`protonwg0`–`protonwg3`, marks `0x6000`/`0x7000`/`0x9000`/`0xf000`, FlintVPN)
- **5 OpenVPN tunnels** (`ovpnclient1`–`ovpnclient5`, marks `0xa000`–`0xe000`, vpn-client)
- **14 total simultaneous VPN tunnels** (limited by fwmark address space)
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

## proton-wg (WireGuard TCP/TLS)

WireGuard over TCP/TLS, managed entirely by FlintVPN (not vpn-client). Uses `proton-wg` — ProtonVPN's wireguard-go fork cross-compiled for ARM64.

```
Kernel WG (UDP):    vpn-client → wgclient1-5 → fwmark 0x1000-0x5000
proton-wg (TCP/TLS): FlintVPN → protonwg0-3  → fwmark 0x6000,0x7000,0x9000,0xf000
OpenVPN:            vpn-client → ovpnclient1-5 → fwmark 0xa000-0xe000
```

Key differences from kernel WG: no route_policy rule, no vpn-client, kill switch always on (blackhole route), device assignment via ipset add (not `uci add_list from_mac`), slot allocation checks both live interfaces AND config files.

Config files: `/etc/fvpn/protonwg/<iface>.{conf,env}`, `mangle_rules.sh` (firewall include), `/etc/init.d/fvpn-protonwg` (boot persistence).

See [docs/proton-wg-internals.md](docs/proton-wg-internals.md) for process targeting, mangle ordering, tunnel ID allocation, and other critical constraints.

## Debugging

### Logs
- `logs/app.log` — actions: connect/disconnect/create/delete/assign
- `logs/error.log` — errors and exceptions with stack traces
- `logs/access.log` — HTTP request log
- Also viewable from Dashboard → Sidebar → Logs

### Common issues
- **Status out of sync**: check `uci show route_policy.fvpn_rule_XXXX.enabled` and `wg show wgclientN`
- **Device not in expected group**: `uci show route_policy | grep from_mac`, check `_resolve_device_assignments`
- **Orphan `@rule[N]`**: open dashboard to trigger self-heal, or `uci rename` manually
- **VPN slow**: try different server. Filogic 880 does 200–400 Mbps WG (CPU-bound, no HW offload)
- **Connecting forever**: `wg show` (latest handshake), `logread | grep openvpn`

### Testing a change
```bash
# Backend
source venv/bin/activate && python -m pytest tests/ --tb=short

# Frontend (must be rebuilt before user tests in browser — Flask serves static/)
cd frontend && export NVM_DIR="$HOME/.nvm" && . "$NVM_DIR/nvm.sh" && npm run build

# Restart server (KEEP secrets.enc and config.json — never delete them)
pkill -f "python backend/app.py"; sleep 1
source venv/bin/activate && nohup python backend/app.py > /tmp/flintvpn.log 2>&1 &
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

Uses UCI `gl-client.{section}.class` strings: `computer`, `phone`, `pad`, `camera`, `watch`, `laptop`, `printer`, `sound`, `television`, `smartappliances`, `games`, `gateway`, `nas`, `server`, `switch`
