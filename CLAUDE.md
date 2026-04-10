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
- **LAN access control**: per-group and per-device firewall policies (allowed/group_only/blocked) with exception lists
- **Kill switch**: per-group packet blackholing when tunnel drops (kernel WG via UCI, proton-wg via blackhole route)
- **WireGuard Stealth/TLS**: traffic looks like normal HTTPS — hardest to detect and block
- **Tor server routing**: filter and connect through ProtonVPN's Tor exit nodes for .onion access
- **Port selection**: choose alternate ports per protocol (WG: 443/88/1224/51820/500/4500, OVPN UDP: 80/51820/4569/1194/5060, OVPN TCP: 443/7770/8443) when ISPs block defaults
- **Smart Protocol**: automatic protocol fallback — if a tunnel doesn't connect within 45s, cycles through WireGuard → OpenVPN → WG TCP/TLS until one works
- **Custom DNS**: per-profile DNS override (e.g. Pi-hole, AdGuard) instead of Proton's default resolver
- **Alternative routing**: DNS-over-HTTPS transport fallback for API calls when Proton servers are blocked (censored networks)
- **NetShield status**: prominent protection-level display on group cards (active indicator when connected)
- **Location/IP check**: sidebar widget showing current public IP, country, and ISP as seen by ProtonVPN
- **Active sessions**: view all connected VPN sessions on the Proton account with exit IP and protocol
- **Live dashboard**: SSE-powered real-time tunnel health, device status, speeds
- **Disaster recovery**: local state backed up to router, auto-restored on unlock
- **GL.iNet compatible**: configs visible in the router's native dashboard as fallback

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
│  secrets.enc, config.json│         │  proton-wg (TCP/TLS)    │
│                          │         │  fvpn_lan iptables      │
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
      "server_scope": {
        "country_code": "DE" | null,
        "city": "Berlin" | null,
        "entry_country_code": "CH" | null,
        "server_id": "<pinned proton id>" | null,
        "features": { "streaming": false, "p2p": false, "secure_core": false, "tor": false }
      },
      "options": { "netshield": 2, "moderate_nat": false, "nat_pmp": false, "vpn_accelerator": true, "secure_core": false, "port": null, "custom_dns": null, "smart_protocol": false },
      "wg_key": "<base64 Ed25519 private key — WG profiles only>",
      "cert_expiry": 1807264162,
      "lan_access": {
        "outbound": "group_only",
        "inbound": "group_only",
        "outbound_allow": [],
        "inbound_allow": ["aa:bb:cc:dd:ee:ff", "<other-profile-uuid>"]
      }
    },
    {
      "id": "<uuid>",
      "type": "no_vpn",
      "name": "Direct",
      "color": "#888",
      "icon": "🌐",
      "is_guest": false,
      "lan_access": { "outbound": "allowed", "inbound": "allowed", "outbound_allow": [], "inbound_allow": [] },
      "display_order": 1
    }
  ],
  "device_assignments": { "aa:bb:cc:dd:ee:ff": "<non-vpn profile uuid>" },
  "device_lan_overrides": {
    "aa:bb:cc:dd:ee:ff": {
      "outbound": "blocked",
      "inbound": null,
      "outbound_allow": ["<group-uuid>"],
      "inbound_allow": []
    }
  }
}
```

Notes:
- VPN profiles have **no** `name` field (read live from router).
- VPN profiles have **no** `status` or `kill_switch` fields (read live).
- All profiles (VPN and non-VPN) use `display_order` for unified dashboard ordering. Groups can be freely interleaved regardless of type or protocol.
- `device_assignments` only contains non-VPN assignments. VPN device→profile lookup goes through `router.get_device_assignments()` which parses `from_mac` lists.
- Display name precedence for devices: `gl-client.alias` (router-canonical custom label) → DHCP hostname → MAC.

### Why some things stay local

- **Color, icon, is_guest, server_scope, options, lan_access**: pure UI/intent metadata, no router-native concept
- **`server_id`**: the link from a local profile to a Proton server (no way to derive it from the router config alone)
- **`wg_key`** (base64 Ed25519 private key): per-profile persistent WireGuard key. The X25519 WG private key is deterministically derived from this via `nacl.bindings.crypto_sign_ed25519_sk_to_curve25519`. Registered with Proton as a named "device" with a 365-day certificate. The router gets the derived X25519 key (in the WG config); the Ed25519 source key stays local for cert refresh.
- **`cert_expiry`** (Unix timestamp): when the persistent certificate expires. Auto-refreshed on unlock if within 30 days of expiry.
- **`lan_access` 3-state policy** (`allowed`/`group_only`/`blocked`): UCI rules + ipsets are the execution layer (per-group `fvpn_lan_<short_id>_ips` ipsets, `fvpn_lan_<short_id>_<dir>drop` rule sections), but they can't be parsed back to the 3-state semantic. The router stores intent in its native format (UCI), but the *interpretation* (what counts as `allowed` vs `group_only`) lives in the local store.
- **`lan_access.{outbound,inbound}_allow` exception lists**: narrow allow lists that pierce a `group_only`/`blocked` posture for specific peers (MAC strings or profile-UUID strings). Same source-of-truth reasoning — iptables ACCEPT rules can't be parsed back to "this was an exception" semantics. Profile-UUID entries reference target groups' ipsets by name (so membership propagates automatically); MAC entries get per-(group, direction) extras ipsets.
- **`device_lan_overrides`**: same — local source, UCI rules are the execution layer. Per-device override sections (`fvpn_devovr_<mac>_*`) are emitted before group sections in UCI section order so they take precedence in the iptables chain.
- **NoVPN/NoInternet group identity**: multiple no-internet groups can coexist with identical router-side firewall rules; only the local store can distinguish them
- **Non-VPN device assignments**: derived from local store (router has no concept)

## Source-of-Truth Sync Mechanisms

### `build_profile_list(router, store_data, proton)` — `vpn_service.py`
Single function that produces the canonical profile list. Iterates `router.get_flint_vpn_rules()` first, merges in local UI metadata by stable `(vpn_protocol, peer_id|client_id)` key (so renamed sections still match), resolves server info live via `_resolve_server_live(proton, ...)`. Final output is sorted by `display_order` (unified ordering across all profile types — VPN and non-VPN can be freely interleaved). Detects:
- **Ghost profiles**: local profile whose router rule was deleted out from under us → `_ghost: true`, `health: red`
- **Orphan profiles**: router rule with no matching local metadata → `_orphan: true`
- **Anonymous-section healing**: when GL.iNet UI replaces `fvpn_rule_9001` with `@rule[N]`, the matcher finds it by `peer_id`/`client_id` and `router.heal_anonymous_rule_section()` issues `uci rename` to restore the canonical name on the next read

### `_build_devices_live(router)` — `app.py`
Live device list builder. Queries `router.get_dhcp_leases()` + `router.get_client_details()` + `_resolve_device_assignments()`. Wrapped by `_get_devices_cached()` with a 5-second TTL to throttle SSH calls during rapid SSE ticks. Cache is invalidated on every SSE tick (10s), on `api_set_device_label`, and on `api_assign_device`. Hostname fallback chain: DHCP → gl-clients `name` → MAC.

### `_resolve_device_assignments(router, store_data)` — `app.py`
Returns `{mac: profile_id}` merging router VPN assignments (canonical via `from_mac`) with local non-VPN assignments. Matching VPN rules to local profiles uses the stable `(protocol, peer_id|client_id)` key.

### `_sync_lan_to_router()` — `app.py` (delegates to `lan_sync.sync_lan_to_router`)
Single reconciler that handles BOTH LAN access (3-state policy + exceptions) and NoInternet enforcement. Replaces the legacy `_rebuild_lan_rules` + `_reconcile_no_internet_rules` pair. The router-side execution is pure UCI: per-group `config ipset` (hash:ip) sections + `config rule` sections referencing them via `option ipset 'name dir'`, with `option extra '-m set ! --match-set X'` for the `group_only` negation case. No custom `fvpn_lan` chain. fw3 manages everything; the rules survive reboot natively from the UCI `list entry` lines.

Triggered on: session unlock, profile create/delete, device assignment, LAN setting change, and SSE tick when `tracker.lan_rules_stale` is set (an IP for a restricted device changed).

Internally:
1. `lan_sync.serialize_lan_state(store, device_ips, assignment_map)` (pure) emits the desired UCI sections + ipset memberships from local intent.
2. `router.fvpn_lan_full_state()` reads live router state.
3. `lan_sync.diff_state(live, desired)` computes a UCI batch + per-ipset add/remove ops.
4. Membership-only changes apply via `ipset add/del` (no firewall reload). Structural changes (rule shape, new/deleted sections) apply via `uci batch` + `firewall reload` (~0.22s, no VPN disruption — empirically verified on Flint 2 firmware 4.8.4).

Section/ipset naming:
- `fvpn_lan_<short_id>_ips` — per-group IP membership
- `fvpn_lan_<short_id>_<dir>drop` / `_<dir>acc_<role>` — per-group rule sections
- `fvpn_extra_<short_id>_<dir>_ips` — per-(group, direction) MAC-exception IP set
- `fvpn_devovr_<mac_no_colons>_<dir>_<role>` — per-device override rule sections
- `fvpn_devovr_<mac_no_colons>_<dir>_ips` — per-device override exception IP set
- `fvpn_noint_ips` + `fvpn_noint_block` — single global NoInternet ipset + rule (handles ALL no-internet groups; the local store distinguishes them, the router only needs membership)

Device overrides emit per-device sections BEFORE group sections in UCI section order so they take precedence in the iptables chain. Outbound override rules use `option src_mac '<mac>'` (no IP needed); inbound override rules use `option dest_ip '<live IP>'` (a DHCP renewal for an overridden device triggers a structural rebuild). Profile-UUID exception entries reference the target group's existing ipset by name, so membership changes propagate automatically without rule rewrites.

### Backup / restore — `_backup_local_state_to_router` + `_check_and_auto_restore` in `app.py`
The router doubles as a disaster-recovery store for the local intent. After every successful `profile_store.save()`, the wrapper pushes the JSON (with a `_meta` envelope: version, ISO timestamp, `br-lan` MAC fingerprint) to `/etc/fvpn/profile_store.bak.json` on the router via `router.write_file`. Best-effort: SSH failures log a warning but never propagate.

On unlock, before any other post-unlock work, `_check_and_auto_restore()` reads the backup file and:
- If missing: no-op.
- If router fingerprint mismatches the live `br-lan` MAC: log warning and skip (the backup belongs to a different router).
- If backup `_meta.saved_at` is NEWER than local file mtime (or local is missing/unparseable): atomically restore the backup data over `profile_store.json`.
- If local is NEWER: push local back to the router as a fresh backup (self-heal stale backup — handles "SSH was down when last save fired").

Both timestamps come from the same machine (the Surface Go), so there's no clock-skew issue. Operation is silent — no UI banners, no toasts. The CLI command `python cli.py reset-local-state` wipes both local and the router backup atomically when you want to start fresh without auto-restoring.

### SSE stream — `api_stream()` in `app.py`
Every 10 seconds, builds the merged profile list and pushes:
- `tunnel_health[profile_id]` — live router health
- `kill_switch[profile_id]` — live router kill_switch
- `profile_names[profile_id]` — live router name (so SSH-side renames propagate)
- `devices[]` — full live device list

The frontend's Svelte stores are mutated in place from each event. No local persistence of any of these fields.

### Auto-optimizer — `auto_optimizer.py`
Background thread. At a configured time of day (within a 2-minute window to tolerate clock drift), it reads the live merged profile list via `build_profile_list_fn(router, data, proton)` and calls `find_better_server` for each VPN profile whose **live `health`** (not cached status) is `green`/`amber`. Uses `_switch_server` to apply changes. Reads `server_blacklist` + `server_favourites` from config. Probes latency from the router to top-10 candidate servers per scope before evaluating.

### Server score refresh — `auto_optimizer._maybe_refresh_server_data()`
Runs every 60 seconds in the poll loop (independent of the daily optimization window). Calls `proton.refresh_server_loads()` when loads are stale (~15min) or `proton.refresh_server_list()` when the full list is stale (~3h). This keeps scores fresh so the ServerPicker and auto-optimizer always see current data — previously scores were only updated when the ProtonVPN GTK app was running.

### "Fastest server" selection algorithm
The selection pipeline for non-pinned servers (scope.server_id is null):

1. **Scope filter**: country, city, entry_country (SC), features (streaming/p2p/secure_core) — AND-combined
2. **Blacklist filter**: remove servers in `config.server_blacklist`
3. **Sort by Proton score** (lower = better)
4. **Favourite boost**: if any favourite is within 30% of the best score, prefer it
5. **Latency tiebreaker** (auto-optimizer only): among servers within 15% of the best score, pick lowest TCP latency from the router

**Known limitation**: Proton's `score` field reflects server load and geographic distance from Proton's infrastructure, but does NOT reflect ISP-specific peering or throughput. Two servers with similar scores on adjacent physical nodes (e.g. node-de-34 vs node-de-35) can have 13x different throughput from the same ISP. The latency tiebreaker helps when scores are close and nodes differ in latency, but cannot measure throughput. For persistent ISP peering issues, the user should blacklist slow physical nodes and/or favourite fast ones — this is the primary mechanism for overriding score-based selection.

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
| **Server Scope** | How a group selects its server. Three independent levels (`country_code`, `city`, `server_id`) each can be specific or `null` ("Fastest"). Cascade rule: a level being null forces all narrower levels to null. Plus a `features` filter (`streaming`, `p2p`, `secure_core`) that constrains which servers qualify. The auto-optimizer respects all of these — e.g. "fastest streaming server in US" always picks a streaming server in US. `entry_country_code` is only meaningful with `secure_core=true` and identifies the SC entry route. See `profile_store.normalize_server_scope`. |
| **Auto-Optimizer** | Background thread that periodically switches VPN groups to better-loaded servers within their scope constraints. Applies blacklist/favourites/latency. Skipped for profiles where the user pinned a specific `server_id`. |
| **Server Blacklist** | List of server IDs excluded from automatic selection (auto-optimizer, "fastest" resolution in ServerPicker). Stored in `config.json` as `server_blacklist`. Pinned servers bypass the blacklist. Mutually exclusive with favourites (adding to one removes from the other). |
| **Server Favourites** | List of server IDs preferred when scores are close. If a favourite's score is within 30% of the best candidate, it wins. Stored in `config.json` as `server_favourites`. |
| **Latency Probe** | TCP connect-time measurement to VPN server entry IPs on port 443. Always runs **from the router** via SSH (never locally — the Surface Go may be behind a VPN tunnel). Uses `curl -w "%{time_connect}"` because BusyBox `nc` lacks `-z`/`-w` flags. Used as a tiebreaker when scores are within 15%. |
| **LAN Access** | Per-group or per-device firewall rules controlling LAN-to-LAN traffic. Three states: `allowed`, `group_only`, `blocked`. Inbound and outbound independent. Each direction may also carry an **exception list** (allowlist of MACs or profile IDs) that pierces `group_only`/`blocked` for specific peers — e.g. `outbound: blocked` + `outbound_allow: [<group X>]` means *"outbound only to Group X, nothing else."* |
| **LAN Exception** | An entry in `lan_access.{outbound,inbound}_allow`. Either a MAC string (specific device) or a profile ID (the whole group, members tracked live). At the device-override layer, exception lists merge additively with the group's. Forward-compatible with future deny-list subtraction; not implemented in v1. |
| **NetShield** | ProtonVPN DNS-level ad/malware blocking. Level 0=off, 1=malware, 2=malware+ads+trackers. Baked into the WG/OVPN config at generation time. |
| **Guest Group** | The group new (previously unseen) MACs are auto-assigned to by the device tracker. Any group type (VPN/NoVPN/NoInternet) can be the guest group. |
| **Anonymous section** | A `@rule[N]` route_policy section (positional reference) created when the GL.iNet UI edits one of our rules. We self-heal these back to `fvpn_rule_*` named sections by matching on `peer_id`/`client_id`. |
| **proton-wg** | Userspace WireGuard binary (ProtonVPN's wireguard-go fork) that supports TCP and TLS transports. Cross-compiled for ARM64, lives at `/usr/bin/proton-wg` on the router. Managed entirely by FlintVPN (not vpn-client). |
| **Persistent cert** | A 365-day WireGuard certificate from `POST /vpn/v1/certificate` with `Mode: "persistent"`. Each VPN profile gets its own Ed25519 key pair registered as a named "device" in Proton's dashboard. No local agent required — the router is fully standalone after config upload. |
| **Smart Protocol** | Per-profile option. When enabled and a tunnel doesn't connect within 45 seconds, automatically cycles through alternate protocols (WG UDP → OVPN UDP → OVPN TCP → WG TCP → WG TLS) until one works. Checks slot availability before each attempt. |
| **Custom DNS** | Per-profile DNS override. When set, replaces Proton's `10.2.0.1` resolver in the WG config. Disables NetShield DNS filtering (server-side cert features still apply but DNS queries go to the custom resolver). |
| **Port Override** | Per-profile port selection. Alternate ports per protocol from Proton's `clientconfig`. Useful when ISPs block default VPN ports (51820 for WG, 1194 for OVPN). |
| **Alternative Routing** | Global setting. When enabled (default), Proton API calls fall back to DNS-over-HTTPS routing through third-party infrastructure (Google/Quad9 DNS) when Proton servers are directly unreachable. Handled transparently by the `proton-vpn-api-core` library's `AutoTransport`. |
| **Tor Server** | ProtonVPN server connected to the Tor network. Allows routing traffic through Tor exit nodes for `.onion` access without the Tor browser. Filtered via the `tor` feature flag in `server_scope.features`. |

## Backend Modules

### `app.py` — Flask REST API + SSE
Main server. Thin routing layer that delegates to `VPNService`. All API endpoints, SSE stream. Backup-to-router and auto-restore-on-unlock helpers.

### `vpn_service.py` — Business logic
Core orchestrator. `VPNService` class owns `build_profile_list`, profile CRUD (`create_profile`, `update_profile`, `delete_profile`), `switch_server`, `change_protocol` (tear down + recreate with different protocol), `change_type` (VPN ↔ NoVPN ↔ NoInternet), `connect_profile`, `disconnect_profile`, `reorder_profiles` (unified `display_order` on all profiles + VPN `uci reorder`), device assignment, and LAN sync delegation. No Flask dependency.

### `lan_sync.py` — UCI-native LAN access execution layer
Pure emitter `serialize_lan_state(store, device_ips, assignment_map)` produces a deterministic dict of desired UCI ipset + rule sections. `diff_state(live, desired)` computes a UCI batch + per-ipset add/remove ops. `sync_lan_to_router(router, ...)` orchestrates: reads live state via `router.fvpn_lan_full_state`, applies the diff via `router.fvpn_uci_apply` (membership-only ops skip the firewall reload). Replaces the legacy `router_api.generate_lan_rules` + the imperative `fvpn_lan` chain.

### `proton_api.py` — ProtonVPN wrapper
Thin synchronous wrapper around `proton-vpn-api-core`. Login (with 2FA), server list, WG/OVPN config generation. WireGuard configs use **persistent-mode certificates** (365-day validity, `Mode: "persistent"` on `POST /vpn/v1/certificate`). Each VPN profile gets its own Ed25519 key pair registered as a named device in Proton's dashboard — no local agent required, the router is fully standalone after config upload. Key methods: `generate_wireguard_config()` (returns config + wg_key + cert_expiry, accepts `port` and `custom_dns` overrides), `refresh_wireguard_cert()` (renews without changing the key), `get_wireguard_x25519_key()` (derives WG key from stored Ed25519), `refresh_server_loads()` / `refresh_server_list()` (keep scores fresh), `get_server_entry_ips()` (resolve server IDs to physical IPs for latency probing), `get_location()` (current IP/country/ISP via `/vpn/v1/location`), `get_sessions()` (active VPN sessions via `/vpn/v1/sessions`), `set_alternative_routing()` (enable/disable DoH transport fallback). Certificate auto-refresh happens on unlock for certs within 30 days of expiry. All VPN options (NetShield, Moderate NAT, NAT-PMP, VPN Accelerator) work with both WireGuard (certificate features) and OpenVPN (username suffixes: `+f{level}`, `+nr`, `+pmp`, `+nst`).

### `router_api.py` — Router SSH management
SSH-based API (Paramiko + key auth) for the Flint 2. Manages WG/OVPN configs via UCI, route policy rules, ipset membership, firewall rules, DHCP leases, gl-clients metadata. Helpers: `get_flint_vpn_rules`, `get_device_assignments`, `get_tunnel_health`, `get_kill_switch`, `get_profile_name`, `rename_profile`, `reorder_vpn_rules`, `heal_anonymous_rule_section`, `_from_mac_tokens` (for case-preserving del_list). FlintVPN UCI helpers: `fvpn_uci_apply`, `fvpn_ipset_membership`, `fvpn_lan_full_state`, `fvpn_lan_wipe_all`. Also `read_file`/`write_file` for the disaster-recovery backup file at `/etc/fvpn/profile_store.bak.json`, and `get_router_fingerprint` (br-lan MAC) for the restore-on-unlock fingerprint check.

### `profile_store.py` — Local JSON persistence
Atomic JSON read/write for the slim local store (UI metadata + non-VPN assignments + LAN overrides). `_sanitize_mac_keys()` strips legacy fields on every save so post-refactor data is automatically cleaned up. WireGuard VPN profiles additionally store `wg_key` (base64 Ed25519 private key for persistent cert management) and `cert_expiry` (Unix timestamp).

### `device_tracker.py` — Background new-device auto-assigner
Minimal background thread. Polls DHCP leases every 30s. The **only** thing it persists is auto-assigning newly-discovered MACs to the guest profile (writes to router for VPN guest, local store for non-VPN guest). Maintains an in-memory `_known_macs` set and `lan_rules_stale` flag for IP-change detection.

### `secrets_manager.py` — Encrypted credentials
Fernet (AES-128-CBC + HMAC-SHA256) with PBKDF2 key derivation. Stores ProtonVPN and router credentials in `secrets.enc`.

### `server_optimizer.py` — Server scoring, filtering, and selection
Pure functions for server selection. Primary ranking by Proton's `score` field (lower = better, matching `proton-vpn-api-core`'s `ServerList.get_fastest_server`). Three layers of filtering/boosting applied in order:

1. **Blacklist** (`filter_blacklisted`): removes servers the user blocked. Stored in `config.json` as `server_blacklist: [id, ...]`. Pinned servers (scope.server_id) bypass the blacklist.
2. **Favourites** (`apply_favourites`): if a favourite server's score is within 30% of the best candidate (`FAVOURITE_SCORE_TOLERANCE=0.30`), prefer it. Stored in `config.json` as `server_favourites: [id, ...]`.
3. **Latency tiebreaker** (`_pick_best_by_latency`): among servers within 15% of the best score (`SCORE_SIMILARITY_THRESHOLD=0.15`), pick the one with the lowest measured TCP latency. Latency data is optional — when absent, falls back to score-only.

Key functions:
- `resolve_scope_to_server(scope, servers, blacklist, favourites, latencies)` — used by profile creation and ServerPicker preview.
- `find_better_server(profile, servers, ..., blacklist, favourites, latencies)` — used by auto-optimizer. Only triggers a switch when the best candidate's score is at least 20% lower than the current server's (`MIN_RELATIVE_IMPROVEMENT=0.20`).

**Limitation**: Proton's score reflects server load and geographic distance from Proton's infrastructure, but does NOT reflect ISP-specific peering or throughput. Two servers with similar scores may have wildly different actual speeds from a given ISP. The latency tiebreaker helps when scores are close, but for servers with different scores (like DE#743 vs DE#747), the user must manually blacklist/favourite to override.

### `latency_probe.py` — TCP latency measurement from router
Measures TCP connect time to VPN server entry IPs. **Probes run from the router via SSH** (not the Surface Go, which may be behind a VPN tunnel). Uses `curl -w "%{time_connect}"` on the router because BusyBox `nc` doesn't support `-z`/`-w` flags and BusyBox `date` lacks nanosecond precision. `probe_servers_via_router(router, servers)` builds a single SSH command that probes all IPs sequentially and parses "IP MS" output lines. A local fallback (`probe_servers_local`) exists for testing but is never used in production — the Surface Go's VPN routing would give misleading results.

### `auto_optimizer.py` — Background server switcher + cert renewal + score refresh
Daemon thread with three jobs running in the `_poll_loop` (every 60 seconds):
1. **Server data refresh** (`_maybe_refresh_server_data`): keeps Proton server scores fresh. Calls `refresh_server_loads()` when loads are stale (~15min) or `refresh_server_list()` when the full list is stale (~3h). Runs every poll cycle regardless of auto-optimize being enabled.
2. **Server optimization**: Within a 2-minute window after the scheduled time, evaluates all connected VPN profiles. Reads blacklist/favourites from `config.json`. Probes latency to candidate servers via the router (`_probe_candidate_latencies` — top 10 per scope). Switches profiles where `find_better_server` returns a result. Enforces `MIN_DWELL_HOURS=6` per-profile cooldown to prevent flapping.
3. **Certificate renewal**: Once per day, refreshes WG persistent certs within 30 days of expiry. Runs independently of auto_optimize — doesn't require it to be enabled. No router interaction needed.

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
| `GroupModal.svelte` | Unified create/edit group modal. Same field order in both modes: type → protocol → VPN options → name → icon/color → guest → LAN access. Create mode opens ServerPicker for VPN groups. Edit mode handles protocol change, type change (VPN ↔ NoVPN ↔ NoInternet), and VPN option regeneration on Save. |
| `ServerPicker.svelte` | 3-level server browser: Country → City → Server. Filters, scope selector. Per-server star (favourite) and ban (blacklist) toggles. "Test latency" button probes from router and shows color-coded ms badges (green <50ms, yellow <150ms, red >=150ms). Blacklisted servers dimmed + strikethrough + sorted last. Favourites sorted first. |
| `LanPeerPicker.svelte` | Multi-select chip picker for LAN access exception lists. Searchable dropdown grouped into Groups + Devices. Inherited (group-source) entries are greyed out and non-removable in DeviceModal. |
| `EmojiPicker.svelte` | Categorized emoji grid with search |
| `ColorPicker.svelte` | Color selection for card accent |
| `SettingsModal.svelte` | Router IP, auto-optimize schedule, server preferences (blacklist/favourites counts + clear all), credentials, master password change |
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
PUT  /api/profiles/reorder              → unified display_order on all profiles + VPN uci reorder
PUT  /api/profiles/:id                  → update metadata (name, color, icon, kill_switch)
DELETE /api/profiles/:id                → delete group + router cleanup + LAN rebuild + NoInternet reconcile

GET  /api/profiles/:id/servers          → ProtonVPN server list (filtered)
PUT  /api/profiles/:id/server           → switch server (regenerate tunnel, carry over devices)
PUT  /api/profiles/:id/protocol         → change VPN protocol (tear down + recreate tunnel)
PUT  /api/profiles/:id/type             → change group type (VPN ↔ NoVPN ↔ NoInternet)
POST /api/profiles/:id/connect          → bring tunnel up; body: {smart_protocol?: true}; returns live health
POST /api/profiles/:id/disconnect       → bring tunnel down; returns live health
PUT  /api/profiles/:id/guest            → set as guest group

GET  /api/devices                       → live device list (5s in-memory TTL)
PUT  /api/devices/:mac/profile          → assign device (router for VPN, local for non-VPN)
PUT  /api/devices/:mac/label            → write to gl-client.alias and .class on router
PUT  /api/profiles/:id/lan-access       → set group LAN policy + exception lists
PUT  /api/devices/:mac/lan-access       → set per-device LAN override + exception lists

POST /api/refresh                       → trigger device tracker poll + server score refresh
POST /api/probe-latency                 → TCP latency probe from router {server_ids:[]} → {latencies:{id:ms}}
GET  /api/stream                        → SSE: tunnel_health + kill_switch + profile_names + devices (10s)

GET  /api/location                      → current public IP/country/ISP via Proton's /vpn/v1/location
GET  /api/sessions                      → active VPN sessions {sessions:[], max_connections: int}
GET  /api/available-ports               → available VPN ports per protocol

GET  /api/logs                          → list log files
GET  /api/logs/:name                    → tail log content
DELETE /api/logs/:name                  → clear a log

GET  /api/settings                      → non-sensitive config (includes server_blacklist, server_favourites)
PUT  /api/settings                      → update router IP etc
GET  /api/settings/server-preferences   → {blacklist:[], favourites:[]}
PUT  /api/settings/server-preferences   → replace blacklist and/or favourites
POST /api/settings/server-preferences/blacklist/:id    → add to blacklist (auto-removes from favourites)
DELETE /api/settings/server-preferences/blacklist/:id  → remove from blacklist
POST /api/settings/server-preferences/favourites/:id   → add to favourites (auto-removes from blacklist)
DELETE /api/settings/server-preferences/favourites/:id → remove from favourites
PUT  /api/settings/credentials          → update encrypted creds
PUT  /api/settings/master-password      → change master password

GET  /                                  → serve Svelte frontend (static/index.html)
```

## Router Interaction Safety Rules

**CRITICAL — violating these rules can kill internet for all devices on the network.**

### SAFE commands (OK to run via SSH):
- `uci show/get/set/add_list/del_list/delete/commit/reorder/rename` — config reads/writes
- `/etc/init.d/vpn-client restart` — only when no tunnels are stuck connecting
- `ipset add/del` — for `src_mac{tunnel_id}` ipsets (the safe MAC-assignment path) AND for `fvpn_lan_*_ips`/`fvpn_noint_ips`/etc. (the LAN access execution layer)
- `/etc/init.d/firewall reload` — empirically verified safe on Flint 2 firmware 4.8.4: ~0.22s, WG handshake unchanged, transfer counters keep incrementing through the reload, mangle MARK rules survive (fw3 surgically updates only its own `!fw3`-marked rules). Use sparingly for structural UCI changes (rule add/delete, ipset add/delete). The dangerous variant is `firewall restart` (which calls stop+start and re-runs `rtp2.sh` via `firewall.vpnclient` include with `option reload='0'`).
- `wg show`, `ifstatus`, `ipset list`, `iptables -L -n` — read-only
- `ubus call gl-clients list/status` — read-only
- `cat`, `grep`, `ls`, `ps` — read-only

### NEVER run these:
- `/etc/init.d/network reload` or `restart` — bricks all routing
- `/etc/init.d/firewall restart` — re-runs the `firewall.vpnclient=include` script (`/usr/bin/rtp2.sh`) on the start cycle, which takes locks, deletes our interfaces, and corrupts route policy rules
- `rtp2.sh` directly — same reason as above
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

WireGuard is UDP-only at the kernel level. ProtonVPN offers WireGuard over TCP (port 443) and TLS/Stealth (port 443, looks like HTTPS). The router's vpn-client only handles kernel WG (UDP). For TCP/TLS, FlintVPN manages the full tunnel lifecycle using `proton-wg` — ProtonVPN's wireguard-go fork cross-compiled for ARM64.

### Architecture
```
Kernel WG (UDP):    vpn-client → wgclient1-5 → fwmark 0x1000-0x5000
proton-wg (TCP/TLS): FlintVPN → protonwg0-3  → fwmark 0x6000,0x7000,0x9000,0xf000
OpenVPN:            vpn-client → ovpnclient1-5 → fwmark 0xa000-0xe000
```

### Fwmark allocation (0xf000 mask — 16 values total)
- `0x0000`: unmarked (reserved)
- `0x1000`–`0x5000`: kernel WG (5 slots, vpn-client)
- `0x6000`, `0x7000`, `0x9000`, `0xf000`: proton-wg (**4 slots**, FlintVPN)
- `0x8000`: default policy / no-VPN
- `0xa000`–`0xe000`: OpenVPN (5 slots, vpn-client)

### Tunnel lifecycle (FlintVPN-managed, no vpn-client)
1. `upload_proton_wg_config()` — writes `.conf` + `.env` to `/etc/fvpn/protonwg/`, creates ipset
2. `start_proton_wg_tunnel()` — starts process, sets up interface/IP/routing/firewall/mangle
3. `stop_proton_wg_tunnel()` — kills process, cleans routing/firewall, keeps config for reconnect
4. `delete_proton_wg_config()` — removes config files + ipset, rebuilds mangle rules

### Mangle MARK rules
Ephemeral iptables rules (lost on firewall reload). A firewall include script at `/etc/fvpn/protonwg/mangle_rules.sh` with `option reload '1'` re-applies them on every reload. Rebuilt by `_rebuild_proton_wg_mangle_rules()` after any tunnel start/stop.

### Boot persistence
OpenWrt init.d service at `/etc/init.d/fvpn-protonwg` (installed on first proton-wg profile creation). On boot: starts all proton-wg processes from env files, sets up routing + mangle rules.

### Config files on router
- `/usr/bin/proton-wg` — the binary (6MB, static ARM64)
- `/etc/fvpn/protonwg/<iface>.conf` — WireGuard config (PrivateKey, Peer, Endpoint:443)
- `/etc/fvpn/protonwg/<iface>.env` — environment vars + FlintVPN metadata (tunnel_id, mark, ipset)
- `/etc/fvpn/protonwg/mangle_rules.sh` — auto-generated firewall include
- `/etc/init.d/fvpn-protonwg` — boot persistence service

### Key differences from kernel WG
- No route_policy UCI rule (FlintVPN manages routing directly)
- No vpn-client involvement (process managed via SSH)
- Kill switch always on (blackhole route, not UCI flag)
- Device assignment via ipset add (not `uci add_list from_mac`)
- Server switch via `wg setconf` on the live interface (same as kernel WG `wg set`)
- Slot allocation checks both live interfaces AND config files (disconnected tunnel reserves its slot)

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
