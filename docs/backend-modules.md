# Backend Modules

Detailed descriptions of every module in the backend. For the package layout and dependency graph, see [backend-structure.md](backend-structure.md).

## Top-Level Modules

### `app.py` — Flask REST API + SSE
Main server. Thin routing layer that delegates to `VPNService`. All API endpoints, SSE stream. Backup-to-router and auto-restore-on-unlock helpers. Runtime state (router, proton, service instances) lives in `service_registry.py`.

### `cli.py` — Click-based terminal interface
Wraps the same backend. Commands: setup, unlock, status, server browse, router status/devices/tunnels, profile CRUD, device assignment, settings.

### `service_registry.py` — Runtime service singleton lifecycle
Holds `ProtonAPI`, `RouterAPI`, and `VPNService` instances plus the `session_unlocked` flag. Lazy-init for router and proton; explicit `reset()` on lock. Tests patch `registry.*` fields instead of module-level globals.

### `consts.py` — Shared constants
`PROFILE_TYPES`, `LAN_STATES`, `PROTOCOLS`, `ADBLOCK_*` — used across modules to avoid magic strings.

---

## `router/` — Router Communication

### `router/api.py` — SSH transport + facade hub
SSH transport (Paramiko + key auth, connect/exec/write_file/read_file) plus lazy-loaded properties for two layers: **tool layer** (`uci`, `ipset_tool`, `iptables`, `iproute`, `service_ctl`) and **feature layer** (`policy`, `tunnel`, `firewall`, `devices`, `wireguard`, `openvpn`, `proton_wg`, `adblock`, `lan_access`). ~270 lines — pure hub, no business logic.

### `router/types.py` — TypedDicts for router data
`WgRouterInfo`, `OvpnRouterInfo`, `ProtonWgRouterInfo`, `TunnelStatus`, `DhcpLease`, `FlintVpnRule`. Provides IDE autocompletion and type safety for the dicts returned by facades.

### `router/tunnel_id_alloc.py` — Shared tunnel ID allocator
`next_tunnel_id(ssh)` scans route_policy, ipsets, and proton-wg `.env` files to find the next unused ID (300-399). Used by RouterWireguard, RouterOpenvpn, and RouterProtonWG.

### `router/ipset_ops.py` — Centralized proton-wg ipset operations
All proton-wg MAC-based ipset mutations: `ensure_mac_set()`, `add_mac()`, `list_members()`, `ensure_and_add()`. Also owns `reconcile_proton_wg_members()` (lightweight re-add after vpn-client restart) and `reconcile_proton_wg_full()` (full ipset creation + member population + mangle rule rebuild on app unlock). Delegates to `router.ipset_tool` for actual ipset commands.

### `router/noint_sync.py` — NoInternet WAN block enforcement
Manages the `fvpn_noint_ips` ipset + firewall rule that blocks WAN access for NoInternet groups. Key functions: `sync_noint_to_router()`, `wipe_noint()`. Uses `router.ipset_tool` and `router.uci` for commands.

### `router/tools/` — Low-level CLI tool wrappers

Package of typed wrappers around the router's CLI tools. Each class takes an SSH executor and produces properly quoted, idempotent shell commands.

- **`uci.py`** — `Uci` class: get/set/delete/commit/show/batch/add_list/del_list/reorder/rename + `parse_show()` for output parsing, `batch_set()` for atomic multi-field ops, `batch_sections()` for structured batch creation, `ensure_firewall_include()` for idempotent script registration. All values are properly escaped via `_quote()`.
- **`ipset.py`** — `Ipset` class: create/add/remove/members/flush/destroy/list_names/membership_batch. Consistent `-exist` flags and `2>/dev/null || true` error suppression.
- **`iptables.py`** — `Iptables` class: ensure_chain/flush_chain/delete_chain/append/insert_if_absent/remove_rule/list_rules. Encapsulates the `-C || -I` idempotent insertion pattern.
- **`iproute.py`** — `Iproute` class: link_exists/link_delete/link_set_up/addr_add/route_add/route_add_blackhole/route_flush_table/rule_add/rule_del/neigh_show.
- **`service_ctl.py`** — `ServiceCtl` class: reload/restart/start/stop/enable/disable + wifi_reload/wifi_up/wifi_down.
- **`wg_show.py`** — `parse_handshake_age()` and `parse_transfer()`. Shared WireGuard stats parsing used by both RouterTunnel and RouterProtonWG.

### `router/facades/` — Feature facades

One facade per router subsystem. Each receives its tool dependencies via constructor injection.

- **`policy.py`** — `RouterPolicy(uci, ssh)`: Route policy rules (`get_flint_vpn_rules`, `reorder_vpn_rules`, `heal_anonymous_rule_section`), kill switch (`set/get_kill_switch`), profile naming (`get_profile_name`, `rename_profile`), MAC token parsing (`from_mac_tokens`), active interfaces.
- **`tunnel.py`** — `RouterTunnel(uci, service_ctl, ssh)`: `bring_tunnel_up/down` (enables/disables route policy rule + vpn-client restart), `get_rule_interface`, `get_tunnel_status/health` (green/amber/red/connecting based on WG handshake age or OVPN interface state).
- **`firewall.py`** — `RouterFirewall(uci, ipset, service_ctl, ssh)`: `fvpn_uci_apply` (UCI batch + firewall reload), `fvpn_ipset_membership/create/destroy`, `setup_mdns_reflection` (avahi for Chromecast/AirPlay).
- **`devices.py`** — `RouterDevices(uci, ipset, iproute, service_ctl, policy, ssh)`: DHCP leases, rich device details (gl-clients + ARP + iwinfo), device-to-VPN assignment (`set_device_vpn`, `remove_device_from_vpn/all_vpn`), static DHCP leases.
- **`wireguard.py`** — `RouterWireguard(uci, service_ctl, alloc_tunnel_id, ssh)`: Kernel WG peer creation (`upload_wireguard_config`), live hot-swap via `wg set` (`update_wireguard_peer_live`), deletion. Peer IDs: 9001-9050.
- **`openvpn.py`** — `RouterOpenvpn(uci, service_ctl, alloc_tunnel_id, ssh)`: OVPN client config management, `.ovpn` + auth file writing, route policy rules. Client IDs: 9051-9099.
- **`proton_wg.py`** — `RouterProtonWG(uci, ipset, iptables, iproute, service_ctl, alloc_tunnel_id, ssh)`: Full proton-wg lifecycle: process start/stop, interface creation, iproute2 routing, firewall zones, iptables mangle rules, init.d boot persistence. 4 slots (protonwg0-3). Per-tunnel dnsmasq for DNS isolation (`_start_proton_wg_dnsmasq`/`_stop_proton_wg_dnsmasq`): creates dnsmasq config, conf-dir, resolv-file, CT zone rules, and DNS REDIRECT to match the firmware's per-tunnel DNS mechanism. DNS port formula: `2000 + (mark >> 12) * 100 + 53`. Also `update_config_live()` (zero-flicker server switch) and `update_tunnel_env()` (tunnel ID healing).
- **`adblock.py`** — `RouterAdblock(uci, ipset, iptables, service_ctl, ssh, ip6tables=None)`: Injects `addn-hosts` blocklist directives into per-tunnel dnsmasq conf-dirs (`/tmp/dnsmasq.d.<iface>/`). Each VPN tunnel's dnsmasq picks up the blocklist via its conf-dir; no-VPN uses the main dnsmasq at `/tmp/dnsmasq.d/`. `sync_adblock(ifaces)` manages snippet injection/removal and persists interface list for firewall-reload recovery. Includes one-time legacy cleanup (`_cleanup_old_redirect_infra`) for migration from the old separate-dnsmasq + ipset + iptables REDIRECT approach. Safety: snippets only injected when the blocklist file has content.
- **`lan_access.py`** — `RouterLanAccess(uci, iptables, service_ctl, ssh)`: Network discovery from UCI wireless/network/firewall, zone forwarding rules, AP isolation, per-device iptables exceptions, network creation/deletion (with MediaTek WiFi driver reload).

---

## `services/` — Business Logic

### `services/vpn_service.py` — Top-level orchestrator facade
Thin facade (~276 lines) that composes `ProfileService`, `DeviceService`, `IpsetOps`, `SmartProtocolManager`, and `profile_list_builder` into a unified interface. Owns tunnel control (`connect_profile`, `disconnect_profile`), smart protocol management, cross-cutting sync operations (`sync_adblock_to_router`, `sync_noint_to_router`, ipset reconciliation), and device delegation. All callers (routes, CLI, background threads) use `VPNService` as the single entry point. No Flask dependency.

### `services/profile_service.py` — Profile CRUD and mutations
`ProfileService` handles profile lifecycle: `create_profile`, `update_profile`, `delete_profile`, `change_type`, `switch_server`, `change_protocol`, `reorder_profiles`, `set_guest_profile`. Uses callbacks for cross-cutting concerns (`cancel_smart_fn`, `sync_noint_fn`, `sync_adblock_fn`) following the same pattern as `DeviceService.assign_device()`. Includes DRY helper methods: `_acquire_lock`, `_create_tunnel`, `_teardown_tunnel`, `_reassign_devices`, `_persist_tunnel_update`, `_sync_lan_state`.

### `services/profile_list_builder.py` — Profile list query
Standalone `build_profile_list()` function that merges three data sources (router route_policy rules, local profile_store metadata, live Proton server data) into the canonical profile list for `/api/profiles`. Read-only — no mutation side-effects. Self-heals anonymous `@rule[N]` sections and detects ghost/orphan profiles.

### `services/backup_service.py` — Profile store backup/restore
`backup_local_state_to_router()` pushes `profile_store.json` to the router wrapped in a `_meta` envelope (timestamp, fingerprint, format version). `check_and_auto_restore()` restores from the router backup on unlock if newer. Silent disaster recovery.

### `services/adblock_service.py` — Blocklist download and merge
`download_and_merge_blocklists()` downloads community blocklists, merges with custom domains, deduplicates, and returns hosts-format content with dual-stack entries (`0.0.0.0` for IPv4 and `::` for IPv6) for upload to the router. Content is injected into per-tunnel dnsmasq instances via `RouterAdblock.upload_blocklist()`.

### `services/device_service.py` — Device assignment, listing, and caching
`DeviceService` handles device discovery (`build_devices_live`), assignment (`assign_device`), labeling (`set_device_label`), and TTL-based caching (`get_devices_cached`). Thread-safe cache with `threading.Lock`. Assignment logic branches by protocol: kernel WG/OVPN → `router.devices.set_device_vpn()`, proton-wg → `IpsetOps.ensure_and_add()` + local store, non-VPN → local store only.

### `services/lan_access_service.py` — LAN access business logic
Orchestrates `RouterLanAccess` (SSH/UCI) with `config.json` persistence. Separate from `VPNService` because LAN access and VPN routing are orthogonal concerns. Zone IDs are truncated to 6 characters (fw3 zone name limit is 11 chars; `fvpn_` prefix takes 5). Exceptions are persisted in `config.json` under `lan_access.exceptions` and re-applied on unlock.

---

## `proton_vpn/` — ProtonVPN Integration

### `proton_vpn/api.py` — ProtonVPN wrapper
Thin synchronous wrapper around `proton-vpn-api-core`. Login (with 2FA), server list, WG/OVPN config generation. WireGuard configs use **persistent-mode certificates** (365-day validity). Each VPN profile gets its own Ed25519 key pair. All VPN options (NetShield, Moderate NAT, NAT-PMP, VPN Accelerator) work with both WireGuard (certificate features) and OpenVPN (username suffixes). See [proton-api-gotchas.md](proton-api-gotchas.md).

### `proton_vpn/server_optimizer.py` — Server scoring and selection
Pure functions. Ranking: Proton `score` (lower = better) → blacklist filter → favourite boost (30% tolerance) → latency tiebreaker (15% similarity). Key functions: `resolve_scope_to_server()`, `find_better_server()`.

### `proton_vpn/latency_probe.py` — TCP latency measurement
**Probes always run from the router via SSH** (never locally — Surface Go is behind VPN). Uses `curl -w "%{time_connect}"` because BusyBox `nc` lacks `-z`/`-w`.

---

## `vpn/` — Protocol Logic

### `vpn/tunnel_strategy.py` — Protocol-specific tunnel operations
Strategy pattern for tunnel create/delete/connect/disconnect/switch across the three protocol families (kernel WG, proton-wg, OpenVPN). Three concrete strategies implement a shared `TunnelStrategy` ABC; callers obtain the right one via `get_strategy(vpn_protocol)`. See [tunnel-strategy-internals.md](tunnel-strategy-internals.md).

### `vpn/smart_protocol.py` — Automatic protocol fallback
`SmartProtocolManager` handles non-blocking protocol fallback when a VPN tunnel doesn't connect within 45s. Cycles through WG UDP → WG TCP → WG TLS → OVPN UDP → OVPN TCP. See [smart-protocol.md](smart-protocol.md).

### `vpn/protocol_limits.py` — Protocol slot enforcement
`MAX_WG_GROUPS=5`, `MAX_OVPN_GROUPS=5`, `MAX_PWG_GROUPS=4`. Two entry points: `check_protocol_slot()` (returns bool) and `require_protocol_slot()` (raises `LimitExceededError`).

### `vpn/profile_healer.py` — Startup self-healing
`ProfileHealer.heal_duplicate_tunnel_ids()` detects proton-wg profiles that share a `tunnel_id` and allocates fresh IDs. Called during `build_profile_list`.

### `vpn/profile_keys.py` — Profile ↔ router key-matching
`local_router_key()` and `router_rule_key()` produce stable `(vpn_protocol, peer_id|client_id)` tuples for matching local profiles to router rules.

---

## `persistence/` — Local Storage

### `persistence/profile_store.py` — Local JSON persistence
Atomic JSON read/write for the slim local store (UI metadata + non-VPN assignments). WireGuard VPN profiles additionally store `wg_key` and `cert_expiry`.

### `persistence/secrets_manager.py` — Encrypted credentials
Fernet (AES-128-CBC + HMAC-SHA256) with PBKDF2 key derivation. Stores ProtonVPN and router credentials in `secrets.enc`.

---

## `background/` — Daemon Threads

### `background/auto_optimizer.py` — Background server switcher
Daemon thread, `_poll_loop` every 60s. Four jobs: (1) server data refresh (~15min loads, ~3h full list), (2) server optimization (daily, `MIN_DWELL_HOURS=6` cooldown), (3) cert renewal (daily, within 30 days of expiry), (4) blocklist update (daily).

### `background/device_tracker.py` — New-device auto-assigner
Polls DHCP leases every 30s. Auto-assigns newly-discovered MACs to the guest profile. Maintains in-memory `_known_macs` set and `noint_stale` flag for IP-change detection.
