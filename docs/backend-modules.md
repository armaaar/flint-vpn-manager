# Backend Modules (`backend/`)

## `app.py` — Flask REST API + SSE
Main server. Thin routing layer that delegates to `VPNService`. All API endpoints, SSE stream. Backup-to-router and auto-restore-on-unlock helpers. Runtime state (router, proton, service instances) lives in `service_registry.py`.

## `service_registry.py` — Runtime service singleton lifecycle
Holds `ProtonAPI`, `RouterAPI`, and `VPNService` instances plus the `session_unlocked` flag. Replaces the old module-level globals in `app.py`. Lazy-init for router and proton; explicit `reset()` on lock. Tests patch `registry.*` fields instead of module-level globals.

## `vpn_service.py` — Profile lifecycle orchestrator
Core orchestrator. `VPNService` owns `build_profile_list`, profile CRUD, `switch_server`, `change_protocol`, `change_type`, `connect_profile`, `disconnect_profile`, `reorder_profiles`. Delegates device management to `DeviceService`, smart protocol to `SmartProtocolManager`, ipset operations to `IpsetOps`, tunnel ID healing to `ProfileHealer`, and protocol slot enforcement to `protocol_limits`. No Flask dependency.

## `protocol_limits.py` — Protocol slot counting and enforcement
Centralized VPN group limit checking. `MAX_WG_GROUPS=5`, `MAX_OVPN_GROUPS=5`, `MAX_PWG_GROUPS=4`. Two entry points: `check_protocol_slot()` (returns bool, used by smart protocol) and `require_protocol_slot()` (raises `LimitExceededError`, used by create/change). Eliminates the 3x duplication that previously existed across `create_profile`, `change_protocol`, and `_smart_has_slot`.

## `ipset_ops.py` — Centralized proton-wg ipset operations
All proton-wg MAC-based ipset mutations go through `IpsetOps`: `ensure_mac_set()`, `add_mac()`, `list_members()`, `ensure_and_add()`. Also owns `reconcile_proton_wg_members()` (lightweight re-add after vpn-client restart) and `reconcile_proton_wg_full()` (full ipset creation + member population + mangle rule rebuild on app unlock). Centralizing ipset operations prevents the class of bugs where ipset create/add/list calls were scattered across 5+ code paths.

## `smart_protocol.py` — Automatic protocol fallback state machine
`SmartProtocolManager` handles non-blocking protocol fallback when a VPN tunnel doesn't connect within 45s. Cycles through WG UDP → WG TCP → WG TLS → OVPN UDP → OVPN TCP. Receives `change_protocol` and switch lock callbacks from VPNService; checks protocol slot availability via `protocol_limits.check_protocol_slot()`. Tor/Secure Core profiles skip OpenVPN in the chain. See [smart-protocol.md](smart-protocol.md) for RLock threading constraints.

## `device_service.py` — Device assignment, listing, and caching
`DeviceService` handles device discovery (`build_devices_live`), assignment (`assign_device`), labeling (`set_device_label`), and TTL-based caching (`get_devices_cached`). Thread-safe cache with `threading.Lock`. Assignment logic branches by protocol: kernel WG/OVPN → router `set_device_vpn()`, proton-wg → `IpsetOps.ensure_and_add()` + local store, non-VPN → local store only.

## `profile_keys.py` — Shared profile ↔ router key-matching helpers
`local_router_key()` and `router_rule_key()` produce stable `(vpn_protocol, peer_id|client_id)` tuples for matching local profiles to router rules. Used by both `build_profile_list` (in vpn_service) and `resolve_assignments` (in device_service). Also contains `default_device()` and `build_ip_to_network_map()`.

## `profile_healer.py` — Startup self-healing for tunnel ID collisions
`ProfileHealer.heal_duplicate_tunnel_ids()` detects proton-wg profiles that share a `tunnel_id` (can happen when two profiles are created between reboots, since ipsets are ephemeral). Allocates a fresh ID, migrates ipset members via `IpsetOps`, and updates the `.env` file on the router. Called during `build_profile_list`.

## `noint_sync.py` — NoInternet WAN block enforcement
Manages the `fvpn_noint_ips` ipset + firewall rule that blocks WAN access for NoInternet groups. Extracted from the old `lan_sync.py`. Key functions: `sync_noint_to_router()`, `wipe_noint()`.

## `proton_api.py` — ProtonVPN wrapper
Thin synchronous wrapper around `proton-vpn-api-core`. Login (with 2FA), server list, WG/OVPN config generation. WireGuard configs use **persistent-mode certificates** (365-day validity, `Mode: "persistent"`). Each VPN profile gets its own Ed25519 key pair registered as a named device in Proton's dashboard. Key methods: `generate_wireguard_config()`, `refresh_wireguard_cert()`, `get_wireguard_x25519_key()`, `refresh_server_loads()` / `refresh_server_list()`, `get_server_entry_ips()`, `get_location()`, `get_sessions()`, `set_alternative_routing()`. All VPN options (NetShield, Moderate NAT, NAT-PMP, VPN Accelerator) work with both WireGuard (certificate features) and OpenVPN (username suffixes: `+f{level}`, `+nr`, `+pmp`, `+nst`). See [proton-api-gotchas.md](proton-api-gotchas.md) for cert modes, deletion limitations, and library quirks.

## `router_api.py` — Router SSH management
SSH-based API (Paramiko + key auth) for the Flint 2. Manages WG/OVPN configs via UCI, route policy rules, ipset membership, firewall rules, DHCP leases, gl-clients metadata. Helpers: `get_flint_vpn_rules`, `get_device_assignments`, `get_tunnel_health`, `get_kill_switch`, `get_profile_name`, `rename_profile`, `reorder_vpn_rules`, `heal_anonymous_rule_section`, `from_mac_tokens` (for case-preserving del_list). FlintVPN UCI helpers: `fvpn_uci_apply`, `fvpn_ipset_membership`. Also `read_file`/`write_file` for disaster-recovery backup, `get_router_fingerprint` for restore fingerprint check.

## `router_devices.py` — Device discovery and online detection
Discovers devices from DHCP leases + `ubus call gl-clients`. For devices on custom bridges (`br-fvpn_*`), online status comes from the ARP neighbor table (`ip neigh show` — `REACHABLE`/`STALE` = online) because `gl-clients` only tracks devices on `br-lan`. WiFi band detection uses `iwinfo` interface names (`ra*` = 2.4G, `rax*` = 5G), which overrides stale `gl-clients` data.

## `profile_store.py` — Local JSON persistence
Atomic JSON read/write for the slim local store (UI metadata + non-VPN assignments). `_sanitize_mac_keys()` strips legacy fields on every save so post-refactor data is automatically cleaned up. WireGuard VPN profiles additionally store `wg_key` (base64 Ed25519 private key for persistent cert management) and `cert_expiry` (Unix timestamp).

## `device_tracker.py` — Background new-device auto-assigner
Minimal background thread. Polls DHCP leases every 30s. The **only** thing it persists is auto-assigning newly-discovered MACs to the guest profile (writes to router for VPN guest, local store for non-VPN guest). Maintains an in-memory `_known_macs` set and `noint_stale` flag for IP-change detection.

## `secrets_manager.py` — Encrypted credentials
Fernet (AES-128-CBC + HMAC-SHA256) with PBKDF2 key derivation. Stores ProtonVPN and router credentials in `secrets.enc`.

## `server_optimizer.py` — Server scoring, filtering, and selection
Pure functions. Ranking: Proton `score` (lower = better) → blacklist filter → favourite boost (30% tolerance) → latency tiebreaker (15% similarity). Key functions: `resolve_scope_to_server()` (profile creation, ServerPicker), `find_better_server()` (auto-optimizer, 20% minimum improvement threshold).

## `latency_probe.py` — TCP latency measurement from router
**Probes always run from the router via SSH** (never locally — Surface Go is behind VPN). Uses `curl -w "%{time_connect}"` because BusyBox `nc` lacks `-z`/`-w`. `probe_servers_local` exists for testing only — never use in production.

## `auto_optimizer.py` — Background server switcher + cert renewal + score refresh + blocklist update
Daemon thread, `_poll_loop` every 60s. Four jobs: (1) server data refresh (~15min loads, ~3h full list), (2) server optimization (daily window, `MIN_DWELL_HOURS=6` cooldown), (3) cert renewal (daily, within 30 days of expiry, independent of auto-optimize), (4) blocklist update (daily, downloads community blocklist and uploads to router).

## `router_lan_access.py` — Router facade for cross-network access control
Discovers networks from UCI `wireless`/`network`/`firewall` config, builds a list of zones with SSIDs, subnets, device counts, and isolation state. **VPN tunnel zones** (`wgclient*`, `ovpnclient*`, `protonwg*`, `wgserver*`, `ovpnserver*`) are filtered out — they are VPN tunnel interfaces, not real LAN networks, and must never appear on the Networks page or in access rules. Manages fw3 zone `forwarding` entries for cross-network traffic rules, toggles per-SSID AP isolation via `wireless.*.isolate`, and applies per-device iptables ACCEPT rules in the `forwarding_rule` chain (with a firewall include script at `/etc/fvpn/lan_access_rules.sh` for reboot persistence). Network creation/deletion uses `_reload_wifi_driver()` which unloads and reloads the `mt_wifi` kernel module — required because MediaTek's driver reads `BssidNum` from `.dat` files only at module load time (see [MediaTek WiFi Driver Constraints](router-reference.md#mediatek-wifi-driver-constraints)). Key methods: `get_networks()`, `get_zone_forwardings()`, `set_zone_forwarding()`, `set_wifi_isolation()`, `create_network()`, `delete_network()`, `apply_device_exceptions()`, `cleanup_exceptions()`. **Known minor issue**: `apply_device_exceptions()` and `_write_firewall_include()` can create duplicate `fvpn_lan_exc` jump rules and fwmark ACCEPT rules in `forwarding_rule` chain on repeated calls. Cosmetic only — rules are idempotent.

## `lan_access_service.py` — LAN access business logic
Orchestrates `RouterLanAccess` (SSH/UCI) with `config.json` persistence. Separate from `VPNService` because LAN access and VPN routing are orthogonal concerns. Zone IDs are truncated to 6 characters (fw3 zone name limit is 11 chars; `fvpn_` prefix takes 5) with collision handling. Methods: `get_lan_overview()` (networks + access rules + exceptions), `get_network_devices()` (devices by zone/subnet), `create_network()` / `delete_network()` (full network lifecycle with WiFi driver reload), `update_access_rules()` (zone forwarding changes), `set_isolation()` (AP isolation toggle), `add_exception()` / `remove_exception()` (device-level iptables rules), `reapply_all()` (boot recovery). Exceptions are persisted in `config.json` under `lan_access.exceptions` and re-applied on unlock.

## `router_adblock.py` — DNS ad-block infrastructure on the router
Manages a second dnsmasq instance (port 5353) with community blocklists. Devices in adblock-enabled groups have their DNS redirected via iptables REDIRECT from port 53 to 5353. The blocking dnsmasq forwards non-blocked queries to the main dnsmasq on 127.0.0.1:53. Uses `fvpn_adblock_macs` hash:mac ipset for per-group MAC matching. Self-healing: checks and provisions on demand. Firewall include script ensures rules survive router reboot.

## `consts.py` — Shared constants
`PROFILE_TYPES`, `LAN_STATES`, `PROTOCOLS`, `ADBLOCK_*` — used across modules to avoid magic strings.

## `tunnel_strategy.py` — Protocol-specific tunnel operations
Strategy pattern for tunnel create/delete/connect/disconnect/switch across the three protocol families (kernel WG, proton-wg, OpenVPN). Encapsulates the differences so `vpn_service.py` doesn't need protocol-specific branches.

## `cli.py` — Click-based terminal interface
Wraps the same backend. Commands: setup, unlock, status, server browse, router status/devices/tunnels, profile CRUD, device assignment, settings.
