# Source-of-Truth Rules

The hardest design constraint in this project. Every piece of state lives at exactly one source. Local JSON only holds fields that have **no** native router or Proton API source.

## Router-canonical (read live, never cached)

| State | UCI / runtime location |
|-------|------------------------|
| VPN tunnel rule existence + name | `route_policy.fvpn_rule_*` (named) or `@rule[N]` (anonymized by GL.iNet UI) |
| Tunnel health (green/amber/red/connecting) | `wg show`, `ifstatus`, `route_policy.{rule}.enabled` |
| Kill switch | `route_policy.{rule}.killswitch` |
| Profile name | `route_policy.{rule}.name` + `wireguard.{peer}.name` + `ovpnclient.{client}.name` (atomic 3-write) |
| WG endpoint | `wireguard.{peer_id}.end_point` |
| **Device → VPN profile** | `route_policy.{rule}.from_mac` (+ `src_mac{tunnel_id}` ipset) |
| Display order | Local `display_order` field (unified across all profile types). VPN section order in `route_policy` is synced via `uci reorder` for routing priority but is NOT the display source. |
| Device hostname / IP | `/tmp/dhcp.leases` |
| Device label / device class | `gl-client.{section}.alias` / `.class` |
| Device online / speeds / signal | `ubus call gl-clients list` |
| NoInternet firewall rules | `fvpn_noint_ips` ipset + `fvpn_noint_block` rule (single global pair, managed by `noint_sync.py`) |

## Proton-canonical (resolved on demand by `server_id`)

Server name, country, city, load, features, score → resolved via `proton.get_server_by_id()` (kept fresh by `auto_optimizer._maybe_refresh_server_data()` every ~15min for loads, ~3h for full list). The local store keeps **only** `server_id` + a tiny cache of fields that come from physical-server selection at config-gen time (`endpoint`, `physical_server_domain`, `protocol`).

## Local-only (`profile_store.json`)

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
      "display_order": 0
    },
    {
      "id": "<uuid>",
      "type": "no_vpn",
      "name": "Direct",
      "color": "#888",
      "icon": "🌐",
      "is_guest": false,
      "display_order": 1
    }
  ],
  "device_assignments": { "aa:bb:cc:dd:ee:ff": "<non-vpn profile uuid>" }
}
```

Notes:
- VPN profiles have **no** `name` field (read live from router).
- VPN profiles have **no** `status` or `kill_switch` fields (read live).
- All profiles (VPN and non-VPN) use `display_order` for unified dashboard ordering. Groups can be freely interleaved regardless of type or protocol.
- `device_assignments` only contains non-VPN assignments. VPN device→profile lookup goes through `router.get_device_assignments()` which parses `from_mac` lists.
- Display name precedence for devices: `gl-client.alias` (router-canonical custom label) → DHCP hostname → MAC.

## Why some things stay local

- **Color, icon, is_guest, server_scope, options**: pure UI/intent metadata, no router-native concept
- **`server_id`**: link from local profile to Proton server (not derivable from router config)
- **`wg_key`** (Ed25519): persistent cert key. X25519 WG key derived via `nacl.bindings.crypto_sign_ed25519_sk_to_curve25519`. Router gets the derived key; Ed25519 source stays local for cert refresh.
- **`cert_expiry`**: auto-refreshed daily by `auto_optimizer.check_and_refresh_certs()` if within 30 days of expiry
- **NoVPN/NoInternet group identity**: multiple no-internet groups can coexist with identical router-side rules; only local store can distinguish them
- **Non-VPN device assignments**: router has no concept of these
- **VPN bypass exceptions** (`config.json` → `vpn_bypass`): exception rules, scopes, custom presets. Router-side artifacts (iptables chain, ipsets, routing table, dnsmasq config, firewall include) are derived from this local config and rebuilt on every change and unlock.

## Sync Mechanisms

### `build_profile_list(router, store_data, proton)` — `vpn_service.py`
Single function that produces the canonical profile list. Iterates `router.get_flint_vpn_rules()` first, merges in local UI metadata by stable `(vpn_protocol, peer_id|client_id)` key (so renamed sections still match), resolves server info live via `_resolve_server_live(proton, ...)`. Final output is sorted by `display_order`. Detects:
- **Ghost profiles**: local profile whose router rule was deleted → `_ghost: true`, `health: red`
- **Orphan profiles**: router rule with no matching local metadata → `_orphan: true`
- **Anonymous-section healing**: GL.iNet UI replaces `fvpn_rule_9001` with `@rule[N]` → self-healed via `uci rename`

### `_build_devices_live(router)` — `app.py`
Live device list. 5-second TTL cache. Hostname fallback: DHCP → gl-clients `name` → MAC.

### `_resolve_device_assignments(router, store_data)` — `app.py`
Merges router VPN assignments (from `from_mac`) with local non-VPN assignments.

### `_sync_noint_to_router()` — `app.py`
Delegates to `noint_sync.sync_noint_to_router`. Manages the `fvpn_noint_ips` ipset + `fvpn_noint_block` firewall rule for NoInternet groups.

### SSE stream — `api_stream()` in `app.py`
Every 10 seconds pushes: `tunnel_health`, `kill_switch`, `profile_names`, `server_info`, `smart_protocol_status`, `devices`. Requires unlock (401 when locked).

### Auto-optimizer — `auto_optimizer.py`
Reads live `build_profile_list`, calls `find_better_server` for connected profiles. Also refreshes server scores (~15min loads, ~3h full list).

### Backup / restore
The router backup at `/etc/fvpn/profile_store.bak.json` is the **source of truth** for the profile store. On every unlock, `check_and_auto_restore()` overwrites the local `profile_store.json` from the router backup — no timestamp comparison, no fingerprint gating. Rules:

- **Backup exists + valid JSON** → always restore (router wins)
- **No backup on router** → reset local store to empty (new router = clean slate)
- **Backup unparseable** → leave local alone (transient error)
- **SSH read failure** → leave local alone

During normal operation, every `ps.save()` pushes the updated store back to the router via a registered callback. This ensures the router backup stays current.

**Router replacement**: Swapping to a new router (no backup) gives a clean slate — zero profiles, zero device assignments. Swapping back to the old router restores its backup seamlessly.

**Ghost profiles**: Only appear mid-session when a router rule is deleted while the app is running (never on startup). Ghosts show `_ghost: true`, `health: red`, with UI guidance to change server (recreate tunnel) or delete.

A factory reset wipes both local and router copies.
