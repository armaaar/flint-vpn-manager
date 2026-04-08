# FlintVPN Manager — Features & Specs

User-facing feature reference. For architecture and source-of-truth rules, see `../CLAUDE.md`.

---

## Group Types

Three kinds of groups (also called "profiles") exist. Each has its own routing semantics.

### VPN groups
Route assigned devices through a ProtonVPN tunnel.

- **Protocols**: WireGuard, OpenVPN/UDP, OpenVPN/TCP
- **Server selection**: 3-level browser (Country → City → Server) with feature filters (streaming, P2P, Secure Core, Tor) and load indicators
- **Server scope** — how the group picks its server:
  - **Country** — auto-pick the best server in the chosen country
  - **City** — auto-pick the best server in the chosen city
  - **Server** — pinned to the exact server, never auto-switched
- **VPN Options** (configurable in the group's edit dialog):
  - **Kill Switch** — block traffic if the tunnel drops (router-canonical, written to `route_policy.killswitch`)
  - **NetShield** — DNS-level ad/malware blocking (Off / Malware / Malware+Ads+Trackers)
  - **VPN Accelerator** — WireGuard-only; up to 400% faster
  - **Moderate NAT** — WireGuard-only; better for gaming/P2P
  - **NAT-PMP** — WireGuard-only; UPnP-style port forwarding
  - **Secure Core** — multi-hop entry through CH/SE/IS
- **Connect/Disconnect** — explicit buttons; live state via SSE
- **Auto-switch hint** — when the current server's load is significantly higher than another in scope, a "⚡ Faster" hint appears with a one-click switch
- **Auto-optimizer** — background thread that, at a configured time of day, switches eligible groups (scope ≠ "server") to lower-load servers

### No VPN groups
Devices use the LAN's normal default route (no VPN). Useful for putting trusted devices on direct internet while keeping LAN isolation rules.

### No Internet groups
Devices have LAN access but no WAN. Implemented as `firewall.fvpn_noinet_<mac>_*` iptables rules per assigned device. Multiple NoInternet groups can coexist (e.g. "Quarantine" + "Printers Only") — they're distinguished by local profile_id, not by router state.

---

## Device Management

- **Discovery** — devices appear automatically from the router's DHCP leases and `ubus call gl-clients` data. Live, no polling delay beyond the SSE 10s tick.
- **Drag-and-drop** — drag a device chip into any group card (or back to the unassigned section). VPN assignments write to `route_policy.from_mac` + `ipset` on the router; non-VPN assignments write to local store.
- **Custom labels** — rename devices via the device modal. Stored in `gl-client.{section}.alias` on the router (canonical), so the GL.iNet UI sees them too.
- **Device type** — 15 GL.iNet classes (`computer`, `phone`, `pad`, `camera`, `watch`, `laptop`, `printer`, `sound`, `television`, `smartappliances`, `games`, `gateway`, `nas`, `server`, `switch`). Bidirectional sync with router.
- **Live metadata** — online status, RX/TX speed, total RX/TX, WiFi signal (dBm), link speed, interface (2.4G / 5G / cable). All read live from the router every API call (with 5s in-memory cache).
- **Display name precedence**: custom label (`gl-client.alias`) → DHCP hostname → MAC.
- **Private MAC indicator** — devices with randomized MACs (2nd hex char ∈ `{2,6,A,E}`) get a `⚠ Private MAC` badge.
- **Guest auto-assignment** — newly-discovered MACs are auto-assigned to whichever group has `is_guest: true` (any type). The device tracker only persists this for new MACs; existing assignments aren't touched.

---

## LAN Access Control

Granular firewall rules controlling device-to-device LAN traffic. Independent of VPN routing — applies whether or not the group's tunnel is up.

- **Three states per direction**:
  - `allowed` — no restriction
  - `group_only` — can only talk to other devices in the same group
  - `blocked` — no LAN access at all
- **Per-group settings** — `outbound` and `inbound` configured in the EditGroup modal
- **Per-device overrides** — individual devices can override group settings (set in DeviceModal)
- **Implementation** — iptables rules in the `fvpn_lan` chain; ipsets `fvpn_lmac_<short>` (MAC set) and `fvpn_lip_<short>` (IP set) per group that needs them
- **Live IP source** — device IPs come from `router.get_dhcp_leases()` at rule-build time, not from any local cache
- **Triggers** — rules are rebuilt on session unlock, profile create/delete, device assignment change, LAN setting change, and when the device tracker detects an IP change for a restricted device

---

## Live Status Sync

Server-Sent Events (`/api/stream`) push every 10 seconds:
- **`tunnel_health`** per VPN profile — `green`/`amber`/`red`/`connecting`/`loading`/`unknown`. Computed live from `wg show` handshake age (or OVPN interface state).
- **`kill_switch`** per VPN profile — live from `route_policy.killswitch`
- **`profile_names`** per VPN profile — live from `route_policy.name`, so renames done via SSH propagate without a manual refresh
- **`better_servers`** per profile (every 3rd tick, ~30s) — passive optimizer hint
- **`devices[]`** — full live device list

The frontend never persists transient state. Loading spinners come from `health: "loading"` (set when an SSH call fails) or `connecting` (live from the router). Connect/disconnect buttons get an immediate optimistic update from the API response, then SSE confirms.

---

## Security

- **Master password** — required on each session. Used to derive a key (PBKDF2) that decrypts `secrets.enc` (Fernet / AES-128-CBC + HMAC-SHA256).
- **Encrypted credential store** — ProtonVPN and router credentials in `secrets.enc`
- **SSH key auth** — `~/.ssh/id_ed25519` → router root. No plaintext passwords.
- **Kill switch** — VPN-side, configured per-group, enforced by `route_policy.killswitch`
- **NetShield** — DNS-level malware/ad blocking, configured per-group

---

## REST API

```
GET    /api/status                      → setup-needed | locked | unlocked
POST   /api/setup                       → first-time credential setup
POST   /api/unlock                      → unlock session

GET    /api/profiles                    → live merged profile list
POST   /api/profiles                    → create group (VPN/NoVPN/NoInternet)
PUT    /api/profiles/reorder            → reorder (VPN → uci reorder, non-VPN → local)
PUT    /api/profiles/:id                → update metadata + kill_switch
DELETE /api/profiles/:id                → delete group + cleanup

GET    /api/profiles/:id/servers        → ProtonVPN server list (filtered)
PUT    /api/profiles/:id/server         → switch server (regenerate tunnel)
POST   /api/profiles/:id/connect        → bring tunnel up; returns live health
POST   /api/profiles/:id/disconnect     → bring tunnel down; returns live health
PUT    /api/profiles/:id/guest          → set as guest group

GET    /api/devices                     → live device list (5s in-memory TTL)
PUT    /api/devices/:mac/profile        → assign device to a profile
PUT    /api/devices/:mac/label          → set custom name + device class
PUT    /api/profiles/:id/lan-access     → set group LAN policy
PUT    /api/devices/:mac/lan-access     → set per-device LAN override

POST   /api/refresh                     → trigger device tracker poll
GET    /api/stream                      → SSE: live state push (10s tick)

GET    /api/logs                        → list log files
GET    /api/logs/:name                  → tail log content
DELETE /api/logs/:name                  → clear a log

GET    /api/settings                    → non-sensitive config
PUT    /api/settings                    → update router IP etc
PUT    /api/settings/credentials        → update encrypted creds
PUT    /api/settings/master-password    → change master password

GET    /                                → serve Svelte frontend
```

---

## Hardware Limits

| Resource | Limit | Source |
|----------|-------|--------|
| WireGuard tunnels | 5 | GL.iNet firmware (`wgclient1`–`wgclient5`, marks `0x1000`–`0x5000`) |
| OpenVPN tunnels | 5 | GL.iNet firmware (`ovpnclient1`–`ovpnclient5`, marks `0xa000`–`0xe000`) |
| Total simultaneous VPN tunnels | 10 | sum of above |
| DHCP devices | 150 | pool `192.168.8.100`–`.249` |
| MACs per group ipset | 65,536 | ipset `hash:mac` default |

---

## Configuration / Storage

| File | Contains | Editable? |
|------|----------|-----------|
| `secrets.enc` | Encrypted Proton + router credentials. **Never delete.** | Via app only |
| `config.json` | Router IP, master password salt, app settings. **Never delete.** | Via SettingsModal |
| `profile_store.json` | UI metadata for profiles, non-VPN device assignments, LAN overrides. Slim by design (see `CLAUDE.md` source-of-truth section) | Via app only |
| `logs/app.log`, `error.log`, `access.log` | Application logs | Cleared via LogsModal |
| `static/` | Compiled Svelte frontend (Vite output) | Rebuilt by `cd frontend && npm run build` |

Everything else (tunnel state, device data, server data) is read live from the router or Proton API on demand.
