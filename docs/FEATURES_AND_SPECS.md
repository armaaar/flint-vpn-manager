# FlintVPN Manager — Features & Specs

User-facing feature reference. For architecture, see [project-overview.md](project-overview.md). For source-of-truth rules, see [source-of-truth.md](source-of-truth.md).

---

## Group Types

Three kinds of groups (also called "profiles") exist. Each has its own routing semantics.

### VPN groups
Route assigned devices through a ProtonVPN tunnel.

- **Protocols**: WireGuard UDP (kernel, fastest), WireGuard TCP (bypasses firewalls), WireGuard TLS/Stealth (looks like HTTPS), OpenVPN/UDP, OpenVPN/TCP
- **Server selection**: 3-level browser (Country → City → Server) with feature filters (Streaming, P2P, Secure Core, Tor) and load indicators. Tor and Secure Core are mutually exclusive (Proton doesn't offer both on the same server).
- **Server scope** — how the group picks its server:
  - **Country** — auto-pick the best server in the chosen country
  - **City** — auto-pick the best server in the chosen city
  - **Server** — pinned to the exact server, never auto-switched
- **VPN Options** (configurable in the group's edit dialog):
  - **Kill Switch** — block traffic if the tunnel drops (router-canonical, written to `route_policy.killswitch`)
  - **NetShield** — DNS-level ad/malware blocking (Off / Malware / Malware+Ads+Trackers)
  - **VPN Accelerator** — up to 400% faster (Proton's speed optimization)
  - **Moderate NAT** — better for gaming/P2P
  - **NAT-PMP** — UPnP-style port forwarding
  - **Secure Core** — multi-hop entry through CH/SE/IS
  - **Port** — override the default VPN port per protocol. Available ports: WG UDP (443, 88, 1224, 51820, 500, 4500), OpenVPN UDP (80, 51820, 4569, 1194, 5060), OpenVPN TCP (443, 7770, 8443). Useful when an ISP blocks the default port. Port resets to "Default" on protocol change. Validated against Proton's advertised port list.
  - **Custom DNS** — override Proton's DNS (10.2.0.1) with a custom resolver (e.g. Pi-hole at 192.168.8.x, AdGuard). Single IPv4 address only. Only available for kernel WireGuard UDP — proton-wg (TCP/TLS) manages DNS separately, and OpenVPN pushes DNS from the server. Overrides NetShield (DNS-level blocking won't work with a custom resolver; the UI warns about this).
  - **Smart Protocol** — when enabled, if the tunnel doesn't connect within 45 seconds, automatically tries alternate protocols in order (WG UDP → OVPN UDP → OVPN TCP → WG TCP → WG TLS). Checks slot availability before each attempt. Excludes OpenVPN for Tor/SC profiles (those servers are WG-only). Non-blocking: `connect_profile()` returns immediately; the SSE tick (10s) monitors health and switches protocols in the background. The frontend shows "Trying wireguard-tcp (3/5)" during retries. Cancelled on disconnect, delete, or type change. Uses per-profile `RLock` for concurrency safety.
- **Connect/Disconnect** — explicit buttons; live state via SSE
- **Auto-optimizer** — background thread that, at a configured time of day, switches eligible groups (scope ≠ "server") to servers with better Proton scores. Uses a 20% relative improvement threshold and 6-hour per-profile cooldown to prevent flapping. When VPN options change (NetShield, Moderate NAT, NAT-PMP, VPN Accelerator), the WireGuard persistent certificate is automatically refreshed before generating the new config (these features are baked into the cert at registration time).

### No VPN groups
Devices use the LAN's normal default route (no VPN). Useful for grouping trusted devices on direct internet.

### No Internet groups
Devices have LAN access but no WAN. Implemented via the `fvpn_noint_ips` ipset + `fvpn_noint_block` firewall rule, managed by `noint_sync.py`. Multiple NoInternet groups can coexist (e.g. "Quarantine" + "Printers Only") -- they're distinguished by local profile_id, not by router state.

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

## Live Status Sync

Server-Sent Events (`/api/stream`) push every 10 seconds:
- **`tunnel_health`** per VPN profile — `green`/`amber`/`red`/`connecting`/`loading`/`unknown`. Computed live from `wg show` handshake age (or OVPN interface state).
- **`kill_switch`** per VPN profile — live from `route_policy.killswitch`
- **`profile_names`** per VPN profile — live from `route_policy.name`, so renames done via SSH propagate without a manual refresh
- **`server_info`** per VPN profile — live server details (name, country, city, load, score). Ensures auto-optimizer server switches propagate to the dashboard without a manual refresh.
- **`smart_protocol_status`** — `{profile_id: {attempting, attempt, total, elapsed}}` for profiles with Smart Protocol retries in progress. The frontend shows "Trying wireguard-tcp (3/5)" during retries.
- **`devices[]`** — full live device list

The SSE loop also runs side effects each tick:
- `tracker.poll_once()` — detect new devices
- `service.tick_smart_protocol()` — monitor and switch protocols for Smart Protocol retries
- `service.sync_noint_to_router()` — reconcile NoInternet firewall rules when device IPs change

The SSE endpoint returns 401 when the session is locked (prevents resource leaks from unauthenticated EventSource connections).

The frontend never persists transient state. Loading spinners come from `health: "loading"` (set when an SSH call fails) or `connecting` (live from the router). Connect/disconnect buttons get an immediate optimistic update from the API response, then SSE confirms.

---

## Server Preferences

- **Blacklist** — exclude servers from automatic selection (auto-optimizer, "fastest" resolution). Pinned servers bypass the blacklist. Managed via star/ban toggles in the ServerPicker or the Settings modal.
- **Favourites** — prefer servers when scores are close. If a favourite's score is within 30% of the best candidate, it wins. Mutually exclusive with blacklist (adding to one removes from the other).
- **Latency probing** — TCP connect-time measurement from the router to VPN server entry IPs on port 443. Uses `curl -w "%{time_connect}"` via SSH. Color-coded badges in ServerPicker: green <50ms, yellow <150ms, red >=150ms.

---

## Location & Sessions

- **Location/IP check** — sidebar widget showing the current public IP, country, and ISP as seen by ProtonVPN's `/vpn/v1/location` endpoint. Click to refresh. Cached for 30 seconds; cache invalidated on tunnel connect/disconnect. Shows error state with retry link on failure.
- **Active sessions** — Settings modal section showing all currently connected VPN sessions on the Proton account with exit IP and protocol. Shows `N/M slots used` (M derived from account tier: 10 for Plus, 1 for Free).

---

## Alternative Routing

Global toggle in Settings. When enabled (default), Proton API calls automatically fall back to DNS-over-HTTPS routing through third-party infrastructure (Google/Quad9 DNS) when Proton's servers are directly unreachable. Useful in censored networks. Handled by the `proton-vpn-api-core` library's `AlternativeRoutingTransport`. Applied at unlock time and updated at runtime when the setting changes.

---

## LAN Access Control

Controls cross-network communication on the router. Operates at the network/zone level (separate from per-group VPN routing).

### Network discovery

Networks are discovered from UCI `wireless`/`network`/`firewall` config. Each network maps to a fw3 zone (e.g. `lan`, `guest`) with its own bridge interface, subnet, and zero or more SSIDs (2.4G / 5G). Device counts are derived from DHCP leases matched against each subnet. The LAN Access page shows all non-WAN zones as collapsible cards.

Devices per network are discovered from DHCP leases supplemented with ARP table entries (`ip neigh`), so devices with static IPs or expired leases still appear in the device list.

### Device isolation (AP isolation)

Per-SSID toggle (`wireless.*.isolate`). When enabled, WiFi clients on the same SSID cannot see each other at L2 -- all traffic must go through the router. Applied to all SSIDs in a zone simultaneously. Toggling triggers `wifi reload` (clients may briefly reconnect).

### Cross-network access rules (zone forwarding)

Traffic between zones is controlled by `firewall.forwarding` UCI entries. Each zone pair has an independent inbound/outbound toggle. Presence of a forwarding entry = allowed; absence = blocked. The UI shows a matrix of inbound/outbound toggles per network pair. Changes are staged locally and applied on Save (one `uci add/delete` + `firewall reload` per rule change).

Router UCI is the source of truth for forwarding state. `config.json` stores intent for UI reference.

### Device exceptions

When cross-network traffic is blocked at the zone level, individual devices can be exempted. Exceptions are iptables ACCEPT rules inserted into the `forwarding_rule` chain (which runs before zone forwarding checks). Each exception specifies:
- **From**: a device IP or entire network subnet
- **To**: a device IP or entire network subnet
- **Direction**: outbound only, inbound only, or both

Exceptions are persisted in `config.json` under `lan_access.exceptions` and written to a firewall include script (`/etc/fvpn/lan_access_rules.sh`) so they survive router reboots. On unlock, `LanAccessService.reapply_all()` re-applies all saved exceptions to iptables.

### mDNS reflection (cross-network device discovery)

Devices on separate networks (e.g. a printer on ArmI, a phone on ArmM) can discover each other via mDNS (Bonjour/AirPrint) through the avahi reflector. Managed automatically — no user toggle needed.

On app unlock and after network create/delete, `LanAccessService._sync_mdns()` ensures:
1. **Avahi reflector** is enabled (`enable-reflector=yes` in `/etc/avahi/avahi-daemon.conf`)
2. **`allow-interfaces`** is set to all active bridge interfaces (e.g. `br-lan,br-guest,br-fvpn_iot`). Without this restriction, avahi sees duplicate packets on both WiFi interfaces and their parent bridges, breaking reflection.
3. **Firewall rules** allow mDNS (UDP 5353) INPUT for zones with `input=REJECT` (e.g. `guest`, `fvpn_*`). The `lan` zone already has `input=ACCEPT`.

New networks created via the app include the mDNS firewall rule in the UCI batch. Discovery only enables finding the device — actual traffic still requires a forwarding rule or device exception.

### LAN Access page

Hash route `#lan-access`. Shows:
- Network cards (collapsible): SSID names, subnet, device count, isolation badge, isolation toggle
- Per-network access rules table: inbound/outbound toggles for each other network
- Device list per network (loaded on expand): name, IP, online status, interface
- Exceptions section: list of active exceptions with add/remove controls
- Exception modal (`ExceptionModal.svelte`): From/To pickers (device or entire network), direction selector

---

## Security

- **Master password** — required on each session. Used to derive a key (PBKDF2) that decrypts `secrets.enc` (Fernet / AES-128-CBC + HMAC-SHA256).
- **Encrypted credential store** — ProtonVPN and router credentials in `secrets.enc`
- **SSH key auth** — `~/.ssh/id_ed25519` → router root. No plaintext passwords.
- **Kill switch** — VPN-side, configured per-group, enforced by `route_policy.killswitch`
- **NetShield** — DNS-level malware/ad blocking, configured per-group. Active status shown prominently on GroupCard when tunnel is connected.

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
PUT    /api/profiles/:id/server         → switch server (regenerate tunnel, refresh cert if options changed)
PUT    /api/profiles/:id/protocol       → change VPN protocol (tear down + recreate)
PUT    /api/profiles/:id/type           → change group type (VPN ↔ NoVPN ↔ NoInternet)
POST   /api/profiles/:id/connect        → bring tunnel up; Smart Protocol monitored via SSE tick
POST   /api/profiles/:id/disconnect     → bring tunnel down; cancels Smart Protocol retry
PUT    /api/profiles/:id/guest          → set as guest group

GET    /api/devices                     → live device list (5s in-memory TTL)
PUT    /api/devices/:mac/profile        → assign device to a profile
PUT    /api/devices/:mac/label          → set custom name + device class
POST   /api/refresh                     → trigger device tracker poll + server score refresh
POST   /api/probe-latency              → TCP latency probe from router {server_ids:[]} → {latencies:{id:ms}}
GET    /api/stream                      → SSE: live state push (10s tick)

GET    /api/location                    → current public IP/country/ISP via Proton (30s cache)
GET    /api/sessions                    → active VPN sessions {sessions:[], max_connections: int}
GET    /api/available-ports             → available VPN ports per protocol

GET    /api/logs                        → list log files
GET    /api/logs/:name                  → tail log content
DELETE /api/logs/:name                  → clear a log

GET    /api/settings                    → non-sensitive config (includes alt routing, blacklist, favourites)
PUT    /api/settings                    → update router IP, alternative routing, etc.
GET    /api/settings/server-preferences → {blacklist:[], favourites:[]}
PUT    /api/settings/server-preferences → replace blacklist and/or favourites
POST   /api/settings/server-preferences/blacklist/:id   → add to blacklist
DELETE /api/settings/server-preferences/blacklist/:id   → remove from blacklist
POST   /api/settings/server-preferences/favourites/:id  → add to favourites
DELETE /api/settings/server-preferences/favourites/:id  → remove from favourites
PUT    /api/settings/credentials        → update encrypted creds
PUT    /api/settings/master-password    → change master password

GET    /api/lan-access/networks                → discovered networks (zones, SSIDs, subnets, counts)
GET    /api/lan-access/networks/:zone/devices  → devices in a specific network
PUT    /api/lan-access/rules                   → update cross-network zone forwarding rules
PUT    /api/lan-access/isolation/:zone         → toggle WiFi AP isolation for a network
GET    /api/lan-access/exceptions              → list device exceptions
POST   /api/lan-access/exceptions              → add device exception
DELETE /api/lan-access/exceptions/:id          → remove device exception

GET    /                                → serve Svelte frontend
```

---

## Hardware Limits

| Resource | Limit | Source |
|----------|-------|--------|
| WireGuard UDP tunnels | 5 | GL.iNet vpn-client (`wgclient1`–`wgclient5`, marks `0x1000`–`0x5000`) |
| WireGuard TCP/TLS tunnels | 4 | FlintVPN proton-wg (`protonwg0`–`protonwg3`, marks `0x6000`/`0x7000`/`0x9000`/`0xf000`) |
| OpenVPN tunnels | 5 | GL.iNet vpn-client (`ovpnclient1`–`ovpnclient5`, marks `0xa000`–`0xe000`) |
| Total simultaneous VPN tunnels | 14 | 5 + 4 + 5 (limited by fwmark address space) |
| DHCP devices | 150 | pool `192.168.8.100`–`.249` |
| MACs per group ipset | 65,536 | ipset `hash:mac` default |

---

## Configuration / Storage

| File | Contains | Editable? |
|------|----------|-----------|
| `secrets.enc` | Encrypted Proton + router credentials. **Never delete.** | Via app only |
| `config.json` | Router IP, master password salt, auto-optimize schedule, alternative routing toggle, server blacklist/favourites. **Never delete.** | Via SettingsModal |
| `profile_store.json` | UI metadata for profiles, non-VPN device assignments. Slim by design (see [source-of-truth.md](source-of-truth.md)) | Via app only |
| `logs/app.log`, `error.log`, `access.log` | Application logs | Cleared via LogsModal |
| `static/` | Compiled Svelte frontend (Vite output) | Rebuilt by `cd frontend && npm run build` |

Everything else (tunnel state, device data, server data) is read live from the router or Proton API on demand.
