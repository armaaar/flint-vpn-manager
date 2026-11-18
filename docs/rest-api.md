# REST API

```
GET/POST /api/status|setup|unlock|lock  → auth lifecycle
GET/POST/PUT/DELETE /api/profiles[/:id] → CRUD, reorder
PUT  /api/profiles/:id/server|protocol|type|guest → server switch, protocol change, type change, guest
POST /api/profiles/:id/connect|disconnect → tunnel up/down (connect accepts {smart_protocol?: true})
GET/PUT /api/devices[/:mac/profile|label] → device list, assign, label
PUT/DELETE /api/devices/:mac/reserved-ip → reserve or release a static IP
POST /api/refresh                       → trigger device poll + score refresh
POST /api/probe-latency                 → {server_ids:[]} → {latencies:{id:ms}}
GET  /api/stream                        → SSE (10s): health, kill_switch, names, server_info, smart_protocol, devices
GET  /api/router-ip|available-ports|vpn-status|server-countries → router WAN IPv4/IPv6, port list, Proton account status, country browse
GET/PUT /api/settings[/server-preferences|credentials|master-password|adblock] → config CRUD
GET  /api/settings/adblock/domains         → paginated blocklist search (?search=&page=&limit=)
POST /api/settings/adblock/update-now      → immediate blocklist download + upload
POST/DELETE /api/settings/server-preferences/blacklist|favourites/:id → toggle
GET/DELETE /api/logs[/:name]            → log viewer
GET  /api/lan-access/networks          → discovered networks (zones, SSIDs, subnets, device counts)
GET  /api/lan-access/networks/:zone/devices → devices in a specific network
POST /api/lan-access/networks          → create a new network (zone, bridge, SSID, subnet, firewall)
PUT    /api/lan-access/networks/:zone  → update an existing network (SSIDs, password, etc.)
DELETE /api/lan-access/networks/:zone  → delete a network and all its resources
PUT  /api/lan-access/rules             → update cross-network zone forwarding rules
PUT  /api/lan-access/isolation/:zone   → toggle WiFi AP isolation for a network
PUT  /api/lan-access/ipv6/:zone       → toggle IPv6 for a network
GET/POST /api/lan-access/exceptions    → list / add device exceptions
DELETE /api/lan-access/exceptions/:id  → remove a device exception
GET  /api/vpn-bypass                   → list exceptions + presets + dnsmasq status
POST /api/vpn-bypass/exceptions        → create bypass exception (from preset or custom rules)
PUT  /api/vpn-bypass/exceptions/:id    → update bypass exception
DELETE /api/vpn-bypass/exceptions/:id  → delete bypass exception
PUT  /api/vpn-bypass/exceptions/:id/toggle → enable/disable bypass exception
POST /api/vpn-bypass/presets           → save custom preset
PUT  /api/vpn-bypass/presets/:id       → update custom preset
DELETE /api/vpn-bypass/presets/:id     → delete custom preset
POST /api/vpn-bypass/dnsmasq-install   → install dnsmasq-full on router
GET  /api/split-vpns[?live=0]          → split VPNs (+ live tunnel status), runtime install state, max slots
POST /api/split-vpns                   → create {name, server, port?, tunnel_mode?, username, password, totp_secret?, master_password, group_ids, domains, cidrs, use_pushed_routes?, enabled?, auto_connect?}
PUT  /api/split-vpns/:id               → update (password/totp_secret + master_password only when changing credentials)
DELETE /api/split-vpns/:id             → tear down tunnel/namespace and delete
POST /api/split-vpns/:id/connect       → {otp?} (default: generated from stored TOTP secret) → start the client in its namespace (≤ ~150s); returns status + client log tail
POST /api/split-vpns/:id/disconnect    → stop the client and remove its namespace
GET  /api/split-vpns/:id/log           → client connect log tail
GET  /api/split-vpns/runtime           → {installed, files, local_files: {barracuda_archive, qemu}}: qemu + Barracuda 5.3.10 CLI/daemon on the router (sha256-checked) and which install sources exist in the local runtime/ folder
POST /api/split-vpns/runtime/install   → no download: verify the local runtime/ files (Barracuda 5.3.10 archive, pinned sha256; qemu-x86_64-flint from tools/qemu/build.sh) and upload them to the router; 400 {error} names a missing file or checksum mismatch
```
