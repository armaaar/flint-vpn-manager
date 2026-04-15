# REST API

```
GET/POST /api/status|setup|unlock|lock  → auth lifecycle
GET/POST/PUT/DELETE /api/profiles[/:id] → CRUD, reorder
PUT  /api/profiles/:id/server|protocol|type|guest → server switch, protocol change, type change, guest
POST /api/profiles/:id/connect|disconnect → tunnel up/down (connect accepts {smart_protocol?: true})
GET/PUT /api/devices[/:mac/profile|label] → device list, assign, label
POST /api/refresh                       → trigger device poll + score refresh
POST /api/probe-latency                 → {server_ids:[]} → {latencies:{id:ms}}
GET  /api/stream                        → SSE (10s): health, kill_switch, names, server_info, smart_protocol, devices
GET  /api/location|available-ports|vpn-status|server-countries → IP check, port list, Proton account status, country browse
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
```
