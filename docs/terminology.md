# Terminology

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
| **DNS Ad Blocker** | Per-group DNS-level blocking via `addn-hosts` injection into per-tunnel dnsmasq conf-dirs. Blocklist file at `/etc/fvpn/blocklist.hosts` with dual-stack entries (IPv4 `0.0.0.0` + IPv6 `::`). Profile field `adblock: true/false`. VPN + NoVPN groups only. `sync_adblock(ifaces)` manages snippet lifecycle. |
| **Anonymous section** | `@rule[N]` from GL.iNet UI edits. Self-healed to `fvpn_rule_*` by `heal_anonymous_rule_section`. |
| **proton-wg** | Userspace WG (TCP/TLS). ARM64 binary at `/usr/bin/proton-wg`. Flint VPN Manager-managed. |
| **Persistent cert** | 365-day WG cert, `Mode: "persistent"`. Per-profile Ed25519 key. No local agent needed. |
| **Smart Protocol** | Auto protocol fallback: 45s timeout → cycles WG UDP → OVPN UDP → OVPN TCP → WG TCP → WG TLS. See [smart-protocol.md](internals/smart-protocol.md). |
| **Custom DNS** | Per-profile DNS override (**kernel WG UDP only**). Single IPv4 (`ipaddress.IPv4Address`). Disables NetShield DNS. |
| **Port Override** | Alternate ports per protocol from Proton's `clientconfig`. |
| **Alternative Routing** | DoH fallback for API calls via `proton-vpn-api-core`'s `AutoTransport`. |
| **Tor Server** | Tor exit node routing via `tor` feature flag in `server_scope.features`. |
| **Network (LAN Access)** | A zone on the router with its own bridge, subnet, and (optionally) SSIDs. Discovered from UCI `wireless`/`network`/`firewall`. Identified by zone name (e.g. `lan`, `guest`). |
| **Zone Forwarding** | A `firewall.forwarding` UCI entry allowing traffic between two fw3 zones. Presence = allowed, absence = blocked. Managed by `router_lan_access.set_zone_forwarding()`. |
| **AP Isolation** | Per-SSID `wireless.*.isolate` flag. When enabled, WiFi clients on the same SSID cannot communicate directly (packets go through the router). Toggled via `router_lan_access.set_wifi_isolation()`. |
| **Device Exception** | An iptables ACCEPT rule in `forwarding_rule` chain allowing a specific device (by IP) to communicate across blocked networks. Persisted in `config.json` under `lan_access.exceptions`, re-applied on unlock. |
