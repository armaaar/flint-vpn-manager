# Flint VPN Manager MCP Tools

The Flint VPN Manager MCP server exposes the app's business operations as tools. When those tools are loaded in a session, prefer them over raw SSH — they handle unlock state, bridge to the app's live data, and won't do anything the UI wouldn't let a user do.

Tools are prefixed `mcp__flint-vpn-manager__flint_…`. This document lists every tool, when to use it, and when you need to fall back to SSH.

## Prerequisites

### Detecting availability
If this session has the MCP tools loaded, you'll see them in your tool list with the `mcp__flint-vpn-manager__flint_` prefix. If not, the MCP server isn't running in this Claude config, and everything must go through SSH (or the REST API at `http://localhost:5000`).

### Unlock
Most tools require the session to be unlocked. Typical startup:

1. `flint_get_status` — returns `setup-needed`, `locked`, or `unlocked`.
2. If `locked`: `flint_unlock` with the master password. **Ask the user for the password.** Don't assume Claude has it stored anywhere — this is a secret that guards the VPN credentials, and it should come from the user each session unless they've explicitly told you otherwise.
3. From then on, use the business-level tools freely.

Unlock is session-scoped in the backend. If the backend restarts, you need to unlock again.

## Tool catalog

### Status & setup

| Tool | Purpose |
|---|---|
| `flint_get_status` | App lock state (`setup-needed` / `locked` / `unlocked`). Safe to call any time. |
| `flint_unlock` | Unlock the app with the master password. |
| `flint_lock` | Lock the app (invalidates the session). |

### Groups / profiles (the core domain)

| Tool | Purpose |
|---|---|
| `flint_list_groups` | List all groups (VPN, NoVPN, NoInternet) with live tunnel health, kill switch, server info. |
| `flint_create_group` | Create a new group (VPN/NoVPN/NoInternet). Args include protocol, server scope, options. |
| `flint_delete_group` | Delete a group + router cleanup. |
| `flint_update_group` | Update group metadata (name, color, icon, kill_switch, adblock, options). |
| `flint_change_group_type` | Convert between VPN ↔ NoVPN ↔ NoInternet. |
| `flint_change_protocol` | Switch a VPN group's protocol (WG UDP / WG TCP / WG TLS / OVPN). |
| `flint_connect` | Bring a VPN tunnel up. Optional Smart Protocol fallback. |
| `flint_disconnect` | Bring a VPN tunnel down. |
| `flint_reorder_groups` | Set display order across all groups. |
| `flint_set_guest_group` | Mark a group as the guest group (auto-assignment target for new MACs). |

### Server selection

| Tool | Purpose |
|---|---|
| `flint_browse_servers` | Browse Proton's server catalog (country → city → server), with filters. |
| `flint_switch_server` | Switch a group's server. Hot-swap (WG + proton-wg) or teardown (OVPN). |
| `flint_get_server_countries` | List available countries for a given group's scope. |
| `flint_get_server_preferences` | Read the blacklist + favourites lists. |
| `flint_toggle_server_preference` | Add/remove a server from blacklist or favourites. |
| `flint_probe_latency` | Router-side TCP latency probe to server IPs on port 443. |
| `flint_get_available_ports` | Available ports per protocol (for port override). |

### Devices

| Tool | Purpose |
|---|---|
| `flint_list_devices` | Full device list with profile assignment, online status, IP, MAC, speed. |
| `flint_assign_device` | Assign a MAC to a group. |
| `flint_label_device` | Set device custom label + type class. |
| `flint_reserve_device_ip` | Create a DHCP static lease for a device. |
| `flint_release_device_ip` | Remove a DHCP static lease. |

### LAN / networks

| Tool | Purpose |
|---|---|
| `flint_list_networks` | List all LAN networks (zones, SSIDs, subnets, device counts). |
| `flint_create_network` | Create a new network (**~15s WiFi outage** — confirm with user). |
| `flint_delete_network` | Delete a user-created network (**~15s WiFi outage**). |
| `flint_update_network` | Update wireless/network settings for a zone. |
| `flint_list_network_devices` | Devices in a specific network (DHCP leases + ARP supplement). |
| `flint_set_isolation` | Toggle WiFi AP isolation for a zone. |
| `flint_set_network_ipv6` | Enable/disable IPv6 on a specific network. |
| `flint_update_access_rules` | Update zone-to-zone forwarding rules. |
| `flint_list_exceptions` | List LAN device exceptions (cross-zone ACCEPT rules). |
| `flint_add_exception` | Add a LAN device exception. |
| `flint_remove_exception` | Remove a LAN device exception. |

### VPN bypass

| Tool | Purpose |
|---|---|
| `flint_list_vpn_bypass` | List bypass exceptions + presets. |
| `flint_add_vpn_bypass` | Create a bypass exception. |
| `flint_remove_vpn_bypass` | Delete a bypass exception. |
| `flint_toggle_vpn_bypass` | Enable/disable a bypass exception. |

### Adblock & DNS

| Tool | Purpose |
|---|---|
| `flint_get_adblock_settings` | Current adblock sources + custom domains. |
| `flint_update_adblock_settings` | Change adblock sources / custom domains. |
| `flint_update_blocklist_now` | Trigger an immediate blocklist re-download. |
| `flint_search_blocked_domains` | Search the current blocklist. |

### Settings

| Tool | Purpose |
|---|---|
| `flint_get_settings` | All non-sensitive app settings. |
| `flint_update_settings` | Update settings (router IP, alt routing, auto-optimize schedule, etc.). |

### Location & status

| Tool | Purpose |
|---|---|
| `flint_get_location` | Current public IP / country / ISP as seen by ProtonVPN. 30s cache. |
| `flint_get_vpn_status` | Alias for `flint_list_groups` in some flows; live tunnel state. |

### Logs

| Tool | Purpose |
|---|---|
| `flint_list_logs` | List available app log files (app / error / access). |
| `flint_read_log` | Tail a log file. |
| `flint_clear_log` | Clear a log. |

### Housekeeping

| Tool | Purpose |
|---|---|
| `flint_refresh` | Trigger device-tracker poll + server score refresh. Useful after manual router state change. |

## MCP vs SSH decision guide

### Use MCP when

- The user wants to **do** something the app supports: connect/disconnect a tunnel, switch servers, add/remove devices from groups, create a network, manage adblock.
- You need **app-level state**: live tunnel health, current location, device-to-group mapping, server preferences.
- You're not sure — MCP is the safer first choice. If it's not enough, you can still SSH afterwards.

### Use SSH when

- The user wants to **understand why something's broken** at a level MCP doesn't expose.
- You need to inspect: `iptables` / `ip6tables` rules, mangle chain order, ipset membership by ipset name, routing tables, `ip rule`, raw `wg show`, conntrack, `logread`, files under `/etc/fvpn/`, or anything requiring `/proc/<pid>/environ`.
- The app is locked or the MCP server isn't loaded and the user needs state, not an operation.
- You need to run a one-off diagnostic script across the router that isn't a single tool call.

### Use the REST API when

- The user is running the Flint VPN Manager backend on port 5000 and wants to exercise an endpoint directly (scripting, curl tests). `http://localhost:5000/api/status`, etc.
- MCP isn't loaded but the backend is — the REST API is the same surface MCP wraps.

### Multi-layer debugging (common pattern)

A realistic debugging session uses both:

1. **MCP: `flint_get_status`** → confirm unlocked.
2. **MCP: `flint_list_groups`** → see the app's view: "Streaming group, protonwg0, health red".
3. **MCP: `flint_list_devices`** → confirm the user's device is assigned to that group.
4. **SSH**: `cat /etc/fvpn/protonwg/protonwg0.env` and `wg show protonwg0 latest-handshakes` → find the actual failure mode (e.g. WG handshake timeout = endpoint unreachable or config mismatch).
5. **SSH**: `tail /tmp/protonwg0.log` → proton-wg process errors.
6. Decide: server change? → back to **MCP: `flint_switch_server`**. Config corruption? → **SSH cleanup + MCP reconnect.**

## Common MCP patterns

### Connect a specific group
```
flint_get_status
flint_unlock (if needed)
flint_list_groups → identify target group by name or id
flint_connect {group_id: "<uuid>", smart_protocol: false}
```

### Assign a device to a group
```
flint_list_devices → find the MAC
flint_list_groups → find the target group id
flint_assign_device {mac: "aa:bb:cc:dd:ee:ff", profile_id: "<uuid>"}
```

### Switch a group's server
```
flint_list_groups → get current scope
flint_browse_servers {profile_id: "<uuid>", country: "DE"} → pick a server
flint_switch_server {profile_id: "<uuid>", server_id: "<proton id>"}
```

### Diagnose a device with no internet
```
# MCP layer first:
flint_list_devices → confirm it's in expected group, online status, ip
flint_list_groups → confirm that group's tunnel is healthy

# Then SSH if MCP says "everything looks fine":
ssh root@192.168.8.1 '
mac="aa:bb:cc:dd:ee:ff"
for s in $(ipset list -n | grep -E "^(src_mac_|pwg_mac_|fvpn_noint_macs)"); do
  ipset test "$s" "$mac" 2>&1 | grep -q "is in set" && echo "in $s"
done
ip route get $(grep -i "$mac" /tmp/dhcp.leases | awk "{print \$3}" | head -1)
'
```

## Things MCP intentionally can NOT do

Don't look for these; they don't exist:
- **Execute arbitrary SSH commands on the router.** That would defeat the app's abstraction boundary. Use SSH directly.
- **Modify UCI directly.** Go through the group/network/device tools, which wrap UCI operations with the necessary reload + recovery logic.
- **Read router logs** (`logread`, `/tmp/protonwg*.log`, `/var/log/openvpn/*.log`). Use SSH.
- **Inspect iptables / ipset / routing tables directly.** Use SSH.
- **Restart router services.** The app does this internally as part of its operations; you can't do a standalone service restart via MCP. Use SSH with care (see `safe-commands.md`).

## When MCP returns an error

- `"locked"` / `"unauthorized"` — call `flint_unlock` first.
- Errors containing `SSH` / `paramiko` — the backend can't talk to the router. Investigate: is the router up? Is the backend running? Are SSH keys intact? Try `ssh root@192.168.8.1 echo ok`.
- `"slot limit exceeded"` — hit the protocol's tunnel slot limit (5 kernel WG, 5 OVPN, 4 proton-wg).
- `"profile not found"` — id wrong or profile deleted since last list. Re-fetch with `flint_list_groups`.
- Domain-specific errors (protocol not allowed for Tor, etc.) — message is usually informative. If not, check `logs/error.log` via `flint_read_log`.

## Final tip: use MCP to read, SSH to diagnose, MCP to fix

MCP reads are fast and give you the app's canonical view. SSH reads give you the router's actual state. When they disagree, SSH is usually correct and MCP shows what the app *thinks* is there. That divergence is itself a debugging signal — something desynced.

After diagnosing the root cause via SSH, the fix usually wants to go through MCP (or the REST API) so the app's local state stays consistent with the router.
