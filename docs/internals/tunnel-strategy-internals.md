# Tunnel Strategy Internals

How protocol-specific VPN tunnel operations are separated using the Strategy pattern, and how to extend it.

## Design

`vpn/tunnel_strategy.py` defines an abstract base class `TunnelStrategy` with six operations that every VPN protocol must implement:

| Method | Purpose |
|--------|---------|
| `create` | Generate config via Proton API, upload to router |
| `delete` | Tear down tunnel, clean up all router-side resources |
| `connect` | Bring tunnel up, return health |
| `disconnect` | Bring tunnel down |
| `switch_server` | Change to a different Proton server (protocol-dependent mechanism) |
| `get_health` | Read live tunnel status from router |

Three concrete strategies implement this interface:

| Strategy | Protocols | Managed by |
|----------|-----------|------------|
| `WireGuardStrategy` | `wireguard` (kernel UDP) | GL.iNet `vpn-client` service |
| `OpenVPNStrategy` | `openvpn` (UDP/TCP) | GL.iNet `vpn-client` service |
| `ProtonWGStrategy` | `wireguard-tcp`, `wireguard-tls` | FlintVPN directly (userspace `proton-wg` binary) |

`ProtonWGStrategy` takes a `transport` parameter (`"tcp"` or `"tls"`) at construction time. The two transports share identical lifecycle logic — only the transport hint passed to `proton.generate_wireguard_config` differs.

## Factory

```python
from vpn.tunnel_strategy import get_strategy

strategy = get_strategy(profile["vpn_protocol"])
strategy.connect(router, profile["router_info"])
```

`get_strategy()` maps protocol strings to strategy instances. This is the only place that knows which class handles which protocol. All callers (primarily `vpn_service.py`) use the uniform `TunnelStrategy` interface — no `if protocol == ...` branches.

## Protocol behaviour matrix

| Behaviour | WireGuard (kernel) | OpenVPN | ProtonWG (TCP/TLS) |
|-----------|-------------------|---------|---------------------|
| **Config upload** | `router.upload_wireguard_config` (UCI peer) | `router.upload_openvpn_config` (UCI client + .ovpn file) | `router.upload_proton_wg_config` (.conf + .env files) |
| **Connect/disconnect** | `bring_tunnel_up/down` (enables/disables route policy rule; vpn-client manages interface) | `bring_tunnel_up/down` (same mechanism) | `start/stop_proton_wg_tunnel` (manages process, interface, routing, firewall directly) |
| **Server switch** | **Hot-swap** — in-place `wg set` peer replacement, zero downtime. Reuses existing Ed25519 key (no new cert registration). Router info unchanged. | **Delete-and-recreate** — captures assigned MACs, section position, enabled state; deletes old config; uploads new; restores position, assignments, and enabled state. Brief flicker. | **Hot-swap** — rewrites `.conf` file + `wg setconf` on live interface. Same zero-flicker approach as kernel WG. Router info unchanged. |
| **Health check** | `router.get_tunnel_health(rule_name)` | `router.get_tunnel_health(rule_name)` | `router.get_proton_wg_health(tunnel_name)` |
| **Delete cleanup** | Deletes WG peer + route policy rule | Deletes OVPN client + route policy rule | Best-effort stop (process + routing + firewall), then deletes config files |
| **Return values** | `(router_info, server_info, wg_key, cert_expiry)` | `(router_info, server_info, None, None)` | `(router_info, server_info, wg_key, cert_expiry)` |

### Why OpenVPN can't hot-swap

OpenVPN reads its config once at startup and has no equivalent of `wg set` / `wg setconf` to reload peers at runtime. A server switch requires tearing down the old client and creating a new one. The `OpenVPNStrategy.switch_server` method preserves continuity by:

1. Reading current `from_mac` device assignments from the router
2. Capturing section order index and enabled state
3. Deleting the old client + rule
4. Uploading the new config
5. Restoring the section position via `reorder_vpn_rules`
6. Re-attaching devices to the new rule
7. Only bringing the tunnel up if it was previously running

### Why WG switch reuses the existing key

`generate_wireguard_config` with an `existing_wg_key` skips cert registration. Re-registering an already-registered key causes a 409 conflict from Proton's API. The existing persistent cert (365-day) is reused — only the endpoint changes. See [proton-api-gotchas.md](proton-api-gotchas.md) and [server-switch-internals.md](server-switch-internals.md).

## Adding a new protocol

1. **Create a new `TunnelStrategy` subclass** in `vpn/tunnel_strategy.py` implementing all six methods.
2. **Add the protocol constant** to `consts.py` (e.g. `PROTO_NEW = "new-protocol"`).
3. **Register it in `get_strategy()`** — map the new protocol string to your strategy class.
4. **Add a router facade** in `router/facades/` if the new protocol needs different config upload, health check, or lifecycle commands. Wire it into `router/api.py` as a lazy property.
5. **Add a slot limit** in `vpn/protocol_limits.py` if the router has a maximum number of simultaneous tunnels for this protocol.

No changes needed in `services/vpn_service.py` — it will automatically use the new strategy via `get_strategy()`.

## Related docs

- [server-switch-internals.md](server-switch-internals.md) — router-level switch mechanics, cert handling, latency probing
- [proton-wg-internals.md](proton-wg-internals.md) — proton-wg process targeting, mangle ordering, tunnel ID allocation
- [smart-protocol.md](smart-protocol.md) — automatic protocol fallback (cycles through strategies when tunnels fail to connect)
- [proton-api-gotchas.md](proton-api-gotchas.md) — persistent vs session certs, 409 conflict on re-registration
