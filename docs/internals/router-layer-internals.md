# Router Layer Internals

How the backend communicates with the GL.iNet Flint 2 router via SSH. For the overall backend package structure, see [backend-structure.md](backend-structure.md).

## Three-Layer Architecture

```
Feature Facades   router/facades/policy, tunnel, devices,
                  wireguard, openvpn, proton_wg,
                  adblock, lan_access, firewall
                  ↓ calls tool methods + raw ssh.exec()
Tool Layer        router/tools/uci, ipset, iptables, iproute, service_ctl
                  ↓ calls ssh.exec()
SSH Transport     router/api.py — exec(), write_file(), read_file()
```

All three layers live inside the `router/` package. External callers (services, background threads) import only `from router.api import RouterAPI` and access everything via `router.policy.*`, `router.tunnel.*`, etc.

## SSH Transport (`router/api.py`)

`RouterAPI` manages the Paramiko SSH connection: `connect()`, `disconnect()`, `exec(command)`, `write_file(path, content)`, `read_file(path)`. It auto-reconnects on connection loss and exposes lazy-loaded properties for both the tool layer and feature layer.

**~270 lines** — pure hub, no business logic. Tool and facade objects are created on first access and cached for the lifetime of the SSH session.

## Tool Layer (`router/tools/`)

Five classes that wrap the router's CLI tools with consistent quoting, error handling, and idempotency. Each takes an `SshExecutor` (anything with `exec/write_file/read_file` — typically `RouterAPI`) and produces properly constructed shell commands.

| Class | Wraps | Key conventions |
|-------|-------|-----------------|
| `Uci` | `uci` CLI | Single-quote escaping via `_quote()`, `batch_set()` for atomic multi-field ops, `batch_sections()` for structured batch data, `parse_show()` for output parsing, `ensure_firewall_include()` for idempotent script registration |
| `Ipset` | `ipset` CLI | Always uses `-exist` on create/add, `2>/dev/null || true` on remove/destroy, `members()` parses awk output |
| `Iptables` | `iptables` CLI | `ensure_chain()` / `delete_chain()` for lifecycle, `insert_if_absent()` for the `-C || -I` pattern |
| `Iproute` | `ip` CLI | `link_exists()` / `link_delete()` / `route_add()` / `rule_add()` etc. |
| `ServiceCtl` | `/etc/init.d/*` + `wifi` | `reload/restart/start/stop/enable/disable` + `wifi_reload/wifi_up/wifi_down` |

**When to use raw `self._ssh.exec()` vs tool layer**: The tool layer covers the 5 high-frequency CLI tools. Other router commands (`wg show`, `cat`, `grep`, `pidof`, `ifstatus`, `ubus call`, `iwinfo`, `curl`, `mkdir`, `rm`, `chmod`, `sed`) are fine as raw `exec()` calls — they're infrequent and don't benefit from a wrapper.

Shared WireGuard parsing lives in `router/tools/wg_show.py`: `parse_handshake_age()` and `parse_transfer()` are used by both `RouterTunnel` and `RouterProtonWG`.

## Feature Facades (`router/facades/`)

Each facade groups related router operations for one domain. Facades receive their tool dependencies explicitly via constructor injection — they never access the full `RouterAPI`:

```python
class RouterPolicy:
    def __init__(self, uci: Uci, ssh: SshExecutor):
        self._uci = uci      # typed tool dependency
        self._ssh = ssh       # raw exec for grep/pipe queries only
```

| Facade | File | Constructor dependencies |
|--------|------|------------------------|
| `RouterPolicy` | `router/facades/policy.py` | `(uci, ssh)` |
| `RouterTunnel` | `router/facades/tunnel.py` | `(uci, service_ctl, ssh)` |
| `RouterFirewall` | `router/facades/firewall.py` | `(uci, ipset, service_ctl, ssh)` |
| `RouterDevices` | `router/facades/devices.py` | `(uci, ipset, iproute, service_ctl, policy, ssh)` |
| `RouterWireguard` | `router/facades/wireguard.py` | `(uci, service_ctl, alloc_tunnel_id, ssh)` |
| `RouterOpenvpn` | `router/facades/openvpn.py` | `(uci, service_ctl, alloc_tunnel_id, ssh)` |
| `RouterProtonWG` | `router/facades/proton_wg.py` | `(uci, ipset, iptables, iproute, service_ctl, alloc_tunnel_id, ssh)` |
| `RouterAdblock` | `router/facades/adblock.py` | `(uci, ipset, iptables, service_ctl, ssh, ip6tables=None)` |
| `RouterLanAccess` | `router/facades/lan_access.py` | `(uci, iptables, service_ctl, ssh)` |

The constructor signature tells you at a glance what each facade depends on. If someone tries to use `self._iptables` in `RouterPolicy`, it's an `AttributeError` — not a silent success because the god object has everything.

## Access Pattern

Callers access facades via `router.<facade>.<method>()`:

```python
from router.api import RouterAPI

router = RouterAPI("192.168.8.1", key_filename="~/.ssh/id_ed25519")

# VPN service
router.policy.get_flint_vpn_rules()
router.tunnel.get_tunnel_health(rule_name)
router.wireguard.upload_wireguard_config(...)
router.devices.set_device_vpn(mac, rule_name)

# LAN access service
router.lan_access.get_networks()
router.lan_access.set_zone_forwarding(src, dest, allowed)
```

Facades are lazy-loaded on first property access — no initialization cost until used.

## Shared Helpers

| Module | Purpose |
|--------|---------|
| `router/tunnel_id_alloc.py` | `next_tunnel_id(ssh)` — scans route_policy + ipsets + .env files for the next unused ID (300-399) |
| `router/ipset_ops.py` | `IpsetOps` — centralized proton-wg MAC-based ipset operations (ensure, add, list, reconcile) |
| `router/noint_sync.py` | NoInternet WAN block — manages `fvpn_noint_ips` ipset + firewall REJECT rule |
| `router/types.py` | TypedDicts: `WgRouterInfo`, `OvpnRouterInfo`, `ProtonWgRouterInfo`, `TunnelStatus`, `DhcpLease`, `FlintVpnRule` |

## Testing Patterns

### Pattern 1: Real RouterAPI with mocked exec (facade integration tests)

Used in `tests/test_router_api.py`. Creates a real `RouterAPI` with `exec()` replaced by a pattern-matching mock:

```python
@pytest.fixture
def mock_router():
    router = RouterAPI("192.168.8.1", password="test")
    router._client = MagicMock()
    router._exec_responses = {}
    router._exec_calls = []
    def mock_exec(command, timeout=30):
        router._exec_calls.append(command)
        for pattern, response in router._exec_responses.items():
            if pattern in command:
                return response
        return ""
    router.exec = mock_exec
    return router
```

Facades are lazy-loaded and receive `RouterAPI` as their SSH executor. Calling `mock_router.tunnel.get_tunnel_health(...)` creates a real `RouterTunnel` that calls `self._ssh.exec()` → the mocked exec. No additional mock setup needed for facades.

### Pattern 2: Full MagicMock router (service-level tests)

Used in `tests/test_vpn_service.py`. The router is a `MagicMock()`, so facade calls auto-create sub-mocks:

```python
mock_router = MagicMock()
mock_router.policy.get_flint_vpn_rules.return_value = [...]
mock_router.tunnel.get_tunnel_health.return_value = "green"
```

### Pattern 3: Tool-layer unit tests

Used in `tests/test_router_tools/`. Each tool class takes a `MagicMock()` SSH executor and tests assert on the exact shell command string produced:

```python
def test_set_simple(uci, ssh):
    uci.set("route_policy.rule.enabled", "1")
    ssh.exec.assert_called_once_with("uci set route_policy.rule.enabled='1'")
```

## Key Design Decisions

1. **Tool layer doesn't call other tools**: Each tool class only calls `self._ssh.exec()`. Cross-tool orchestration happens in the feature layer.

2. **Idempotency is built into tools**: `Ipset.create()` always uses `-exist`. `Iptables.delete_chain()` suppresses errors. `Uci.delete()` uses `2>/dev/null; true`. Callers don't need to add error suppression.

3. **Firewall reload is explicit**: Tool-layer methods never trigger a firewall reload implicitly. The feature layer decides when to reload after a batch of changes.

4. **Constructor injection**: Facades declare exactly which tools they use. This makes dependencies visible and prevents accidental coupling to unrelated router subsystems.

5. **`RouterAPI` is a hub, not a god object**: It holds tool and facade properties but has no business logic (~270 lines). All protocol-specific, device, and firewall logic lives in the facades.

6. **Raw `exec()` is OK for non-tool commands**: The tool layer covers UCI, ipset, iptables, iproute2, and service control. Other shell commands (`wg show`, `cat`, `grep`, `pidof`, `ubus call`, `iwinfo`) use raw `exec()` — wrapping them would add ceremony without benefit.
