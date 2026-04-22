# MCP Server

Flint VPN Manager ships with an optional [Model Context Protocol](https://modelcontextprotocol.io/) server that exposes 40+ tools to any MCP-compatible client — Claude Desktop, Claude Code, Cursor, or a custom client over stdio. It lets an AI agent operate every feature of the app without the human needing to click through the UI.

The paired [flint-vpn-manager skill](../skills/flint-vpn-manager/) documents each tool, explains when to use MCP vs. raw SSH, and gives operational best practices. If you're setting up MCP to use with Claude, install the skill too:

```bash
npx skills add armaaar/flint-vpn-manager
```

## What you get

The server exposes tools under the `flint_*` prefix, grouped by module:

| Module | Examples |
|---|---|
| **Session** | `flint_get_status`, `flint_unlock`, `flint_lock` |
| **Groups/tunnels** | `flint_list_groups`, `flint_create_group`, `flint_connect`, `flint_disconnect`, `flint_switch_server`, `flint_change_protocol` |
| **Devices** | `flint_list_devices`, `flint_assign_device`, `flint_label_device`, `flint_reserve_device_ip` |
| **Servers** | `flint_browse_servers`, `flint_get_server_countries`, `flint_toggle_server_preference`, `flint_probe_latency` |
| **LAN networks** | `flint_list_networks`, `flint_create_network`, `flint_update_access_rules`, `flint_add_exception` |
| **VPN bypass** | `flint_list_vpn_bypass`, `flint_add_vpn_bypass`, `flint_toggle_vpn_bypass` |
| **Adblock** | `flint_get_adblock_settings`, `flint_update_blocklist_now`, `flint_search_blocked_domains` |
| **Settings** | `flint_get_settings`, `flint_update_settings` |
| **Status** | `flint_get_location`, `flint_get_vpn_status` |
| **Logs** | `flint_list_logs`, `flint_read_log`, `flint_clear_log` |

Full catalog with descriptions and usage patterns: [skills/flint-vpn-manager/references/mcp-tools.md](../skills/flint-vpn-manager/references/mcp-tools.md).

## Prerequisites

- The Flint VPN Manager backend must be **installed** (including the `--system-site-packages` venv and the ProtonVPN desktop app — see [installation.md](installation.md)).
- The backend must be **running on port 5000**. The MCP server is a thin wrapper over the REST API; it does not talk to the router directly.
- You must know the **master password**. The backend starts locked, and the first MCP call must be `flint_unlock` before any other tool works.

## Configure your MCP client

### Claude Code (in-repo)

The repo ships with a `.mcp.json` at the root that Claude Code auto-detects when launched from the repo directory:

```json
{
  "mcpServers": {
    "flint-vpn": {
      "type": "stdio",
      "command": "bash",
      "args": ["-c", "source venv/bin/activate && cd backend && python -m mcp_server"]
    }
  }
}
```

Run `claude` from inside the repo and the tools will be available immediately (prefix `mcp__flint-vpn__flint_*`).

### Claude Code (from any directory)

Add to your user-scope config at `~/.claude/settings.json` (or the project-scope equivalent):

```json
{
  "mcpServers": {
    "flint-vpn": {
      "type": "stdio",
      "command": "bash",
      "args": ["-c", "cd /absolute/path/to/flint-vpn-manager && source venv/bin/activate && cd backend && python -m mcp_server"]
    }
  }
}
```

Replace `/absolute/path/to/flint-vpn-manager` with your clone location.

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS (or `%APPDATA%\Claude\claude_desktop_config.json` on Windows — note that even if Claude Desktop runs on Windows/macOS, the MCP server itself must run on the Linux host where the backend is installed):

```json
{
  "mcpServers": {
    "flint-vpn": {
      "command": "ssh",
      "args": [
        "user@<linux-host>",
        "cd /path/to/flint-vpn-manager && source venv/bin/activate && cd backend && python -m mcp_server"
      ]
    }
  }
}
```

If Claude Desktop runs on the same Linux box as the backend, use the in-repo config pattern above.

### Any other MCP client

The server speaks stdio. Invoke with:

```bash
cd /path/to/flint-vpn-manager
source venv/bin/activate
cd backend
python -m mcp_server
```

The process reads MCP JSON-RPC from stdin and writes to stdout. Clients that support stdio transport (Cursor, custom scripts, etc.) can wire it in directly.

## First-call flow

Every session starts in a locked state. The MCP server exposes three lock-lifecycle tools:

1. `flint_get_status` — returns `setup-needed`, `locked`, or `unlocked`
2. `flint_unlock` — takes the master password; unlocks the backend
3. `flint_lock` — explicit lock (optional; the session auto-locks on backend restart)

The agent should check status first, ask the human for the master password if locked, then proceed. The [flint-vpn-manager skill](../skills/flint-vpn-manager/) codifies this flow — install it for best results with Claude.

## What MCP cannot do

Intentional omissions. Use the backend directly or SSH for these:

- **Arbitrary SSH commands on the router** — would defeat the app's abstraction boundary
- **Direct UCI modifications** — go through the group/network/device tools, which wrap UCI with necessary reload/recovery logic
- **Reading router logs** (`logread`, `/tmp/protonwg*.log`) — use SSH
- **Inspecting iptables/ipset/routing tables directly** — use SSH
- **Restarting router services** — the app does this internally; standalone control isn't exposed

The companion skill documents when to fall back to SSH and gives concrete diagnostic recipes: [skills/flint-vpn-manager/references/debug-recipes.md](../skills/flint-vpn-manager/references/debug-recipes.md).

## Troubleshooting

**"locked" / "unauthorized"** — you haven't called `flint_unlock` yet this session.

**Errors containing `SSH` / `paramiko`** — the backend can't talk to the router. Check: is the router up? Is `config.json`'s `router_ip` correct? Can you `ssh root@<router-ip>` by hand?

**`ModuleNotFoundError: proton_vpn_api_core`** — the venv wasn't created with `--system-site-packages`. See [installation.md](installation.md#protonvpn--desktop-app-required-on-the-host).

**Tools don't appear in Claude's tool list** — check `claude mcp list` (Claude Code) or the Claude Desktop logs for connection errors. Run the command manually to see stdout; successful startup writes nothing but the server process should stay alive waiting for stdin input.

**Backend not on port 5000** — edit `backend/app.py` or set an override; the MCP server hardcodes `http://localhost:5000`.

**"slot limit exceeded"** on `flint_create_group` — hit a protocol slot limit (5 kernel WG, 5 OpenVPN, 4 proton-wg). Delete an unused group first.
