# FlintVPN Manager

![CI](https://github.com/armaaar/flint-vpn-manager/actions/workflows/ci.yml/badge.svg)
[![License: PolyForm Noncommercial 1.0.0](https://img.shields.io/badge/license-PolyForm%20NC%201.0.0-blue)](LICENSE)

A self-hosted web dashboard for managing **ProtonVPN** WireGuard and OpenVPN tunnels on a **GL.iNet Flint 2 (GL-MT6000)** router. Group your devices, assign each group to a different VPN exit (or no VPN at all), and manage everything from a single Aircove-style dashboard reachable from any device on your LAN.

---

## ⚠️ Important disclaimer — read first

This is a **personal hobby project** built for one very specific setup:

- **Router**: GL.iNet Flint 2 (GL-MT6000), OpenWrt-based firmware **4.8.4**
- **VPN provider**: ProtonVPN (free or paid) — with the **official ProtonVPN Linux desktop app installed on the host**
- **Host**: A Linux machine on the same LAN running Python 3.12+ (tested on Ultramarine/Fedora; other modern distros should work but are not verified)

It has been developed, tested, and operated **only** on this combination. It is **not guaranteed to work** — and may actively break things — on:

- Different GL.iNet routers or firmware versions
- Non-GL.iNet routers, even if they run OpenWrt
- Other VPN providers
- **macOS or Windows hosts** — the project depends on the ProtonVPN Linux desktop app (`proton-vpn-gnome-desktop` / `proton-vpn-api-core`) and the Linux D-Bus secret service, neither of which are available on other OSes
- Untested Linux distributions (there is no cross-distro test matrix)

**Misconfiguration can knock every device on your LAN offline.** The project drives low-level router configuration (UCI, ipsets, iptables, route policy) over SSH. There's no undo button. There is also **no support** — open an issue if you want to share context, but don't expect personal troubleshooting.

**Use at your own risk.** See [SECURITY.md](SECURITY.md) for the threat model.

---

## Features

- **Per-device VPN routing** — drag a device into a group, it routes through that group's tunnel. Backed by `route_policy` + `ipset`, no `rtp2.sh` foot-guns.
- **Multiple simultaneous tunnels** — up to 5 kernel WireGuard + 4 WireGuard TCP/TLS (proton-wg) + 5 OpenVPN, each with its own ProtonVPN exit.
- **Group types** — VPN, NoVPN (direct), or NoInternet (LAN-only).
- **Live ProtonVPN integration** — server browser by country/city, NetShield, Moderate NAT, NAT-PMP, VPN Accelerator, Secure Core, Tor exits.
- **Auto-optimizer** — background thread that swaps each group to a less-loaded server once a day.
- **Kill switch** per group, live from the router.
- **LAN access policies** — `allowed` / `group_only` / `blocked` per group or per device, via fw3 zones and separate subnets.
- **Guest group** — newly seen MACs are auto-assigned to your chosen group.
- **Device labels & types** sync bidirectionally with the GL.iNet UI (`gl-client.alias` / `.class`).
- **DNS ad-blocker** (optional) — per-group DNS-level blocking of ads/trackers/malware via a second dnsmasq instance.
- **Smart Protocol** — automatic fallback from WireGuard → OpenVPN → WG-over-TLS when a tunnel won't connect.
- **Persistent WireGuard certificates** — 365-day validity; router keeps tunneling even if the host is off.
- **Encrypted credentials** — Fernet (AES-128 + HMAC) with PBKDF2, unlocked by a master password.

---

## Architecture

```
Linux host on LAN                       GL.iNet Flint 2 Router
┌──────────────────────────┐            ┌──────────────────────────┐
│  Flask backend :5000     │──SSH────▶ │  OpenWrt + GL.iNet FW    │
│  Svelte frontend (static)│            │  WireGuard (kernel)      │
│  ProtonVPN API (keyring) │            │  OpenVPN                 │
│  profile_store.json      │            │  proton-wg (userspace)   │
│  secrets.enc, config.json│            │  route_policy + ipset    │
└──────────────────────────┘            │  fvpn_lan iptables       │
                                        └──────────────────────────┘
```

The router is the **source of truth** for tunnel state, device→group mappings, kill switch, group names, and ordering. The host's local JSON store only holds UI metadata (color, icon, server scope, options) and non-VPN assignments. Every read goes live to the router over SSH; almost nothing is cached on the host.

For the full source-of-truth contract and module-by-module breakdown, see [`CLAUDE.md`](CLAUDE.md) and the [`docs/`](docs/) folder (especially [`docs/project-overview.md`](docs/project-overview.md), [`docs/backend-structure.md`](docs/backend-structure.md), and [`docs/proton-wg-internals.md`](docs/proton-wg-internals.md)).

---

## Prerequisites

### Router
- **GL.iNet Flint 2 (GL-MT6000)** on firmware **4.8.4**
- SSH access enabled with public-key authentication to `root`
- **proton-wg binary installed** (see [Router setup](#router-setup) below) — only required if you want WireGuard TCP/TLS tunnels for restrictive networks; skippable if you only use kernel WireGuard and OpenVPN

### Host
- **Linux only.** The app will not run on macOS or Windows (see below).
- On the same LAN as the router
- **Python 3.12+** (3.13 also tested)
- **Node.js 20+** (for the one-time frontend build)

### ProtonVPN — desktop app required on the host

This project does **not** re-implement the ProtonVPN authentication stack. Instead it reuses the official `proton-vpn-api-core` library plus the system keyring (D-Bus secret service) that the ProtonVPN Linux desktop app sets up. In practice this means:

1. **Install the official ProtonVPN Linux desktop app** on the host before installing this project. See the [ProtonVPN Linux download page](https://protonvpn.com/support/official-linux-vpn-ubuntu/) for your distribution. It installs `proton-vpn-api-core` system-wide and wires up the secret service.
2. **You do not need to log in via the GTK app** — FlintVPN Manager does its own login flow. But the libraries and D-Bus services the GTK app installs are what let `proton-vpn-api-core` work.
3. **The Python venv must be created with `--system-site-packages`** so that `import proton_vpn_api_core` picks up the system-wide install. A normal isolated venv will not work.
4. **A ProtonVPN account** (free or paid). 2FA is supported.

If you cannot or will not install the ProtonVPN desktop app on the host, this project will not run. That constraint is structural, not a packaging oversight — the project deliberately relies on Proton's own libraries to avoid drifting from their auth flow.

---

## Router setup

### 1. Enable SSH

In the GL.iNet admin UI: **System → Advanced Settings → LuCI → System → Administration**, or via `ssh root@192.168.8.1` with the admin password. Set the router to allow key-based login and install your public key at `/etc/dropbear/authorized_keys`:

```bash
ssh-copy-id -i ~/.ssh/id_ed25519.pub root@192.168.8.1
# Then verify:
ssh root@192.168.8.1 "echo connected"
```

### 2. Install proton-wg (optional, for WireGuard TCP/TLS)

Kernel WireGuard over UDP is fast but some restrictive networks block it. `proton-wg` is ProtonVPN's userspace WireGuard-over-TLS helper that makes traffic look like ordinary HTTPS.

The binary is distributed by ProtonVPN — check your Proton subscriber area or ProtonVPN's developer resources for the Linux ARM64 build targeting MediaTek Filogic 880. Place it on the router:

```bash
scp proton-wg root@192.168.8.1:/usr/bin/proton-wg
ssh root@192.168.8.1 "chmod +x /usr/bin/proton-wg && proton-wg --version"
```

If you skip this step, the app will still work — you just won't be able to create WG-TCP/TLS tunnels. Kernel WG and OpenVPN work without it.

### 3. (Optional) Install adblock-fast

For the built-in per-group DNS ad-blocker:

```bash
ssh root@192.168.8.1 "opkg update && opkg install adblock-fast dnsmasq-full"
```

---

## App installation

> **Prerequisite reminder:** Install the [ProtonVPN Linux desktop app](#protonvpn--desktop-app-required-on-the-host) on the host **before** running the steps below. The venv needs `--system-site-packages` so it can reach the Proton libraries the desktop app installs — a plain venv will fail with `ModuleNotFoundError: proton_vpn_api_core`.

```bash
# Clone
git clone https://github.com/armaaar/flint-vpn-manager.git
cd flint-vpn-manager

# Backend — note --system-site-packages is REQUIRED
python -m venv --system-site-packages venv
source venv/bin/activate
pip install -r requirements.txt

# Frontend (one-time build; Flask serves from static/)
cd frontend
npm install
npm run build
cd ..

# Run
python backend/app.py
```

The dashboard is now at `http://<host-ip>:5000` and reachable from any device on the LAN.

### First-launch wizard

On first launch the UI walks you through:

1. Setting a **master password** (used to encrypt `secrets.enc` with AES-128-GCM via PBKDF2)
2. Entering **ProtonVPN credentials** (with 2FA if enabled)
3. Confirming the **router IP** (defaults to `192.168.8.1`)

After that, every restart only needs the master password to unlock.

---

## Configuration

No `.env` file. Runtime config lives in two places:

### `config.json` (auto-created on first launch)

| Field | Type | Default | Purpose |
|-------|------|---------|---------|
| `router_ip` | string | `"192.168.8.1"` | Router LAN address |
| `ssh_key_path` | string | `"~/.ssh/id_ed25519"` | SSH private key for router auth |

### Environment variables

| Variable | Purpose |
|----------|---------|
| `FLINT_SSH_KEY` | Overrides `ssh_key_path` from config. Useful for CI or when running under a different user. |

The resolution order for the SSH key path is: `FLINT_SSH_KEY` env var → `config.json`'s `ssh_key_path` → default `~/.ssh/id_ed25519`.

---

## How to use it — interfaces

The backend exposes the same functionality through three independent interfaces. Pick whichever fits your workflow.

### 1. Web UI (primary)

The Svelte dashboard at `http://<host-ip>:5000` is the expected daily-use interface. Every feature in the app is reachable from it: group management, device assignment, server browser, adblock, LAN access, logs, settings.

### 2. REST API

A plain HTTP/JSON API serves the same underlying service layer the UI uses. Useful for scripts, cron-driven automation, or embedding in a home-automation setup (e.g. toggle a group's kill switch from Home Assistant).

See [`docs/rest-api.md`](docs/rest-api.md) for the full endpoint reference. Every route takes an unlocked session — authenticate via the `/api/unlock` endpoint with your master password first.

### 3. MCP server (for AI agents)

The project includes an optional [Model Context Protocol](https://modelcontextprotocol.io/) server at [`backend/mcp_server/`](backend/mcp_server/) that exposes 40+ tools (list devices, create a group, switch server, read logs, etc.) to any MCP-compatible client — Claude Desktop, Claude Code, or your own MCP client.

Start it locally with:

```bash
source venv/bin/activate
cd backend && python -m mcp_server
```

The repo's [`.mcp.json`](.mcp.json) wires it up for Claude Code automatically; point any other MCP client at the same command. The MCP server talks to the REST API under the hood, so the backend must be running on `:5000`.

### No CLI

There is deliberately no standalone CLI — the REST API covers every scripted use case, and maintaining a separate Click-style CLI alongside it was more surface area than value. If you want one-shot commands, curl against the REST API.

---

## Daily use

Start in the background:

```bash
source venv/bin/activate
nohup python backend/app.py > /tmp/flintvpn.log 2>&1 &
```

Stop:

```bash
pkill -f "python backend/app.py"
```

Logs (also viewable from Dashboard → Sidebar → Logs):
- `logs/app.log` — user actions (connect/disconnect/create/delete/assign)
- `logs/error.log` — exceptions and stack traces
- `logs/access.log` — HTTP request log

---

## Development

```bash
# Backend with hot-reload (Flask debug)
source venv/bin/activate && python backend/app.py

# Frontend dev server (hot reload, proxies API to :5000)
cd frontend && npm run dev     # → http://localhost:5173

# Backend unit tests (no router, no Proton creds)
source venv/bin/activate && python -m pytest tests/ -m "not integration"

# Backend integration tests (requires live router on 192.168.8.1)
python -m pytest tests/ -m integration

# Frontend unit tests (vitest)
cd frontend && npm test

# Frontend E2E tests (Playwright — needs backend running on :5000)
cd frontend && npx playwright test
```

**Important:** The frontend **must be rebuilt** (`cd frontend && npm run build`) before testing in a browser against the Flask server, since Flask serves the contents of `static/` directly — the dev server on :5173 is only for interactive development.

---

## Safety rules

Driving a router's firewall and routing over SSH means a typo can take the whole LAN offline. The codebase enforces these rules internally; if you're modifying router-interaction code, respect them manually too.

**Never run against the router:**
- `/etc/init.d/network reload` or `restart` — bricks all routing
- `/etc/init.d/firewall restart` — re-runs `rtp2.sh`, corrupts route policy
- `rtp2.sh` directly — same reason
- `ifup` / `ifdown` — bypasses vpn-client, creates catch-all routes
- `conntrack -D` — breaks active connections

**Safe:**
- `uci show/get/set/add_list/del_list/delete/commit/reorder/rename`
- `/etc/init.d/firewall reload` (~0.22s, WG handshakes survive)
- `ipset add/del` against our MAC-assignment sets
- `wg show`, `ifstatus`, `ipset list`, `iptables -L`, `cat`, `grep`, `ls`, `ps` — any read-only command

Full rules and reasoning in [`CLAUDE.md`](CLAUDE.md#router-interaction-safety-rules) and [`docs/proton-wg-internals.md`](docs/proton-wg-internals.md).

---

## Project layout

```
backend/
  app.py                       Flask REST API + SSE stream
  consts.py                    Shared constants (protocols, profile types)
  service_registry.py          Runtime singleton holding router/proton/service
  services/                    Business-logic layer (orchestrates router + proton)
  router/
    api.py                     SSH transport (paramiko) + tunnel facades
    facades/                   Domain facades (policy, devices, firewall, tunnel, etc.)
    tools/                     Low-level wrappers (uci, ipset, iptables, iproute, wg show)
  proton_vpn/
    api.py                     ProtonVPN API wrapper (login, servers, configs)
    latency_probe.py           TCP connect-time probes (run FROM the router)
    server_optimizer.py        Pure scoring/filtering functions
  background/
    auto_optimizer.py          Daily server-load rebalancer
    device_tracker.py          New-device auto-assignment
  persistence/
    profile_store.py           Atomic local JSON store (UI metadata only)
    secrets_manager.py         Fernet-encrypted credential vault
  mcp_server/                  Optional MCP server — 40+ tools for AI agents
frontend/
  src/                         Svelte 5 + Vite source
  e2e/                         Playwright E2E tests
static/                        Built frontend (served by Flask, gitignored)
tests/                         pytest backend tests (unit + @pytest.mark.integration)
docs/                          Detailed architecture, internals, specs
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Small focused PRs welcomed; large redesigns should be discussed in an issue first. All tests that require a live router or ProtonVPN session must be marked `@pytest.mark.integration` — CI only runs the unmarked ones.

## Security

See [SECURITY.md](SECURITY.md) for reporting guidance and the threat model.

## License

This project is licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE). Personal, research, educational, charitable, and hobby use is permitted. Commercial use is **not** permitted.

This is a personal hobby project shared in the hope it's useful to other tinkerers. It's not intended for use by commercial enterprises, corporations, or governments.
