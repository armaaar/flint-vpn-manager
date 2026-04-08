# FlintVPN Manager

A self-hosted web dashboard for managing **ProtonVPN** WireGuard and OpenVPN tunnels on a **GL.iNet Flint 2 (GL-MT6000)** router. Group your devices, assign each group to a different VPN exit (or no VPN at all), and manage everything from a single Aircove-style dashboard reachable from any device on your LAN.

> Built for a specific home setup: a Surface Go 2 running the Flask backend + Svelte frontend, talking to a Flint 2 over SSH. Not a general-purpose product — but the code is documented well enough to adapt.

## Features

- **Per-device VPN routing** — drag a device into a group, it routes through that group's tunnel. Backed by `route_policy` + `ipset`, no `rtp2.sh` foot-guns.
- **Multiple simultaneous tunnels** — up to 5 WireGuard + 5 OpenVPN (router limit), each with its own ProtonVPN exit.
- **Group types** — VPN, NoVPN (direct), or NoInternet (LAN-only).
- **Live ProtonVPN integration** — server browser by country/city, NetShield, Moderate NAT, NAT-PMP, VPN Accelerator, Secure Core.
- **Auto-optimizer** — background thread that swaps each group to a less-loaded server once a day.
- **Kill switch** per group, live from the router.
- **LAN access policies** — `allowed` / `group_only` / `blocked` per group or per device, applied via iptables.
- **Guest group** — newly seen MACs are auto-assigned to your chosen group.
- **Device labels & types** sync bidirectionally with the GL.iNet UI (`gl-client.alias` / `.class`).
- **Encrypted credentials** — Fernet (AES-128 + HMAC) with PBKDF2, unlocked by a master password.
- **CLI included** — every dashboard action is also a `cli.py` command.

## Architecture

```
Surface Go 2 (host)                  GL.iNet Flint 2 Router
┌──────────────────────────┐         ┌─────────────────────────┐
│  Flask (app.py :5000)    │──SSH──▶│  OpenWrt + GL.iNet FW   │
│  Svelte (static/)        │         │  WireGuard / OpenVPN    │
│  ProtonVPN API           │         │  route_policy + ipset   │
│  profile_store.json      │         │  fvpn_lan iptables      │
│  secrets.enc, config.json│         │  vpn-client service     │
└──────────────────────────┘         └─────────────────────────┘
```

The router is the **source of truth** for tunnel state, device→group mappings, kill switch, group names, and ordering. The local JSON store only holds UI metadata (color, icon, server scope, options) and non-VPN assignments. Every read goes live to the router via SSH; nothing is cached except a 5-second TTL on the device list.

See [`CLAUDE.md`](CLAUDE.md) for the full source-of-truth contract and module-by-module breakdown.

## Requirements

- **Router**: GL.iNet Flint 2 (GL-MT6000), firmware 4.8.4+, with SSH key auth set up to root
- **Host**: Linux machine on the LAN with Python 3.12+ and Node 20+
- **Account**: ProtonVPN (free or paid). 2FA supported.
- **System packages**: `proton-vpn-api-core` (the venv is created with `--system-site-packages` because the Proton library ships via the GTK desktop app on most distros)

## Setup

```bash
# 1. Clone
git clone <your-fork-url> flint-vpn-manager
cd flint-vpn-manager

# 2. Backend
python -m venv --system-site-packages venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Frontend
cd frontend && npm install && npm run build && cd ..

# 4. SSH key to router (one time)
ssh-copy-id -i ~/.ssh/id_ed25519 root@192.168.8.1

# 5. Run
python app.py
# → http://<host-ip>:5000
```

On first launch the dashboard walks you through:

1. Setting a master password (encrypts `secrets.enc`)
2. Entering ProtonVPN credentials (with 2FA if enabled)
3. Confirming the router IP

After that, every restart only needs the master password to unlock.

## Daily Use

```bash
# Start the server in the background
source venv/bin/activate
nohup python app.py > /tmp/flintvpn.log 2>&1 &

# Or use the CLI for one-off actions
python cli.py status
python cli.py profile list
python cli.py device assign aa:bb:cc:dd:ee:ff <profile-id>
```

## Development

```bash
# Backend with auto-reload
source venv/bin/activate && python app.py

# Frontend dev server (hot reload, proxies API to :5000)
cd frontend && npm run dev   # → http://localhost:5173

# Tests
python -m pytest tests/
cd frontend && npx vitest run
```

The frontend **must be rebuilt** (`npm run build`) before testing in the browser against the Flask server, since Flask serves `static/` directly.

## Safety Rules (Important)

This project drives a router whose misconfiguration can take the whole LAN offline. The codebase enforces these, but if you hack on it:

- **Never** run `/etc/init.d/network reload`, `firewall reload`, `rtp2.sh`, `ifup`/`ifdown`, or `conntrack -D` against the router.
- Device assignment goes through `ipset add/del` + `uci commit`, never `rtp2.sh`.
- File transfer uses `write_file()` (stdin pipe) — never heredocs or base64, which corrupt keys/certs.

Full rules in [`CLAUDE.md`](CLAUDE.md).

## Project Layout

```
app.py              Flask REST API + SSE stream
router_api.py       SSH-based router management (paramiko)
proton_api.py       ProtonVPN API wrapper
profile_store.py    Atomic local JSON store (UI metadata only)
device_tracker.py   Background new-device auto-assigner
auto_optimizer.py   Background daily server-load optimizer
server_optimizer.py Pure server comparison logic
secrets_manager.py  Fernet-encrypted credential vault
cli.py              Click-based CLI mirroring the dashboard
frontend/           Svelte 5 + Vite source
static/             Built frontend (served by Flask, gitignored)
tests/              pytest backend tests
```

## License

Personal project. No license granted — fork and adapt for your own home setup.
