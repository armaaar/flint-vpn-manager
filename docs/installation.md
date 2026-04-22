# Installation

Full setup for Flint VPN Manager. If you're just skimming, the [README quick-start](../README.md#quick-install) is enough; this doc covers the details and the common stumbling blocks.

> Before starting: read the [disclaimer](../README.md#️-important-disclaimer--read-first) in the README. This project is tested on one specific hardware + firmware + VPN combination.

## Prerequisites

### Router

- **GL.iNet Flint 2 (GL-MT6000)** on firmware **4.8.4**
- SSH access enabled with public-key authentication to `root` — see [router-setup.md](router-setup.md)
- **proton-wg binary installed** (optional — only needed for WireGuard TCP/TLS tunnels on restrictive networks; see [router-setup.md](router-setup.md#install-proton-wg))

### Host

- **Linux only.** The app will not run on macOS or Windows (see the ProtonVPN section below).
- On the same LAN as the router
- **Python 3.12+** (3.13 tested)
- **Node.js 20+** (for the one-time frontend build)

### ProtonVPN — desktop app required on the host

This project does **not** re-implement the ProtonVPN authentication stack. Instead it reuses the official `proton-vpn-api-core` library plus the system keyring (D-Bus secret service) that the ProtonVPN Linux desktop app sets up. In practice this means:

1. **Install the official ProtonVPN Linux desktop app** on the host before installing this project. See the [ProtonVPN Linux download page](https://protonvpn.com/support/official-linux-vpn-ubuntu/) for your distribution. It installs `proton-vpn-api-core` system-wide and wires up the secret service.
2. **You do not need to log in via the GTK app** — Flint VPN Manager does its own login flow. But the libraries and D-Bus services the GTK app installs are what let `proton-vpn-api-core` work.
3. **The Python venv must be created with `--system-site-packages`** so that `import proton_vpn_api_core` picks up the system-wide install. A normal isolated venv will not work.
4. **A ProtonVPN account** (free or paid). 2FA is supported.

If you cannot or will not install the ProtonVPN desktop app on the host, this project will not run. That constraint is structural, not a packaging oversight — the project deliberately relies on Proton's own libraries to avoid drifting from their auth flow.

---

## Install

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

Additional fields are written as you use the app (adblock sources, server preferences, etc.). Don't hand-edit the file while the app is running — the save-back path will clobber your changes on the next SSE tick.

### Environment variables

| Variable | Purpose |
|----------|---------|
| `FLINT_SSH_KEY` | Overrides `ssh_key_path` from config. Useful for CI or when running under a different user. |

The resolution order for the SSH key path is: `FLINT_SSH_KEY` env var → `config.json`'s `ssh_key_path` → default `~/.ssh/id_ed25519`.

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

## Next steps

- Set up the router for the first time: [router-setup.md](router-setup.md)
- Use the MCP server from Claude Code or Claude Desktop: [mcp-server.md](mcp-server.md)
- Scripted access via the REST API: [rest-api.md](rest-api.md)
- Feature reference: [features-and-specs.md](features-and-specs.md)
