# FlintVPN Manager

![CI](https://github.com/armaaar/flint-vpn-manager/actions/workflows/ci.yml/badge.svg)
[![License: PolyForm Noncommercial 1.0.0](https://img.shields.io/badge/license-PolyForm%20NC%201.0.0-blue)](LICENSE)

A self-hosted web dashboard for managing **ProtonVPN** WireGuard and OpenVPN tunnels on a **GL.iNet Flint 2 (GL-MT6000)** router. Group your devices, assign each group to a different VPN exit (or no VPN at all), and manage everything from a single Aircove-style dashboard reachable from any device on your LAN.

---

## ⚠️ Important disclaimer — read first

This is a **personal hobby project** built for one very specific setup:

- **Router**: GL.iNet Flint 2 (GL-MT6000), OpenWrt-based firmware **4.8.4**
- **VPN provider**: ProtonVPN (free or paid) — with the **official ProtonVPN Linux desktop app installed on the host**
- **Host**: A Linux machine on the same LAN running Python 3.12+

It has been developed, tested, and operated **only** on this combination. It is **not guaranteed to work** on other routers, firmware versions, VPN providers, or non-Linux hosts. Misconfiguration can knock every device on your LAN offline. There is **no support**. **Use at your own risk.** See [SECURITY.md](SECURITY.md) for the threat model.

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
- **DNS ad-blocker** (optional) — per-group DNS-level blocking of ads/trackers/malware.
- **Smart Protocol** — automatic fallback from WireGuard → OpenVPN → WG-over-TLS when a tunnel won't connect.
- **Persistent WireGuard certificates** — 365-day validity; router keeps tunneling even if the host is off.
- **Encrypted credentials** — Fernet (AES-128 + HMAC) with PBKDF2, unlocked by a master password.

For the detailed feature reference, see [docs/features-and-specs.md](docs/features-and-specs.md).

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

The router is the **source of truth** for tunnel state, device→group mappings, kill switch, group names, and ordering. The host's local JSON store only holds UI metadata. Deep architecture: [CLAUDE.md](CLAUDE.md) + [docs/internals/](docs/internals/).

---

## Quick install

```bash
# Install ProtonVPN Linux desktop app first (required — see full docs)

git clone https://github.com/armaaar/flint-vpn-manager.git
cd flint-vpn-manager
python -m venv --system-site-packages venv
source venv/bin/activate
pip install -r requirements.txt
cd frontend && npm install && npm run build && cd ..
python backend/app.py
```

Dashboard at `http://<host-ip>:5000`. First launch runs a setup wizard for master password + ProtonVPN credentials + router IP.

**Full instructions (prerequisites, ProtonVPN app requirement, configuration):** [docs/installation.md](docs/installation.md)
**Router setup (SSH keys, proton-wg, adblock):** [docs/router-setup.md](docs/router-setup.md)

---

## Interfaces

Pick whichever fits your workflow — all three expose the same functionality:

- **Web UI** at `http://<host-ip>:5000` — the primary interface, every feature is reachable.
- **REST API** — for scripts, cron, home-automation integration. Full endpoint reference: [docs/rest-api.md](docs/rest-api.md).
- **MCP server** (optional) — lets an AI agent (Claude Desktop, Claude Code, etc.) drive the app. Setup and tool catalog: [docs/mcp-server.md](docs/mcp-server.md). A companion [Claude Code skill](skills/flint-vpn-manager/) is included for agent-assisted debugging; install via `npx skills add armaaar/flint-vpn-manager`.

There's deliberately no standalone CLI — the REST API covers every scripted use case.

---

## Project layout

```
backend/              Flask REST API + MCP server
  app.py, consts.py, service_registry.py
  services/           Business-logic layer
  router/             SSH transport + domain facades
  proton_vpn/         ProtonVPN API wrapper
  background/         Auto-optimizer, device tracker
  persistence/        Profile store + encrypted credential vault
  mcp_server/         Model Context Protocol server
frontend/             Svelte 5 + Vite
static/               Built frontend (served by Flask, gitignored)
tests/                pytest backend tests (unit + @pytest.mark.integration)
docs/                 User-facing documentation
  internals/          Implementation deep-dives (contributor reading)
skills/               Claude Code skills
```

---

## Safety

Driving a router's firewall and routing over SSH means a typo can take the whole LAN offline. The codebase enforces safety rules internally; if you're modifying router-interaction code, follow [CLAUDE.md's Router Interaction Safety Rules](CLAUDE.md#router-interaction-safety-rules) and the constraints in [docs/internals/proton-wg-internals.md](docs/internals/proton-wg-internals.md).

---

## Contributing · Security · License

- **Contributing**: [CONTRIBUTING.md](CONTRIBUTING.md) — scope, dev setup, PR checklist
- **Security**: [SECURITY.md](SECURITY.md) — threat model and reporting
- **License**: [PolyForm Noncommercial 1.0.0](LICENSE) — personal, research, educational, charitable, and hobby use permitted; commercial use not permitted

This is a personal hobby project shared in the hope it's useful to other tinkerers. It's not intended for use by commercial enterprises, corporations, or governments.
