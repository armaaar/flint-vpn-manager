# Flint VPN Manager — Project Overview

A local web dashboard for managing ProtonVPN WireGuard and OpenVPN profiles on a GL.iNet Flint 2 (GL-MT6000) router. Runs on a small always-on Linux host on the LAN, serves a Svelte frontend to any device on the LAN.

## Features

- **3 VPN protocols**: WireGuard UDP (fastest), WireGuard TCP/TLS (bypasses firewalls), OpenVPN UDP/TCP (most compatible)
- **Up to 14 simultaneous tunnels**: 5 WG UDP + 4 WG TCP/TLS + 5 OpenVPN
- **Per-device VPN routing**: assign any device to any VPN group via MAC-based ipset rules
- **Persistent WireGuard certificates**: 365-day certs, router works standalone without the host machine
- **Auto-optimizer**: daily background task switches VPN groups to faster servers (by Proton score + latency tiebreaker)
- **Server score refresh**: background thread keeps Proton server scores fresh (~15min loads, ~3h full list)
- **Server blacklist & favourites**: exclude bad servers, prefer known-good ones — persisted in `config.json`
- **Latency probing**: TCP connect-time measurement from the router's direct WAN to VPN server IPs
- **Auto cert renewal**: background daily check refreshes WG certs within 30 days of expiry
- **Server picker**: 3-level browser (Country → City → Server) with star/ban toggles and latency test
- **Kill switch**: per-group packet blackholing when tunnel drops (kernel WG via UCI, proton-wg via blackhole route)
- **WireGuard Stealth/TLS**: traffic looks like normal HTTPS — hardest to detect and block
- **Tor server routing**: filter and connect through ProtonVPN's Tor exit nodes for .onion access
- **Port selection**: choose alternate ports per protocol (WG: 443/88/1224/51820/500/4500, OVPN UDP: 80/51820/4569/1194/5060, OVPN TCP: 443/7770/8443) when ISPs block defaults
- **Smart Protocol**: automatic protocol fallback — if a tunnel doesn't connect within 45s, cycles through WireGuard → OpenVPN → WG TCP/TLS until one works
- **Custom DNS**: per-profile DNS override (e.g. Pi-hole, AdGuard) instead of Proton's default resolver
- **Alternative routing**: DNS-over-HTTPS transport fallback for API calls when Proton servers are blocked (censored networks)
- **DNS Ad Blocker**: per-group DNS-level ad/tracker/malware blocking via second dnsmasq instance with community blocklists (OISD). Stacks with NetShield.
- **LAN access control**: create/delete networks, per-network isolation, cross-network access rules with device exceptions, enforced via separate subnets and fw3 zone forwarding
- **NetShield status**: prominent protection-level display on group cards (active indicator when connected)
- **Location/IP check**: sidebar widget showing current public IP, country, and ISP as seen by ProtonVPN
- **Active sessions**: view all connected VPN sessions on the Proton account with exit IP and protocol
- **Live dashboard**: SSE-powered real-time tunnel health, device status, speeds
- **Disaster recovery**: local state backed up to router, auto-restored on unlock
- **GL.iNet compatible**: configs visible in the router's native dashboard as fallback

For detailed feature specs, see [features-and-specs.md](features-and-specs.md).

## Architecture

```
Host machine (this repo)             GL.iNet Flint 2 Router
┌──────────────────────────┐         ┌─────────────────────────┐
│  Flask (backend/ :5000)  │──SSH──▶│  OpenWrt + GL.iNet FW   │
│  Svelte (static/)        │         │  WireGuard / OpenVPN    │
│  ProtonVPN API (keyring) │         │  route_policy + ipset   │
│  profile_store.json      │         │  vpn-client service     │
│  secrets.enc, config.json│         │  proton-wg (TCP/TLS)    │
│                          │         │  fvpn_noint ipset       │
└──────────────────────────┘         └─────────────────────────┘
```

## Environment

- **Python**: 3.14 with `--system-site-packages` venv (for Proton libs from GTK app)
- **Node**: v24 via nvm (`export NVM_DIR="$HOME/.nvm" && . "$NVM_DIR/nvm.sh"`)
- **Router**: GL.iNet Flint 2 (GL-MT6000), firmware 4.8.4, OpenWrt
- **SSH**: Key auth (`~/.ssh/id_ed25519` → router root)
- **ProtonVPN**: Session from GTK app via system keyring. User has 2FA enabled.

## Key Dependencies

### Backend (requirements.txt)
- `flask` — REST API server
- `paramiko` — SSH client for router management
- `cryptography` — Fernet encryption for secrets
- `click` — CLI framework
- `proton-vpn-api-core` — ProtonVPN official library (system-wide)
- `pytest` — test framework

### Frontend (frontend/package.json)
- `svelte` — UI framework
- `vite` — build tool + dev server
- `svelte-dnd-action` — drag and drop for groups and devices
- `vitest` — test framework
- `happy-dom` — test environment
