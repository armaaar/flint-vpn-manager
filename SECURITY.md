# Security Policy

FlintVPN Manager handles two kinds of sensitive material:

1. **ProtonVPN account credentials** (stored encrypted in `secrets.enc`, unlocked by a master password)
2. **Router SSH access** (a key that allows root commands on the router)

A vulnerability in this project could therefore expose a VPN account or let an attacker pivot to full router control. I take that seriously even for a hobby project.

---

## Threat model

**In scope:**
- Authentication bypass (anything that lets an unauthenticated caller reach authenticated endpoints, read encrypted state, or issue router commands)
- Remote code execution, SSRF, shell injection into any SSH command
- Credential exposure in logs, error messages, or HTTP responses
- Route/DNS leaks where traffic intended for a VPN tunnel is sent outside it
- Integrity — any way to tamper with `profile_store.json` or `secrets.enc` from a remote caller

**Out of scope** — explicitly **not** part of the threat model:
- Attacks requiring physical LAN access. This app is intended to run on a trusted home LAN; the Flask port is not authenticated at the network layer.
- Local attackers with read access to the host filesystem (they can read `secrets.enc` directly).
- DoS against the backend (a hobbyist Flask app has no realistic defence).
- Anything requiring a compromised ProtonVPN account.
- Reports against dependencies (`paramiko`, `cryptography`, Flask, etc.) — please report those upstream.

---

## Reporting a vulnerability

**Preferred:** use GitHub's [private security advisory](https://github.com/armaaar/flint-vpn-manager/security/advisories/new) feature. That keeps the report confidential until we've discussed a fix.

**Alternative:** open a GitHub issue titled `Security: <short description>` with only enough detail to let me contact you privately — then we move to a private channel for specifics. **Do not** include exploit details in a public issue.

**Response expectations:**
- Best-effort acknowledgement within **7 days**
- This is a solo-maintained hobby project with no SLAs, no bug bounty, and no guarantees
- If a fix lands, you'll be credited (if you want to be) in the release notes

## Hardening suggestions for operators

If you're running this in any environment you care about:

- **Bind the backend to `127.0.0.1` or a VPN-only interface** rather than `0.0.0.0`. The default is to listen on all interfaces to be reachable from LAN devices; if that's more exposure than you want, front it with something you control.
- **Use a dedicated SSH key for the router**, not your general-purpose personal key.
- **Keep the master password strong** — it's the only thing guarding `secrets.enc` if the host is ever compromised.
- **Keep the host and router firmware patched**. This project makes no effort to defend against a compromised router or a compromised host.
