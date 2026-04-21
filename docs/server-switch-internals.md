# Server Switch Implementation Notes

Non-obvious details about how server switching works across protocols.

## Kernel WireGuard (UDP): hot-swap via wg set

`setup_instance_via.lua` (called by `vpn-client restart`) only generates a fresh `wgclient` interface when none exists for that `peer_id`. If `wgclient1` is already running, vpn-client restart leaves it untouched.

This means UCI updates alone are NOT sufficient for a live server switch — the live interface must be updated via `wg set` to add the new peer and remove the old peer. This is a zero-flicker hot-swap: the tunnel stays up during the peer swap.

## OpenVPN: full teardown

OpenVPN cannot hot-swap peers. Server switches require the full delete + recreate flow with a brief flicker during restart.

## proton-wg (TCP/TLS): wg setconf

Uses `wg setconf` on the live interface, similar to kernel WG's `wg set`.

## WG cert handling during switch

When switching servers with an `existing_wg_key`, `generate_wireguard_config` must NOT re-register the cert. Re-registering an already-registered key causes a 409 conflict from Proton's API. The existing cert is reused — only the endpoint changes.

## Latency probing

Latency probes ALWAYS run from the router via SSH, never locally. The host machine may be behind a VPN tunnel, which would give misleading results. The `probe_servers_local` fallback in `latency_probe.py` exists for unit testing only — never use it in production paths.
