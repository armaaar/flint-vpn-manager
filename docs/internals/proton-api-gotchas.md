# Proton API Gotchas

Non-obvious behaviors and limitations of the ProtonVPN API and `proton-vpn-api-core` library.

## Persistent vs Session certificates

- **Persistent mode** (`Mode: "persistent"`, 365 days): no Local Agent required. The router is fully standalone after config upload. This is what FlintVPN uses.
- **Session mode** (`Mode: "session"`, 7 days): requires a Local Agent at `10.2.0.1:65432` (JSON over mutual TLS) to authenticate after WG handshake. Without the agent, the server keeps the connection in `HARD_JAILED` state — WG handshake succeeds but the exit gateway drops all forwarded traffic.

## Certificate deletion is not possible via API

`DELETE /vpn/v1/certificate` requires `password` scope and returns 403 with a normal VPN session token. The only way to delete registered persistent cert devices is through the Proton web dashboard: account.protonvpn.com → Downloads → WireGuard configurations.

## Library attribute renames

The installed `proton-vpn-api-core` (from the GTK app) renamed `country.cities` to `country.locations` in a recent update. Always check the installed library source at system Python paths, not the online docs.

## OpenVPN username suffixes

VPN options are encoded differently per protocol:
- **WireGuard**: certificate features (baked in at cert registration time)
- **OpenVPN**: username suffixes: `+f{level}` (NetShield), `+nr` (Moderate NAT), `+pmp` (NAT-PMP), `+nst` (no split tunneling / VPN Accelerator)

## Alternative Routing (DoH fallback)

When enabled, Proton API calls fall back to DNS-over-HTTPS through Google/Quad9 DNS when Proton servers are directly unreachable. Handled by the library's `AutoTransport` — no application code needed beyond `set_alternative_routing(True)`.
