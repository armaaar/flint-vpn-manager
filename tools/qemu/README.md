# Split VPN runtime

The Barracuda VPN client is x86-64 only; the router is ARM64. It runs under
qemu user-mode emulation inside a network namespace (see
`docs/internals/split-vpn-internals.md`). Both pieces live in `runtime/`
(gitignored) and are uploaded by **Split VPNs → Install runtime**
(`POST /api/split-vpns/runtime/install`).

| File in `runtime/` | Where it comes from |
|---|---|
| `VPNClient_5.3.10_Linux.tar.gz` | Barracuda download portal (dlportal.barracudanetworks.com → NAC / VPN Client; account required). sha256 pinned in `consts.SPLITVPN_BARRACUDA` (same as the AUR `barracudavpn-bin` pin). The archive may also sit in the repo root or `~/Downloads`. |
| `qemu-x86_64-flint` (+ `.sha256`) | `tools/qemu/build.sh` (Docker): Debian's qemu 10.0.13 + `rtnetlink-passthrough.patch`, static ARM64. |

Why the patch: stock qemu-user rejects rtnetlink message types it has no
translator for (`EOPNOTSUPP`); the 5.3 daemon sends policy-rule messages at
startup and aborts (`PNLNetlink Object could not be retrieved`). x86-64 and
ARM64 share byte order and LP64 struct layout, so unknown types pass through
unchanged.

Why 5.3.x: the last public Linux build (5.1.4, 2020) is dropped by current
gateways right after TLS, before authentication.
