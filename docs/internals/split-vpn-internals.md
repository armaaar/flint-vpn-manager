# Split VPN internals

A **split VPN** is a third-party VPN that runs on the router and carries only
selected destinations for selected groups; those groups keep their Proton
tunnel for everything else. First (and only) type: **Barracuda CloudGen
Firewall** (proprietary TINA protocol, TCP/UDP 691), e.g. a company VPN.

Code: `backend/router/facades/split_vpn.py` (router side, pure builders are
unit-tested), `backend/services/split_vpn_service.py`, `backend/routes/split_vpn.py`,
`backend/mcp_server/tools/split_vpn.py`, `frontend/src/lib/components/splitvpn/`.

## Why it looks like this

- **TINA has no open-source client** and the gateway answers IKEv2 with
  `NO_PROPOSAL_CHOSEN` for every common suite (site-to-site only), so the
  official client is the only option. Barracuda only ships it for **x86**;
  the Flint 2 is ARM64 → the statically linked **Barracuda VPN Client 5.3.10**
  (`barracudavpn` CLI + `barracudavpn-daemon`) runs under **`qemu-x86_64`
  user-mode emulation**, using a patched static qemu we build ourselves
  (see "Runtime" below). Throughput is CPU-bound but fine for work traffic.
- **Why 5.3.10 and not 5.1.4.** 5.1.4 (2020) is the last *public* Linux build,
  but current gateways drop it right after the TLS handshake, before
  authentication. 5.3.x is only on the vendor portal (account required), so
  the app can't download it; it's installed from local files.
- **Network namespace per VPN.** The client installs routes, creates its
  tunnel interface and wants to rewrite `/etc/resolv.conf`. Inside `fvpn_sv<N>`
  none of that can affect the router. Namespace DNS (`/etc/netns/fvpn_svN/resolv.conf`)
  is **public resolvers (1.1.1.1, 9.9.9.9)**, never the WAN's: company VPNs
  can push private ranges that overlap the home side (seen live: the gateway
  pushed `192.168.0.0/22` while the WAN is `192.168.0.0/24` with the modem's
  DNS at `192.168.0.1`), which would send the client's own lookups into the tunnel.
- **Fail closed.** Each slot's table has `blackhole default metric 10000`
  under the veth route, and the namespace's FORWARD policy is DROP except
  veth→`tun+`/`tap+` (5.3 creates an L3 `tap0`). Work traffic is dropped
  when the tunnel is down — never sent through Proton or the WAN.

## Router layout (slot N = 0..3)

| Thing | Value |
|---|---|
| Namespace / veth | `fvpn_svN`, host `fvsvNh` (`10.250.N.1/30`) ↔ ns `fvsvNn` (`10.250.N.2/30`) |
| fwmark / table / rule prio | `0xA000 + N·0x1000` / `1010+N` / `90` (before bypass 100 and tunnels 6000) |
| Destination ipset | `fvpn_svN_dst` (`hash:net`) |
| Mangle chain | `FVPN_SPLITVPN`, jumped from `ROUTE_POLICY` position 1 (like `FVPN_BYPASS`) |
| Filter chain | `FVPN_SPLITVPN_FWD`, jumped from `FORWARD` position 1 |
| Files | `/etc/fvpn/splitvpn/bin/{qemu-x86_64,barracudavpn,barracudavpn-daemon}`, `/etc/fvpn/splitvpn/svctl.sh`, `/etc/fvpn/splitvpn/svN/{barracudavpn.toml,daemon.log,connect.log}` (dir root-owned, 0700) |
| Daemon run dir | `/tmp/fvsvNrun`, bind-mounted over `/run` inside the namespace (socket `barracudavpn/daemon.sock`) |
| Persistence | firewall include `fvpn_splitvpn` → `/etc/fvpn/splitvpn_rules.sh` (reload=1); everything under `/etc/fvpn/` is in the sysupgrade keep-list |
| DNS | `fvpn-splitvpn.conf` in the group's dnsmasq conf-dir (`/tmp/dnsmasq.d.<wgclientN|protonwgN>` or `/tmp/dnsmasq.d` for NoVPN): `server=/dom/<VPN DNS>` + `ipset=/dom/fvpn_svN_dst` |

Packet path: LAN device → `ROUTE_POLICY` → `FVPN_SPLITVPN` marks if
`src ∈ group MAC ipset` **and** `dst ∈ fvpn_svN_dst` → tunnel chains skip
marked packets → `ip rule fwmark … lookup 1010+N` → `default via 10.250.N.2
dev fvsvNh` → namespace → `tap0` (MASQUERADE) → work network. Replies come
back the same way; `fvsvNh` has `rp_filter=2` (loose) because the reply
source (a work IP) is otherwise routed via WAN.

The client's own outer connection leaves the namespace via `10.250.N.1`
and is NATed out of the WAN (`MASQUERADE -s 10.250.N.2`), i.e. **not**
through Proton — corporate gateways often block VPN exit IPs.

The VPN's DNS servers get host routes `/32 via 10.250.N.2` so dnsmasq (on
the router) can query them through the tunnel.

## Client specifics (Barracuda 5.3.10: daemon + CLI)

- **Two processes.** `barracudavpn-daemon` owns the tunnel; the
  `barracudavpn` CLI only talks to it over `/run/barracudavpn/daemon.sock`
  (plus POSIX message queues). `svctl.sh start` launches the daemon
  (`-f -c $DIR -x $DIR/daemon.log`) in the namespace, waits up to 20s for the
  socket, then runs the CLI.
- **Shared `/run`.** OpenWrt has no `/run`, and every `ip netns exec` gets its
  own mount namespace, so a bind mount made for the daemon is invisible to a
  later CLI call. Both are started through the same wrapper (`nsx`), which
  bind-mounts the per-slot dir `/tmp/fvsvNrun` over `/run` before `exec`.
- **Config** = `barracudavpn.toml` (format taken from the 5.3.10 daemon's own
  auto-generated file, built by `build_client_toml`): `[profile.Default]`
  with `server`, `serverport`, `tunnelmode`, `dynssa = 2` (user/password),
  `otpmode = "STATIC"` (send the one-time password at login), `writedns = "NO"`,
  `connecttimeout = 30` (AD+OTP auth is slow); then `[state] active_profile = "Default"`.
  The daemon refuses a config dir that isn't root-owned or is group/world-
  writable, so svctl does `chown -R root:root` + `chmod 700` on every start.
  Tunnel mode TCP works through NAT.
- **Secrets.** Without a TTY the 5.3 CLI does not prompt, so the server
  password and OTP must be passed as `--serverpwd` / `--onetimepwd`. They
  still reach the router via a 0600 file on svctl's **stdin** (never in an SSH
  command string or a log); svctl reads them into shell variables and puts
  them on the CLI's argv, so they're visible in the router's process list
  (root only) for the few seconds the CLI runs.
- **Server cert (TOFU).** On first contact the CLI asks
  `Accept Server Cert (Y/N)?`; svctl pipes `Y`. Afterwards the pinned cert
  must match.
- **Tunnel interface** is an L3 **`tap0`** (5.1.x used `tun0`); the namespace
  firewall allows both `tun+` and `tap+`.
- `--status` (via the daemon) shows STATE, IPv4, DNSv4, ROUTESv4
  (`parse_status`). Stop = `--stop` + kill everything in `ip netns pids`.
- **Process names**: workers don't show as `qemu-x86_64`. Kill by
  `ip netns pids <ns>`. Never `pgrep -f`/`pkill -f` on a path that appears in
  your own SSH command line — it matches (and kills) your own shell.
- **busybox gotchas** hit in svctl: `sleep` takes whole seconds only (no
  `sleep 0.5`); `timeout` can only run binaries, not shell functions (the
  connect line repeats the `nsx` command inline instead of `timeout … nsx`).
- **Limitation — one Barracuda instance at a time.** busybox has no
  `unshare`, so slots only get network + per-call mount namespaces; the
  daemon's POSIX message queues are **not** separated per slot. Up to 4
  slots are configurable, but only one connected Barracuda VPN is
  guaranteed to work.

### Verified live (2026-11-18)

Connected to `vpn.example.com` (TCP 691). Pushed routes `10.99.10.0/24`,
`10.99.20.0/24`, `10.99.30.0/24`, `192.168.0.0/22`; pushed DNS `10.99.1.53`
(`DC01.corp.example`). `corp.example` resolves through the tunnel from
the Work group's dnsmasq; Work-group traffic to the pushed ranges goes
through the namespace; everything else from the Work group goes via Proton.

## Data

- `config.json` → `split_vpns.vpns[]`: `id, type, slot, name, server, port,
  tunnel_mode, username, group_ids, domains, cidrs, use_pushed_routes,
  enabled, pushed_routes, pushed_dns, last_connected_at`.
- **Or SOPS**: with `secret_ref` set, `split_vpns.<ref>.{username,password,totp_secret}`
  is decrypted from `secrets/flint.enc.yaml` on demand (see `docs/sops-secrets.md`);
  nothing is copied into `secrets.enc`.
- `secrets.enc` → `split_vpn_credentials: {id: {password, totp}}` (`totp` =
  parsed secret: base32 + digits/period/algorithm, from a bare secret or an
  `otpauth://totp/` URI); written with the master password (UI asks for it),
  loaded into memory on unlock.
- One-time codes are generated on demand (`backend/vpn/totp.py`, RFC 6238,
  stdlib only) and never stored. If the current code has <10s left the
  connect waits for the next window (the emulated handshake is slow).

## Lifecycle

- **Connect** (`POST /api/split-vpns/:id/connect`, optional `{otp}` override): write ctl script +
  client config → `svctl.sh start` (sets up namespace, starts client, ≤150s)
  → `--status` → record pushed routes/DNS → `reapply_all()`.
- **reapply_all** runs on unlock and after every change, for all enabled VPNs
  with groups, tunnel up or not (fail-closed semantics). dnsmasq is only
  restarted when the snippet content changed (restart blips DNS for everyone).
- **Auto-connect monitor** (`SplitVpnService.start_monitor`, started on
  unlock, stopped on lock): every 60s, for enabled VPNs with `auto_connect`
  and stored password + TOTP, reconnects when the tunnel is down. Failures
  back off exponentially (2 min → 1 h) so a wrong password can't lock the
  account. A manual disconnect pauses it until the next manual connect.
- After a router reboot the namespace is gone; the firewall include restores
  the routing rules (marked traffic hits the blackhole) and the monitor
  reconnects within a minute (while the app is unlocked).

## Runtime install

Nothing is downloaded. The runtime is three files built/obtained on the app
host and kept in the gitignored `runtime/` folder (see `tools/qemu/README.md`):

| File in `runtime/` | Source | Check |
|---|---|---|
| `VPNClient_5.3.10_Linux.tar.gz` | Barracuda download portal (dlportal.barracudanetworks.com → NAC / VPN Client, account required). May also sit in the repo root or `~/Downloads`. | archive sha256 pinned in `consts.SPLITVPN_BARRACUDA`, plus per-binary sha256 for `barracudavpn` and `barracudavpn-daemon` (extracted from the `.deb` inside) |
| `qemu-x86_64-flint` (+ `.sha256`) | `tools/qemu/build.sh` (Docker): Debian's qemu 10.0.13 (hash-checked source) + `tools/qemu/rtnetlink-passthrough.patch`, static ARM64 | must match its `.sha256` |

Why the qemu patch: stock qemu-user rejects rtnetlink message types it has no
translator for (e.g. `RTM_*RULE`) with `EOPNOTSUPP`; the 5.3 daemon sends
policy-rule messages at startup and aborts with
`PNLNetlink Object could not be retrieved`. Passing unknown types through
unchanged is safe because x86-64 and ARM64 share byte order and LP64 struct
layout.

`POST /api/split-vpns/runtime/install` verifies the local files, extracts in
Python (no `ar`/`tar` binaries needed) and uploads with
`RouterAPI.write_bytes` (`scp -O` — the router has no sftp-server) to
`/etc/fvpn/splitvpn/bin/{qemu-x86_64,barracudavpn,barracudavpn-daemon}`.
`GET /api/split-vpns/runtime` returns `installed`, `files` (router copies
sha256-checked; qemu against the local `.sha256` when present) and
`local_files: {barracuda_archive, qemu}` (which install sources exist
locally; the UI names the missing ones).
