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
  the Flint 2 is ARM64 → the statically linked `barracudavpn` 5.1.4 runs
  under **`qemu-x86_64` user-mode emulation** (Debian's static build).
  Startup ~0.3s; throughput is CPU-bound but fine for work traffic.
- **Network namespace per VPN.** The client installs routes, creates `tun0`
  and wants to rewrite `/etc/resolv.conf`. Inside `fvpn_sv<N>` none of that
  can affect the router. `ip netns exec` also gives it a private mount
  namespace; `svctl.sh` mounts a tmpfs over `/var/run` there because the
  client uses a fixed pid file.
- **Fail closed.** Each slot's table has `blackhole default metric 10000`
  under the veth route, and the namespace's FORWARD policy is DROP except
  veth→`tun+`. Work traffic is dropped when the tunnel is down — never sent
  through Proton or the WAN.

## Router layout (slot N = 0..3)

| Thing | Value |
|---|---|
| Namespace / veth | `fvpn_svN`, host `fvsvNh` (`10.250.N.1/30`) ↔ ns `fvsvNn` (`10.250.N.2/30`) |
| fwmark / table / rule prio | `0xA000 + N·0x1000` / `1010+N` / `90` (before bypass 100 and tunnels 6000) |
| Destination ipset | `fvpn_svN_dst` (`hash:net`) |
| Mangle chain | `FVPN_SPLITVPN`, jumped from `ROUTE_POLICY` position 1 (like `FVPN_BYPASS`) |
| Filter chain | `FVPN_SPLITVPN_FWD`, jumped from `FORWARD` position 1 |
| Files | `/etc/fvpn/splitvpn/bin/{qemu-x86_64,barracudavpn}`, `/etc/fvpn/splitvpn/svctl.sh`, `/etc/fvpn/splitvpn/svN/{barracudavpn.conf,ca/,connect.log}` |
| Persistence | firewall include `fvpn_splitvpn` → `/etc/fvpn/splitvpn_rules.sh` (reload=1); everything under `/etc/fvpn/` is in the sysupgrade keep-list |
| DNS | `fvpn-splitvpn.conf` in the group's dnsmasq conf-dir (`/tmp/dnsmasq.d.<wgclientN|protonwgN>` or `/tmp/dnsmasq.d` for NoVPN): `server=/dom/<VPN DNS>` + `ipset=/dom/fvpn_svN_dst` |

Packet path: LAN device → `ROUTE_POLICY` → `FVPN_SPLITVPN` marks if
`src ∈ group MAC ipset` **and** `dst ∈ fvpn_svN_dst` → tunnel chains skip
marked packets → `ip rule fwmark … lookup 1010+N` → `default via 10.250.N.2
dev fvsvNh` → namespace → `tun0` (MASQUERADE) → work network. Replies come
back the same way; `fvsvNh` has `rp_filter=2` (loose) because the reply
source (a work IP) is otherwise routed via WAN.

The client's own outer connection leaves the namespace via `10.250.N.1`
and is NATed out of the WAN (`MASQUERADE -s 10.250.N.2`), i.e. **not**
through Proton — corporate gateways often block VPN exit IPs.

The VPN's DNS servers get host routes `/32 via 10.250.N.2` so dnsmasq (on
the router) can query them through the tunnel.

## Client specifics (barracudavpn 5.1.4)

- Config: `barracudavpn.conf` with `KEY = value` lines (format reverse-
  engineered from the client's own config screen). `DYNSSA = 2` = User/Pass
  auth. `WRITEDNS = NO`. `HANDSHAKETIMEOUT = 30` (AD+OTP auth is slow).
  Tunnel mode TCP works through NAT; the UDP handshake timed out.
- CLI: `--start --login <user>` then it prompts for the server password and
  `Enter One Time Password :` → `svctl.sh start` pipes `password\notp\n`
  from a 0600 file in `/tmp` (deleted right after) — never `--serverpwd`.
- Server cert: verified against `svN/ca/`; on first connect the client asks
  and (non-interactively) accepts the cert, then pins it.
- A daemon "worker" stays in the namespace after the console exits;
  `--status` talks to it over loopback (shows STATE, IPv4, DNSv4, ROUTESv4).
  Stop = `--stop` + kill everything in `ip netns pids`.
- **Process names**: workers don't show as `qemu-x86_64`. Kill by
  `ip netns pids <ns>`. Never `pgrep -f`/`pkill -f` on a path that appears in
  your own SSH command line — it matches (and kills) your own shell.

## Data

- `config.json` → `split_vpns.vpns[]`: `id, type, slot, name, server, port,
  tunnel_mode, username, group_ids, domains, cidrs, use_pushed_routes,
  enabled, pushed_routes, pushed_dns, last_connected_at`.
- **Or SOPS**: with `secret_ref` set, `split_vpns.<ref>.{username,password,totp_secret}`
  is decrypted from `secrets/flint.sops.yaml` on demand (see `docs/sops-secrets.md`);
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

`POST /api/split-vpns/runtime/install` downloads the pinned artifacts in
`consts.SPLITVPN_RUNTIME` (archive sha256 **and** extracted binary sha256
checked), extracts in Python (no `ar`/`tar` binaries needed) and uploads with
`RouterAPI.write_bytes` (`scp -O` — the router has no sftp-server).
