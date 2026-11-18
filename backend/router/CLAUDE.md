# backend/router — working notes

Everything here ends up as shell commands on the live router. Root `CLAUDE.md`
"Router Interaction Safety Rules" apply to every command you generate or run.
Layering (SSH → tools → facades) is in `docs/internals/router-layer-internals.md`.

## Rules that bit us

- **Never `pgrep -f`/`pkill -f` on a string that also appears in your own
  command line** (local shell or the remote `sh -c` over SSH) — it matches and
  kills the shell running it. Kill by PID, by exact process name (`pgrep -x`),
  or, for split VPNs, by namespace: `ip netns pids <ns> | xargs -r kill`.
- The router has **no sftp-server**: plain `scp` fails. `RouterAPI.write_file`
  / `write_bytes` stream over SSH (<1MB) or use `scp -O`.
- Facades build commands; put the command *construction* in pure module-level
  functions (`build_*`) so tests can assert on strings without SSH.
- Every iptables rule the app owns lives in an `fvpn_*` firewall include
  (`reload='1'`) so it survives `firewall reload`. `--comment` tags must not
  contain spaces (self-cleaning sweeps word-split them).
- WiFi: compute `BssidNum` and `ra<N>`/`rax<N>` **per radio** from UCI
  (`lan_access._RADIOS`). The radios differ since firmware 4.11 (mesh AP on 5G).
- **Never `rmmod mt_wifi` on firmware ≥ 4.11** — it panicked the router and the
  unflushed UCI commit was lost. `_reload_wifi_driver` syncs + reboots there.
  Run `sync` after committing UCI before any risky step.
- **Firmware ≥ 4.11 checks VPN IP conflicts**: a kernel WG tunnel stays
  "connecting" while any local interface holds its address (10.2.0.2), unless
  `network.<ifname>.gl_vpn_instance=1`. Every `protonwgN` needs that marker
  section (disabled, `proto=none`, no device, so no network reload). See
  `build_gl_vpn_instance_marker_cmds` and proton-wg-internals.md.
- Only app-created networks (`fvpn_*`) may be deleted; GL's own networks use
  anonymous firewall sections the delete code can't clean.
- **GL only VPN-routes `lan`/`guest` by default**: its `VPN_PREROUTING_HOOK`
  jumps to mangle `ROUTE_POLICY` only for `-i br-lan`/`-i br-guest`, and zone
  forwardings to the VPN zones are only made from those. Every app network must
  be in `route_policy.global.append_source_if` (space-separated; GL validates
  each with `ubus call network.interface.<if> status`; applied by a
  `vpn-client restart`). `RouterLanAccess.sync_vpn_source_ifs` keeps it in sync.
- **Never accept "mark != 0" in FORWARD without an `-o` VPN interface** — it
  lets VPN-grouped devices reach other LAN bridges. Accepts are scoped to
  `-o wgclient+/ovpnclient+/protonwg+/fvsv+` (`vpn_egress_accept_rules`).
- **busybox**: `sleep` takes whole seconds only; `timeout` runs binaries, not
  shell functions; there's no `unshare` (and no `nc -z`, `date +%N`,
  `grep -P`). Test generated scripts against busybox, not your host shell.

## fwmark / table map (mask 0xf000)

| Mark | Owner | Table |
|---|---|---|
| 0x1000–0x5000 | GL vpn-client (kernel WG / OVPN) | 1001–1005, prio 6000 |
| 0x6000, 0x7000, 0x9000, 0xf000 | proton-wg | 1006, 1007, 1009, 1015, prio 6000 |
| 0x8000 | VPN bypass (WAN) | 1008, prio 100 |
| 0xa000–0xd000 | split VPN slots 0–3 | 1010–1013, prio 90 |

Pick new marks only from what's left, and update this table.

## Split VPNs

`facades/split_vpn.py` — read `docs/internals/split-vpn-internals.md` first.
The Barracuda 5.3.10 client (`barracudavpn-daemon` + `barracudavpn` CLI) runs
in netns `fvpn_sv<N>` under a patched `qemu-x86_64` (tools/qemu/); the
generated `svctl.sh` is the only thing that starts/stops it. Daemon and CLI
share `/tmp/fvsv<N>run` bind-mounted over `/run` (OpenWrt has no `/run`, and
each `ip netns exec` has its own mount namespace). The tunnel is an L3 **`tap0`**
(the namespace firewall allows `tun+` and `tap+`). Credentials reach svctl on
stdin from a 0600 tmpfs file — never put a password or OTP in an SSH command
string or a log (svctl itself passes them to the CLI as args, root-visible on
the router only while it runs). OTPs come from `backend/vpn/totp.py`. Only one
connected Barracuda instance is guaranteed (no `unshare`, so the daemon's
message queues aren't per-slot).
