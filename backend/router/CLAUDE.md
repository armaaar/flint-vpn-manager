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
- Only app-created networks (`fvpn_*`) may be deleted; GL's own networks use
  anonymous firewall sections the delete code can't clean.

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
The Barracuda client runs in netns `fvpn_sv<N>` under `qemu-x86_64`; the
generated `svctl.sh` is the only thing that starts/stops it. Credentials reach
the client on stdin from a 0600 tmpfs file — never put a password or OTP in a
command string. OTPs come from `backend/vpn/totp.py` (stored TOTP secret).
