# proton-wg Implementation Notes

Non-obvious constraints and gotchas for the proton-wg (WireGuard TCP/TLS) subsystem.

## Process targeting

`killall proton-wg` kills ALL proton-wg processes simultaneously, dropping co-running tunnels. The correct approach is to read `/proc/<pid>/environ` to identify the target tunnel's process by `PROTON_WG_INTERFACE_NAME`, then kill only that PID.

## Mangle rule ordering

Mangle MARK rules MUST be created AFTER `firewall reload` in `start_proton_wg_tunnel()`. Creating them before the reload causes fw3 to wipe them immediately (fw3 only preserves its own `!fw3`-marked rules).

The firewall include at `/etc/fvpn/protonwg/mangle_rules.sh` has `option reload '1'`, meaning it re-runs on every `firewall reload`. This is the persistence mechanism — the rules themselves are ephemeral.

## Why firewall reload is safe but restart is not

`firewall.vpnclient` include has `option reload='0'` — it only runs on firewall `start` (not `reload`). So:
- `firewall reload` → safe (~0.22s, rtp2.sh NOT re-executed, WG handshakes survive)
- `firewall restart` → dangerous (calls stop+start, re-runs rtp2.sh, corrupts our interfaces)

## Tunnel ID allocation

`_next_tunnel_id()` must check BOTH:
1. `route_policy` UCI sections (for kernel WG and OVPN tunnels)
2. Existing `pwg_mac_*` ipsets on the router (for proton-wg tunnels)

Checking only route_policy will produce tunnel_id collisions because proton-wg tunnels have no route_policy entry. This was a real bug where two proton-wg tunnels got the same tunnel_id.

## No route_policy rule

proton-wg tunnels have no `route_policy` entry. This means:
- They don't appear in `router.get_flint_vpn_rules()` — matched separately
- `display_order` is local-only (can't use `uci reorder`)
- Device assignment uses `ipset add` directly (not `uci add_list from_mac`)
- Kill switch is always-on via blackhole route (not UCI `killswitch` flag)

## Ipset naming and vpn-client isolation

proton-wg ipsets use the `pwg_mac_` prefix (e.g. `pwg_mac_303`) instead of the `src_mac_` prefix used by kernel WG/OVPN. This is critical because `/etc/init.d/vpn-client restart` flushes all `src_mac_*` ipsets. The distinct prefix makes proton-wg device assignments immune to vpn-client restarts — zero downtime, zero traffic leaks.

## Persistent device assignments (.macs files)

Device-to-tunnel MAC assignments are stored in three places (triple-write):

1. **Router `.macs` file** (`/etc/fvpn/protonwg/{iface}.macs`) — one MAC per line, persistent on router filesystem. The firewall include script reads these to populate ipsets on every firewall reload, reboot, or manual invocation. This is the primary persistence layer — it works without the app running.
2. **Router ipset** (`pwg_mac_{tunnel_id}`) — kernel-level, provides immediate routing effect on assignment. Ephemeral but rebuilt from `.macs` files by the firewall include.
3. **Local store** (`profile_store.json` → `device_assignments`) — backup used by app-level resolution and self-healing.

The firewall include (`mangle_rules.sh`) is fully self-contained: it creates ipsets, populates them from `.macs` files, and applies mangle rules. No app intervention required for recovery.

## dns_mark.ko procfs gotcha — zero-byte writes are no-ops

GL.iNet's `dns_mark.ko` exposes per-rule MAC lists at `/proc/dns_mark/rule<id>/macs`. The handler has a non-obvious quirk that broke device-unassignment cleanup before the fix in `_dns_mark_register_cmd`: **zero-byte writes are silently ignored.**

Empirically verified live on the Flint 2 (against rule302):

| Operation | Effect |
|---|---|
| `echo "AA:BB:CC:DD:EE:FF" > .../macs` | **Replaces content** |
| `: > .../macs` (shell truncate, no write) | **No-op — list unchanged** |
| `cat empty_file > .../macs` | **No-op — list unchanged** |
| `echo "" > .../macs` (writes one `\n`) | **Clears the list** |
| `cat one_mac.macs > .../macs` | **Replaces** (not append) |

So when a device is unassigned and the persistent `.macs` file is rewritten empty, a naive `cat .macs > /proc/.../macs` does nothing — the kernel keeps matching the stale MAC and the device's DNS queries keep getting marked through the tunnel it no longer belongs to. Always force-clear with `echo "" > .../macs` before the cat.

Also note: the **only** delete API at module level is `/proc/dns_mark/clear`, which wipes ALL rules regardless of the value written. Never use it — it would nuke GL.iNet's wgclient rules and strand every device on a vpn-client group.

## Device assignment must trigger mangle rebuild

Adding/removing a MAC on a proton-wg group updates three pieces of state — the `.macs` file, the `pwg_mac_<id>` ipset, and `/proc/dns_mark/rule<id>/macs` (the kernel pre-routing DNS marker). The first two are written directly in the assignment code path; the third is only touched by `rebuild_mangle_rules()`. So `assign_device()` calls the rebuild at the end, otherwise dns_mark drifts out of sync and unassigned devices keep DNS-routing through the old tunnel.

## Tunnel MTU and MSS clamp (wg-tls PMTU black hole)

Proton's wg-tls re-encapsulates WireGuard inside obfuscated TLS-over-TCP, adding ~120 bytes of overhead vs plain WG's ~60. The kernel's default 1420 MTU on `protonwgN` causes full-MTU TCP segments to black-hole inside the TLS outer connection — most visibly as Amazon Prime Video failing the 11 MB Ignition bootloader fetch with `curl error 18 / "bytes missing"`. ICMP "Packet Too Big" doesn't survive Proton's TLS framing, so PMTUD never triggers and fw3's zone `mtu_fix='1'` (which uses `--clamp-mss-to-pmtu`) is useless here.

**Per-protocol defaults** live in `consts.PROTO_DEFAULT_MTU` (one source of truth, also reused by the kernel-WG facade):

- `wireguard` → 1420 (plain UDP)
- `wireguard-tcp` → 1380
- `wireguard-tls` → 1320

**Persistence:** `upload_proton_wg_config` writes `FVPN_MTU=N` into the tunnel's `.env`. `start_proton_wg_tunnel` reads it via `_read_env_mtu` and applies it with `ip link set mtu` after bringing the link up. Legacy envs without the field fall back to the per-protocol default keyed off `PROTON_WG_SOCKET_TYPE` — no migration needed.

**Override:** set `profile.options["mtu"]` to override the per-protocol default.

**MSS clamp:** `rebuild_mangle_rules` emits a deterministic fixed-MSS clamp per active tunnel into `mangle_rules.sh`:

- `mss_v4 = mtu − 40`, `mss_v6 = mtu − 60` (computed by `_mss_for_mtu`)
- Rules inserted at `-I FORWARD 1` so they take precedence over fw3's `--clamp-mss-to-pmtu` rule
- Both directions (`-i` and `-o protonwgN`), both families when v6 is enabled
- Each rule tagged with `-m comment --comment fvpn-mss-<iface>` (hyphenated, no spaces — see below)
- The script's leading sweep `iptables -t mangle -S FORWARD | grep fvpn-mss | sed 's/-A /-D /' | while read line; do iptables -t mangle $line; done` removes any prior copies before re-adding, so re-runs (every firewall reload) are idempotent

**Sysctl:** `ensure_router_sysctl()` writes `/etc/sysctl.d/99-fvpn.conf` with `net.ipv4.tcp_mtu_probing=1`. The router's own TCP stack uses this to escape PMTU black holes when it originates connections through the tunnel.

### iptables comment convention — never spaces

The MSS clamp's idempotency depends on its self-cleaning sweep matching the rules it emitted. `iptables-save` quotes any `--comment` value containing whitespace (`--comment "foo bar"`), and word-splitting on the unquoted `iptables -t mangle $line` reads the literal `"` characters as part of the words → the delete fails silently → duplicates accumulate per reconnect. Always use a space-free tag (`fvpn-mss-protonwg0`, hyphens or underscores). This applies to **any** iptables `--comment` used by a self-cleaning sweep, not just MSS clamps.

## Device registration names

Proton cert registrations use `"Flint VPN Manager-{profile_name}"` as the device name. Since persistent certs cannot be deleted via the VPN API (requires `password` scope, returns 403 with VPN token), meaningful names matter. Cleanup is only possible through the Proton web dashboard at account.protonvpn.com → Downloads → WireGuard configurations.
