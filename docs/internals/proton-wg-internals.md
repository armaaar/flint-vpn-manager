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

## Device registration names

Proton cert registrations use `"Flint VPN Manager-{profile_name}"` as the device name. Since persistent certs cannot be deleted via the VPN API (requires `password` scope, returns 403 with VPN token), meaningful names matter. Cleanup is only possible through the Proton web dashboard at account.protonvpn.com → Downloads → WireGuard configurations.
