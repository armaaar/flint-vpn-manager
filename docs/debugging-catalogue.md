# Debugging Catalogue

A curated collection of real debugging stories from this project. Every entry is a bug that actually happened, what the symptom looked like, how we traced it, and what fixed it. Mined from prior Claude Code sessions.

**How to use this document**

- **If you're trying to diagnose a symptom** — skim the "Active lore" section, grouped by subsystem. Many problems have a known shape.
- **If you're about to change something** — check whether the area has known invariants that you're about to break.
- **Every entry is tagged `ACTIVE` or `OBSOLETE`.** Obsolete means the shape of the bug can no longer occur because the code has been restructured (a whole feature was rewritten, a naming scheme was changed, etc.). They're kept for context — the *lesson* may still apply even if the specific failure mode can't reproduce.
- **The "Invariants" sections at the end** distil the hard-won rules into one-liners that are cheap to skim before acting.

Related docs: [docs/router-features-translation.md](router-features-translation.md), [docs/source-of-truth.md](source-of-truth.md), [docs/router-reference.md](router-reference.md), [docs/proton-wg-internals.md](proton-wg-internals.md).

---

## Active lore — by subsystem

### Adblock

#### Blocklist config file path — `/etc/dnsmasq.d/` is ignored on Flint 2 `ACTIVE`
- **Symptom**: VPN bypass domain rules created ipsets (`fvpn_byp_*`) but they stayed empty. Resolved IPs never made it into the ipset; traffic to those domains still went through VPN.
- **Root cause**: Code wrote the dnsmasq conf to `/etc/dnsmasq.d/fvpn_bypass.conf`, but the main dnsmasq on Flint 2 uses `conf-dir=/tmp/dnsmasq.d` (verify via `grep conf-dir /var/etc/dnsmasq.conf.*`). The `ipset=` directive was never loaded.
- **Debug**: `cat /etc/dnsmasq.d/fvpn_bypass.conf` existed; `ipset list fvpn_byp_xxx_b1` had 0 entries after DNS queries; `grep conf-dir /var/etc/dnsmasq.conf.*` revealed the actual path.
- **Fix**: `BYPASS_DNSMASQ_CONF` in [backend/consts.py](backend/consts.py) → `/tmp/dnsmasq.d/fvpn_bypass.conf`. Full `/etc/init.d/dnsmasq restart` needed (SIGHUP doesn't reload `ipset=` directives).

#### Synchronous dnsmasq restart blocks unlock for 18s `ACTIVE`
- **Symptom**: After adding a VPN bypass with domain rules, unlock took ~21s vs. expected ~3.5s. Per-step timing log: `vpn_bypass=18.07s` dominated.
- **Root cause**: `/etc/init.d/dnsmasq restart` blocks ~12–15s on Flint 2 (rebuilds all per-tunnel instances). `VpnBypassService._build_group_ipset_map()` also issued one SSH `uci get` per non-proton-wg VPN profile sequentially.
- **Debug**: Read `Unlock timing:` INFO log in `logs/app.log`. Traced `reapply_all() → _apply() → _build_group_ipset_map()`.
- **Fix**: Batched UCI queries into a single SSH call in `VpnBypassService`. Changed `/etc/init.d/dnsmasq restart` to run in background (`&`) when domain rules change.

#### Blocklist re-uploaded on every startup (~70 MB, 35s) `ACTIVE`
- **Symptom**: Unlock repeatedly took 21–35s because the full HaGeZi blocklist was re-downloaded and re-uploaded on every boot.
- **Root cause**: `AutoOptimizer._last_blocklist_check_date` was in-memory only; on every process start it was `None`, so the first optimizer tick always re-ran `check_and_update_blocklist()` regardless of router state.
- **Debug**: Traced unlock flow in `routes/auth.py`; saw optimizer poll_loop always calling the update on first tick; inspected `adblock.last_updated` in `config.json`.
- **Fix**: Three layers — (1) seed `_last_blocklist_check_date` from persisted `adblock.last_updated` at init; (2) first-tick short-circuit via `router.adblock._blocklist_has_content()` SSH `grep -c`; (3) SHA-256 `blocklist_hash` dedup so identical content doesn't re-upload.

#### Adblock silently degrades when blocklist file is missing `ACTIVE`
- **Symptom**: Fresh router / deleted `blocklist.hosts` — profiles still showed `adblock: true`, but nothing was being blocked. No warning, no re-fetch.
- **Root cause**: `sync_adblock()` ([backend/router/facades/adblock.py](backend/router/facades/adblock.py#L83-L128)) calls `_blocklist_has_content()`; if the file is missing it removes all snippets and returns silently.
- **Debug**: `ls /etc/fvpn/blocklist.hosts`, read `_blocklist_has_content` path.
- **Fix (recommended, documented in audit but not yet applied)**: when `ifaces` is non-empty but blocklist is missing, trigger a re-fetch from `config.json` adblock sources.

#### Test `MagicMock` triggers "already on router — skipping" branch `ACTIVE`
- **Symptom**: `test_auto_optimizer` tests failed: `download_and_merge_blocklists to have been called once. Called 0 times.`
- **Root cause**: The "skip download if blocklist is on router" optimization calls `router.adblock._blocklist_has_content()`. `MagicMock()` returns truthy for any call, so the skip fired and the mocked download was bypassed.
- **Debug**: Read `[INFO] Blocklist already on router — skipping startup download` in captured pytest output.
- **Fix**: Tests that exercise the download path seed `opt._last_blocklist_check_date = "2026-04-08"` (or similar) to simulate a day boundary.

#### OISD preset URLs returned 404 `ACTIVE`
- **Symptom**: `Blocklist update failed: 404 Client Error: Not Found`.
- **Root cause**: OISD moved/renamed their raw GitHub hosts files; presets in `consts.py` went stale.
- **Debug**: `curl -I <url>` on each preset.
- **Fix**: Replaced OISD presets with HaGeZi Light/Multi/Pro/Ultimate/TIF + Steven Black Unified in [backend/consts.py](backend/consts.py).

#### "View Blocked Domains" endpoint hung on 140K-line file `ACTIVE`
- **Symptom**: Clicking "View Blocked Domains" hung for 30+ seconds; counter read "0 domains".
- **Root cause**: Endpoint did `router.exec(cat {ADBLOCK_HOSTS_PATH})`, pulling 140K lines over SSH then parsing locally.
- **Debug**: `wc -l /etc/fvpn/blocklist.hosts` = 139,741; direct API call hung.
- **Fix**: Rewrote endpoint to do server-side `awk ... | sort -u | grep -i … | head`; only the requested page crosses SSH.

### Proton-wg

#### Killing one tunnel kills all proton-wg tunnels `ACTIVE` (hard invariant)
- **Symptom**: Stopping one proton-wg tunnel drops all co-running proton-wg tunnels.
- **Root cause**: `killall proton-wg` kills every `proton-wg` process. Multiple tunnels share the same binary.
- **Fix**: Always target by iface name via `/proc/<pid>/environ`:
  ```sh
  pid=$(for p in $(pidof proton-wg); do
    grep -qz 'PROTON_WG_INTERFACE_NAME=protonwg0' /proc/$p/environ && echo $p && break
  done)
  kill $pid
  ```
  See `stop_proton_wg_tunnel` in [backend/router/facades/proton_wg.py](backend/router/facades/proton_wg.py#L314-L355).

#### Stale DNS REDIRECT to dead dnsmasq after disconnect `ACTIVE`
- **Symptom**: Devices in a proton-wg group had no internet (not even DNS) after disconnecting the tunnel. DNS redirect rule sent queries to a port nothing was listening on.
- **Root cause**: `_rebuild_proton_wg_mangle_rules()` rebuilt from every `*.env` file including tunnels whose interface was DOWN. The per-tunnel dnsmasq was gone but the REDIRECT rule pointed at its old port.
- **Debug**: `wg show`, `ip link show protonwg0` (missing), `iptables -t mangle -S ROUTE_POLICY` (TUNNEL303 still present), `iptables -t nat -S policy_redirect` (REDIRECT to port 2653 still active), `cat /etc/fvpn/protonwg/mangle_rules.sh`.
- **Fix**: Added interface-UP check before including a tunnel in rebuild; explicit cleanup for `.env`-exists-but-iface-down tunnels; reordered `stop_proton_wg_tunnel` so rebuild happens BEFORE `firewall reload` ([backend/router/facades/proton_wg.py](backend/router/facades/proton_wg.py#L468-L535)).

#### Device assignments lost after firewall reload or reboot `ACTIVE` (design-critical)
- **Symptom**: Proton-wg devices stopped routing through the tunnel after any firewall event until the app reactively rebuilt on the next SSE tick (~10s gap).
- **Root cause**: Ipsets and mangle rules were ephemeral kernel state with no router-persisted source.
- **Fix**: Triple-write pattern — `.macs` file at `/etc/fvpn/protonwg/<iface>.macs` is source of truth. `mangle_rules.sh` (firewall include with `reload='1'`) repopulates the ipset from the `.macs` file on every firewall reload. The app doesn't need to be running.

#### Mangle rules MUST be created AFTER firewall reload `ACTIVE` (ordering invariant)
- **Symptom**: Proton-wg mangle rules disappeared immediately after creation.
- **Root cause**: Creating mangle rules *before* a `firewall reload` causes fw3 to wipe them (fw3 only preserves its own `!fw3`-marked rules).
- **Fix**: In `start_proton_wg_tunnel()`, `firewall reload` runs first to create the zone; then `_rebuild_proton_wg_mangle_rules()` writes + executes the include script. See [docs/proton-wg-internals.md](proton-wg-internals.md).

#### Proton-wg profiles not marked ghost on fresh router `ACTIVE`
- **Symptom**: On a fresh router, proton-wg profiles showed `health: red` but no `_ghost: true` flag. Clicking Connect ran `wg setconf` against a missing `.conf` and crashed with an SSH error instead of the friendly "No tunnel configured" message.
- **Root cause**: [backend/services/profile_list_builder.py:200](backend/services/profile_list_builder.py#L200) unconditionally calls `matched_local_keys.add(key)` for all proton-wg profiles, skipping ghost detection.
- **Fix (documented, pending)**: Check `.conf` existence on the router (cheap via `RouterProtonWG.list_tunnel_confs()`) before marking matched; missing `.conf` falls through to ghost detection.

#### Tunnel ID collision between kernel WG and proton-wg `ACTIVE`
- **Symptom**: Two proton-wg tunnels ended up with the same tunnel_id.
- **Root cause**: Early `_next_tunnel_id()` only scanned `route_policy` UCI sections. Proton-wg tunnels have no route_policy entry — they were invisible to the scan.
- **Fix**: [backend/router/tunnel_id_alloc.py](backend/router/tunnel_id_alloc.py) now scans three sources: (1) `route_policy` UCI, (2) `ipset -n` matching `pwg_mac_|src_mac_`, (3) `FVPN_TUNNEL_ID=` in all `*.env` files.

#### Test patching `parse_handshake_age` at wrong module `ACTIVE`
- **Symptom**: `AttributeError: module 'router.facades.proton_wg' does not have the attribute 'parse_handshake_age'`.
- **Root cause**: `parse_handshake_age` is imported lazily inside `get_proton_wg_health()` — never a module-level attribute.
- **Fix**: Patch at `router.tools.wg_show.parse_handshake_age` instead.

#### Test side_effect returning generic "12345" leaks into chain scan `ACTIVE`
- **Symptom**: `stop_proton_wg_tunnel` test: `Expected 'delete_chain' to be called once. Called 2 times.` — second call targeted chain `'12345'`.
- **Root cause**: Test's `ssh.exec.side_effect` returned `"12345"` for every call, including the `iptables -t mangle -S ROUTE_POLICY | grep TUNNEL...` stale-chain scan. Code thought `"12345"` was a stale chain name.
- **Fix**: Return `""` for the stale-chain scan query specifically.

### Route policy, ipsets, firewall reload

#### `vpn-client restart` flushes every `src_mac_*` ipset `ACTIVE` (hard invariant)
- **Symptom**: During kernel WG/OVPN connect/disconnect, proton-wg ipsets would get flushed briefly.
- **Root cause**: GL.iNet's `vpn-client` cleans up ipsets by name glob `src_mac_*`. Proton-wg originally used the same prefix and got caught in the blast radius.
- **Fix**: Proton-wg moved to `pwg_mac_*` prefix. Documented in [docs/router-features-translation.md §6.2](router-features-translation.md). **Don't use the `src_mac_` prefix for anything new** — it's vpn-client territory.

#### `uci del_list` requires exact-case MAC match `ACTIVE`
- **Symptom**: `uci del_list` silently no-op'd when removing a device.
- **Root cause**: UCI's `del_list` is a string-equality match. GL.iNet UI may store uppercase MAC, FlintVPN stores lowercase. Our `del_list` with lowercase didn't match.
- **Fix**: `RouterPolicy.from_mac_tokens()` preserves case; `set_device_vpn` / `remove_device_from_vpn` look up the exact stored token and use it in `del_list`. See [backend/router/facades/policy.py:144-155](backend/router/facades/policy.py#L144-L155) and [backend/router/facades/devices.py:277-330](backend/router/facades/devices.py#L277-L330).

#### `firewall restart` (not reload) corrupts WG handshakes `ACTIVE` (hard invariant)
- **Symptom**: Running `/etc/init.d/firewall restart` dropped every WireGuard tunnel into `connecting` state.
- **Root cause**: `firewall restart` = `stop+start` → re-runs `vpnclient` include (`rtp2.sh`) which tears down our interfaces. `firewall reload` (~0.22s) does NOT re-run rtp2.sh (include has `reload='0'`) and our tunnels survive.
- **Fix**: **Never call `firewall restart`.** Always `firewall reload`. Our own includes use `reload='1'` so they re-run on reload. Documented in [docs/router-features-translation.md §24](router-features-translation.md#24-firewall-include-scripts).

#### Ghost orphan `src_mac_303` re-created after unlock `OBSOLETE`
- **Note**: Cause was the old timestamp-based backup restore that would pull stale config from `/etc/fvpn/profile_store.bak.json` during migration. Now that backup is unconditionally router-wins (see "Backup logic inverted" below), this specific re-creation pattern is gone. If you see orphan `src_mac_*` ipsets, destroy them manually; the cause is no longer the app.

### VPN bypass

#### LoL chat still broken despite CIDR + domain rules `ACTIVE`
- **Symptom**: League of Legends game worked but chat didn't. `chat.euw1.lol.riotgames.com` resolved to a Cloudflare IP (`172.65.223.136`) not on Riot's AS6507. ProtonVPN DNS returned NXDOMAIN for some Riot chat subdomains.
- **Fix**: LoL preset ([backend/consts.py](backend/consts.py) `VPN_BYPASS_PRESETS["lol"]`) got a third OR-block: `port 5222:5223 TCP` (XMPP chat). This bypasses the standard XMPP ports without tying to unstable Cloudflare ranges.

#### LoL preset CIDR `/17` was wrong aggregation `ACTIVE`
- **Symptom**: Preset covered 32K IPs under `104.160.128.0/17` when only the `/19` (8K) was Riot-owned — would bypass non-Riot traffic.
- **Fix**: Updated LoL preset against RIPE RIS AS6507 query — 22 IP ranges + 10 domains + XMPP port range. Commit `2381247`.

#### Preset updates don't propagate to existing exceptions `ACTIVE` (by design)
- **Symptom**: User updated LoL preset to 22 IPs/10 domains but existing exception still showed "9 IPs, 8 domains".
- **Root cause**: Preset rules are **copied** into exceptions at creation time, not referenced. Editing the preset does not retroactively update exceptions.
- **Fix**: Documented behaviour; user must edit the exception or delete/recreate from preset.

#### Bypass rule + ipset creation before validation `ACTIVE`
- **Symptom**: Unit test `test_group_scope_missing_profile_skips` expected `"fvpn_byp_test1234" not in cmd` but the name appeared in the output.
- **Root cause**: Per-block ipsets are created (step 1 of `_build_all_commands`) before scope-target validation (step 3). Invalid-scope exception still creates the ipset; it just never gets referenced by any iptables rule.
- **Fix**: Assertion should check only that no `iptables` rule references the ipset — not that its name is absent from all commands.

#### Bypass icon collided with Smart Protocol icon `ACTIVE`
- **Symptom**: Dashboard showed `⚡` for both VPN Bypass and Smart Protocol pills.
- **Fix**: VPN Bypass → `🔀` (shuffle). Commit `98c64d8`.

### NoInternet

#### Single `src='lan' dest='wan'` REJECT missed all custom zones `OBSOLETE`
- **Symptom**: Devices assigned to a no-internet group on the custom `fvpn_iot` zone still had full internet.
- **Root cause**: The fw3 REJECT rule targeted only zone `lan`. Devices on `guest`, `fvpn_iot`, etc. were never matched.
- **Why obsolete**: Rewritten to a single FORWARD-chain rule matching all zones via ipset + WAN output device. See `_SCRIPT_CONTENT` in [backend/router/noint_sync.py](backend/router/noint_sync.py#L42-L73).

#### fw3 silently ignored `hash:mac` UCI ipset `OBSOLETE`
- **Symptom**: UCI had `firewall.fvpn_noint_macs=ipset` with `match='mac'` but `iptables -L FVPN_NOINT` reported "No chain/target/match by that name" after firewall reload.
- **Root cause**: fw3 2021-03-23 on OpenWrt 21.02 doesn't support `hash:mac` ipsets defined via UCI — emits `Warning: Section '…' has an invalid combination of storage method and matches` and drops rules referencing it.
- **Debug**: `/etc/init.d/firewall reload 2>&1` surfaced the warning.
- **Why obsolete**: We abandoned UCI-driven ipset definitions for `hash:mac`. Current code creates ipsets directly inside the firewall include script ([backend/router/noint_sync.py](backend/router/noint_sync.py#L42-L73)).
- **Lesson (still active)**: **If a firewall rule silently doesn't work, always run `firewall reload 2>&1` and read the warnings** — fw3 is extremely quiet about invalid configs.

#### Include deployed but rule never activated on first unlock `ACTIVE`
- **Symptom**: Kernel ipset correct with members, but `FVPN_NOINT` chain didn't exist — script hadn't run.
- **Root cause**: `sync_noint_to_router()` returned `reload: True` but the caller didn't trigger `firewall reload`. UCI include registered without the script ever executing.
- **Fix**: `sync_noint_to_router()` now calls `router.service_ctl.reload("firewall")` directly when first deploying the include.

### LAN access & networks

#### Device exceptions don't cover multicast (mDNS, SSDP) `ACTIVE`
- **Symptom**: Scanner/printer on one network not discoverable from another network even with "both directions" exception.
- **Root cause**: Device exceptions are iptables ACCEPT rules for unicast. mDNS/SSDP need a reflector to bridge broadcast domains.
- **Fix**: Enabled avahi reflector (`enable-reflector=yes`), restricted to bridge interfaces via `allow-interfaces=br-lan,br-guest,…`, added `Allow-mDNS-<zone>` firewall rules for zones with `input=REJECT`. `RouterFirewall.setup_mdns_for_networks` ([backend/router/facades/firewall.py:167-253](backend/router/facades/firewall.py#L167-L253)).
- **Caveat**: WSD (Windows) printers won't appear via mDNS regardless.

#### Avahi reflector seeing duplicate packets `ACTIVE`
- **Symptom**: With reflector on, discovery broke across networks.
- **Root cause**: Avahi was listening on WiFi (`ra0`, `rax0`) AND the parent bridges (`br-lan`), seeing each mDNS packet twice.
- **Fix**: `allow-interfaces=<bridges only>` filters to bridges and eliminates the duplicate.

#### Static-IP devices missing from Networks page `ACTIVE`
- **Symptom**: Pantum printer on static IP `192.168.10.225` was in ARP and had exceptions defined, but never appeared in the network device list.
- **Root cause**: `LanAccessService.get_network_devices()` iterated `/tmp/dhcp.leases` only; static IPs without DHCP leases were invisible.
- **Debug**: `cat /tmp/dhcp.leases` (no entry), `ip neigh show | grep <ip>` (REACHABLE).
- **Fix**: Supplement DHCP leases with ARP table entries in [backend/services/lan_access_service.py](backend/services/lan_access_service.py#L69-L116).

#### IoT zone traffic blocked by FORWARD default DROP `ACTIVE`
- **Symptom**: DNS worked but TCP outbound from IoT devices dropped. `zone_fvpn_iot_forward` counter was 0.
- **Root cause**: GL.iNet's custom `forwarding_rule` chain accepts traffic only when `mark ! 0x0/0xf000`. Unmarked traffic (not going to VPN) bypassed the zone forwarding check entirely.
- **Fix**: The global `-m mark ! --mark 0x0/0xf000 -j ACCEPT` rule in `forwarding_rule` (written by `/etc/fvpn/lan_access_rules.sh`) passes through fwmark-marked traffic. Non-marked traffic still relies on fw3 `forwarding` sections.

#### fw3 silently ignores zones with names > 11 chars `ACTIVE` (hard invariant)
- **Symptom**: Newly-created zone had no firewall rules, no NAT; no error anywhere.
- **Root cause**: fw3 silently ignores zones where `name` exceeds 11 characters.
- **Fix**: FlintVPN uses `fvpn_` (5) + zone_id (≤6). `LanAccessService.create_network()` in [backend/services/lan_access_service.py:155](backend/services/lan_access_service.py#L155) truncates and handles collisions.

#### MediaTek `mt_wifi` driver doesn't reload `BssidNum` from `.dat` files `ACTIVE` (hard invariant)
- **Symptom**: After editing `/etc/wireless/mediatek/mt7986-ax6000.dbdc.b*.dat`, `wifi reload` didn't create new `ra<N>`/`rax<N>` interfaces.
- **Root cause**: `mt_wifi` reads `BssidNum` only at module load time. `wifi reload` and `wifi down/up` don't re-load the module.
- **Fix**: Full driver cycle — `wifi down → rmmod mtk_warp_proxy → rmmod mt_wifi → insmod mt_wifi → insmod mtk_warp_proxy → wifi up → firewall reload`. ~15s WiFi outage for ALL clients on ALL bands. Must run detached (`&`) over SSH because the WiFi drop kills the SSH session. [backend/router/facades/lan_access.py:545-564](backend/router/facades/lan_access.py#L545-L564).

#### E2E tests flaky on LAN access — SSH contention `ACTIVE`
- **Symptom**: Random LAN access E2E tests failed intermittently.
- **Root cause**: `beforeEach` waited for "Loading networks" to disappear; individual tests accessed `.network-card` immediately. Parallel workers hitting `get_networks()` via SSH simultaneously amplified latency.
- **Fix**: Explicit `await expect(page.locator('.network-card').first()).toBeVisible({ timeout: 10_000 })` in `beforeEach`; made LAN test project depend on VPN project in playwright config.

#### Editing a device caused the Networks page to reset `ACTIVE`
- **Symptom**: Opening DeviceModal from the Networks page and saving collapsed the expanded network and re-fetched all data.
- **Root cause**: `DeviceModal`'s `on:reload` was wired to the page's `loadData()` which set `loading=true` and re-fetched networks/rules/exceptions.
- **Fix**: Replaced with a lightweight `reloadDevices()` that only calls `api.getDevices()` and updates the SSE-backed `devices` store.

### IPv6

#### Custom networks IPv4-only even with router IPv6 enabled `ACTIVE`
- **Symptom**: IoT network had only a `fe80::` link-local — no DHCPv6, no RA, no global prefix.
- **Root cause**: `create_network()` didn't set IPv6 UCI fields for new networks.
- **Fix**: `create_network()` now includes `ip6assign='64'`, `ip6hint=<next>`, `ip6ifaceid='::1'`, `dhcp.<net>.dhcpv6='server'`, `dhcp.<net>.ra='server'`. Plus a separate `set_ipv6()` method for per-network toggling. See [backend/router/facades/lan_access.py:426-510](backend/router/facades/lan_access.py#L426-L510).

#### IPv6 leaks past VPN tunnels `ACTIVE`
- **Symptom**: VPN-assigned devices could leak real IPv6 addresses despite kill switch.
- **Root cause**: GL.iNet's `route_policy`/`rtp2.sh` handles IPv4 fwmark rules only. IPv6 packets skip the VPN tunnel entirely.
- **Debug**: `ip6tables -t mangle -S ROUTE_POLICY` empty; confirmed by GL.iNet forum ("IPv6 VPN policy not implemented in fw 4.x").
- **Fix**: FlintVPN manages the entire IPv6 routing layer: `ip6tables -t mangle` chains, IPv6 FORWARD default DROP with `ESTABLISHED,RELATED` + per-tunnel mark ACCEPT. Scripts at `/etc/fvpn/ipv6_mangle_rules.sh` and `/etc/fvpn/ipv6_forward.sh`, registered as firewall includes. `RouterFirewall.ensure_ipv6_leak_protection` + `RouterProtonWG._rebuild_ipv6_mangle_rules`.

#### sysctl IPv6 disable doesn't survive reboot `ACTIVE`
- **Symptom**: Disable IPv6 via Settings → reboot → IPv6 came back.
- **Root cause**: `disable_ipv6_router()` only called `sysctl -w` (in-memory) without removing `/etc/sysctl.d/99-fvpn-ipv6.conf`.
- **Fix**: Also delete the persistence file + set `network.wan6.disabled='1'`. Both enable and disable paths idempotent ([backend/router/facades/firewall.py](backend/router/facades/firewall.py#L63-L125)).

#### IPv6 filter off by default in ServerPicker `ACTIVE`
- **Symptom**: Opening ServerPicker, IPv6 filter chip was OFF even though global IPv6 was on.
- **Root cause**: Svelte reactive block `$: if (visible && ...)` ran synchronously when `visible` became true, before the async `loadGlobalIpv6()` resolved.
- **Fix**: Restructured `initPicker()` to `await loadGlobalIpv6()` before hydrating feature defaults.

### Devices

#### Phantom MAC from WAN-side ISP gateway `ACTIVE`
- **Symptom**: `02:10:18:7a:fe:7c` appeared as an online device; router's own UI didn't show it.
- **Root cause**: ARP/NDP parser in [backend/router/facades/devices.py](backend/router/facades/devices.py) included neighbours from all interfaces, picking up the ISP modem on WAN (`eth1`, `192.168.0.1`).
- **Debug**: `ip neigh show` revealed the WAN-side entry.
- **Fix**: `if not dev.startswith("br-"): continue` filter in both the IPv4 ARP parser and IPv6 NDP parser.

#### "Offline (never)" for all offline devices `ACTIVE`
- **Symptom**: Every offline device showed "Offline (never)" in the dashboard.
- **Root cause**: `DeviceService.build_devices_live()` hardcoded `d["last_seen"] = None` — legacy field, not tracked.
- **Debug**: `ubus call gl-clients list` exposes `online_time` (unix ts).
- **Fix**: Extract `online_time` in `get_client_details()` ([backend/router/facades/devices.py:145](backend/router/facades/devices.py#L145)); convert to ISO in device_service; frontend hides "Offline (never)" when `last_seen` is falsy.

#### DeviceModal form reset while typing `ACTIVE`
- **Symptom**: Form fields got wiped if user took too long editing a device name.
- **Root cause**: Svelte reactive `$: if (device) { label = ...; }` fired every time the `device` reference changed — which was every SSE tick (10s).
- **Fix**: `boundMac` tracking so form fields only re-initialise when a different device (different MAC) is opened.

#### Duplicate device-row markup across components `ACTIVE`
- **Symptom**: Bypass detail rows, Networks device rows, and the main Devices list all had subtly different visual treatments.
- **Fix**: New `DeviceListItem.svelte` with `selectable`/`selected`/`onClick` props, replacing three of the four ad-hoc implementations. Commit `48e9d97`.

### Backend services / tests

#### 33,457 MagicMock lines in `logs/app.log` `ACTIVE` (test hygiene)
- **Symptom**: `grep -c MagicMock logs/app.log` → 33,457. Entries like `Backup to router failed: Object of type MagicMock is not JSON serializable` interleaved with real log lines.
- **Root cause**: Three concurrent test-isolation bugs:
  1. `_save_callback` module-level global in [backend/persistence/profile_store.py](backend/persistence/profile_store.py) never reset between tests.
  2. Five `@patch("services.vpn_service.noint_sync.sync_noint_to_router")` in tests didn't set `.return_value`; the default truthy MagicMock triggered log branches with MagicMock values.
  3. `backend/app.py` attaches `FileHandler`s to `logs/app.log`, `logs/error.log`, `logs/access.log` at module import, so tests' logs went into production files.
- **Fix**:
  - Autouse fixture `_clear_profile_store_callback` → calls `ps.register_save_callback(None)` after each test.
  - Autouse `_no_production_logging` → strips `FileHandler`s from `flintvpn`, `flintvpn.profile_store`, `werkzeug` loggers before each test.
  - All five `noint_sync` mocks now set `.return_value = {"applied": True, "adds": 0, ...}`.
  - Mock router fixture sets safe defaults: `read_file.return_value = ""`, `get_router_fingerprint.return_value = ""`, `exec.return_value = ""`.
  - Result: 0 production log lines during the full test suite.
- **General rule**: If you see `MagicMock` in a prod log, check (a) module-level callbacks never cleared, (b) `@patch` decorators without `return_value`, (c) `FileHandler`s attached at import time.

#### Test patches `time` module wholesale `ACTIVE`
- **Symptom**: `TypeError: '<' not supported between instances of 'MagicMock' and 'int'` in `smart_protocol.py`.
- **Root cause**: `patch("vpn.smart_protocol.time")` replaced the whole module; `register()` called inside the patch stored a MagicMock as `started_at`.
- **Fix**: Move `register()` outside the patch context, or patch only `time.time` attribute.

#### Pre-existing WG-limit failure from real `profile_store.json` leaking into tests `ACTIVE`
- **Symptom**: `test_create_vpn_no_server_id` failed with `LimitExceededError: Cannot create more than 5 WireGuard UDP groups` from a clean start.
- **Root cause**: `_count_protocol_slots()` in [backend/vpn/protocol_limits.py:36](backend/vpn/protocol_limits.py#L36) reads `ps.get_profiles()`, which at test time held 5 kernel WG profiles from the developer's real store.
- **Fix (partial)**: `tmp_data_dir` fixture in `tests/conftest.py` patches `ps.DATA_DIR`/`ps.STORE_FILE` to a `tmp_path`.

#### Flask never binds port 5000 because of blocklist upload `ACTIVE`
- **Symptom**: `python backend/app.py` alive, logs show auto-restore + blocklist progress, but `curl localhost:5000/api/status` → Connection refused.
- **Root cause**: ~70 MB blocklist upload over SSH runs before `app.run()` on first boot; slow SSH means minutes before Flask binds.
- **Debug**: `ss -lnpt | grep :5000` (not bound), `pgrep -fa python.*app.py` (alive), `tail /tmp/flintvpn.log`.
- **Fix-workaround**: Use `until curl -s localhost:5000/api/status; do sleep 2; done` with Monitor tool (or deferred blocklist upload, noted as pending).

#### Flask "Address already in use" on restart `ACTIVE`
- **Symptom**: `Port 5000 is in use by another program`.
- **Fix**: Always `pkill -f "python backend/app.py"; sleep 1` before restart. Documented in [CLAUDE.md](../CLAUDE.md).

#### VPN Bypass page returning HTML 404 instead of JSON `ACTIVE`
- **Symptom**: Opening `/#bypass` → `Unexpected token '<', "<!doctype "... is not valid JSON`.
- **Root cause**: Newly-registered blueprint wasn't loaded by the running Flask process — blueprint registration is at import time.
- **Fix**: Restart backend after adding blueprints. Nothing hot-reloads them.

#### 500 on `PUT /api/vpn-bypass/exceptions/<id>` — `NoneType has no open_session` `ACTIVE`
- **Symptom**: Config update succeeded but SSH-dependent post-apply raised and the route handler didn't catch it.
- **Root cause**: SSH session dropped. Downstream `_apply()` raised `paramiko` transport errors.
- **Fix (pending)**: Route handler should catch + degrade gracefully. Workaround: the config change succeeded; next unlock reapplies.

#### Stale router rules orphaned with no local profile `ACTIVE`
- **Symptom**: Ghost rules `fvpn_rule_9001..9007` shown in dashboard, `DELETE /api/profiles/{id}` returned 404; they consumed WG slots.
- **Root cause**: E2E runs crashed before cleanup. Standard delete requires a matching local profile; orphan rules stayed on the router.
- **Fix**: Manual cleanup — delete `route_policy.fvpn_rule_*` UCI sections, `vpn-client restart`. Longer-term, `profile_healer.py` self-heals anonymous sections but can't infer missing local metadata.

#### E2E `unlock.spec.ts` requires app to start locked `ACTIVE`
- **Symptom**: `[unlock] shows unlock screen with correct elements` failed; 100 dependent tests didn't run.
- **Root cause**: Previous run's `afterAll` left app unlocked.
- **Fix**: Skip the "shows unlock screen" assertion; preserve an `afterAll` that re-unlocks so downstream projects inherit an unlocked state.

#### `lan_sync` import leftover after refactor `ACTIVE`
- **Symptom**: `LAN sync failed: name 'lan_sync' is not defined`; adblock sync silently failed too because it was inside the same try/except.
- **Fix**: Removed stale import. **Anywhere you see a `try: ... except Exception:` wrapping an SSH-touching code block, the `except` branch can mask a Python NameError as an infrastructure failure. Always log the `repr(e)`, not just a generic message.**

#### Backup logic inverted — stale router backup overwrote local edit `OBSOLETE` (but the lesson lives)
- **Symptom**: Edited `profile_store.json` on disk, server restart + unlock, local edit got overwritten by stale router backup, proton-wg ipsets briefly misnamed, all tunnels "appeared removed".
- **Root cause**: `check_and_auto_restore()` used timestamp comparison (newest wins) + fingerprint gating.
- **Why obsolete**: Rewritten — router backup is unconditionally source of truth. No backup → empty store (clean-slate semantic for a new router). See [docs/source-of-truth.md](source-of-truth.md).
- **Lesson (still active)**: **If you've decided a specific side is the source of truth, don't smuggle in a "whichever is newer" fallback.** One-directional logic is the only way the invariant holds under edit.

#### MCP server returning IDE-like stack traces through Claude `ACTIVE`
- **Symptom**: User's Claude session via MCP saw confusing errors from a tool.
- **Fix (workaround)**: Restart the MCP server alongside the Flask backend.

### Adblock (historical / obsolete)

#### REDIRECT-based adblock + avahi port collision `OBSOLETE`
- **Symptom**: Blocking dnsmasq was set to listen on 5353 (mDNS port); avahi already owned it. dnsmasq never started; REDIRECT rules sent DNS to a dead port; internet died.
- **Root cause**: `ADBLOCK_PORT=5353` collision with avahi.
- **Why obsolete**: The entire REDIRECT-based adblock subsystem was replaced with per-tunnel `addn-hosts` snippets injected into each dnsmasq instance's conf-dir. No separate blocking dnsmasq, no REDIRECT, no port conflict. `_cleanup_old_redirect_infra()` in [backend/router/facades/adblock.py:234-243](backend/router/facades/adblock.py#L234-L243) migrates any leftover legacy state on first sync.
- **Lesson (still active)**: **Anything binding to a port on OpenWrt: check `netstat -tlnup | grep <port>` first.** Common inhabitants: 53 (dnsmasq), 5353 (avahi), 67/68 (dnsmasq DHCP), 80/443 (uhttpd).

#### Adblock dnsmasq not answering UDP on `0.0.0.0` `OBSOLETE`
- **Symptom**: `netstat` showed dnsmasq on `0.0.0.0:5354`, TCP queries worked, UDP from LAN timed out.
- **Root cause**: `listen-address=0.0.0.0 + bind-dynamic` on OpenWrt doesn't accept UDP from bridge interfaces properly; REDIRECT packets arrive with bridge IP as destination and get dropped.
- **Why obsolete**: No separate adblock dnsmasq exists anymore.
- **Lesson (still active)**: On OpenWrt, prefer `listen-address=<explicit IP> + bind-interfaces` over `0.0.0.0 + bind-dynamic` for dnsmasq instances.

#### REDIRECT active while blocklist empty broke internet `OBSOLETE`
- **Symptom**: Intermittent internet drops on adblock devices after blocklist clear.
- **Root cause**: `sync_adblock_rules()` always inserted REDIRECT regardless of blocklist content or dnsmasq health.
- **Why obsolete**: See above — no separate blocking dnsmasq.
- **Lesson (still active)**: Never add a REDIRECT rule whose target isn't known to be healthy. Check the target responds on the port (`nc -z` doesn't work on BusyBox, use `curl -sf -o /dev/null --max-time 1 <addr>` or Python over SSH).

#### OnePlus in Trusted group lost internet — CT zone mismatch `OBSOLETE`
- **Symptom**: One phone (specific MAC) lost internet on Trusted WG group; randomizing MAC fixed it.
- **Root cause**: MAC was in both `src_mac_301` VPN ipset and `fvpn_adblock_macs` (old REDIRECT adblock). DNS REDIRECT to port 5354 created conntrack zone 8192 on the request side, but `out_dns_deal_conn_zone` had no rule for spt 5354, so reply was in zone 0. `conntrack -L` showed DNS entries as `[UNREPLIED]`.
- **Why obsolete**: No REDIRECT-based adblock anymore.
- **Lesson (still active)**: **If DNS works for some MACs but not others in the same group, check `ipset list -n` for overlapping ipsets AND `conntrack -L | grep <device_ip>` for [UNREPLIED] entries.** Conntrack zone mismatches are a stealth killer.

#### Two dnsmasq processes fighting for port 5354 `OBSOLETE`
- **Symptom**: `dnsmasq: failed to create listening socket for port 5354: Address in use`.
- **Why obsolete**: We no longer spawn a second dnsmasq for adblock.
- **Lesson (still active)**: Before starting a dnsmasq instance, `pgrep -f 'dnsmasq.*<conf>' | xargs kill 2>/dev/null; sleep 0.5` to clear stragglers.

#### BusyBox `nslookup` doesn't support custom ports `ACTIVE` (tooling gotcha)
- **Symptom**: `BusyBox nslookup google.com 127.0.0.1 5354` → `invalid number 'ort=5354'`.
- **Fix**: Use `dig -p <port>` from your workstation, or pipe into Python on the router for DNS tests. Memory: `feedback_router_busybox_limits.md`.

#### BusyBox `nc` has no `-z` or `-w` `ACTIVE` (tooling gotcha)
- **Fix**: Use `curl -sf -o /dev/null --max-time 1 -w '%{time_connect}' tcp://<ip>:<port>` for TCP reachability/latency from the router.

#### BusyBox `date` has no nanoseconds `ACTIVE` (tooling gotcha)
- **Fix**: Don't use `date +%N` on the router. For latency measurement use `curl -w '%{time_connect}'`.

### Frontend polish

#### Various `DeviceRow` / `DeviceListItem` cleanups `ACTIVE`
- See §Devices above — covered by the `DeviceListItem.svelte` consolidation.

---

## Invariants — one-line rules

Paste-ready reminders to skim before acting on the router.

### Router interaction
- **Use `firewall reload`, never `firewall restart`** — restart re-runs `rtp2.sh` and kills our tunnels.
- **`vpn-client restart` flushes every `src_mac_*` ipset.** Proton-wg is safe because it's on `pwg_mac_*`.
- **Don't use the `src_mac_*` prefix for anything new.** That's vpn-client's namespace.
- **`uci del_list` is case-sensitive.** Read the exact stored token before deleting.
- **Mangle rules must be created AFTER `firewall reload`.** Otherwise fw3 wipes them.
- **fw3 silently ignores zones with names > 11 chars** and UCI `hash:mac` ipsets. Always `firewall reload 2>&1` and read warnings.
- **A firewall include with `reload='1'` re-runs on every firewall reload.** `reload='0'` runs only on `firewall start`. Our includes are all `reload='1'`.

### Proton-wg
- **`killall proton-wg` kills every proton-wg tunnel.** Always target by iface via `/proc/<pid>/environ`.
- **`.macs` files are the source of truth.** Kernel ipsets are rebuilt from them by the mangle_rules.sh firewall include.
- **Don't rebuild mangle rules for tunnels whose iface is down.** DNS REDIRECT would point at a dead per-tunnel dnsmasq.
- **`_next_tunnel_id` must scan route_policy AND ipsets AND `.env` files.** Missing one causes collisions.

### DNS
- **Main dnsmasq uses `conf-dir=/tmp/dnsmasq.d`** on Flint 2 — `/etc/dnsmasq.d/` is ignored.
- **`ipset=` directives in dnsmasq need a full restart**, not SIGHUP, to take effect.
- **`killall -HUP dnsmasq` works for hosts file changes** but not for removing `addn-hosts` entries that came from deleted conf-dir files — those need a full restart.
- **Proton-wg DNS port = `2000 + (mark >> 12) * 100 + 53`** → 2653, 2753, 2953, 3553.

### BusyBox tooling
- No `nc -z / -w`. No `date +%N`. No `nslookup -p`. Use `curl -sf --max-time N` for port/latency tests.

### Backup / profile store
- **Router backup is unconditional source of truth on unlock.** No fingerprinting, no timestamp comparison.
- **If you edit `profile_store.json` on disk, force a save through the API** (PUT any profile) to push the corrected backup to the router.

### Testing
- **Module-level globals (`_save_callback`) and `FileHandler`s at import time leak between tests.** Use autouse fixtures in `tests/conftest.py` to reset them.
- **`@patch` decorators without `.return_value` produce truthy MagicMocks** that silently fire log branches.
- **Don't patch entire modules (`patch("pkg.time")`).** Patch specific attributes (`patch("pkg.time.time")`).
- **When patching a lazily-imported symbol, patch at the definition module** (e.g. `router.tools.wg_show.parse_handshake_age`), not the caller.
- **E2E tests need deterministic state between projects.** If one project unlocks, later ones rely on that state — don't add a test that re-locks without restoring.

### General debugging
- **Read `firewall reload 2>&1` warnings** — fw3 is silent about invalid rules.
- **`try: ... except Exception: log.warning("...")` hides Python NameErrors** as infrastructure failures. Log `repr(e)`.
- **If DNS works for some MACs but not others, check ipsets and `conntrack -L | grep <ip>`** for [UNREPLIED] entries.
- **Before starting anything on a port, `netstat -tlnup | grep :<port>`** to check who's already there.
- **Orphan `@rule[N]` after GL.iNet UI edits**: `uci rename route_policy.@rule[N]=fvpn_rule_XXXX`. Self-healing also runs on unlock.

---

## References

- [docs/router-features-translation.md](router-features-translation.md) — feature → router artifact mapping
- [docs/router-reference.md](router-reference.md) — naming, limits, MediaTek constraints
- [docs/source-of-truth.md](source-of-truth.md) — state-ownership rules
- [docs/proton-wg-internals.md](proton-wg-internals.md) — proton-wg non-obvious constraints
- [docs/server-switch-internals.md](server-switch-internals.md) — hot-swap vs teardown mechanics
- [docs/smart-protocol.md](smart-protocol.md) — protocol fallback details
