# Upgrade log

Newest first. Append findings, decisions and fixes as they happen — this is the memory that makes
the next upgrade faster.

---

## 4.9.0 → 4.11.0 (stable) — started 2026-11-18 — STATUS: flashed + router verified; waiting for app unlock + app-level checks

### Post-upgrade (flashed by user ~11:33, Keep Settings on)
- **The app kept running during the flash** (it's a systemd unit `flint-vpn-manager.service` that
  auto-restarts, so `pkill` alone doesn't stop it). Only harmless SSH connect errors in the log.
  Stop it with `sudo systemctl stop flint-vpn-manager.service`. Also: `pkill -f "python backend/app.py"`
  kills the calling shell too (its own command line matches) → use `pkill -f "venv/bin/python backend/app.py"`.
- After restart the app comes up **locked** → the user unlocks it (master password isn't stored anywhere Claude can read).
- `verify.sh`: 65 PASS, 1 FAIL → the FAIL was a **wrong check**, not breakage: 4.11 Mesh added
  `bbss5g` (AP, rax3, disabled) and `bsta5g` (STA, apclix0, disabled) on 5G. The firmware itself
  raised the 5G `BssidNum` to 5 (boot-time mtk-wifi-configurator self-heals from UCI). The check now
  counts AP-mode ifaces only and covers the highest index → 66/0/0.
- **Real upgrade-caused app bug found + fixed**: `lan_access.create_network/delete_network` used the
  5G `BssidNum` for both radios (sed + `ra<N>`/`rax<N>`). On 4.11 that would have given a new network
  `ra5` on a 4-slot 2.4G radio (2.4G SSID never comes up) and left 2.4G's BssidNum unchanged. Now
  per radio from UCI: lowest free index, `BssidNum = max(#AP ifaces, max index + 1)`. Tests use the
  real 4.11 layout. 1063 backend tests green.
- All tunnels handshook after boot (wgclient1-4 + protonwg0). ip rules, route_policy, ipsets, ubus:
  identical set (order only). `vpn-client` init identical. `rtp2.sh` changed: router-local OUTPUT
  policy only (process_gid DROP → new `VPN_LOCAL_POLICY_DROP` chain, `output_vpn_bypass_{tcp,udp}_ports`
  ipsets for wg/ovpn *server* ports, DNS port 5453 connmark). No change to MAC-based forwarding
  policy, fwmarks, tables, or `firewall.vpnclient reload=0` → no app impact.
- New packages: mesh (prplmesh, gl-sdk5-mesh, amx/usp libs), upnp (miniupnpd-iptables), vlan,
  network-quality, security-scan, `bash`, `iw`, `fping`, `ebtables`. Removed: gl-sdk4-lan, ssmtp,
  some UI plugins. None used by the app.
- Docs updated: firmware version in CLAUDE.md / installation.md / project-overview.md;
  BssidNum rules in router-reference.md + router-features-translation.md §17.
- Open risk: 5G will need `BssidNum=6` once the Work network is added — >5 unverified on MT7986.
  Option: delete the disabled legacy GL `iot` network (iot2g/iot5g, duplicate ra2/rax2 ifnames) to
  free a slot on each radio.

### Facts established
- Router was on **4.9.0** (CLAUDE.md said 4.8.4 — stale; fix at close-out).
- 4.11.0 stable (released 2026-09-28) stays on **OpenWrt 21.02-SNAPSHOT, kernel 5.4.238**, fw3/iptables.
  4.11.1 is incremental. The **OP25 beta** (OpenWrt 25, kernel 6.12, nftables) is a different
  platform — do not install.
- GL forum thread "Flint 2 firmware 4.11.0/4.11.1" regressions: PPPoE → clients lose internet / empty
  client list; WireGuard broken for one user after clean install; UI/SSH slow until a hard power-cycle.
  Several users rolled back to 4.9.1. Our WAN is **DHCP on eth1**, so the PPPoE issue shouldn't apply.
  Staff ask for clean installs when reporting bugs.
- `/etc/sysupgrade.conf` already had the app block (added 2026-07-02): `/etc/fvpn/`, both fvpn init
  scripts + rc.d links, `99-fvpn.conf`, `99-fvpn-bridge-nf.conf`, `99-disable-ipv6.conf`,
  `/usr/bin/proton-wg`, `/root/eth_recoveries.log`. `sysupgrade -l` confirms they're kept.
- **Not kept**: `/etc/wireless/mediatek/mt7986-ax6000.dbdc.b{0,1}.dat` (app set `BssidNum=4`, ROM
  has `1`). Decided NOT to add them to the keep-list (new firmware may ship new driver params);
  verify.sh checks BssidNum vs wifi-iface count post-upgrade instead. `/etc/init.d/mtk-wifi-configurator`
  (Lua bytecode, START=15) reads/writes BssidNum at boot — may self-heal; verify.
- No packages the app needs are outside ROM (`dnsmasq-full`, `ipset`, `kmod-veth`, `kmod-tun`,
  `openvpn-openssl`, `wireguard-tools` all ROM). Extras beyond ROM are GL-managed LuCI + netifyd.
  `adblock-fast` (docs/router-setup.md) is not installed and not needed.
- No OpenVPN groups exist → `/etc/openvpn/profiles/` not a concern this time.
- Router has no `sftp-server`: plain `scp` fails ("ash: /usr/libexec/sftp-server: not found").
  Use ssh pipes or `scp -O`.
- vpn-client ip rules live at **prio 6000** (`fwmark 0xN000/0xf000 lookup 100N`), kill switch at prio
  9910 blackhole, LAN at prio 50 → table 9910, bypass at prio 100 → table 1008.

### Pre-flight results
- Snapshot: `~/flint-router-backups/2026-11-18-pre-4.11.0/` (includes `sysupgrade -b` config backup).
- `verify.sh`: PASS=65 WARN=1 FAIL=0. WARN = `protonwg0` (Streaming group, 0 devices, already red
  before the upgrade) — pre-existing, not upgrade-related.

### Unrelated code issues spotted during the inventory (not fixed, not upgrade blockers)
- `proton_wg.py:712` uses `grep -oP` — BusyBox grep has no `-P`.
- `_rebuild_ipv6_mangle_rules` computes vpn-client mark as `0x1000 + tunnel_id` (`proton_wg.py:944-947`);
  live marks are `0x1000..0x5000` → likely wrong for tunnel_id ≥ 300.
- `/tmp/dnsmasq.d/fvpn_bypass.conf` is only rewritten on unlock — domain bypass is lost after a
  router reboot until the app unlocks.
- Docs drift: router-features-translation.md §1/§16/§27 (see agent inventory).

### Next
1. User: GL UI → Upgrade → 4.11.0 stable, **Keep Settings ON**. Stop the app first.
2. Post: `verify.sh`, post snapshot + diff, app-level checks (references/verification.md §3).
3. Close-out: CLAUDE.md firmware version → 4.11.0; update this log's STATUS.
