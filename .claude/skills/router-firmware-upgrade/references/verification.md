# Post-upgrade verification & fixes

Order matters: router-level checks first (app stopped), then the app.

## 1. Automated router checks

```bash
.claude/skills/router-firmware-upgrade/scripts/verify.sh            # read-only, PASS/WARN/FAIL per item
.claude/skills/router-firmware-upgrade/scripts/snapshot.sh ~/flint-router-backups/<date>-post-<ver>
diff -r ~/flint-router-backups/<pre> ~/flint-router-backups/<post>   # skip the .tar.gz files
```

Most informative diffs: `ip-rules.txt`, `iptables.txt` (chain names GL uses), `ubus-list.txt`,
`kmods.txt` (dns_mark / mt_wifi still loaded), `opkg-installed.txt`, and the GL scripts
(`tar xzf gl-scripts.tar.gz` in both, then diff `etc/init.d/vpn-client` and `usr/bin/rtp2.sh` —
changes there are the most likely source of subtle routing breakage).

## 2. Fix recipes for FAILs

| FAIL | Why it matters | Fix |
|---|---|---|
| Platform checks (21.02 / 5.4 / fw3 / legacy iptables) | Whole firewall layer assumes these | Wrong image (OP24/OP25 beta?). Roll back to stable. Don't try to patch. |
| `sysupgrade.conf keeps ...` | Next upgrade would lose app files | Re-append the "Flint VPN Manager custom paths" block (see snapshot `sysupgrade.conf.txt`). |
| `/usr/bin/proton-wg` missing | All WG-TCP/TLS groups dead | Restore from snapshot: `tar xzf fvpn-files.tar.gz usr/bin/proton-wg`, then `ssh root@192.168.8.1 'cat > /usr/bin/proton-wg && chmod +x /usr/bin/proton-wg' < usr/bin/proton-wg` (no sftp → no plain scp). |
| `profile_store.bak.json` missing | **Don't unlock the app yet** — unlock with no backup wipes the local store and pushes the empty store back (`backup_service.py`). Restore the file from the snapshot first. |
| proton-wg `.conf` missing | Profile becomes a ghost; recreating issues new Proton keys | Restore `/etc/fvpn/protonwg/` from the snapshot. |
| `fvpn-protonwg` / `fvpn-eth-watchdog` not enabled | proton-wg tunnels don't start at boot | `/etc/init.d/fvpn-protonwg enable; /etc/init.d/fvpn-eth-watchdog enable` |
| firewall include script missing | Rules silently absent after reboot | Unlock the app (re-writes lan_access, bypass, pwg mangle, noint is only rewritten if its UCI include is missing → restore `/etc/fvpn/noint_rules.sh` from snapshot). Adblock include is only rewritten on a profile edit → toggle adblock on a group off/on. |
| Package missing | Feature broken (e.g. bypass-by-domain needs dnsmasq-full) | `opkg update && opkg install <pkg>` |
| `firewall.vpnclient reload != 0` | `firewall reload` would re-run rtp2.sh → app's safe-reload assumption broken | Stop. Re-read `docs/internals/proton-wg-internals.md`; don't run the app until understood. |
| dns_mark / gl-clients / chains missing | GL changed internals → app logic needs porting | Diff GL scripts pre/post; record findings in upgrade-log.md; fix code. |
| `cfg01411c` dnsmasq conf missing | Adblock on main instance writes to wrong path (`adblock.py` hardcodes it) | `ls /var/etc/dnsmasq.conf.*`, update the hardcoded name (better: discover it dynamically). |
| `BssidNum < wifi-ifaces` / SSID not up | Extra SSIDs (ArmG, ArmI + IoT devices) don't broadcast | `sed -i 's/^BssidNum=.*/BssidNum=<n>/'` on both `mt7986-ax6000.dbdc.b{0,1}.dat`, then full driver reload (`wifi down; rmmod mtk_warp_proxy; rmmod mt_wifi; insmod mt_wifi; insmod mtk_warp_proxy; wifi up`, see router-reference.md). The boot-time `mtk-wifi-configurator` (Lua) also touches BssidNum — check whether it self-healed first. |

## 3. App-level checks (after router checks pass)

1. Start the app (CLAUDE.md "Restart server"), unlock (`flint_unlock`).
2. `flint_list_groups`: every VPN group that was green before is green; `router_info` unchanged
   (same `peer_id`, `tunnel_id`, `rule_name`).
3. `flint_list_devices`: device→group assignments match the pre snapshot (`uci-route_policy.txt`
   `from_mac` lists, `/etc/fvpn/protonwg/*.macs`).
4. `flint_list_networks`: ArmM/ArmG/ArmI present, access rules + exceptions unchanged.
5. From a device in a VPN group: public IP is the Proton exit; kill switch holds when the
   tunnel is disconnected (disconnect a test group, confirm no internet, reconnect).
6. Adblock: a blocked domain resolves to `0.0.0.0` from an adblock group device.
7. `pytest tests/` still green (no router needed, but catches nothing firmware-specific — the
   live checks above are the real test).
