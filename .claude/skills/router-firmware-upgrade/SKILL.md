---
name: router-firmware-upgrade
description: Runbook for upgrading the GL.iNet Flint 2 (GL-MT6000) router firmware without breaking Flint VPN Manager — pre-upgrade snapshot and backups, sysupgrade keep-list, choosing the right image, keep-settings vs clean install, post-upgrade verification of every GL.iNet internal the app depends on (vpn-client, route_policy, rtp2.sh, dns_mark.ko, gl-clients ubus, fw3/iptables), restore and rollback. Use this whenever the user mentions upgrading, updating, flashing, reflashing, factory-resetting or rolling back the router/Flint 2/GL.iNet firmware, a new GL.iNet release (4.x, OP24/OP25), or when the app breaks right after a firmware change — even if they don't say "skill" or "runbook".
---

# Router firmware upgrade (Flint 2)

The app drives undocumented GL.iNet internals over SSH, so a firmware upgrade can silently break
routing for every device on the LAN. This runbook keeps the upgrade reversible and makes the
breakage visible fast. The **live log of the current/last upgrade** is in
`references/upgrade-log.md` — read it first, and append to it as you work (findings, decisions,
fixes, open items). That log is how the next upgrade benefits from this one.

Read `CLAUDE.md` → "Router Interaction Safety Rules" before touching the router. Those rules apply
during the upgrade too (never `network restart`, `firewall restart`, `ifup/ifdown`, `conntrack -D`).

## 0. Pick the right image

- Use the **stable** channel for `mt6000` from https://dl.gl-inet.com/router/mt6000/ .
- Stock GL firmware is built on the closed MTK SDK and stays on **OpenWrt 21.02 / kernel 5.4 /
  fw3 + iptables**. The app's firewall layer (fw3 includes, `iptables-save` sweeps, `firewall reload`
  semantics, mangle MARK rules) assumes exactly that.
- **Do not install the OP24/OP25 beta branches** (OpenWrt 24/25, kernel 6.x, fw4/nftables). They are
  a different platform: fw3 includes, `rtp2.sh`, `dns_mark.ko` and the vpn-client stack would all need
  re-verification and likely a port. Treat that as a project, not an upgrade.
- Before flashing, skim the GL forum thread for the release (`forum.gl-inet.com`, "Flint 2 firmware
  X.Y") for regressions relevant to this setup (WAN is DHCP on `eth1`; WG/OVPN policy routing; WiFi).

## 1. Pre-upgrade (all read-only, safe any time)

1. Confirm health first — a broken baseline makes post-upgrade diffs meaningless:
   `scripts/verify.sh` must be all PASS (WARNs explained), plus `flint_list_groups` /
   `flint_list_devices` look right. Note any pre-existing reds in the upgrade log so they aren't
   blamed on the new firmware later.
2. Snapshot the router (script streams over ssh — the router has no `sftp-server`, so `scp` fails;
   use `scp -O` if you ever need scp):
   ```bash
   .claude/skills/router-firmware-upgrade/scripts/snapshot.sh ~/flint-router-backups/$(date +%F)-pre-<target>
   ```
   Output holds secrets (WiFi PSKs, WG private keys) → lives in `~/flint-router-backups/`, never in the repo.
3. Check the keep-list. `/etc/sysupgrade.conf` must list everything the app put outside `/etc/config`:
   `/etc/fvpn/`, `/etc/init.d/fvpn-protonwg`, `/etc/init.d/fvpn-eth-watchdog`, their `/etc/rc.d/` links,
   `/etc/sysctl.d/99-fvpn*.conf`, `/etc/sysctl.d/99-disable-ipv6.conf`, `/usr/bin/proton-wg`.
   Verify with `ssh root@192.168.8.1 'sysupgrade -l' | grep -E 'fvpn|proton'`.
   `/usr/bin/proton-wg` is the critical one — it is not part of any package and is not
   re-downloadable automatically.
   Known gap: the WiFi driver files `/etc/wireless/mediatek/mt7986-ax6000.dbdc.b{0,1}.dat` (the app
   bumps `BssidNum` when it creates networks) are **not** kept. That's deliberate — new firmware may
   ship new driver params — so it's handled as a post-upgrade check instead.
4. Check packages that aren't in the ROM (`opkg-added-beyond-rom.txt` in the snapshot). Sysupgrade
   replaces the rootfs, so anything installed with `opkg` is gone afterwards. The app needs
   `dnsmasq-full`, `ipset`, `kmod-veth`, `kmod-tun`, `openvpn-openssl`, `wireguard-tools` — all in ROM
   on 4.9.0; re-check on new versions.
5. Copy `profile_store.bak.json` off the router (it's in the snapshot's `fvpn-files.tar.gz`). It is
   the app's source of truth — losing it means the app starts from an empty store.

## 2. Keep settings vs clean install

- **Default: keep settings.** The app's state (UCI sections `fvpn_*`, `/etc/fvpn/`, ipset `.macs`
  files, profile_store backup) only survives with keep-settings. GL forum staff often advise clean
  installs for bug reports — that advice targets GL features, not our custom state.
- **Clean install only as a fallback** if the kept-settings upgrade misbehaves. Then restore by:
  re-enabling SSH key (docs/router-setup.md), restoring `/usr/bin/proton-wg` + `/etc/fvpn/` from the
  snapshot, then letting the app re-provision on unlock. Expect to re-create networks/SSIDs.
- **Rollback**: flashing the previous stable (e.g. 4.9.x) via GL UI or U-Boot recovery
  (hold reset at power-on → http://192.168.1.1) is always possible.

## 3. Flash

The user flashes (GL admin UI → Upgrade → Local/Online upgrade, **Keep Settings checked**) — it
cuts internet for the whole LAN for several minutes, so it's their call when. Stop the app first
so background threads (auto-optimizer, smart protocol, health) don't fire SSH commands at a
half-booted router. The app runs as a systemd unit that auto-restarts, so:
`sudo systemctl stop flint-vpn-manager.service` (start it again after verification). Don't use
`pkill -f "python backend/app.py"` from a tool shell — the pattern matches the shell's own command
line and kills it.

After the restart the app is **locked**; the user has to unlock it (the master password isn't
available to Claude).

## 4. Post-upgrade verification

With the app still stopped:
1. `scripts/verify.sh` — read-only PASS/WARN/FAIL over every artifact and GL internal the app relies
   on (platform, kept files, packages, vpn-client/rtp2/dns_mark/gl-clients, ip rules, iptables chains,
   WG handshakes, WiFi BssidNum + SSIDs).
2. `scripts/snapshot.sh` into `...-post-<target>` and diff against the pre snapshot.
3. Fix FAILs using the table in `references/verification.md` §2. One trap deserves a mention here:
   if `/etc/fvpn/profile_store.bak.json` is missing, **do not unlock the app** — unlock with no backup
   wipes the local store and pushes the empty store back to the router. Restore the file first.
4. Only then start the app, unlock, and run the app-level checks in `references/verification.md` §3.

If a check in verify.sh turns out to be wrong for the new firmware (internal moved, not broken),
fix the check and record why in the upgrade log.

Also diff GL's own scripts between the snapshots — new firmware features often land as new UCI
sections the app's code makes assumptions about (4.11's mesh added 5G wifi-ifaces and broke the
app's one-BssidNum-for-both-radios logic). For each new/changed thing, ask "which app code path
assumes the old shape?" — grep the facades for the section type / file / chain name:
```bash
cd ~/flint-router-backups; for d in <pre> <post>; do mkdir -p /tmp/gl-$d; tar xzf $d/gl-scripts.tar.gz -C /tmp/gl-$d; done
diff -ru /tmp/gl-<pre> /tmp/gl-<post>        # rtp2.sh / vpn-client / firewall.* changes
diff <pre>/uci-wireless.txt <post>/uci-wireless.txt   # same for network, firewall, route_policy
```

## 5. Close out

- Update `CLAUDE.md` → Environment → firmware version, and any doc whose facts changed.
- Append the outcome to `references/upgrade-log.md`.
