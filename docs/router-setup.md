# Router setup

One-time setup on the GL.iNet Flint 2 (GL-MT6000) before running Flint VPN Manager against it.

## 1. Enable SSH + install your public key

The router needs to accept root login via SSH key. Easiest path is to use the GL.iNet UI to enable SSH, then copy your host's public key to the router's authorized-keys file.

In the GL.iNet admin UI: **System → Advanced Settings → LuCI → System → Administration**. Confirm SSH is enabled (it is by default) and that PubkeyAuthentication is on.

From the host:

```bash
ssh-copy-id -i ~/.ssh/id_ed25519.pub root@192.168.8.1
# Then verify:
ssh root@192.168.8.1 "echo connected"
```

If `ssh-copy-id` isn't available, paste your public key manually into `/etc/dropbear/authorized_keys` on the router (Dropbear, not OpenSSH, on OpenWrt).

## 2. Install proton-wg

Kernel WireGuard over UDP is fast but some restrictive networks (public WiFi, corporate networks, certain ISPs) block it. `proton-wg` is ProtonVPN's userspace WireGuard-over-TLS helper that makes traffic look like ordinary HTTPS.

Installing it is **optional** — if you only need kernel WG and OpenVPN, you can skip this step. The app will simply refuse to create WG-TCP/TLS profiles until the binary is present.

The binary is distributed by ProtonVPN — check your Proton subscriber area or ProtonVPN's developer resources for the Linux ARM64 build targeting MediaTek Filogic 880. Place it on the router:

```bash
scp proton-wg root@192.168.8.1:/usr/bin/proton-wg
ssh root@192.168.8.1 "chmod +x /usr/bin/proton-wg && proton-wg --version"
```

The app manages the rest — config generation, mangle rules, per-tunnel dnsmasq, tunnel ID allocation — automatically when you create a WG-TCP/TLS profile.

See [internals/proton-wg-internals.md](internals/proton-wg-internals.md) for non-obvious constraints if you're debugging proton-wg behaviour.

## 3. (Optional) Install adblock packages

For the built-in per-group DNS ad-blocker:

```bash
ssh root@192.168.8.1 "opkg update && opkg install adblock-fast dnsmasq-full"
```

`dnsmasq-full` replaces the default `dnsmasq-mini` and is required for the `ipset=` directive used by VPN Bypass domain rules. `adblock-fast` is the upstream package the project integrates with.

Without these packages, the app's adblock and VPN-bypass-by-domain features won't work; everything else does.

---

## Verify the setup

A quick sanity check before launching the app:

```bash
# SSH key auth works
ssh root@192.168.8.1 "echo ok"

# Router firmware version
ssh root@192.168.8.1 "cat /etc/openwrt_release | grep VERSION"

# proton-wg present (if installed)
ssh root@192.168.8.1 "proton-wg --version"

# adblock + dnsmasq-full present (if installed)
ssh root@192.168.8.1 "opkg list-installed | grep -E '(adblock-fast|dnsmasq-full)'"
```

If all of the above succeed, you're ready to run the app. See [installation.md](installation.md).
