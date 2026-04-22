---
name: flint-vpn-manager
description: Debug, inspect, or modify a GL.iNet Flint 2 (GL-MT6000) router running Flint VPN Manager — ProtonVPN WireGuard/OpenVPN/proton-wg tunnels, device-to-VPN assignments, LAN networks and zones, adblock, kill switch, VPN bypass exceptions, mangle/ipset routing, and related OpenWrt/UCI/firewall state. Use whenever the user mentions their Flint router, a VPN tunnel being up/down/slow, a specific device not reaching the internet, ipsets, fwmarks, route_policy, UCI config, proton-wg, wg show, dnsmasq blocklist, NoInternet groups, zone forwarding rules, adblock, or any router/firewall symptom — even if they don't explicitly name the router or Flint VPN Manager.
---

# Flint VPN Manager Operations & Debugging

A skill for Claude sessions working with a GL.iNet Flint 2 router that runs [Flint VPN Manager](https://github.com/armaaar/flint-vpn-manager). There are two ways to operate the router: the **Flint VPN Manager MCP server** (preferred) and **raw SSH** (fallback). This skill tells you which to use, and gives you enough router-level knowledge to debug issues without needing the Flint VPN Manager repo open.

## What you can assume

- **The router**: GL.iNet Flint 2 (GL-MT6000), OpenWrt-based firmware ~4.8.x. Default LAN address is `192.168.8.1`. The actual address may differ — check the user's `config.json` (field `router_ip`) or ask them.
- **The management app**: Flint VPN Manager — a Flask+Svelte app running on a Linux host on the user's LAN. It manipulates the router over SSH and manages ProtonVPN tunnels (WG UDP via vpn-client, WG TCP/TLS via proton-wg, OpenVPN via vpn-client), device assignments, LAN networks, adblock, VPN bypass exceptions, and more. REST API on port `5000` by default.
- **SSH access**: Root login via an SSH key. Every SSH example in this skill uses `ssh root@192.168.8.1 '<command>'`; substitute the user's actual IP if different.

If the user is asking about *their* router, *their* VPN, or anything touching a GL.iNet Flint and ProtonVPN, it's almost certainly this stack. Don't assume it's a generic OpenWrt question.

## The MCP-first rule

Before touching the router with raw SSH, check whether the Flint VPN Manager MCP tools are loaded in this session. You can recognise them by the `mcp__flint-vpn-manager__flint_*` prefix — e.g. `flint_get_status`, `flint_list_groups`, `flint_connect`, `flint_assign_device`.

**If MCP tools are available**, prefer them for anything they cover — they're the supported API surface, they handle unlock, and they won't accidentally do something dangerous. Typical flow:

1. `flint_get_status` — check if the app is locked or unlocked.
2. If locked, `flint_unlock` with the master password. **Ask the user for the password** — don't assume it's stored anywhere in your context.
3. Use `flint_list_groups`, `flint_list_devices`, `flint_list_networks`, `flint_get_status`, `flint_list_logs`, etc. for reads.
4. Use `flint_connect`, `flint_disconnect`, `flint_switch_server`, `flint_assign_device`, `flint_update_settings`, etc. for writes.

See `references/mcp-tools.md` for a full catalog, what each tool does, and which tasks MCP can *not* do (so you know when to fall back to SSH).

**If MCP tools are not available**, you can still do anything — you just need SSH. But if the user is asking you to *operate* the app (connect a tunnel, create a group, change a setting), and MCP isn't loaded, say so and ask whether they want to start the MCP server, use SSH directly, or hit the REST API on `http://localhost:5000`.

## When SSH is the right tool

MCP covers the app's business operations. It doesn't cover low-level router state that you need when diagnosing *why* something's broken. Use SSH directly for:

- Reading `iptables` / `ip6tables` rules (mangle chain order, jump targets, counters).
- Inspecting `ipset` membership, especially `pwg_mac_*`, `src_mac_*`, `fvpn_noint_macs`, `fvpn_byp_*`.
- Checking `ip route show table <N>`, `ip rule show`, `wg show`, `ifstatus`.
- Reading files under `/etc/fvpn/`, `/etc/config/`, `/tmp/dhcp.leases`, `/tmp/dnsmasq.d*/`, `/var/log/openvpn/*.log`, `/tmp/protonwg*.log`.
- Running `logread`, `conntrack -L`, `ubus call …`, `iwinfo`.
- Any UCI operation the MCP surface doesn't expose (`uci show firewall`, `uci show wireless`, etc.).

All of these are **read-only** and safe. Examples in `references/debug-recipes.md`.

## Non-negotiable safety invariants

These rules aren't arbitrary — every one was learned from a real bug that broke something. Violate them at your peril.

1. **Never run `/etc/init.d/firewall restart`.** Always `reload`. Restart re-runs GL.iNet's `rtp2.sh` include, which tears down Flint VPN Manager's WireGuard interfaces and corrupts active handshakes. `reload` re-runs the app's own firewall-include scripts (`reload='1'`) but leaves `rtp2.sh` alone (`reload='0'`), so tunnels survive.
2. **Never `killall proton-wg`.** It kills every proton-wg tunnel (they share one binary). Target a specific process by its `PROTON_WG_INTERFACE_NAME` env var in `/proc/<pid>/environ`. See `references/debug-recipes.md`.
3. **Never use the `src_mac_*` ipset prefix for anything new.** That namespace belongs to GL.iNet's `vpn-client`, which globs and flushes every `src_mac_*` on `/etc/init.d/vpn-client restart`. The app's proton-wg uses `pwg_mac_*` specifically to avoid that blast radius.
4. **`/etc/init.d/network restart` will brick the LAN.** Same for `ifup` / `ifdown` on production interfaces. If you need to poke an interface, use `ubus call network.interface.<name> up` — scoped, safe, doesn't flush the world.
5. **UCI `del_list` is exact-string matching — case matters.** Read the stored token first (`uci get <path>.from_mac`) and delete using exactly that case. GL.iNet's UI writes uppercase MACs; the app writes lowercase. Mixing them looks like it worked but silently no-ops.
6. **fw3 silently ignores zone names > 11 characters and `hash:mac` ipsets defined via UCI.** No error, no warning — just no rules. If a firewall rule doesn't seem to take effect, run `/etc/init.d/firewall reload 2>&1` and read the warnings. fw3 is mute about invalid configs unless you look.
7. **The router backup at `/etc/fvpn/profile_store.bak.json` is the unconditional source of truth** for the app's profile store. On unlock, local state is overwritten from the router. If you edit `profile_store.json` locally on the host, push the change through the API (PUT any profile) so it backs up to the router — don't expect local edits to survive a restart otherwise.

More invariants in `references/gotchas.md`.

## Where to look for what

| You're dealing with… | Load reference |
|---|---|
| Understanding what a specific ipset / UCI section / fwmark means | `references/router-layout.md` |
| Figuring out which SSH commands are safe to run | `references/safe-commands.md` |
| A specific symptom (device has no internet, tunnel stuck, adblock broken…) | `references/debug-recipes.md` |
| A "wait, this is surprising" moment (rule doesn't take effect, MAC case, MediaTek WiFi) | `references/gotchas.md` |
| Which MCP tool to use for a given operation | `references/mcp-tools.md` |

You don't need to read all references up-front — read them when the user's question gets specific enough that you need the detail.

## Standard operating procedure

For any non-trivial router question:

1. **State what you think is happening.** One sentence. This forces you to have a hypothesis before running commands and helps the user correct you early if you've misunderstood.
2. **If MCP is available and the question is about app-level state (profiles, tunnels, devices, settings), start there.** `flint_get_status` + the relevant list tool is usually enough to confirm or rule out the hypothesis in one or two calls.
3. **If the question is about router-level state (routing, firewall, ipsets, files, DNS), SSH in read-only mode first.** `uci show`, `ipset list`, `iptables -L`, `wg show`, `cat /etc/fvpn/…`. Never mutate state just to check it.
4. **Before any mutation**, confirm with the user unless they've already explicitly authorised it. This is especially true for anything involving `firewall reload`, `vpn-client restart`, `wifi` operations, or config deletion.
5. **Report back with concrete evidence.** Quote UCI keys, ipset members, fwmark values, log lines. "I looked and it's fine" is useless; "`ip rule show | grep 0x6000` returns no entry, and `/etc/fvpn/protonwg/protonwg0.env` has `FVPN_MARK=0x6000` — so the ip rule is missing" is actionable.

## One-liner snapshot command

When you need a comprehensive view of router state in one shot:

```bash
ssh root@192.168.8.1 '
echo "=== route_policy ==="; uci show route_policy
echo "=== fvpn zones & includes ==="; uci show firewall | grep -E "fvpn_|include"
echo "=== wg show ==="; wg show
echo "=== ip rule ==="; ip rule show; echo "-- ipv6:"; ip -6 rule show
echo "=== mangle ROUTE_POLICY ==="; iptables -t mangle -L ROUTE_POLICY -n -v --line-numbers
echo "=== ipsets ==="; ipset list -n
echo "=== /etc/fvpn/ ==="; find /etc/fvpn -maxdepth 3 -type f
echo "=== proton-wg procs ==="; for p in $(pidof proton-wg 2>/dev/null); do echo "PID $p:"; cat /proc/$p/environ 2>/dev/null | tr "\0" "\n" | grep PROTON_WG; done
echo "=== DHCP leases ==="; cat /tmp/dhcp.leases
'
```

Use this as your first move when the user says "something's wrong with the router" without naming what.
