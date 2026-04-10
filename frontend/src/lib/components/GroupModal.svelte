<script>
  import { api } from '../api.js';
  import { profiles, showToast } from '../stores/app.js';
  import EmojiPicker from './EmojiPicker.svelte';
  import ColorPicker from './ColorPicker.svelte';
  import LanPeerPicker from './LanPeerPicker.svelte';
  import HelpTooltip from './HelpTooltip.svelte';
  import { createEventDispatcher } from 'svelte';

  /** For create mode: controls visibility. */
  export let visible = false;
  /** For edit mode: pass the profile to edit (null = create mode). */
  export let profile = null;
  /** Callback to open the server picker (create-VPN flow). */
  export let onNeedServer = null;

  const dispatch = createEventDispatcher();

  $: mode = profile ? 'edit' : 'create';
  $: isOpen = mode === 'edit' ? !!profile : visible;

  // Live-resolve from store so SSE pushes propagate in edit mode.
  $: liveProfile = profile ? ($profiles.find(p => p.id === profile.id) || profile) : null;

  const MAX_WG_GROUPS = 5;
  const MAX_OVPN_GROUPS = 5;
  const MAX_PWG_GROUPS = 4;

  // ── Form state ────────────────────────────────────────────────────────
  let type = 'vpn', name = '', icon = '🔒', color = '#00aaff', isGuest = false;
  let vpnProtocol = 'wireguard';
  let wgTcpTransport = 'tcp';
  let ovpnProtocol = 'udp';
  let killSwitch = true;
  let netshield = '2';
  let accelerator = true;
  let moderateNat = false;
  let natPmp = false;
  let portOverride = '';  // '' = default, or specific port number
  let customDns = '';     // '' = Proton DNS, or custom DNS IP
  let smartProtocol = false;
  let lanOutbound = 'allowed', lanInbound = 'allowed';
  let lanOutboundAllow = [];
  let lanInboundAllow = [];
  let error = '';
  let saving = false, deleting = false;

  // Edit-mode change detection
  let initialType = 'vpn';
  let initialProto = 'wireguard';
  let initialOptions = { killSwitch: true, netshield: '2', accelerator: true, moderateNat: false, natPmp: false, portOverride: '', customDns: '', smartProtocol: false };

  $: typeChanged = mode === 'edit' && type !== initialType;
  $: protocolChanged = mode === 'edit' && type === 'vpn' && vpnProtocol !== initialProto;
  // Reset port when protocol changes (port options differ per protocol)
  $: if (protocolChanged) portOverride = '';
  $: optionsChanged = mode === 'edit' && (
    netshield !== initialOptions.netshield ||
    accelerator !== initialOptions.accelerator ||
    moderateNat !== initialOptions.moderateNat ||
    natPmp !== initialOptions.natPmp ||
    portOverride !== initialOptions.portOverride ||
    customDns !== initialOptions.customDns ||
    smartProtocol !== initialOptions.smartProtocol
  );

  // ── Helpers ───────────────────────────────────────────────────────────
  const MAC_RE = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i;
  function rawListToEntries(raw) {
    return (raw || []).map(v => ({ value: v, type: MAC_RE.test(v) ? 'mac' : 'profile' }));
  }
  function entriesToRawList(entries) {
    return (entries || []).map(e => e.value);
  }

  // ── Protocol slot counts (exclude current profile in edit mode) ──────
  $: wgCount = $profiles.filter(p => p.type === 'vpn' && p.router_info?.vpn_protocol === 'wireguard' && p.id !== liveProfile?.id).length;
  $: pwgCount = $profiles.filter(p => p.type === 'vpn' && (p.router_info?.vpn_protocol || '').startsWith('wireguard-') && p.id !== liveProfile?.id).length;
  $: ovpnCount = $profiles.filter(p => p.router_info?.vpn_protocol === 'openvpn' && p.id !== liveProfile?.id).length;
  $: limitReached = type === 'vpn' && (
    (vpnProtocol === 'wireguard' && wgCount >= MAX_WG_GROUPS) ||
    (vpnProtocol === 'wireguard-tcp' && pwgCount >= MAX_PWG_GROUPS) ||
    (vpnProtocol === 'openvpn' && ovpnCount >= MAX_OVPN_GROUPS)
  ) && (mode === 'create' || protocolChanged);

  // ── Populate form ────────────────────────────────────────────────────
  let lastLoadedId = null;

  // Create mode: reset on open
  $: if (mode === 'create' && visible) resetForm();

  // Edit mode: load from profile
  $: if (mode === 'edit' && liveProfile && liveProfile.id !== lastLoadedId) {
    lastLoadedId = liveProfile.id;
    type = liveProfile.type || 'vpn';
    initialType = type;
    name = liveProfile.name;
    icon = liveProfile.icon;
    color = liveProfile.color;
    isGuest = liveProfile.is_guest || false;
    lanOutbound = liveProfile.lan_access?.outbound || 'allowed';
    lanInbound = liveProfile.lan_access?.inbound || 'allowed';
    lanOutboundAllow = rawListToEntries(liveProfile.lan_access?.outbound_allow);
    lanInboundAllow = rawListToEntries(liveProfile.lan_access?.inbound_allow);
    killSwitch = liveProfile.kill_switch === true;
    const opts = liveProfile.options || {};
    netshield = String(opts.netshield ?? '0');
    accelerator = opts.vpn_accelerator !== false;
    moderateNat = !!opts.moderate_nat;
    natPmp = !!opts.nat_pmp;
    portOverride = opts.port ? String(opts.port) : '';
    customDns = opts.custom_dns || '';
    smartProtocol = !!opts.smart_protocol;
    initialOptions = { killSwitch, netshield, accelerator, moderateNat, natPmp, portOverride, customDns, smartProtocol };
    // Protocol
    const curProto = liveProfile.router_info?.vpn_protocol || 'wireguard';
    if (curProto === 'wireguard-tls') { vpnProtocol = 'wireguard-tcp'; wgTcpTransport = 'tls'; }
    else if (curProto === 'wireguard-tcp') { vpnProtocol = 'wireguard-tcp'; wgTcpTransport = 'tcp'; }
    else { vpnProtocol = curProto; }
    initialProto = vpnProtocol;
    const serverProto = liveProfile.server?.protocol || '';
    ovpnProtocol = serverProto.endsWith('tcp') ? 'tcp' : 'udp';
    error = '';
  }
  $: if (!profile) lastLoadedId = null;

  function resetForm() {
    type = 'vpn'; name = ''; icon = '🔒'; color = '#00aaff'; isGuest = false;
    vpnProtocol = 'wireguard'; wgTcpTransport = 'tcp'; ovpnProtocol = 'udp';
    killSwitch = true; netshield = '2'; accelerator = true; moderateNat = false; natPmp = false;
    portOverride = ''; customDns = ''; smartProtocol = false;
    lanOutbound = 'allowed'; lanInbound = 'allowed';
    lanOutboundAllow = []; lanInboundAllow = [];
    error = '';
  }

  function onTypeChange() {
    if (mode === 'create') {
      const icons = { vpn: '🔒', no_vpn: '🌐', no_internet: '🚫' };
      icon = icons[type] || '🔒';
    }
    error = '';
  }

  function applyPreset(preset) {
    if (preset === 'open') { lanOutbound = 'allowed'; lanInbound = 'allowed'; }
    else if (preset === 'isolated') { lanOutbound = 'group_only'; lanInbound = 'group_only'; }
    else if (preset === 'locked') { lanOutbound = 'blocked'; lanInbound = 'blocked'; }
  }

  // ── Submit ────────────────────────────────────────────────────────────
  function buildVpnOptions() {
    const opts = {
      netshield: parseInt(netshield),
      vpn_accelerator: accelerator,
      moderate_nat: moderateNat,
      nat_pmp: natPmp,
    };
    if (portOverride) opts.port = parseInt(portOverride);
    if (customDns.trim()) opts.custom_dns = customDns.trim();
    if (smartProtocol) opts.smart_protocol = true;
    return opts;
  }

  function effectiveProtocol() {
    return vpnProtocol === 'wireguard-tcp' ? `wireguard-${wgTcpTransport}` : vpnProtocol;
  }

  async function submit() {
    if (!name.trim()) { error = 'Name required'; return; }
    if (limitReached) { error = 'Protocol limit reached. Try a different protocol or delete an existing group.'; return; }
    error = '';

    if (mode === 'create') {
      await doCreate();
    } else {
      await doEdit();
    }
  }

  async function doCreate() {
    if (type === 'vpn') {
      visible = false;
      if (onNeedServer) {
        const savedState = {
          lanOut: lanOutbound, lanIn: lanInbound,
          outAllow: entriesToRawList(lanOutboundAllow),
          inAllow: entriesToRawList(lanInboundAllow),
          opts: buildVpnOptions(), ks: killSwitch,
        };
        onNeedServer(async (serverId, _options, scope) => {
          const body = {
            name, type, color, icon, is_guest: isGuest,
            server_id: serverId, options: savedState.opts,
            vpn_protocol: effectiveProtocol(),
            ovpn_protocol: ovpnProtocol,
            server_scope: scope,
            kill_switch: savedState.ks,
          };
          const res = await api.createProfile(body);
          if (res.error) { showToast(res.error, true); return; }
          const hasLan = savedState.lanOut !== 'allowed' || savedState.lanIn !== 'allowed'
            || savedState.outAllow.length || savedState.inAllow.length;
          if (hasLan) {
            await api.setProfileLanAccess(res.id, {
              outbound: savedState.lanOut, inbound: savedState.lanIn,
              outbound_allow: savedState.outAllow, inbound_allow: savedState.inAllow,
            });
          }
          showToast(`Created ${icon} ${name}`);
          dispatch('reload');
        }, vpnProtocol);
      }
      return;
    }

    // Non-VPN create
    const res = await api.createProfile({ name, type, color, icon, is_guest: isGuest });
    if (res.error) { error = res.error; return; }
    const outAllow = entriesToRawList(lanOutboundAllow);
    const inAllow = entriesToRawList(lanInboundAllow);
    const hasLan = lanOutbound !== 'allowed' || lanInbound !== 'allowed' || outAllow.length || inAllow.length;
    if (hasLan) {
      await api.setProfileLanAccess(res.id, {
        outbound: lanOutbound, inbound: lanInbound,
        outbound_allow: outAllow, inbound_allow: inAllow,
      });
    }
    visible = false;
    showToast(`Created ${icon} ${name}`);
    dispatch('reload');
  }

  async function doEdit() {
    if (!liveProfile || saving) return;

    // Type change to VPN needs server selection — open ServerPicker
    if (typeChanged && type === 'vpn') {
      close();
      if (onNeedServer) {
        const savedState = {
          profileId: liveProfile.id, ks: killSwitch, opts: buildVpnOptions(),
          lanOut: lanOutbound, lanIn: lanInbound,
          outAllow: entriesToRawList(lanOutboundAllow),
          inAllow: entriesToRawList(lanInboundAllow),
        };
        onNeedServer(async (serverId, _options, scope) => {
          const res = await api.changeType(savedState.profileId, {
            type: 'vpn',
            vpn_protocol: effectiveProtocol(),
            server_id: serverId,
            options: savedState.opts,
            kill_switch: savedState.ks,
            server_scope: scope,
            ovpn_protocol: ovpnProtocol,
          });
          if (res?.error) { showToast(res.error, true); return; }
          // Apply LAN access after type change
          const hasLan = savedState.lanOut !== 'allowed' || savedState.lanIn !== 'allowed'
            || savedState.outAllow.length || savedState.inAllow.length;
          if (hasLan) {
            await api.setProfileLanAccess(savedState.profileId, {
              outbound: savedState.lanOut, inbound: savedState.lanIn,
              outbound_allow: savedState.outAllow, inbound_allow: savedState.inAllow,
            });
          }
          showToast('Changed to VPN group');
          dispatch('reload');
        }, vpnProtocol);
      }
      return;
    }

    saving = true;
    try {
      // 1. Type change (VPN → non-VPN, or non-VPN ↔ non-VPN)
      if (typeChanged) {
        showToast(initialType === 'vpn' ? 'Removing tunnel…' : 'Changing type…');
        const res = await api.changeType(liveProfile.id, { type });
        if (res?.error) { showToast(res.error, true); return; }
      }

      // 2. Metadata
      const update = { name, icon, color };
      if (type === 'vpn' && !typeChanged && killSwitch !== initialOptions.killSwitch) {
        update.kill_switch = killSwitch;
      }
      await api.updateProfile(liveProfile.id, update);
      if (isGuest) await api.setGuestProfile(liveProfile.id);

      // 3. LAN access
      await api.setProfileLanAccess(liveProfile.id, {
        outbound: lanOutbound, inbound: lanInbound,
        outbound_allow: entriesToRawList(lanOutboundAllow),
        inbound_allow: entriesToRawList(lanInboundAllow),
      });

      // 4. Protocol change (VPN → VPN, different protocol)
      if (type === 'vpn' && !typeChanged && protocolChanged) {
        showToast('Switching protocol…');
        const res = await api.changeProtocol(liveProfile.id, {
          vpn_protocol: effectiveProtocol(),
          options: buildVpnOptions(),
          server_scope: liveProfile.server_scope,
          ovpn_protocol: ovpnProtocol,
        });
        if (res?.error) { showToast(res.error, true); return; }
      } else if (type === 'vpn' && !typeChanged && optionsChanged && liveProfile.server?.id) {
        // 5. VPN options changed without protocol change — regenerate tunnel
        showToast('Regenerating tunnel with new options…');
        const res = await api.changeServer(liveProfile.id, {
          server_id: liveProfile.server.id,
          options: buildVpnOptions(),
          server_scope: liveProfile.server_scope,
        });
        if (res?.error) { showToast(res.error, true); return; }
      }

      close();
      showToast('Group updated');
      dispatch('reload');
    } finally {
      saving = false;
    }
  }

  async function deleteGroup() {
    if (!confirm(`Delete "${name}"? All devices will be unassigned.`)) return;
    deleting = true;
    await api.deleteProfile(liveProfile.id);
    deleting = false;
    close();
    showToast('Group deleted');
    dispatch('reload');
  }

  function close() {
    if (mode === 'create') { visible = false; }
    else { profile = null; }
    dispatch('close');
  }
</script>

{#if isOpen}
<div class="modal-overlay active" on:click|self={close}>
  <div class="modal">
    <div class="modal-header">
      <h2>{mode === 'create' ? 'Create Group' : 'Edit Group'}</h2>
      <button class="modal-close" on:click={close}>&times;</button>
    </div>
    <div class="modal-body">

      <!-- Group Type -->
      <div class="form-group">
        <label for="gm-type" class="required">Group Type</label>
        <select id="gm-type" bind:value={type} on:change={onTypeChange}>
          <option value="vpn">VPN — Route through ProtonVPN tunnel</option>
          <option value="no_vpn">No VPN — Direct internet (no tunnel)</option>
          <option value="no_internet">No Internet — LAN only, block WAN</option>
        </select>
        <div class="type-descriptions">
          {#if type === 'vpn'}
            <span class="hint">All device traffic routes through a ProtonVPN tunnel.</span>
          {:else if type === 'no_vpn'}
            <span class="hint">Devices route through your ISP directly. Useful for devices that break under VPN.</span>
          {:else}
            <span class="hint">Devices get a LAN IP but all internet access is blocked. Ideal for printers and local-only sensors.</span>
          {/if}
        </div>
        {#if typeChanged && initialType === 'vpn' && type !== 'vpn'}
          <div class="opt-warning">Saving will tear down the VPN tunnel. Devices stay assigned.</div>
        {/if}
      </div>

      <!-- VPN Protocol -->
      {#if type === 'vpn'}
      <div class="form-group">
        <label class="required">VPN Protocol</label>
        <div class="protocol-cards">
          <button type="button" class="protocol-card" class:selected={vpnProtocol === 'wireguard'}
                  on:click={() => vpnProtocol = 'wireguard'}>
            <div class="proto-name">WireGuard</div>
            <div class="proto-desc">Fastest speeds, lowest latency. UDP only. Best for most users.</div>
            <div class="proto-slots">{wgCount}/{MAX_WG_GROUPS} used</div>
          </button>
          <button type="button" class="protocol-card" class:selected={vpnProtocol === 'wireguard-tcp'}
                  on:click={() => vpnProtocol = 'wireguard-tcp'}>
            <div class="proto-name">WireGuard TCP</div>
            <div class="proto-desc">WireGuard over TCP/TLS. Bypasses firewalls that block UDP.</div>
            <div class="proto-slots">{pwgCount}/{MAX_PWG_GROUPS} used</div>
          </button>
          <button type="button" class="protocol-card" class:selected={vpnProtocol === 'openvpn'}
                  on:click={() => vpnProtocol = 'openvpn'}>
            <div class="proto-name">OpenVPN</div>
            <div class="proto-desc">Most compatible. Works on restricted networks.</div>
            <div class="proto-slots">{ovpnCount}/{MAX_OVPN_GROUPS} used</div>
          </button>
        </div>
        {#if limitReached}
          <div class="limit-error">Protocol limit reached. Try a different protocol or delete an existing group.</div>
        {/if}
      </div>

      {#if vpnProtocol === 'wireguard-tcp'}
      <div class="form-group">
        <label>WireGuard TCP Transport</label>
        <select bind:value={wgTcpTransport}>
          <option value="tcp">TCP (recommended)</option>
          <option value="tls">Stealth / TLS (looks like HTTPS, hardest to block)</option>
        </select>
        <span class="hint">Use Stealth in hotels, offices, or countries that actively detect and block VPN traffic.</span>
      </div>
      {/if}

      {#if vpnProtocol === 'openvpn'}
      <div class="form-group">
        <label>OpenVPN Transport</label>
        <select bind:value={ovpnProtocol}>
          <option value="udp">UDP (faster, recommended)</option>
          <option value="tcp">TCP (bypasses firewalls, slower)</option>
        </select>
      </div>
      {/if}

      {#if protocolChanged}
        <div class="opt-warning">Saving will switch the protocol and briefly disconnect the tunnel. Devices stay assigned.</div>
      {/if}

      <details class="protocol-help">
        <summary>When to use which protocol?</summary>
        <div class="help-content">
          <h4>WireGuard (Recommended)</h4>
          <ul>
            <li><strong>Speed:</strong> 2-4x faster than OpenVPN, runs in the kernel</li>
            <li><strong>Latency:</strong> Lower latency, ideal for gaming and video calls</li>
            <li><strong>CPU:</strong> Much lower resource usage on the router</li>
          </ul>
          <h4>WireGuard TCP</h4>
          <ul>
            <li><strong>Bypass firewalls:</strong> WireGuard speeds over TCP port 443</li>
            <li><strong>Stealth/TLS:</strong> Looks like normal HTTPS. Hardest to detect and block.</li>
            <li><strong>Tradeoff:</strong> Slightly higher latency (TCP overhead)</li>
          </ul>
          <h4>OpenVPN</h4>
          <ul>
            <li><strong>Compatibility:</strong> Widest device and network support</li>
            <li><strong>TCP mode:</strong> Port 443, hard to block</li>
            <li><strong>Fallback:</strong> Use when WireGuard doesn't connect</li>
          </ul>
        </div>
      </details>

      <!-- VPN Options -->
      <div class="vpn-options-section">
        <div class="section-header"><span class="section-title">VPN Options</span></div>
        <div class="form-group">
          <label for="gm-netshield" class="opt-label-with-help">
            NetShield
            <HelpTooltip title="NetShield">
              <p>Blocks ads, trackers, and malware at the DNS level. Use the highest level by default.</p>
            </HelpTooltip>
          </label>
          <select id="gm-netshield" bind:value={netshield}>
            <option value="0">Off</option>
            <option value="1">Malware</option>
            <option value="2">Malware + Ads + Trackers</option>
          </select>
        </div>
        <div class="option-item">
          <input type="checkbox" id="gm-killswitch" bind:checked={killSwitch}>
          <label for="gm-killswitch">
            Kill Switch
            <span class="opt-hint">— block traffic if the tunnel drops</span>
          </label>
          <HelpTooltip title="Kill Switch">
            <p>If the VPN drops, devices lose all internet instead of leaking through your ISP.</p>
          </HelpTooltip>
        </div>
        <div class="option-item">
          <input type="checkbox" id="gm-acc" bind:checked={accelerator}>
          <label for="gm-acc">
            VPN Accelerator
            <span class="opt-hint">— up to 400% faster (recommended)</span>
          </label>
          <HelpTooltip title="VPN Accelerator">
            <p>Proton's speed-tuning tweaks — same encryption, just faster.</p>
          </HelpTooltip>
        </div>
        <div class="option-item">
          <input type="checkbox" id="gm-mn" bind:checked={moderateNat}>
          <label for="gm-mn">
            Moderate NAT
            <span class="opt-hint">— better for gaming/P2P</span>
          </label>
          <HelpTooltip title="Moderate NAT">
            <p>Fixes "Strict NAT" issues with gaming consoles, voice/video calls, and P2P apps.</p>
          </HelpTooltip>
        </div>
        <div class="option-item">
          <input type="checkbox" id="gm-nm" bind:checked={natPmp}>
          <label for="gm-nm">
            NAT-PMP
            <span class="opt-hint">— UPnP-style port forwarding</span>
          </label>
          <HelpTooltip title="NAT-PMP (Port Forwarding)">
            <p>Lets apps inside the tunnel accept incoming connections. Turn on for torrent seeding or hosting.</p>
          </HelpTooltip>
        </div>
        <div class="form-group" style="margin-top:8px">
          <label for="gm-port" class="opt-label-with-help">
            Port
            <HelpTooltip title="Port Override">
              <p>Use a non-default port when your ISP blocks the standard VPN port. Leave as Default unless connections fail.</p>
            </HelpTooltip>
          </label>
          <select id="gm-port" bind:value={portOverride}>
            <option value="">Default</option>
            {#if vpnProtocol === 'wireguard'}
              {#each [443, 88, 1224, 51820, 500, 4500] as p}
                <option value={String(p)}>{p} UDP</option>
              {/each}
            {:else if vpnProtocol === 'wireguard-tcp'}
              <option value="443">443 TCP</option>
            {:else if vpnProtocol === 'openvpn' && ovpnProtocol === 'udp'}
              {#each [80, 51820, 4569, 1194, 5060] as p}
                <option value={String(p)}>{p} UDP</option>
              {/each}
            {:else if vpnProtocol === 'openvpn' && ovpnProtocol === 'tcp'}
              {#each [443, 7770, 8443] as p}
                <option value={String(p)}>{p} TCP</option>
              {/each}
            {/if}
          </select>
        </div>
        <div class="form-group" style="margin-top:8px">
          <label for="gm-dns" class="opt-label-with-help">
            Custom DNS
            <HelpTooltip title="Custom DNS">
              <p>Override Proton's DNS with your own resolver (e.g. Pi-hole, AdGuard). Leave blank to use Proton's DNS (required for NetShield to work).</p>
            </HelpTooltip>
          </label>
          <input id="gm-dns" bind:value={customDns}
                 placeholder={vpnProtocol === 'openvpn' ? 'Not available for OpenVPN' : 'e.g. 1.1.1.1 (single IP)'}
                 disabled={vpnProtocol === 'openvpn'}>
          {#if vpnProtocol === 'openvpn'}
            <span class="hint">Custom DNS is only supported for WireGuard protocols.</span>
          {:else if customDns.trim() && parseInt(netshield) > 0}
            <div class="opt-warning">Custom DNS overrides NetShield. DNS-level ad/tracker blocking won't work with a custom resolver.</div>
          {/if}
        </div>
        <div class="option-item">
          <input type="checkbox" id="gm-smart" bind:checked={smartProtocol}>
          <label for="gm-smart">
            Smart Protocol
            <span class="opt-hint">— auto-try other protocols if connection fails</span>
          </label>
          <HelpTooltip title="Smart Protocol">
            <p>When enabled, if the tunnel doesn't connect within 45 seconds, FlintVPN automatically tries alternate protocols (WireGuard, OpenVPN, WG TCP/TLS) until one works.</p>
          </HelpTooltip>
        </div>
        {#if mode === 'edit' && optionsChanged && !protocolChanged}
          <div class="opt-warning">Changing VPN options will regenerate the tunnel and briefly disconnect.</div>
        {/if}
      </div>
      {/if}

      <!-- Name -->
      <div class="form-group">
        <label for="gm-name" class="required">Group Name</label>
        <input id="gm-name" bind:value={name} placeholder="e.g. Streaming, Gaming, Printers">
      </div>

      <!-- Icon + Color -->
      <div style="display:flex;gap:12px;align-items:flex-end">
        <div class="form-group" style="width:auto">
          <label>Icon</label>
          <EmojiPicker bind:value={icon} />
        </div>
        <div class="form-group" style="width:auto">
          <label>Card Color</label>
          <ColorPicker bind:value={color} />
        </div>
      </div>

      <!-- Guest -->
      <div class="option-item" style="margin-top:4px">
        <input type="checkbox" id="gm-guest" bind:checked={isGuest}>
        <label for="gm-guest">Set as Guest group</label>
        <span class="tooltip-trigger" title="New devices joining the network will be automatically assigned to this group.">?</span>
      </div>

      <!-- LAN Access -->
      <div class="lan-section">
        <div class="section-header">
          <span class="section-title">LAN Access</span>
          <div class="lan-presets">
            <button type="button" class="preset-btn" class:active={lanOutbound === 'allowed' && lanInbound === 'allowed'}
                    on:click={() => applyPreset('open')} title="Full LAN access">Open</button>
            <button type="button" class="preset-btn" class:active={lanOutbound === 'group_only' && lanInbound === 'group_only'}
                    on:click={() => applyPreset('isolated')} title="Devices only talk within this group">Isolated</button>
            <button type="button" class="preset-btn" class:active={lanOutbound === 'blocked' && lanInbound === 'blocked'}
                    on:click={() => applyPreset('locked')} title="No LAN access, internet only">Locked Down</button>
          </div>
        </div>
        <div class="lan-controls">
          <div class="lan-control">
            <label for="gm-lan-out">Outbound</label>
            <select id="gm-lan-out" bind:value={lanOutbound}>
              <option value="allowed">Allowed</option>
              <option value="group_only">Group Only</option>
              <option value="blocked">Blocked</option>
            </select>
            {#if lanOutbound !== 'allowed'}
              <div class="exc-label">Exceptions (always allowed):</div>
              <LanPeerPicker bind:value={lanOutboundAllow} excludeProfileId={liveProfile?.id} />
            {/if}
          </div>
          <div class="lan-control">
            <label for="gm-lan-in">Inbound</label>
            <select id="gm-lan-in" bind:value={lanInbound}>
              <option value="allowed">Allowed</option>
              <option value="group_only">Group Only</option>
              <option value="blocked">Blocked</option>
            </select>
            {#if lanInbound !== 'allowed'}
              <div class="exc-label">Exceptions (always allowed):</div>
              <LanPeerPicker bind:value={lanInboundAllow} excludeProfileId={liveProfile?.id} />
            {/if}
          </div>
        </div>
        <div class="lan-hint">Controls whether devices in this group can communicate with devices in other groups on the local network.</div>
      </div>

      <!-- Delete (edit only) -->
      {#if mode === 'edit'}
      <div style="margin-top:16px;padding-top:16px;border-top:1px solid var(--border)">
        <button class="btn-danger btn-sm" on:click={deleteGroup} disabled={deleting || saving}>
          {#if deleting}Deleting...{:else}Delete Group{/if}
        </button>
      </div>
      {/if}

      {#if error}<div class="error-msg">{error}</div>{/if}
    </div>
    <div class="modal-footer">
      <button class="btn-outline" on:click={close}>Cancel</button>
      <button class="btn-primary" on:click={submit} disabled={saving || deleting || limitReached}>
        {#if saving}Saving...{:else}{mode === 'create' ? 'Create Group' : 'Save'}{/if}
      </button>
    </div>
  </div>
</div>
{/if}

<style>
  .option-item { display: flex; align-items: center; gap: 8px; padding: 8px 10px; border-radius: var(--radius-xs); }
  .option-item input[type="checkbox"] { width: 18px; height: 18px; accent-color: var(--accent); cursor: pointer; }
  .option-item label { font-size: .85rem; cursor: pointer; }
  .opt-label-with-help { display: flex; align-items: center; }
  .opt-hint { color: var(--fg3); font-weight: 400; font-size: .78rem; }
  .tooltip-trigger { display: inline-flex; align-items: center; justify-content: center; width: 16px; height: 16px; border-radius: 50%; background: var(--border); color: var(--fg3); font-size: .65rem; font-weight: 700; cursor: help; }
  .type-descriptions { margin-top: 6px; }
  .limit-error { font-size: .82rem; color: var(--red); background: var(--red-bg); padding: 8px 10px; border-radius: var(--radius-xs); margin-top: 6px; }
  button:disabled { opacity: 0.5; cursor: not-allowed; }

  .vpn-options-section { margin-top: 16px; padding-top: 16px; border-top: 1px solid var(--border); }
  .vpn-options-section .form-group { margin-bottom: 8px; }
  .opt-warning { margin-top: 8px; padding: 8px 10px; background: rgba(243,156,18,.15); border-radius: var(--radius-xs); font-size: .75rem; color: #f39c12; line-height: 1.4; }

  .protocol-cards { display: flex; gap: 10px; }
  .protocol-card { flex: 1; padding: 12px; border: 2px solid var(--border); border-radius: var(--radius-xs); background: var(--bg); cursor: pointer; text-align: left; transition: var(--transition); }
  .protocol-card:hover { border-color: var(--fg3); }
  .protocol-card.selected { border-color: var(--accent); background: rgba(0,180,216,.08); }
  .proto-name { font-size: .9rem; font-weight: 600; margin-bottom: 4px; color: var(--fg); }
  .proto-desc { font-size: .75rem; color: var(--fg2); line-height: 1.4; }
  .proto-slots { font-size: .7rem; color: var(--fg3); margin-top: 6px; }

  .protocol-help { margin-top: 8px; }
  .protocol-help summary { font-size: .82rem; color: var(--accent); cursor: pointer; padding: 6px 0; }
  .protocol-help summary:hover { text-decoration: underline; }
  .help-content { font-size: .8rem; color: var(--fg2); line-height: 1.5; padding: 10px; background: var(--bg); border-radius: var(--radius-xs); margin-top: 4px; }
  .help-content h4 { font-size: .85rem; color: var(--fg); margin: 8px 0 4px; }
  .help-content h4:first-child { margin-top: 0; }
  .help-content ul { margin: 0 0 0 16px; padding: 0; }
  .help-content li { margin-bottom: 3px; }

  .lan-section { margin-top: 16px; padding-top: 16px; border-top: 1px solid var(--border); }
  .section-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; }
  .section-title { font-size: .9rem; font-weight: 600; color: var(--fg); }
  .lan-presets { display: flex; gap: 4px; }
  .preset-btn { padding: 4px 10px; font-size: .7rem; border-radius: var(--radius-xs); border: 1px solid var(--border2); background: var(--bg3); color: var(--fg2); cursor: pointer; font-weight: 500; transition: var(--transition); }
  .preset-btn:hover { border-color: var(--accent); color: var(--accent); }
  .preset-btn.active { background: var(--accent); color: #fff; border-color: var(--accent); }
  .lan-controls { display: flex; gap: 12px; }
  .lan-control { flex: 1; }
  .lan-control label { display: block; font-size: .75rem; color: var(--fg3); margin-bottom: 4px; text-transform: uppercase; letter-spacing: .05em; }
  .lan-control select { width: 100%; padding: 8px; background: var(--bg3); border: 1px solid var(--border2); border-radius: var(--radius-xs); color: var(--fg); font-size: .85rem; }
  .lan-hint { font-size: .75rem; color: var(--fg3); margin-top: 8px; line-height: 1.4; }
  .exc-label { font-size: .68rem; color: var(--fg3); margin-top: 8px; text-transform: uppercase; letter-spacing: .04em; }
</style>
