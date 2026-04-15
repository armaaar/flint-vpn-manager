<script>
  import { devices, profiles, showToast, movingDevices, smartProtocolStatus, reloadData } from '../../stores/app';
  import { api } from '../../api';
  import { isOnline, deviceIcon, sortDevices } from '../../utils/device';
  import { countryFlagUrl } from '../../utils/country';
  import { derivedConnState, getStatusClass, getStatusLabel, getStatusBorderColor } from '../../utils/profile';
  import { buildGradient } from '../../utils/color';

  import { dndzone } from 'svelte-dnd-action';
  import DeviceRow from '../devices/DeviceRow.svelte';
  import { createEventDispatcher } from 'svelte';

  export let profile;
  const dispatch = createEventDispatcher();

  const MAC_RE = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i;
  $: devs = sortDevices($devices.filter(d => d.profile_id === profile.id)).map(d => ({ ...d, id: d.mac }));
  $: onlineCount = devs.filter(d => isOnline(d)).length;

  let deviceItems = [];
  let draggingDevices = false;
  // Only sync from store when NOT dragging
  $: if (!draggingDevices) deviceItems = devs;

  let showOptions = false;
  // NetShield level → label
  const NETSHIELD_LABELS = ['Off', 'Malware', 'Malware + Ads + Trackers'];
  $: netshieldLabel = NETSHIELD_LABELS[profile.options?.netshield ?? 0] || 'Off';

  function handleDeviceDndConsider(e) {
    draggingDevices = true;
    deviceItems = e.detail.items;
  }

  async function handleDeviceDndFinalize(e) {
    deviceItems = e.detail.items;
    const currentMacs = new Set(devs.map(d => d.mac));
    const newDevices = deviceItems.filter(d => !currentMacs.has(d.mac));

    // Optimistically update the store so both source and target groups
    // reflect the move immediately — no snap-back
    if (newDevices.length > 0) {
      const newMacs = new Set(newDevices.map(d => d.mac));
      movingDevices.update(s => { newMacs.forEach(m => s.add(m)); return new Set(s); });
      devices.update(list => {
        for (const dev of list) {
          if (newMacs.has(dev.mac)) dev.profile_id = profile.id;
        }
        return [...list];
      });
    }

    draggingDevices = false;

    // API calls + reload in background
    for (const d of newDevices) {
      if (!d.mac || !MAC_RE.test(d.mac)) {
        console.warn('DnD: skipping invalid MAC', d.mac, d.id);
        continue;
      }
      const res = await api.assignDevice(d.mac, profile.id);
      if (res.error) showToast(res.error, true);
    }
    if (newDevices.length > 0) {
      await new Promise(r => setTimeout(r, 0)); // let other finalize handlers run first
      await reloadData();
      movingDevices.update(s => { newDevices.forEach(d => s.delete(d.mac)); return new Set(s); });
    }
  }

  // Health is the canonical state, read live from the router via SSE.
  // Possible values: 'green' | 'amber' | 'red' | 'connecting' | 'loading' | 'unknown'
  // 'green'/'amber' = connected, 'connecting'/'loading' = transitioning, others = disconnected.
  $: connState = derivedConnState(profile);
  $: statusClass = getStatusClass(profile);
  $: statusLabel = getStatusLabel(profile);
  $: headerGradient = buildGradient(profile, connState);
  $: statusBorderColor = getStatusBorderColor(profile);
  $: isTransitioning = connState === 'transitioning';
  $: smartStatus = $smartProtocolStatus[profile.id] || null;

  async function connect() {
    if (!profile.server) {
      dispatch('pickserver', { profileId: profile.id });
      return;
    }
    // Optimistic UI: show connecting spinner immediately, BEFORE the (slow) API call.
    // The API response or next SSE tick will replace this with the live router health.
    profiles.update(list => {
      const p = list.find(x => x.id === profile.id);
      if (p) p.health = 'connecting';
      return [...list];
    });
    const res = await api.connectProfile(profile.id);
    if (res.error) {
      showToast(res.error, true);
      // Roll back to disconnected on error
      profiles.update(list => {
        const p = list.find(x => x.id === profile.id);
        if (p) p.health = 'red';
        return [...list];
      });
      return;
    }
    if (res.health) {
      profiles.update(list => {
        const p = list.find(x => x.id === profile.id);
        if (p) p.health = res.health;
        return [...list];
      });
    }
    dispatch('reload');
  }

  async function disconnect() {
    // Optimistic UI: show "checking" spinner immediately while we wait for the router.
    profiles.update(list => {
      const p = list.find(x => x.id === profile.id);
      if (p) p.health = 'loading';
      return [...list];
    });
    const res = await api.disconnectProfile(profile.id);
    if (res.error) {
      showToast(res.error, true);
      // Roll back — call get_tunnel_health on next SSE tick will set the real value
      profiles.update(list => {
        const p = list.find(x => x.id === profile.id);
        if (p) p.health = 'green';  // assume still connected
        return [...list];
      });
      return;
    }
    if (res.health) {
      profiles.update(list => {
        const p = list.find(x => x.id === profile.id);
        if (p) p.health = res.health;
        return [...list];
      });
    }
    dispatch('reload');
  }
</script>

<div class="group-card" style="--card-color: {profile.color}; --status-color: {statusBorderColor}">
  <div class="group-status-header {statusClass}" class:non-vpn-header={profile.type !== 'vpn'} style="background: {headerGradient}">
    <div class="group-top">
      <div>
        <span class="group-name">{profile.icon} {profile.name}</span>
        {#if profile.is_guest}
          <span class="badge-guest">GUEST</span>
        {/if}
        <div class="group-status-label">
          {#if smartStatus}
            Trying {smartStatus.attempting || '...'} ({smartStatus.attempt}/{smartStatus.total})
          {:else}
            {statusLabel}
          {/if}
          <span class="conn-type">
            {#if profile.type === 'no_vpn'}Direct
            {:else if profile.type === 'no_internet'}LAN Only
            {:else if profile.router_info?.vpn_protocol === 'openvpn'}
              {profile.server?.protocol === 'openvpn-tcp' ? 'OVPN TCP' : 'OVPN UDP'}
            {:else if profile.router_info?.vpn_protocol === 'wireguard-tls'}Stealth
            {:else if profile.router_info?.vpn_protocol === 'wireguard-tcp'}WG TCP
            {:else}WG
            {/if}
          </span>
        </div>
      </div>
      <div class="group-header-actions">
        <span class="drag-handle" title="Drag to reorder">⠿</span>
        <button class="group-settings-btn" on:click|stopPropagation={() => dispatch('edit', profile)}
                title="Group settings">⚙</button>
      </div>
    </div>

    {#if profile.type === 'vpn' && profile.server?.name}
      <div class="group-server">
        <span class="group-server-name">
          <img class="flag-img" src={countryFlagUrl(profile.server.country_code)} alt="" /> {profile.server.name} · {profile.server.city || ''}
        </span>
        <button class="group-server-menu"
                on:click|stopPropagation={() => dispatch('pickserver', { profileId: profile.id })}
                title="Change server">…</button>
      </div>
      {#if profile.server && profile.server.ipv6 === false && profile.router_info?.ipv6}
        <div class="ipv6-warning">IPv6 blocked — server does not support IPv6</div>
      {/if}
    {/if}

    {#if profile.type === 'vpn'}
      <div class="group-connect-area">
        {#if isTransitioning}
          <button class="btn-transition btn-lg" disabled>
            <span class="btn-spinner"></span>
            {getStatusLabel(profile)}
          </button>
        {:else if connState === 'connected'}
          <button class="btn-disconnect btn-lg" on:click={disconnect}>Disconnect</button>
        {:else}
          <button class="btn-connect btn-lg" on:click={connect}>
            {profile.server ? 'Connect' : 'Choose Server'}
          </button>
        {/if}
      </div>
    {/if}
  </div>

  {#if profile.type === 'vpn'}
    <button class="vpn-options-toggle" on:click={() => showOptions = !showOptions}
            title="VPN options">
      <span class="opt-summary">
        {#if profile.kill_switch}<span class="opt-pill ks-on" title="Kill switch enabled">🛡 KS</span>{/if}
        {#if (profile.options?.netshield ?? 0) > 0}
          <span class="opt-pill ns-on" class:ns-active={connState === 'connected'}
                title="NetShield {netshieldLabel}{connState === 'connected' ? ' — Active' : ''}">
            ⛨ NS{profile.options.netshield}
          </span>
        {/if}
        {#if profile.adblock}<span class="opt-pill ab-on" title="DNS Ad Blocker">🚫 Ads</span>{/if}
        {#if profile.options?.smart_protocol}<span class="opt-pill sp-on" title="Smart Protocol">⚡ SP</span>{/if}
        {#if profile.server_scope?.features?.tor}<span class="opt-pill tor-on" title="Tor routing">🧅</span>{/if}
      </span>
      <span class="caret">{showOptions ? '▴' : '▾'}</span>
    </button>
    {#if showOptions}
      <div class="vpn-options">
        <div class="opt-row">
          <span class="opt-label">Kill Switch</span>
          <span class="opt-value">{profile.kill_switch ? 'On' : 'Off'}</span>
        </div>
        <div class="opt-row">
          <span class="opt-label">NetShield</span>
          <span class="opt-value">{netshieldLabel}</span>
        </div>
        <div class="opt-row">
          <span class="opt-label">Moderate NAT</span>
          <span class="opt-value">{profile.options?.moderate_nat ? 'On' : 'Off'}</span>
        </div>
        <div class="opt-row">
          <span class="opt-label">NAT-PMP</span>
          <span class="opt-value">{profile.options?.nat_pmp ? 'On' : 'Off'}</span>
        </div>
        <div class="opt-row">
          <span class="opt-label">VPN Accelerator</span>
          <span class="opt-value">{profile.options?.vpn_accelerator !== false ? 'On' : 'Off'}</span>
        </div>
        {#if profile.options?.port}
          <div class="opt-row">
            <span class="opt-label">Port</span>
            <span class="opt-value">{profile.options.port}</span>
          </div>
        {/if}
        {#if profile.options?.custom_dns}
          <div class="opt-row">
            <span class="opt-label">Custom DNS</span>
            <span class="opt-value">{profile.options.custom_dns}</span>
          </div>
        {/if}
        {#if profile.adblock}
          <div class="opt-row">
            <span class="opt-label">DNS Ad Blocker</span>
            <span class="opt-value">On</span>
          </div>
        {/if}
        {#if profile.options?.smart_protocol}
          <div class="opt-row">
            <span class="opt-label">Smart Protocol</span>
            <span class="opt-value">On</span>
          </div>
        {/if}
        {#if profile.options?.secure_core}
          <div class="opt-row">
            <span class="opt-label">Secure Core</span>
            <span class="opt-value">On</span>
          </div>
        {/if}
        {#if profile.server_scope?.features?.tor}
          <div class="opt-row">
            <span class="opt-label">Tor</span>
            <span class="opt-value">On</span>
          </div>
        {/if}
        {#if profile.server_scope?.type && profile.server_scope.type !== 'server'}
          <div class="opt-row">
            <span class="opt-label">Auto-pick</span>
            <span class="opt-value">
              {profile.server_scope.type === 'country' ? 'Best in country' : 'Best in city'}
            </span>
          </div>
        {/if}
      </div>
    {/if}
  {/if}

  {#if profile.type !== 'vpn' && profile.type !== 'no_internet' && profile.adblock}
    <div class="adblock-indicator">
      <span class="opt-pill ab-on" title="DNS Ad Blocker">🚫 Ads</span>
    </div>
  {/if}

  <div class="group-devices">
    <div class="device-list-header">
      <span>Device name</span>
      <span class="device-count-badge">{onlineCount}/{devs.length}</span>
    </div>
    <div class="device-drop-zone"
         use:dndzone={{ items: deviceItems, type: 'devices', flipDurationMs: 150, dropTargetStyle: { outline: '2px dashed var(--accent)', outlineOffset: '-2px' } }}
         on:consider={handleDeviceDndConsider}
         on:finalize={handleDeviceDndFinalize}>
      {#each deviceItems as device (device.id)}
        <DeviceRow {device} on:select={(e) => dispatch('deviceselect', e.detail)} />
      {/each}
    </div>
    {#if deviceItems.length === 0}
      <div class="no-devices">Drop devices here</div>
    {/if}
  </div>
</div>

<style>
  .group-card { background: var(--surface); border-radius: var(--radius); box-shadow: var(--shadow); width: 300px; flex: 0 0 300px; overflow: hidden; display: flex; flex-direction: column; border-left: 6px solid var(--status-color, #636e72); transition: border-color .3s ease; }
  .group-status-header { padding: 20px; border-radius: 0; position: relative; min-height: 140px; display: flex; flex-direction: column; justify-content: space-between; }
  .group-status-header.non-vpn-header { min-height: auto; border-bottom: 1px solid var(--border); }
  .group-top { display: flex; justify-content: space-between; align-items: flex-start; }
  .group-name { font-size: 1.1rem; font-weight: 700; color: #fff; text-shadow: 0 1px 3px rgba(0,0,0,.3); }
  .badge-guest { font-size: .65rem; background: rgba(46,204,113,.25); color: #fff; padding: 2px 6px; border-radius: 3px; font-weight: 600; margin-left: 6px; vertical-align: middle; }
  .group-header-actions { display: flex; gap: 4px; align-items: center; }
  .drag-handle { color: rgba(255,255,255,.4); cursor: grab; font-size: 1.1rem; padding: 4px; user-select: none; }
  .drag-handle:hover { color: rgba(255,255,255,.7); }
  .group-settings-btn { background: rgba(255,255,255,.15); border: none; color: #fff; width: 32px; height: 32px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 1rem; cursor: pointer; backdrop-filter: var(--glass-blur); }
  .group-settings-btn:hover { background: rgba(255,255,255,.3); }
  .group-status-label { font-size: .8rem; font-weight: 600; text-transform: uppercase; letter-spacing: .08em; color: rgba(255,255,255,.85); margin-top: 6px; display: flex; align-items: center; gap: 6px; }
  .conn-type { font-size: .6rem; padding: 2px 6px; border-radius: 3px; background: rgba(255,255,255,.2); color: rgba(255,255,255,.7); font-weight: 500; letter-spacing: .03em; }
  .group-server { display: flex; align-items: center; gap: 8px; margin-top: 12px; }
  .group-server-name { font-size: .95rem; color: #fff; font-weight: 500; flex: 1; }
  .group-server-menu { background: none; border: none; color: rgba(255,255,255,.7); font-size: 1.2rem; padding: 4px; cursor: pointer; letter-spacing: 2px; }
  .group-server-menu:hover { color: #fff; }
  .ipv6-warning { font-size: .75rem; color: var(--warning, #e2b93d); padding: 4px 0 0; }
  :global(.flag-img) { width: 20px; height: 15px; vertical-align: middle; border-radius: 2px; object-fit: cover; }
  .proto-tag { font-size: .6rem; padding: 1px 5px; border-radius: 3px; font-weight: 700; vertical-align: middle; margin-left: 4px; }
  .proto-tag.wg { background: rgba(46,204,113,.2); color: #2ecc71; }
  .proto-tag.ovpn { background: var(--accent-bg); color: var(--accent); }
  .group-connect-area { margin-top: 14px; }

  .vpn-options-toggle {
    display: flex; align-items: center; justify-content: space-between;
    padding: 8px 16px; background: var(--bg2); border: none; border-bottom: 1px solid var(--border);
    cursor: pointer; width: 100%; font-size: .75rem; color: var(--fg2);
  }
  .vpn-options-toggle:hover { background: var(--bg3); }
  .opt-summary { display: flex; gap: 6px; align-items: center; }
  .opt-pill {
    display: inline-flex; align-items: center; padding: 2px 7px; border-radius: 10px;
    font-size: .68rem; font-weight: 600; letter-spacing: .03em;
  }
  .opt-pill.ks-on { background: rgba(46,204,113,.18); color: #2ecc71; }
  .opt-pill.ns-on { background: var(--accent-bg); color: var(--accent); }
  .opt-pill.ns-active { background: rgba(46,204,113,.2); color: #2ecc71; font-weight: 600; }
  .opt-pill.sp-on { background: rgba(243,156,18,.18); color: #f39c12; }
  .opt-pill.ab-on { background: rgba(231,76,60,.18); color: #e74c3c; }
  .adblock-indicator { padding: 4px 12px 0; }
  .opt-pill.tor-on { background: rgba(155,89,182,.18); color: #9b59b6; }
  .caret { color: var(--fg3); font-size: .7rem; }
  .vpn-options {
    padding: 8px 16px 12px; background: var(--bg2); border-bottom: 1px solid var(--border);
    font-size: .78rem;
  }
  .opt-row { display: flex; justify-content: space-between; padding: 4px 0; }
  .opt-label { color: var(--fg3); }
  .opt-value { color: var(--fg); font-weight: 500; }

  .group-devices { flex: 1; }
  .device-list-header { display: flex; align-items: center; padding: 10px 16px; border-bottom: 1px solid var(--border); font-size: .75rem; color: var(--fg3); text-transform: uppercase; letter-spacing: .05em; }
  .device-count-badge { margin-left: auto; color: var(--fg2); }
  .device-drop-zone { min-height: 40px; }
  .no-devices { padding: 16px; text-align: center; color: var(--fg3); font-size: .85rem; }

  :global(.btn-connect) { background: #fff; color: var(--bg); font-weight: 700; padding: 14px 0; font-size: 1rem; width: 100%; border-radius: var(--radius-sm); border: none; cursor: pointer; text-transform: uppercase; letter-spacing: .2px; }
  :global(.btn-connect:hover) { background: var(--accent); color: #fff; }
  :global(.btn-disconnect) { background: var(--glass-bg); color: #fff; border: none; font-weight: 700; padding: 14px 0; font-size: 1rem; width: 100%; border-radius: var(--radius-sm); cursor: pointer; backdrop-filter: var(--glass-blur); box-shadow: var(--shadow); text-transform: uppercase; letter-spacing: .2px; }
  :global(.btn-disconnect:hover) { background: var(--glass-hover); }
  :global(.btn-transition) { background: rgba(255,255,255,.15); color: rgba(255,255,255,.8); font-weight: 600; padding: 14px 0; font-size: 1rem; width: 100%; border-radius: var(--radius-sm); border: none; cursor: wait; display: flex; align-items: center; justify-content: center; gap: 8px; backdrop-filter: var(--glass-blur); text-transform: uppercase; letter-spacing: .2px; }
  .btn-spinner { display: inline-block; width: 16px; height: 16px; border: 2px solid rgba(255,255,255,.3); border-top-color: #fff; border-radius: 50%; animation: spin .6s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }

  @media (max-width: 700px) {
    .group-card { width: 100%; flex: 1 1 100%; }
  }
</style>
