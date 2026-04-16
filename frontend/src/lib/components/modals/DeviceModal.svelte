<script>
  import { api } from '../../api';
  import { profiles, showToast } from '../../stores/app';
  import { timeAgo, formatBytes, formatSpeed } from '../../utils/format';
  import { isOnline, isRandomMac, DEVICE_TYPES, deviceTypeLabel } from '../../utils/device';
  import { createEventDispatcher, onMount } from 'svelte';
  export let device = null;
  const dispatch = createEventDispatcher();

  let bypassExceptions = [];
  let bypassLoaded = false;

  $: if (device) loadBypass();

  async function loadBypass() {
    try {
      const data = await api.getBypassOverview();
      bypassExceptions = data.exceptions || [];
      bypassLoaded = true;
    } catch { bypassExceptions = []; bypassLoaded = true; }
  }

  // Exceptions directly targeting this device's MAC
  $: directExceptions = device ? bypassExceptions.filter(e => {
    const targets = Array.isArray(e.scope_target) ? e.scope_target : (e.scope_target ? [e.scope_target] : []);
    return targets.includes(device.mac);
  }) : [];

  // Exceptions targeting the device's group (inherited)
  $: inheritedExceptions = device ? bypassExceptions.filter(e => {
    if (e.scope === 'global') return false; // global shown separately
    const targets = Array.isArray(e.scope_target) ? e.scope_target : (e.scope_target ? [e.scope_target] : []);
    return device.profile_id && targets.includes(device.profile_id) && !targets.includes(device.mac);
  }) : [];

  // Global exceptions
  $: globalExceptions = bypassExceptions.filter(e => e.scope === 'global' && e.enabled);

  $: deviceGroup = device ? $profiles.find(p => p.id === device.profile_id) : null;

  let label = '';
  let deviceClass = '';
  let targetProfileId = '';
  let reserveIp = false;
  let originalReserveIp = false;
  let boundMac = '';

  $: if (device && device.mac !== boundMac) {
    boundMac = device.mac;
    label = device.label || '';
    deviceClass = device.device_class || '';
    targetProfileId = device.profile_id || '';
    reserveIp = !!device.reserved_ip;
    originalReserveIp = !!device.reserved_ip;
  } else if (!device) {
    boundMac = '';
  }

  $: online = device ? isOnline(device) : false;

  let saving = false;

  async function save() {
    if (!device || saving) return;
    saving = true;
    const mac = device.mac;

    try {
      if (label !== (device.label || '') || deviceClass !== (device.device_class || '')) {
        await api.setDeviceLabel(mac, label, deviceClass);
      }

      const newPid = targetProfileId || null;
      if (newPid !== device.profile_id) {
        const res = await api.assignDevice(mac, newPid);
        if (res.error) { showToast(res.error, true); saving = false; return; }
      }

      if (reserveIp !== originalReserveIp) {
        try {
          if (reserveIp) {
            await api.reserveDeviceIp(mac, device.ip);
          } else {
            await api.releaseDeviceIp(mac);
          }
        } catch (err) {
          showToast(err.message || 'Failed to update IP reservation', true);
          saving = false;
          return;
        }
      }

      dispatch('close');
      dispatch('reload');
    } finally {
      saving = false;
    }
  }

  function close() { dispatch('close'); }
</script>

{#if device}
<div class="modal-overlay active">
  <div class="modal">
    <div class="modal-header">
      <h2>{device.display_name}</h2>
      <button class="modal-close" on:click={close}>&times;</button>
    </div>
    <div class="modal-body">

      <!-- Info grid -->
      <div class="info-grid">
        <span class="info-label">MAC Address</span><span>{device.mac.toUpperCase()}</span>
        <span class="info-label">IP Address</span>
        <span>
          {device.ip || 'Unknown'}
          {#if device.reserved_ip}<span class="badge-reserved">Reserved</span>{/if}
        </span>
        {#if device.ipv6_addresses && device.ipv6_addresses.length}
          <span class="info-label">IPv6</span>
          <span class="ipv6-addrs">{device.ipv6_addresses.join(', ')}</span>
        {/if}
        <span class="info-label">Hostname</span><span>{device.hostname || 'Not detected'}</span>
        <span class="info-label">Status</span>
        <span>
          {#if online}
            <span class="status-online">Online</span>
          {:else}
            Offline{#if device.last_seen} ({timeAgo(device.last_seen)}){/if}
          {/if}
        </span>
        {#if device.network}
          <span class="info-label">Network</span><span>{device.network}</span>
        {/if}
        {#if device.iface}
          <span class="info-label">Interface</span><span>{device.iface}</span>
        {/if}
        {#if device.signal_dbm}
          <span class="info-label">WiFi Signal</span><span>{device.signal_dbm} dBm</span>
        {/if}
        {#if device.link_speed_mbps}
          <span class="info-label">Link Speed</span><span>{device.link_speed_mbps} Mbps</span>
        {/if}
        {#if online && (device.rx_speed || device.tx_speed)}
          <span class="info-label">Current Speed</span>
          <span>↓ {formatSpeed(device.rx_speed)}  ↑ {formatSpeed(device.tx_speed)}</span>
        {/if}
        {#if device.total_rx || device.total_tx}
          <span class="info-label">Total Traffic</span>
          <span>↓ {formatBytes(device.total_rx)}  ↑ {formatBytes(device.total_tx)}</span>
        {/if}
        {#if isRandomMac(device.mac)}
          <span class="info-label">Warning</span>
          <span class="warning-text">⚠ Private MAC — may change on reconnect</span>
        {/if}
      </div>

      <!-- VPN Bypass Exceptions (above form, Networks-style) -->
      {#if bypassLoaded && (directExceptions.length > 0 || inheritedExceptions.length > 0 || globalExceptions.length > 0)}
        <div class="bypass-section">
          <h4 class="bypass-header">🔀 VPN Bypass ({directExceptions.length + inheritedExceptions.length + globalExceptions.length})</h4>
          <div class="bypass-list">
            {#each directExceptions as exc}
              <div class="bypass-row" class:bypass-disabled={!exc.enabled}>
                <span class="bypass-name">{exc.name}</span>
                <span class="bypass-badge bypass-direct">Direct</span>
                {#if !exc.enabled}<span class="bypass-badge bypass-off">Off</span>{/if}
              </div>
            {/each}
            {#each inheritedExceptions as exc}
              <div class="bypass-row" class:bypass-disabled={!exc.enabled}>
                <span class="bypass-name">{exc.name}</span>
                <span class="bypass-badge bypass-inherited">via {deviceGroup ? deviceGroup.name : 'Group'}</span>
                {#if !exc.enabled}<span class="bypass-badge bypass-off">Off</span>{/if}
              </div>
            {/each}
            {#each globalExceptions as exc}
              <div class="bypass-row">
                <span class="bypass-name">{exc.name}</span>
                <span class="bypass-badge bypass-global">Global</span>
              </div>
            {/each}
          </div>
        </div>
      {/if}

      <div class="form-group">
        <label for="dl">Custom Name</label>
        <input id="dl" bind:value={label} placeholder="e.g. Living Room TV, Dad's Phone">
        <span class="hint">Give this device a friendly name. Leave blank to use the auto-detected hostname.</span>
      </div>

      <div class="form-group">
        <label for="dc">Device Type</label>
        <select id="dc" bind:value={deviceClass}>
          <option value="">Auto-detect</option>
          {#each Object.entries(DEVICE_TYPES) as [key, { icon, label }]}
            <option value={key}>{icon} {label}</option>
          {/each}
        </select>
        <span class="hint">Synced with the router. Changes here update both the dashboard and router.</span>
      </div>

      <div class="form-group">
        <label for="dg" class="required">Assign to Group</label>
        <select id="dg" bind:value={targetProfileId}>
          {#each $profiles as p}
            <option value={p.id}>{p.icon} {p.name}</option>
          {/each}
          <option value="">Unassigned</option>
        </select>
        {#if deviceGroup}
          <span class="hint">Currently in {deviceGroup.icon} {deviceGroup.name}</span>
        {/if}
      </div>

      {#if device.ip}
      <div class="option-item">
        <input type="checkbox" id="rip" bind:checked={reserveIp} />
        <label for="rip">
          Reserve IP ({device.ip})
          <span class="opt-hint">— always assign this IP via DHCP</span>
        </label>
      </div>
      {/if}

    </div>
    <div class="modal-footer">
      <button class="btn-outline" on:click={close}>Cancel</button>
      <button class="btn-primary" on:click={save} disabled={saving}>
        {#if saving}Saving...{:else}Save{/if}
      </button>
    </div>
  </div>
</div>
{/if}

<style>
  .info-grid {
    display: grid; grid-template-columns: auto 1fr; gap: 4px 14px;
    font-size: .85rem; margin-bottom: 18px; padding: 14px;
    background: var(--bg); border-radius: var(--radius-xs);
  }
  .info-label { color: var(--fg3); }
  .status-online { color: var(--green); font-weight: 500; }
  .warning-text { color: var(--amber); }
  .badge-reserved { font-size: 0.7rem; font-weight: 600; padding: 2px 8px; border-radius: 10px; text-transform: uppercase; letter-spacing: 0.2px; background: var(--green-bg); color: var(--green); margin-left: 6px; }
  .option-item { display: flex; align-items: center; gap: 8px; padding: 8px 10px; border-radius: var(--radius-xs); }
  .option-item input[type="checkbox"] { width: 18px; height: 18px; accent-color: var(--accent); cursor: pointer; }
  .option-item label { font-size: .85rem; cursor: pointer; }
  .opt-hint { color: var(--fg3); font-weight: 400; font-size: .78rem; }

  /* VPN Bypass section — matches Networks page exception style */
  .bypass-section { margin-bottom: 18px; padding: 14px; background: var(--surface); border-radius: var(--radius-sm, 8px); }
  .bypass-header { margin: 0 0 10px; font-size: .9rem; color: var(--fg2); font-weight: 500; }
  .bypass-list { display: flex; flex-direction: column; gap: 6px; }
  .bypass-row { display: flex; align-items: center; gap: 10px; padding: 8px 12px; background: var(--bg); border: 1px solid var(--border); border-radius: 6px; font-size: .85rem; }
  .bypass-row.bypass-disabled { opacity: 0.5; }
  .bypass-name { flex: 1; font-weight: 500; }
  .bypass-badge { font-size: 0.7rem; font-weight: 600; padding: 2px 8px; border-radius: 10px; text-transform: uppercase; letter-spacing: 0.2px; }
  .bypass-direct { background: var(--amber-bg); color: var(--amber); }
  .bypass-inherited { background: var(--green-bg); color: var(--green); }
  .bypass-global { background: var(--accent-bg); color: var(--accent); }
  .bypass-off { background: var(--red-bg); color: var(--red); }
</style>
