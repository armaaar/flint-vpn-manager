<script>
  import { api } from '../api.js';
  import { profiles, showToast } from '../stores/app.js';
  import { timeAgo, isOnline, isRandomMac, formatBytes, formatSpeed, DEVICE_TYPES, deviceTypeLabel } from '../utils.js';
  import { createEventDispatcher } from 'svelte';

  export let device = null;
  const dispatch = createEventDispatcher();

  let label = '';
  let deviceClass = '';
  let targetProfileId = '';
  let lanOutbound = null;
  let lanInbound = null;

  $: if (device) {
    label = device.label || '';
    deviceClass = device.device_class || '';
    targetProfileId = device.profile_id || '';
    // null means inherit from group
    lanOutbound = device.lan_inherited ? null : (device.lan_outbound || null);
    lanInbound = device.lan_inherited ? null : (device.lan_inbound || null);
  }

  $: online = device ? isOnline(device) : false;
  $: assignedProfile = device?.profile_id ? $profiles.find(p => p.id === device.profile_id) : null;
  $: groupLanOut = assignedProfile?.lan_access?.outbound || 'allowed';
  $: groupLanIn = assignedProfile?.lan_access?.inbound || 'allowed';

  const LAN_LABELS = { allowed: 'Allowed', group_only: 'Group Only', blocked: 'Blocked' };

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

      // Save LAN access overrides if device is assigned
      if (newPid || device.profile_id) {
        await api.setDeviceLanAccess(mac, { outbound: lanOutbound, inbound: lanInbound });
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
<div class="modal-overlay active" on:click|self={close}>
  <div class="modal">
    <div class="modal-header">
      <h2>{device.display_name}</h2>
      <button class="modal-close" on:click={close}>&times;</button>
    </div>
    <div class="modal-body">

      <!-- Info grid -->
      <div class="info-grid">
        <span class="info-label">MAC Address</span><span>{device.mac}</span>
        <span class="info-label">IP Address</span><span>{device.ip || 'Unknown'}</span>
        <span class="info-label">Hostname</span><span>{device.hostname || 'Not detected'}</span>
        <span class="info-label">Status</span>
        <span>
          {#if online}
            <span class="status-online">Online</span>
          {:else}
            Offline ({timeAgo(device.last_seen)})
          {/if}
        </span>
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
      </div>

      <!-- LAN Access Override (only when assigned to a group) -->
      {#if targetProfileId}
        <div class="lan-section">
          <div class="lan-title">LAN Access</div>
          <div class="lan-controls">
            <div class="lan-control">
              <label for="dl-lan-out">Outbound</label>
              <select id="dl-lan-out" bind:value={lanOutbound}>
                <option value={null}>Inherit ({LAN_LABELS[groupLanOut]})</option>
                <option value="allowed">Allowed</option>
                <option value="group_only">Group Only</option>
                <option value="blocked">Blocked</option>
              </select>
            </div>
            <div class="lan-control">
              <label for="dl-lan-in">Inbound</label>
              <select id="dl-lan-in" bind:value={lanInbound}>
                <option value={null}>Inherit ({LAN_LABELS[groupLanIn]})</option>
                <option value="allowed">Allowed</option>
                <option value="group_only">Group Only</option>
                <option value="blocked">Blocked</option>
              </select>
            </div>
          </div>
          <div class="lan-hint">Override the group's LAN access settings for this specific device. "Inherit" uses the group setting.</div>
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

  .lan-section { margin-top: 16px; padding-top: 16px; border-top: 1px solid var(--border); }
  .lan-title { font-size: .9rem; font-weight: 600; color: var(--fg); margin-bottom: 10px; }
  .lan-controls { display: flex; gap: 12px; }
  .lan-control { flex: 1; }
  .lan-control label { display: block; font-size: .75rem; color: var(--fg3); margin-bottom: 4px; text-transform: uppercase; letter-spacing: .05em; }
  .lan-control select { width: 100%; padding: 8px; background: var(--bg3); border: 1px solid var(--border2); border-radius: var(--radius-xs); color: var(--fg); font-size: .85rem; }
  .lan-hint { font-size: .75rem; color: var(--fg3); margin-top: 8px; line-height: 1.4; }
</style>
