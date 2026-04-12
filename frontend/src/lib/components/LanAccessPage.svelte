<script>
  import { api } from '../api.js';
  import { devices, showToast } from '../stores/app.js';
  import { createEventDispatcher, onMount } from 'svelte';
  import ExceptionModal from './ExceptionModal.svelte';
  import DeviceModal from './DeviceModal.svelte';

  const dispatch = createEventDispatcher();

  let networks = [];
  let accessRules = [];
  let exceptions = [];
  let loading = true;
  let savingRules = false;
  let expandedZone = null;
  let networkDevices = {};
  let showExceptionModal = false;
  let pendingRules = [];

  // Create form
  let showCreateForm = false;
  let createName = '';
  let createPassword = '';
  let createIsolation = true;
  let creating = false;

  // Delete
  let deleting = null;

  // Device modal — track by MAC so it stays reactive to store updates
  let selectedMac = null;
  $: selectedDevice = selectedMac ? $devices.find(d => d.mac === selectedMac) || null : null;

  // Collapsible WiFi settings per network
  let wifiSettingsOpen = {};

  onMount(() => loadData());

  const loadData = async () => {
    loading = true;
    try {
      const data = await api.getNetworks();
      networks = data.networks || [];
      accessRules = data.access_rules || [];
      exceptions = data.exceptions || [];
      pendingRules = accessRules.map(r => ({ ...r }));
    } catch (e) {
      showToast(e.message, true);
    } finally {
      loading = false;
    }
  };

  const loadDevices = async (zoneId) => {
    if (networkDevices[zoneId]) return;
    try {
      const data = await api.getNetworkDevices(zoneId);
      networkDevices[zoneId] = data.devices || [];
      networkDevices = networkDevices;
    } catch (e) {
      showToast(e.message, true);
    }
  };

  const toggleExpand = (zoneId) => {
    if (expandedZone === zoneId) {
      expandedZone = null;
    } else {
      expandedZone = zoneId;
      const network = networks.find(n => n.id === zoneId);
      if (network) ensureSsidEdits(network);
      networks = networks;
      loadDevices(zoneId);
    }
  };

  const toggleRule = (src, dest) => {
    pendingRules = pendingRules.map(r =>
      r.src_zone === src && r.dest_zone === dest
        ? { ...r, allowed: !r.allowed }
        : r
    );
  };

  $: rulesChanged = JSON.stringify(pendingRules) !== JSON.stringify(accessRules);

  const saveRules = async () => {
    savingRules = true;
    try {
      await api.updateAccessRules(pendingRules);
      accessRules = pendingRules.map(r => ({ ...r }));
      showToast('Access rules saved');
    } catch (e) {
      showToast(e.message, true);
    } finally {
      savingRules = false;
    }
  };

  const toggleIsolation = async (network) => {
    const newState = !network.isolation;
    try {
      await api.setIsolation(network.id, newState);
      network.isolation = newState;
      networks = networks;
      showToast(`${newState ? 'Isolation enabled' : 'Isolation disabled'} — WiFi clients may briefly reconnect`);
    } catch (e) {
      showToast(e.message, true);
    }
  };

  const toggleEnabled = async (network) => {
    const newState = !network.enabled;
    try {
      await api.updateNetwork(network.id, { enabled: newState });
      network.enabled = newState;
      networks = networks;
      showToast(`Network ${newState ? 'enabled' : 'disabled'} — WiFi will briefly reconnect`);
    } catch (e) {
      showToast(e.message, true);
    }
  };

  const updateSsid = async (network, ssid) => {
    const settings = {};
    if (ssid.editName !== ssid.name) settings.ssid = ssid.editName;
    if (ssid.editPassword.length > 0) settings.key = ssid.editPassword;
    if (ssid.editHidden !== ssid.hidden) settings.hidden = ssid.editHidden;
    if (ssid.editEncryption !== ssid.encryption) settings.encryption = ssid.editEncryption;
    if (ssid.editDisabled !== ssid.disabled) settings.disabled = ssid.editDisabled;
    if (Object.keys(settings).length === 0) return;
    try {
      await api.updateNetwork(network.id, { ssids: [{ section: ssid.section, ...settings }] });
      if (settings.ssid) ssid.name = settings.ssid;
      if (settings.key) ssid.password = settings.key;
      if ('hidden' in settings) ssid.hidden = settings.hidden;
      if ('encryption' in settings) ssid.encryption = settings.encryption;
      if ('disabled' in settings) ssid.disabled = settings.disabled;
      networks = networks;
      showToast('WiFi settings updated — clients may briefly reconnect');
    } catch (e) {
      showToast(e.message, true);
    }
  };

  const createNetwork = async () => {
    if (!createName || !createPassword || createPassword.length < 8) {
      showToast('Name and password (8+ chars) required', true);
      return;
    }
    creating = true;
    try {
      await api.createNetwork({ name: createName, password: createPassword, isolation: createIsolation });
      showCreateForm = false;
      createName = '';
      createPassword = '';
      showToast('Network created — WiFi reloading');
      await loadData();
    } catch (e) {
      showToast(e.message, true);
    } finally {
      creating = false;
    }
  };

  const deleteNetwork = async (zoneId) => {
    deleting = zoneId;
    try {
      await api.deleteNetwork(zoneId);
      showToast('Network deleted');
      expandedZone = null;
      await loadData();
    } catch (e) {
      showToast(e.message, true);
    } finally {
      deleting = null;
    }
  };

  const handleAddException = async (data) => {
    try {
      const res = await api.addException(data);
      exceptions = [...exceptions, res.exception];
      showExceptionModal = false;
      showToast('Exception added');
    } catch (e) {
      showToast(e.message, true);
    }
  };

  const removeException = async (id) => {
    try {
      await api.removeException(id);
      exceptions = exceptions.filter(e => e.id !== id);
      showToast('Exception removed');
    } catch (e) {
      showToast(e.message, true);
    }
  };

  const otherNetworks = (zoneId) => networks.filter(n => n.id !== zoneId);
  const ssidLabel = (network) => network.ssids.map(s => s.name).join(' / ') || network.zone;
  const canDelete = (network) => network.id !== 'lan' && network.id !== 'guest';

  const selectDevice = (mac) => { selectedMac = mac; };
  const groupDevices = (devices) => {
    const groups = { '5G': [], '2.4G': [], 'Ethernet': [], 'Other': [] };
    for (const d of devices || []) {
      const iface = d.iface || '';
      if (iface === '5G') groups['5G'].push(d);
      else if (iface === '2.4G') groups['2.4G'].push(d);
      else if (iface === 'cable' || iface === 'Ethernet') groups['Ethernet'].push(d);
      else groups['Other'].push(d);
    }
    return Object.entries(groups).filter(([, devs]) => devs.length > 0);
  };

  // Editable SSID state — initialized when expanding
  const ensureSsidEdits = (network) => {
    for (const ssid of network.ssids) {
      if (!('editName' in ssid)) {
        ssid.editName = ssid.name;
        ssid.editPassword = '';
        ssid.editHidden = ssid.hidden;
        ssid.editEncryption = ssid.encryption;
        ssid.editDisabled = ssid.disabled;
      }
    }
  };

  const ssidDirty = (ssid) =>
    ssid.editName !== ssid.name ||
    ssid.editPassword.length > 0 ||
    ssid.editHidden !== ssid.hidden ||
    ssid.editEncryption !== ssid.encryption ||
    ssid.editDisabled !== ssid.disabled;
</script>

<div class="lan-page">
  <div class="page-header">
    <button class="btn-back" on:click={() => dispatch('back')}>← Back</button>
    <h2>Networks</h2>
  </div>

  {#if loading}
    <div class="loading">Loading networks...</div>
  {:else}
    {#each networks as network (network.id)}
      <div class="network-card" class:expanded={expandedZone === network.id} class:disabled-net={!network.enabled}>
        <div class="network-header" on:click={() => toggleExpand(network.id)}>
          <div class="network-info">
            <span class="network-name">{ssidLabel(network)}</span>
            <span class="network-meta">
              {network.subnet}
              {#if !network.enabled}<span class="badge badge-off">Disabled</span>{/if}
            </span>
          </div>
          <div class="network-badges">
            <span class="badge" class:badge-green={!network.isolation} class:badge-red={network.isolation}>
              {network.isolation ? 'Isolated' : 'Free talk'}
            </span>
            <span class="badge badge-count">{network.device_count} devices</span>
          </div>
          <span class="chevron">{expandedZone === network.id ? '▼' : '▶'}</span>
        </div>

        {#if expandedZone === network.id}
          <div class="network-body">
            <!-- Enable / Isolation toggles -->
            <div class="toggles-row">
              {#if network.id !== 'lan'}
                <div class="option-item">
                  <input type="checkbox" id="net-en-{network.id}" checked={network.enabled} on:change={() => toggleEnabled(network)}>
                  <label for="net-en-{network.id}">Enabled</label>
                </div>
              {/if}
              <div class="option-item">
                <input type="checkbox" id="net-iso-{network.id}" checked={network.isolation}
                       on:change={() => toggleIsolation(network)} disabled={!network.enabled}>
                <label for="net-iso-{network.id}">
                  Device isolation
                  <span class="opt-hint">— {network.isolation ? 'devices cannot see each other' : 'devices communicate freely'}</span>
                </label>
              </div>
            </div>

            <!-- Per-SSID wireless settings -->
            {#if network.ssids.length > 0}
              <div class="ssid-settings">
                <h4 class="collapsible-header" on:click={() => { wifiSettingsOpen[network.id] = !wifiSettingsOpen[network.id]; wifiSettingsOpen = wifiSettingsOpen; }}>
                  <span class="collapse-chevron">{wifiSettingsOpen[network.id] ? '▼' : '▶'}</span> WiFi Settings
                </h4>
                {#if wifiSettingsOpen[network.id]}
                {#each network.ssids as ssid (ssid.section)}
                  <div class="ssid-card" class:ssid-disabled={ssid.editDisabled}>
                    <div class="ssid-header">
                      <span class="ssid-band">{ssid.band}</span>
                      <div class="option-item">
                        <input type="checkbox" id="en-{ssid.section}" checked={!ssid.editDisabled}
                               on:change={() => { ssid.editDisabled = !ssid.editDisabled; networks = networks; }}>
                        <label for="en-{ssid.section}">Enabled</label>
                      </div>
                    </div>
                    <div class="ssid-fields">
                      <div class="form-group">
                        <label>SSID</label>
                        <input type="text" bind:value={ssid.editName} placeholder="Network name">
                      </div>
                      <div class="form-group">
                        <label>Password</label>
                        <input type="text" bind:value={ssid.editPassword} placeholder="Leave empty to keep current" autocomplete="off">
                      </div>
                      <div class="form-group">
                        <label>Security</label>
                        <select bind:value={ssid.editEncryption}>
                          <option value="psk2">WPA2-PSK</option>
                          <option value="sae">WPA3-SAE</option>
                          <option value="sae-mixed">WPA2/WPA3 Mixed</option>
                          <option value="none">Open (no password)</option>
                        </select>
                      </div>
                      <div class="option-item">
                        <input type="checkbox" id="hid-{ssid.section}" bind:checked={ssid.editHidden}>
                        <label for="hid-{ssid.section}">Hidden SSID</label>
                      </div>
                    </div>
                    {#if ssidDirty(ssid)}
                      <button class="btn-primary btn-sm" on:click={() => updateSsid(network, ssid)}>Save {ssid.band}</button>
                    {/if}
                  </div>
                {/each}
                {/if}
              </div>
            {/if}

            <!-- Access rules table -->
            {#if otherNetworks(network.id).length > 0}
              <div class="rules-section">
                <h4>Network Access</h4>
                <table class="rules-table">
                  <thead><tr><th>Network</th><th>Inbound</th><th>Outbound</th></tr></thead>
                  <tbody>
                    {#each otherNetworks(network.id) as other}
                      <tr>
                        <td class="rule-network">{ssidLabel(other)}</td>
                        <td>
                          <button class="rule-toggle" class:allowed={pendingRules.find(r => r.src_zone === other.id && r.dest_zone === network.id)?.allowed}
                                  on:click={() => toggleRule(other.id, network.id)}>
                            {pendingRules.find(r => r.src_zone === other.id && r.dest_zone === network.id)?.allowed ? '✅' : '🔒'}
                          </button>
                        </td>
                        <td>
                          <button class="rule-toggle" class:allowed={pendingRules.find(r => r.src_zone === network.id && r.dest_zone === other.id)?.allowed}
                                  on:click={() => toggleRule(network.id, other.id)}>
                            {pendingRules.find(r => r.src_zone === network.id && r.dest_zone === other.id)?.allowed ? '✅' : '🔒'}
                          </button>
                        </td>
                      </tr>
                    {/each}
                  </tbody>
                </table>
                {#if rulesChanged}
                  <button class="btn-primary btn-save" on:click={saveRules} disabled={savingRules}>
                    {savingRules ? 'Saving...' : 'Save Rules'}
                  </button>
                {/if}
                <p class="rules-hint">Inbound = other → this. Outbound = this → other. Changes apply after Save.</p>
              </div>
            {/if}

            <!-- Devices grouped by connection -->
            <div class="devices-section">
              <h4>Devices ({networkDevices[network.id]?.length || 0})</h4>
              {#if !networkDevices[network.id]}
                <div class="loading-sm">Loading...</div>
              {:else if networkDevices[network.id].length === 0}
                <div class="empty-sm">No devices on this network</div>
              {:else}
                {#each groupDevices(networkDevices[network.id]) as [group, devices]}
                  <div class="device-group-label">{group}</div>
                  <div class="device-list">
                    {#each devices as device}
                      <button class="device-row" on:click={() => selectDevice(device.mac)}>
                        <span class="device-dot" class:online={device.online}></span>
                        <span class="device-name">{device.display_name}</span>
                        <span class="device-meta">{device.ip} · {device.mac}</span>
                        <span class="device-arrow">›</span>
                      </button>
                    {/each}
                  </div>
                {/each}
              {/if}
            </div>

            <!-- Delete -->
            {#if canDelete(network)}
              <div class="delete-section">
                <button class="btn-danger btn-sm" on:click={() => deleteNetwork(network.id)} disabled={deleting === network.id}>
                  {deleting === network.id ? 'Deleting...' : 'Delete Network'}
                </button>
              </div>
            {/if}
          </div>
        {/if}
      </div>
    {/each}

    <!-- Create network -->
    {#if showCreateForm}
      <div class="create-form">
        <h4>Create Network</h4>
        <div class="form-group"><label>Name</label><input type="text" bind:value={createName} placeholder="e.g. IoT"></div>
        <div class="form-group"><label>Password</label><input type="password" bind:value={createPassword} placeholder="Min 8 characters"></div>
        <div class="option-item">
          <input type="checkbox" id="create-iso" bind:checked={createIsolation}>
          <label for="create-iso">Device isolation <span class="opt-hint">— recommended for IoT</span></label>
        </div>
        <div class="create-actions">
          <button class="btn-outline btn-sm" on:click={() => { showCreateForm = false; }}>Cancel</button>
          <button class="btn-primary btn-sm" on:click={createNetwork} disabled={creating}>{creating ? 'Creating...' : 'Create'}</button>
        </div>
      </div>
    {:else}
      <button class="btn-outline create-btn" on:click={() => { showCreateForm = true; }}>+ Create Network</button>
    {/if}

    <!-- Exceptions -->
    <div class="exceptions-section">
      <div class="section-header">
        <h3>Exceptions ({exceptions.length})</h3>
        <button class="btn-outline btn-sm" on:click={() => { showExceptionModal = true; }}>+ Add Exception</button>
      </div>
      {#if exceptions.length === 0}
        <p class="empty-sm">No exceptions. Exceptions allow specific devices to communicate across blocked networks.</p>
      {:else}
        <div class="exception-list">
          {#each exceptions as exc}
            <div class="exception-row">
              <span class="exc-label">{exc.label || `${exc.from_ip} → ${exc.to_ip}`}</span>
              <span class="exc-direction">{exc.direction === 'both' ? '⟷' : exc.direction === 'outbound' ? '→' : '←'}</span>
              <span class="exc-ips">{exc.from_ip} — {exc.to_ip}</span>
              <button class="exc-delete" on:click={() => removeException(exc.id)} title="Remove">✕</button>
            </div>
          {/each}
        </div>
      {/if}
    </div>
  {/if}
</div>

{#if showExceptionModal}
  <ExceptionModal {networks} {networkDevices}
    on:save={(e) => handleAddException(e.detail)}
    on:close={() => { showExceptionModal = false; }}
    on:loadDevices={(e) => loadDevices(e.detail)} />
{/if}

<DeviceModal device={selectedDevice} on:close={() => selectedMac = null} on:reload={loadData} />

<style>
  .lan-page { max-width: 800px; margin: 0 auto; padding: 20px; }
  .page-header { display: flex; align-items: center; gap: 12px; margin-bottom: 24px; }
  .page-header h2 { margin: 0; font-size: 1.3rem; }
  .btn-back { background: none; border: none; color: var(--accent); cursor: pointer; font-size: .9rem; padding: 4px 8px; }
  .btn-back:hover { text-decoration: underline; }
  .loading { text-align: center; padding: 40px; color: var(--fg3); }

  .network-card { background: var(--bg2); border: 1px solid var(--border); border-radius: var(--radius); margin-bottom: 12px; overflow: hidden; }
  .network-card.disabled-net { opacity: 0.6; }
  .network-card.expanded { border-color: var(--accent); }
  .network-header { display: flex; align-items: center; padding: 14px 16px; cursor: pointer; gap: 12px; }
  .network-header:hover { background: var(--bg3); }
  .network-info { flex: 1; }
  .network-name { font-weight: 600; font-size: .95rem; }
  .network-meta { display: block; font-size: .75rem; color: var(--fg3); margin-top: 2px; }
  .network-badges { display: flex; gap: 6px; }
  .chevron { color: var(--fg3); font-size: .8rem; }

  .badge { padding: 2px 8px; border-radius: 10px; font-size: .7rem; font-weight: 500; }
  .badge-green { background: rgba(46,204,113,.15); color: var(--green); }
  .badge-red { background: rgba(231,76,60,.15); color: var(--red); }
  .badge-off { background: var(--bg3); color: var(--fg3); }
  .badge-count { background: var(--bg3); color: var(--fg2); }

  .network-body { padding: 0 16px 16px; border-top: 1px solid var(--border); }
  .toggles-row { display: flex; align-items: center; gap: 16px; padding: 12px 0; flex-wrap: wrap; }
  .option-item { display: flex; align-items: center; gap: 8px; padding: 6px 0; }
  .option-item input[type="checkbox"] { width: 18px; height: 18px; accent-color: var(--accent); cursor: pointer; flex-shrink: 0; }
  .option-item label { font-size: .85rem; cursor: pointer; }
  .opt-hint { color: var(--fg3); font-weight: 400; }

  .ssid-settings { margin-top: 12px; }
  .ssid-settings h4 { font-size: .85rem; color: var(--fg2); margin: 0 0 8px; }
  .ssid-card { background: var(--bg); border-radius: var(--radius-xs); padding: 14px; margin-bottom: 8px; }
  .ssid-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; }
  .ssid-band { font-size: .75rem; font-weight: 600; color: var(--fg3); text-transform: uppercase; letter-spacing: .04em; }
  .ssid-disabled { opacity: 0.5; }
  .ssid-disabled .ssid-fields { pointer-events: none; }
  .ssid-fields .form-group { margin-bottom: 10px; }

  .rules-section { margin-top: 12px; }
  .rules-section h4 { font-size: .85rem; color: var(--fg2); margin: 0 0 8px; }
  .rules-table { width: 100%; border-collapse: collapse; font-size: .85rem; }
  .rules-table th { text-align: left; padding: 6px 10px; font-size: .7rem; text-transform: uppercase; color: var(--fg3); letter-spacing: .04em; border-bottom: 1px solid var(--border); }
  .rules-table td { padding: 8px 10px; border-bottom: 1px solid var(--border); }
  .rule-network { font-weight: 500; }
  .rule-toggle { background: none; border: 1px solid var(--border); border-radius: 6px; padding: 4px 12px; cursor: pointer; font-size: .9rem; transition: var(--transition); }
  .rule-toggle:hover { border-color: var(--accent); }
  .rule-toggle.allowed { background: rgba(46,204,113,.1); border-color: var(--green); }
  .btn-save { margin-top: 10px; }
  .rules-hint { font-size: .7rem; color: var(--fg3); margin-top: 6px; }

  .devices-section { margin-top: 16px; }
  .devices-section h4 { font-size: .85rem; color: var(--fg2); margin: 0 0 8px; }
  .device-group-label { font-size: .7rem; color: var(--fg3); text-transform: uppercase; letter-spacing: .04em; margin: 8px 0 4px; }
  .device-list { display: flex; flex-direction: column; gap: 4px; }
  .collapsible-header { cursor: pointer; user-select: none; }
  .collapsible-header:hover { color: var(--fg); }
  .collapse-chevron { font-size: .7rem; color: var(--fg3); margin-right: 4px; }

  .device-row { display: flex; align-items: center; gap: 8px; padding: 6px 10px; background: var(--bg); border: none; border-radius: var(--radius-xs); font-size: .82rem; width: 100%; text-align: left; color: var(--fg); cursor: pointer; font-family: inherit; }
  .device-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--fg3); flex-shrink: 0; }
  .device-dot.online { background: var(--green); }
  .device-name { font-weight: 500; flex: 1; }
  .device-meta { color: var(--fg3); font-size: .75rem; font-family: var(--font-mono); }
  .device-row:hover { background: var(--bg3); }
  .device-arrow { color: var(--fg3); font-size: 1.1rem; }
  .loading-sm, .empty-sm { font-size: .8rem; color: var(--fg3); padding: 8px; }

  .delete-section { margin-top: 16px; padding-top: 12px; border-top: 1px solid var(--border); }
  .btn-danger { background: var(--red); color: #fff; border: none; padding: 6px 14px; border-radius: var(--radius-xs); cursor: pointer; font-size: .8rem; }
  .btn-danger:hover { opacity: .85; }
  .btn-danger:disabled { opacity: .5; cursor: not-allowed; }

  .create-btn { display: block; width: 100%; margin: 12px 0; padding: 14px; text-align: center; border-style: dashed; }
  .create-form { background: var(--bg2); border: 1px solid var(--border); border-radius: var(--radius); padding: 16px; margin: 12px 0; }
  .create-form h4 { margin: 0 0 12px; font-size: .95rem; }
  .create-actions { display: flex; gap: 8px; margin-top: 12px; justify-content: flex-end; }

  .exceptions-section { margin-top: 24px; }
  .section-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; }
  .section-header h3 { margin: 0; font-size: 1rem; }
  .exception-list { display: flex; flex-direction: column; gap: 6px; }
  .exception-row { display: flex; align-items: center; gap: 10px; padding: 10px 12px; background: var(--bg2); border: 1px solid var(--border); border-radius: var(--radius-xs); font-size: .85rem; }
  .exc-label { flex: 1; font-weight: 500; }
  .exc-direction { font-size: 1rem; }
  .exc-ips { color: var(--fg3); font-size: .75rem; font-family: var(--font-mono); }
  .exc-delete { background: none; border: none; color: var(--fg3); cursor: pointer; font-size: .9rem; padding: 2px 6px; }
  .exc-delete:hover { color: var(--red); }
</style>
