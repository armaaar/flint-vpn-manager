<script>
  import { api } from '../../api';
  import { devices, showToast } from '../../stores/app';
  import { isOnline } from '../../utils/device';
  import { createEventDispatcher, onMount } from 'svelte';
  import ExceptionModal from './ExceptionModal.svelte';
  import DeviceModal from '../modals/DeviceModal.svelte';

  const dispatch = createEventDispatcher();

  let networks = [];
  let accessRules = [];
  let exceptions = [];
  let loading = true;
  let savingRules = false;
  let expandedZone = null;
  let showExceptionModal = false;
  let pendingRules = [];

  // Derive per-network device lists reactively from the global devices store (SSE-updated)
  $: networkDevices = (() => {
    const byZone = {};
    for (const d of $devices) {
      const zone = d.network_zone;
      if (zone) {
        if (!byZone[zone]) byZone[zone] = [];
        byZone[zone].push(d);
      }
    }
    return byZone;
  })();

  // Create form
  let showCreateForm = false;
  let createName = '';
  let createPassword = '';
  let createIsolation = true;
  let creating = false;

  // Delete
  let deleting = null;

  // Per-action loading states
  let togglingIsolation = null;   // zone id
  let togglingEnabled = null;     // zone id
  let savingSsid = null;          // ssid section
  let removingException = null;   // exception id

  // WiFi warning confirmation
  let wifiWarning = null; // { message, onConfirm }

  function confirmWifiAction(message, onConfirm) {
    wifiWarning = { message, onConfirm };
  }

  function dismissWarning() { wifiWarning = null; }

  async function acceptWarning() {
    const fn = wifiWarning.onConfirm;
    wifiWarning = null;
    await fn();
  }

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

  const toggleExpand = (zoneId) => {
    if (expandedZone === zoneId) {
      expandedZone = null;
    } else {
      expandedZone = zoneId;
      const network = networks.find(n => n.id === zoneId);
      if (network) ensureSsidEdits(network);
      networks = networks;
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

  const _doToggleIsolation = async (network) => {
    togglingIsolation = network.id;
    const newState = !network.isolation;
    try {
      await api.setIsolation(network.id, newState);
      network.isolation = newState;
      networks = networks;
      showToast(`${newState ? 'Isolation enabled' : 'Isolation disabled'}`);
    } catch (e) {
      showToast(e.message, true);
    } finally {
      togglingIsolation = null;
    }
  };
  const toggleIsolation = (network) => {
    const bands = network.ssids.filter(s => !s.disabled).map(s => s.band).join(' & ');
    confirmWifiAction(
      `This will briefly disconnect WiFi clients on ${bands || 'all bands'} of "${ssidLabel(network)}".`,
      () => _doToggleIsolation(network),
    );
  };

  const _doToggleEnabled = async (network) => {
    togglingEnabled = network.id;
    const newState = !network.enabled;
    try {
      await api.updateNetwork(network.id, { enabled: newState });
      network.enabled = newState;
      networks = networks;
      showToast(`Network ${newState ? 'enabled' : 'disabled'}`);
    } catch (e) {
      showToast(e.message, true);
    } finally {
      togglingEnabled = null;
    }
  };
  const toggleEnabled = (network) => {
    const action = network.enabled ? 'Disabling' : 'Enabling';
    confirmWifiAction(
      `${action} will briefly disconnect WiFi clients on both bands of "${ssidLabel(network)}".`,
      () => _doToggleEnabled(network),
    );
  };

  const _doUpdateSsid = async (network, ssid) => {
    const settings = {};
    if (ssid.editName !== ssid.name) settings.ssid = ssid.editName;
    if (ssid.editPassword !== (ssid.password || '')) settings.key = ssid.editPassword;
    if (ssid.editHidden !== ssid.hidden) settings.hidden = ssid.editHidden;
    if (ssid.editEncryption !== ssid.encryption) settings.encryption = ssid.editEncryption;
    if (ssid.editDisabled !== ssid.disabled) settings.disabled = ssid.editDisabled;
    if (Object.keys(settings).length === 0) return;
    savingSsid = ssid.section;
    try {
      await api.updateNetwork(network.id, { ssids: [{ section: ssid.section, ...settings }] });
      if (settings.ssid) ssid.name = settings.ssid;
      if (settings.key) ssid.password = settings.key;
      if ('hidden' in settings) ssid.hidden = settings.hidden;
      if ('encryption' in settings) ssid.encryption = settings.encryption;
      if ('disabled' in settings) ssid.disabled = settings.disabled;
      ssid.editPassword = '';
      networks = networks;
      showToast('WiFi settings updated');
    } catch (e) {
      showToast(e.message, true);
    } finally {
      savingSsid = null;
    }
  };
  const updateSsid = (network, ssid) => {
    confirmWifiAction(
      `This will briefly disconnect WiFi clients on ${ssid.band} of "${ssidLabel(network)}".`,
      () => _doUpdateSsid(network, ssid),
    );
  };

  const _doCreateNetwork = async () => {
    creating = true;
    try {
      await api.createNetwork({ name: createName, password: createPassword, isolation: createIsolation });
      showCreateForm = false;
      createName = '';
      createPassword = '';
      showToast('Network created');
      await loadData();
    } catch (e) {
      showToast(e.message, true);
    } finally {
      creating = false;
    }
  };
  const createNetwork = () => {
    if (!createName || !createPassword || createPassword.length < 8) {
      showToast('Name and password (8+ chars) required', true);
      return;
    }
    confirmWifiAction(
      'Creating a network requires reloading the WiFi driver. ALL WiFi clients on ALL bands will disconnect for ~15 seconds.',
      _doCreateNetwork,
    );
  };

  const _doDeleteNetwork = async (zoneId) => {
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
  const deleteNetwork = (zoneId) => {
    const net = networks.find(n => n.id === zoneId);
    const label = net ? ssidLabel(net) : zoneId;
    confirmWifiAction(
      `Deleting "${label}" requires reloading the WiFi driver. ALL WiFi clients on ALL bands will disconnect for ~15 seconds.`,
      () => _doDeleteNetwork(zoneId),
    );
  };

  let editingException = null; // exception being edited

  const handleSaveException = async (data) => {
    const isEdit = !!editingException;
    try {
      // Add new first, then delete old — so we never lose the exception on error
      const res = await api.addException(data);
      if (isEdit) {
        await api.removeException(editingException.id);
        exceptions = exceptions.filter(e => e.id !== editingException.id);
      }
      exceptions = [...exceptions, res.exception];
      showExceptionModal = false;
      editingException = null;
      showToast(isEdit ? 'Exception updated' : 'Exception added');
    } catch (e) {
      showToast(e.message, true);
    }
  };

  const editException = (exc) => {
    editingException = exc;
    showExceptionModal = true;
  };

  const removeException = async (id) => {
    removingException = id;
    try {
      await api.removeException(id);
      exceptions = exceptions.filter(e => e.id !== id);
      showToast('Exception removed');
    } catch (e) {
      showToast(e.message, true);
    } finally {
      removingException = null;
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
        ssid.editPassword = ssid.password || '';
        ssid.editHidden = ssid.hidden;
        ssid.editEncryption = ssid.encryption;
        ssid.editDisabled = ssid.disabled;
        ssid.showPassword = false;
      }
    }
  };

  const ssidDirty = (ssid) =>
    ssid.editName !== ssid.name ||
    ssid.editPassword !== (ssid.password || '') ||
    ssid.editHidden !== ssid.hidden ||
    ssid.editEncryption !== ssid.encryption ||
    ssid.editDisabled !== ssid.disabled;
</script>

<div class="lan-page">
  <div class="page-header">
    <button class="btn-back" on:click={() => dispatch('back')}>← Back</button>
    <h2>Networks</h2>
    <div style="flex:1"></div>
    <button class="btn-outline btn-sm" on:click={loadData} disabled={loading}>
      {#if loading}<span class="spinner-inline"></span>{:else}↻ Refresh{/if}
    </button>
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
            <span class="badge badge-count">{(networkDevices[network.id] || []).length} devices</span>
          </div>
          <span class="chevron">{expandedZone === network.id ? '▼' : '▶'}</span>
        </div>

        {#if expandedZone === network.id}
          <div class="network-body">
            <!-- Enable / Isolation toggles -->
            <div class="toggles-row">
              {#if network.id !== 'lan'}
                <div class="option-item">
                  <input type="checkbox" id="net-en-{network.id}" checked={network.enabled}
                         on:change={() => toggleEnabled(network)} disabled={togglingEnabled === network.id}>
                  <label for="net-en-{network.id}">
                    {#if togglingEnabled === network.id}<span class="spinner-inline"></span>{/if}
                    Enabled
                  </label>
                </div>
              {/if}
              <div class="option-item">
                <input type="checkbox" id="net-iso-{network.id}" checked={network.isolation}
                       on:change={() => toggleIsolation(network)} disabled={!network.enabled || togglingIsolation === network.id}>
                <label for="net-iso-{network.id}">
                  {#if togglingIsolation === network.id}<span class="spinner-inline"></span>{/if}
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
                        <div class="password-field">
                          <input type={ssid.showPassword ? 'text' : 'password'} bind:value={ssid.editPassword} autocomplete="off">
                          <button type="button" class="password-toggle" on:click={() => { ssid.showPassword = !ssid.showPassword; networks = networks; }}
                                  title={ssid.showPassword ? 'Hide password' : 'Show password'}>
                            {ssid.showPassword ? '🙈' : '👁'}
                          </button>
                        </div>
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
                      <button class="btn-primary btn-sm" on:click={() => updateSsid(network, ssid)} disabled={savingSsid === ssid.section}>
                        {savingSsid === ssid.section ? 'Saving...' : `Save ${ssid.band}`}
                      </button>
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
              <h4>Devices ({(networkDevices[network.id] || []).length})</h4>
              {#if (networkDevices[network.id] || []).length === 0}
                <div class="empty-sm">No devices on this network</div>
              {:else}
                {#each groupDevices(networkDevices[network.id]) as [group, devs]}
                  <div class="device-group-label">{group}</div>
                  <div class="device-list">
                    {#each devs as device}
                      <button class="device-row" on:click={() => selectDevice(device.mac)}>
                        <span class="device-dot" class:online={isOnline(device)}></span>
                        <span class="device-name">{device.display_name}</span>
                        <span class="device-meta">{device.ip} · {device.mac.toUpperCase()}</span>
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
        <button class="btn-outline btn-sm" on:click={() => { editingException = null; showExceptionModal = true; }}>+ Add Exception</button>
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
              <button class="exc-edit" on:click={() => editException(exc)} title="Edit">✎</button>
              <button class="exc-delete" on:click={() => removeException(exc.id)} title="Remove" disabled={removingException === exc.id}>
                {removingException === exc.id ? '⏳' : '✕'}
              </button>
            </div>
          {/each}
        </div>
      {/if}
    </div>
  {/if}
</div>

{#if showExceptionModal}
  <ExceptionModal {networks} {networkDevices} exception={editingException}
    on:save={(e) => handleSaveException(e.detail)}
    on:close={() => { showExceptionModal = false; editingException = null; }} />
{/if}

<DeviceModal device={selectedDevice} on:close={() => selectedMac = null} on:reload={loadData} />

{#if wifiWarning}
<div class="modal-overlay active" on:click|self={dismissWarning}>
  <div class="modal wifi-warning-modal">
    <div class="modal-header">
      <h2>WiFi Restart Required</h2>
      <button class="modal-close" on:click={dismissWarning}>&times;</button>
    </div>
    <div class="modal-body">
      <div class="wifi-warning-icon">&#9888;</div>
      <p class="wifi-warning-text">{wifiWarning.message}</p>
      <p class="wifi-warning-hint">Devices will automatically reconnect once the restart completes.</p>
    </div>
    <div class="modal-footer">
      <button class="btn-outline" on:click={dismissWarning}>Cancel</button>
      <button class="btn-primary" on:click={acceptWarning}>Continue</button>
    </div>
  </div>
</div>
{/if}

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
  .exc-edit { background: none; border: none; color: var(--fg3); cursor: pointer; font-size: .9rem; padding: 2px 6px; }
  .exc-edit:hover { color: var(--accent); }
  .exc-delete:hover { color: var(--red); }
  .exc-delete:disabled { opacity: .5; cursor: not-allowed; }

  .spinner-inline { display: inline-block; width: 12px; height: 12px; border: 2px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: spin .6s linear infinite; vertical-align: middle; margin-right: 4px; }
  @keyframes spin { to { transform: rotate(360deg); } }

  .password-field { display: flex; align-items: center; gap: 0; position: relative; }
  .password-field input { flex: 1; padding-right: 36px; }
  .password-toggle { position: absolute; right: 4px; background: none; border: none; cursor: pointer; font-size: 1rem; padding: 4px 6px; color: var(--fg3); line-height: 1; }
  .password-toggle:hover { color: var(--fg); }

  .wifi-warning-modal { max-width: 420px; }
  .wifi-warning-icon { font-size: 2rem; text-align: center; margin-bottom: 8px; color: var(--amber); }
  .wifi-warning-text { font-size: .9rem; line-height: 1.5; margin: 0 0 8px; }
  .wifi-warning-hint { font-size: .8rem; color: var(--fg3); margin: 0; }
</style>
