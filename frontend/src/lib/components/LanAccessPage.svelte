<script>
  import { api } from '../api.js';
  import { showToast } from '../stores/app.js';
  import { createEventDispatcher, onMount } from 'svelte';
  import ExceptionModal from './ExceptionModal.svelte';

  const dispatch = createEventDispatcher();

  let networks = [];
  let accessRules = [];
  let exceptions = [];
  let loading = true;
  let savingRules = false;
  let expandedZone = null;
  let networkDevices = {};
  let showExceptionModal = false;
  let pendingRules = []; // staged changes before save

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
      networkDevices = networkDevices; // trigger reactivity
    } catch (e) {
      showToast(e.message, true);
    }
  };

  const toggleExpand = (zoneId) => {
    if (expandedZone === zoneId) {
      expandedZone = null;
    } else {
      expandedZone = zoneId;
      loadDevices(zoneId);
    }
  };

  const getRule = (src, dest) =>
    pendingRules.find(r => r.src_zone === src && r.dest_zone === dest);

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

  const ssidLabel = (network) =>
    network.ssids.map(s => s.name).join(' / ') || network.zone;
</script>

<div class="lan-page">
  <div class="page-header">
    <button class="btn-back" on:click={() => dispatch('back')}>← Back</button>
    <h2>LAN Access</h2>
  </div>

  {#if loading}
    <div class="loading">Loading networks...</div>
  {:else if networks.length === 0}
    <div class="empty-state">No networks found on the router.</div>
  {:else}
    <!-- Networks -->
    {#each networks as network (network.id)}
      <div class="network-card" class:expanded={expandedZone === network.id} class:disabled={!network.enabled}>
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
            <!-- Isolation toggle -->
            <div class="isolation-row">
              <label class="toggle-label">
                <input type="checkbox" checked={network.isolation}
                       on:change={() => toggleIsolation(network)}
                       disabled={!network.enabled}>
                Device isolation
              </label>
              <span class="toggle-hint">
                {network.isolation
                  ? 'Devices on this network cannot see each other'
                  : 'Devices on this network communicate freely'}
              </span>
            </div>

            <!-- Access rules table -->
            {#if otherNetworks(network.id).length > 0}
              <div class="rules-section">
                <h4>Network Access</h4>
                <table class="rules-table">
                  <thead>
                    <tr>
                      <th>Network</th>
                      <th title="Traffic from other networks TO this network">Inbound</th>
                      <th title="Traffic FROM this network to other networks">Outbound</th>
                    </tr>
                  </thead>
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
                <p class="rules-hint">
                  Inbound = other network → this network.
                  Outbound = this network → other network.
                  Changes apply after Save.
                </p>
              </div>
            {/if}

            <!-- Devices list -->
            <div class="devices-section">
              <h4>Devices ({networkDevices[network.id]?.length || 0})</h4>
              {#if !networkDevices[network.id]}
                <div class="loading-sm">Loading...</div>
              {:else if networkDevices[network.id].length === 0}
                <div class="empty-sm">No devices on this network</div>
              {:else}
                <div class="device-list">
                  {#each networkDevices[network.id] as device}
                    <div class="device-row">
                      <span class="device-dot" class:online={device.online}></span>
                      <span class="device-name">{device.display_name}</span>
                      <span class="device-meta">{device.ip} · {device.iface || device.mac}</span>
                    </div>
                  {/each}
                </div>
              {/if}
            </div>
          </div>
        {/if}
      </div>
    {/each}

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
              <span class="exc-direction">
                {exc.direction === 'both' ? '⟷' : exc.direction === 'outbound' ? '→' : '←'}
              </span>
              <span class="exc-ips">{exc.from_ip} — {exc.to_ip}</span>
              <button class="exc-delete" on:click={() => removeException(exc.id)} title="Remove exception">✕</button>
            </div>
          {/each}
        </div>
      {/if}
    </div>
  {/if}
</div>

{#if showExceptionModal}
  <ExceptionModal
    {networks}
    {networkDevices}
    on:save={(e) => handleAddException(e.detail)}
    on:close={() => { showExceptionModal = false; }}
    on:loadDevices={(e) => loadDevices(e.detail)}
  />
{/if}

<style>
  .lan-page { max-width: 800px; margin: 0 auto; padding: 20px; }
  .page-header { display: flex; align-items: center; gap: 12px; margin-bottom: 24px; }
  .page-header h2 { margin: 0; font-size: 1.3rem; }
  .btn-back { background: none; border: none; color: var(--accent); cursor: pointer; font-size: .9rem; padding: 4px 8px; }
  .btn-back:hover { text-decoration: underline; }

  .loading, .empty-state { text-align: center; padding: 40px; color: var(--fg3); }

  .network-card { background: var(--bg2); border: 1px solid var(--border); border-radius: var(--radius); margin-bottom: 12px; overflow: hidden; }
  .network-card.disabled { opacity: 0.6; }
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

  .isolation-row { display: flex; align-items: center; gap: 12px; padding: 12px 0; }
  .toggle-label { font-size: .85rem; cursor: pointer; display: flex; align-items: center; gap: 6px; }
  .toggle-hint { font-size: .75rem; color: var(--fg3); }

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
  .device-list { display: flex; flex-direction: column; gap: 4px; }
  .device-row { display: flex; align-items: center; gap: 8px; padding: 6px 10px; background: var(--bg); border-radius: var(--radius-xs); font-size: .82rem; }
  .device-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--fg3); flex-shrink: 0; }
  .device-dot.online { background: var(--green); }
  .device-name { font-weight: 500; flex: 1; }
  .device-meta { color: var(--fg3); font-size: .75rem; font-family: monospace; }
  .loading-sm, .empty-sm { font-size: .8rem; color: var(--fg3); padding: 8px; }

  .exceptions-section { margin-top: 24px; }
  .section-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; }
  .section-header h3 { margin: 0; font-size: 1rem; }
  .exception-list { display: flex; flex-direction: column; gap: 6px; }
  .exception-row { display: flex; align-items: center; gap: 10px; padding: 10px 12px; background: var(--bg2); border: 1px solid var(--border); border-radius: var(--radius-xs); font-size: .85rem; }
  .exc-label { flex: 1; font-weight: 500; }
  .exc-direction { font-size: 1rem; }
  .exc-ips { color: var(--fg3); font-size: .75rem; font-family: monospace; }
  .exc-delete { background: none; border: none; color: var(--fg3); cursor: pointer; font-size: .9rem; padding: 2px 6px; }
  .exc-delete:hover { color: var(--red); }
</style>
