<script>
  import { profiles, devices, unassignedDevices, protonLoggedIn, showToast, movingDevices } from '../stores/app.js';
  import { api } from '../api.js';
  import { deviceIcon, isRandomMac, isOnline } from '../device-utils.js';
  import { dndzone } from 'svelte-dnd-action';
  import GroupCard from './GroupCard.svelte';
  import DeviceModal from './DeviceModal.svelte';
  import GroupModal from './GroupModal.svelte';
  import ServerPicker from './ServerPicker.svelte';
  import SettingsPage from './SettingsPage.svelte';
  import LanAccessPage from './LanAccessPage.svelte';
  import LogsModal from './LogsModal.svelte';

  let refreshing = false;
  let initialLoading = true;
  let location = null;
  let locationLoading = false;
  let selectedDevice = null;
  let showCreate = false;
  let editProfile = null;
  let dashboardView = 'dashboard'; // 'dashboard' | 'settings' | 'lan-access'
  let settingsTab = '';  // passed to SettingsPage from hash
  let showLogs = false;
  let showServerPicker = false;
  let serverPickerProfileId = null;
  let serverPickerCallback = null;
  let serverPickerProtocol = 'wireguard';

  import { onMount, onDestroy } from 'svelte';
  import { TRIGGERS, SOURCES } from 'svelte-dnd-action';
  const MAC_RE = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i;

  // Local copy of profiles for DnD manipulation
  let groupItems = [];
  $: groupItems = $profiles.map(p => ({ ...p }));

  function readHash() {
    const hash = window.location.hash.replace('#', '');
    if (hash.startsWith('settings')) {
      dashboardView = 'settings';
      settingsTab = hash.split('/')[1] || '';
    } else if (hash === 'lan-access') {
      dashboardView = 'lan-access';
      settingsTab = '';
    } else {
      dashboardView = 'dashboard';
      settingsTab = '';
    }
  }

  function navigateTo(view, tab = '') {
    if (view === 'settings') {
      window.location.hash = tab ? `settings/${tab}` : 'settings';
    } else if (view === 'lan-access') {
      window.location.hash = 'lan-access';
    } else {
      window.location.hash = '';
    }
    dashboardView = view;
    settingsTab = tab;
  }

  function onHashChange() { readHash(); }

  onMount(async () => {
    readHash();
    window.addEventListener('hashchange', onHashChange);
    await reload();
    initialLoading = false;
    loadLocation();
  });

  onDestroy(() => {
    if (typeof window !== 'undefined') window.removeEventListener('hashchange', onHashChange);
  });

  let locationError = false;
  async function loadLocation() {
    locationLoading = true;
    locationError = false;
    try {
      location = await api.getLocation();
    } catch {
      location = null;
      locationError = true;
    }
    locationLoading = false;
  }

  async function reload() {
    const [p, d] = await Promise.all([api.getProfiles(), api.getDevices()]);
    profiles.set(p);
    devices.set(d);
  }

  function handleGroupDndConsider(e) {
    groupItems = e.detail.items;
  }

  async function handleGroupDndFinalize(e) {
    groupItems = e.detail.items;
    const newOrder = groupItems.map(p => p.id);
    profiles.set(groupItems);
    await api.reorderProfiles(newOrder);
  }

  // Unassigned devices DnD
  let unassignedItems = [];
  let draggingUnassigned = false;
  $: if (!draggingUnassigned) unassignedItems = $unassignedDevices.map(d => ({ ...d, id: d.mac }));

  function handleUnassignedDndConsider(e) {
    draggingUnassigned = true;
    unassignedItems = e.detail.items;
  }

  async function handleUnassignedDndFinalize(e) {
    unassignedItems = e.detail.items;
    const currentMacs = new Set($unassignedDevices.map(d => d.mac));
    const newDevices = unassignedItems.filter(d => !currentMacs.has(d.mac));

    // Optimistically update the store
    if (newDevices.length > 0) {
      const newMacs = new Set(newDevices.map(d => d.mac));
      movingDevices.update(s => { newMacs.forEach(m => s.add(m)); return new Set(s); });
      devices.update(list => {
        for (const dev of list) {
          if (newMacs.has(dev.mac)) dev.profile_id = null;
        }
        return [...list];
      });
    }

    draggingUnassigned = false;

    for (const d of newDevices) {
      if (!d.mac || !MAC_RE.test(d.mac)) {
        console.warn('DnD: skipping invalid MAC', d.mac, d.id);
        continue;
      }
      await api.assignDevice(d.mac, null);
    }
    if (newDevices.length > 0) {
      await reload();
      movingDevices.update(s => { newDevices.forEach(d => s.delete(d.mac)); return new Set(s); });
    }
  }

  async function doRefresh() {
    refreshing = true;
    await api.refresh();
    await reload();
    refreshing = false;
    showToast('Refreshed');
  }

  function openServerPicker(e) {
    serverPickerProfileId = e.detail?.profileId || null;
    serverPickerCallback = null;
    showServerPicker = true;
  }

  function handleNeedServer(callback, protocol = 'wireguard') {
    serverPickerProfileId = null;
    serverPickerCallback = callback;
    serverPickerProtocol = protocol;
    showServerPicker = true;
  }

  async function handleServerSelect(e) {
    showServerPicker = false;
    const { serverId, options, scope } = e.detail;

    if (serverPickerCallback) {
      await serverPickerCallback(serverId, options, scope);
      serverPickerCallback = null;
      await reload();
      return;
    }

    if (serverPickerProfileId) {
      const res = await api.changeServer(serverPickerProfileId, {
        server_id: serverId, options, server_scope: scope,
      });
      if (res.error) {
        showToast(res.error, true);
      } else {
        showToast('Server switched');
      }
      await reload();
    }
  }
</script>

<div class="app">
  <!-- Sidebar -->
  <nav class="sidebar">
    <div class="sidebar-logo">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="28" height="28"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      FlintVPN
    </div>
    <div class="sidebar-nav">
      <a href="#" class:active={dashboardView === 'dashboard'} on:click|preventDefault={() => navigateTo('dashboard')}><span class="nav-icon">☰</span> Dashboard</a>
      <a href="#lan-access" class:active={dashboardView === 'lan-access'} on:click|preventDefault={() => navigateTo('lan-access')}><span class="nav-icon">🔗</span> LAN Access</a>
      <a href="#settings" class:active={dashboardView === 'settings'} on:click|preventDefault={() => navigateTo('settings')}><span class="nav-icon">⚙</span> Settings</a>
      <a href="#" on:click|preventDefault={() => showLogs = true}><span class="nav-icon">📋</span> Logs</a>
    </div>
    <div class="sidebar-bottom">
      {#if location}
        <a href="#" on:click|preventDefault={loadLocation} title="Your public IP as seen by ProtonVPN. Click to refresh.">
          <span class="nav-icon">🌍</span>
          <span class="location-info">
            <span class="location-ip">{location.ip}</span>
            <span class="location-detail">{location.country}{location.isp ? ' · ' + location.isp : ''}</span>
          </span>
        </a>
      {:else if locationLoading}
        <a href="#"><span class="nav-icon">🌍</span> Checking IP...</a>
      {:else if locationError}
        <a href="#" on:click|preventDefault={loadLocation}><span class="nav-icon">🌍</span> IP check failed (retry)</a>
      {:else}
        <a href="#" on:click|preventDefault={loadLocation}><span class="nav-icon">🌍</span> Check IP</a>
      {/if}
      <a href="#" title="ProtonVPN API session status. 'Ready' means we can fetch servers and generate configs.">
        <span class="nav-icon" style="color: {$protonLoggedIn ? 'var(--green)' : 'var(--red)'}">●</span>
        Proton API: {$protonLoggedIn ? 'Ready' : 'Not logged in'}
      </a>
      <a href="#" title="Number of devices seen on the router">
        <span class="nav-icon" style="color: {$devices.length > 0 ? 'var(--green)' : 'var(--fg3)'}">●</span>
        Router: {$devices.length > 0 ? $devices.length + ' devices' : 'No data'}
      </a>
    </div>
  </nav>

  <!-- Main content -->
  <div class="content">
    {#if dashboardView === 'settings'}
      <SettingsPage initialTab={settingsTab} on:back={() => navigateTo('dashboard')} on:tabchange={(e) => navigateTo('settings', e.detail)} />
    {:else if dashboardView === 'lan-access'}
      <LanAccessPage on:back={() => navigateTo('dashboard')} />
    {:else}
    <div class="content-header">
      <h2>Dashboard</h2>
      <div class="header-actions">
        <button class="btn-outline btn-sm" on:click={doRefresh} disabled={refreshing}>
          {#if refreshing}<span class="spinner"></span>{:else}↻ Refresh{/if}
        </button>
      </div>
    </div>

    <!-- Groups row -->
    {#if initialLoading}
      <div class="groups-container">
        <div class="loading-groups">
          <span class="spinner-lg"></span>
          <p>Loading groups...</p>
        </div>
      </div>
    {:else}
      <div class="groups-container"
           use:dndzone={{ items: groupItems, type: 'groups', flipDurationMs: 200, dropTargetStyle: { outline: '2px dashed var(--accent)', outlineOffset: '4px' }, dragDisabled: false }}
           on:consider={handleGroupDndConsider}
           on:finalize={handleGroupDndFinalize}>
        {#each groupItems as profile (profile.id)}
          <GroupCard {profile}
            on:edit={(e) => editProfile = e.detail}
            on:pickserver={openServerPicker}
            on:deviceselect={(e) => selectedDevice = e.detail}
            on:reload={reload} />
        {/each}
      </div>
      <div style="margin-top:-8px;margin-bottom:16px">
        <div class="add-group-card" style="width:auto;flex:none;display:inline-block">
          <button class="add-group-btn" on:click={() => { showCreate = true; }}>+ Add Group</button>
        </div>
      </div>
    {/if}

    <!-- Unassigned devices -->
    <div class="unassigned-section">
      <div class="unassigned-title">Unassigned Devices ({unassignedItems.length})</div>
      <div class="unassigned-drop-zone"
           use:dndzone={{ items: unassignedItems, type: 'devices', flipDurationMs: 150, dropTargetStyle: { outline: '2px dashed var(--fg3)', outlineOffset: '-2px' } }}
           on:consider={handleUnassignedDndConsider}
           on:finalize={handleUnassignedDndFinalize}>
        {#each unassignedItems as d (d.id)}
          <div class="unassigned-chip-wrap" class:moving={$movingDevices.has(d.mac)}>
            <button class="unassigned-chip" class:offline={!isOnline(d)}
                    on:click={() => selectedDevice = d}>
              <span class="online-dot" class:on={isOnline(d)}
                    title={isOnline(d) ? 'Online' : 'Offline'}></span>
              <span>{deviceIcon(d)}</span>
              <span>{d.display_name}</span>
              {#if isRandomMac(d.mac)}
                <span class="badge-random" title="Private/randomized MAC">⚠ Private MAC</span>
              {/if}
            </button>
          </div>
        {/each}
      </div>
      {#if unassignedItems.length === 0}
        <div class="unassigned-empty">Drop devices here to unassign them</div>
      {/if}
    </div>
    {/if}
  </div>
</div>

<!-- Modals -->
<DeviceModal device={selectedDevice} on:close={() => selectedDevice = null} on:reload={reload} />
<GroupModal bind:visible={showCreate} onNeedServer={handleNeedServer} on:reload={reload} />
<GroupModal bind:profile={editProfile} on:reload={reload} />
<ServerPicker bind:visible={showServerPicker} profileId={serverPickerProfileId} vpnProtocol={serverPickerProtocol} on:select={handleServerSelect} on:close={() => showServerPicker = false} />
<LogsModal bind:visible={showLogs} />

<style>
  .add-group-card { background: var(--surface); border-radius: var(--radius); box-shadow: var(--shadow); width: 300px; flex: 0 0 300px; padding: 24px; }
  .add-group-btn { display: flex; align-items: center; justify-content: center; gap: 8px; padding: 14px; border: 2px dashed var(--border2); border-radius: var(--radius-sm); color: var(--accent); font-size: .95rem; font-weight: 600; cursor: pointer; transition: var(--transition); background: transparent; width: 100%; }
  .add-group-btn:hover { border-color: var(--accent); background: rgba(0,180,216,.05); }
  .add-group-hint { color: var(--fg3); font-size: .8rem; text-align: center; margin-top: 8px; }

  .unassigned-section { margin-top: 24px; background: var(--surface); border-radius: var(--radius); padding: 16px 20px; }
  .unassigned-title { font-size: .9rem; font-weight: 600; margin-bottom: 10px; color: var(--fg2); }
  .unassigned-drop-zone { display: flex; flex-wrap: wrap; gap: 8px; min-height: 40px; padding: 4px; }
  .unassigned-chip-wrap { display: inline-flex; }
  .unassigned-empty { padding: 12px; text-align: center; color: var(--fg3); font-size: .82rem; }
  .unassigned-chip { display: flex; align-items: center; gap: 6px; padding: 8px 12px; background: var(--bg3); border: none; color: var(--fg); border-radius: var(--radius-xs); font-size: .825rem; cursor: pointer; transition: var(--transition); font-family: inherit; }
  .unassigned-chip:hover { background: var(--surface2); }
  .unassigned-chip.offline { opacity: .55; }
  .online-dot { width: 8px; height: 8px; border-radius: 50%; background: #636e72; flex-shrink: 0; }
  .online-dot.on { background: #2ecc71; box-shadow: 0 0 4px rgba(46,204,113,.6); }
  .unassigned-chip-wrap.moving { opacity: .5; animation: shimmer 1.2s ease-in-out infinite; pointer-events: none; }
  @keyframes shimmer { 0%, 100% { opacity: .5; } 50% { opacity: .3; } }
  .badge-random { font-size: .65rem; padding: 2px 6px; border-radius: 3px; font-weight: 600; background: rgba(243,156,18,.12); color: var(--amber); }

  .location-info { display: flex; flex-direction: column; gap: 1px; }
  .location-ip { font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: .82rem; color: var(--fg); font-weight: 500; }
  .location-detail { font-size: .7rem; color: var(--fg3); }

  .spinner { display: inline-block; width: 14px; height: 14px; border: 2px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: spin .6s linear infinite; }
  .spinner-lg { display: inline-block; width: 28px; height: 28px; border: 3px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: spin .6s linear infinite; }
  .loading-groups { display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 12px; min-height: 200px; width: 100%; color: var(--fg3); }
  @keyframes spin { to { transform: rotate(360deg); } }

  @media (max-width: 900px) {
    .add-group-card { width: 100%; flex: 1 1 100%; }
  }
</style>
