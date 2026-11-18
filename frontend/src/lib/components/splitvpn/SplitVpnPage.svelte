<script lang="ts">
  import { api } from '../../api';
  import { profiles, showToast } from '../../stores/app';
  import { createEventDispatcher, onMount } from 'svelte';
  import type { SplitVpn, SplitVpnOverview, SplitVpnConnectResult, Profile } from '../../types';
  import { timeAgo } from '../../utils/format';
  import { unixToIso } from '../../utils/splitVpn';
  import SplitVpnModal from './SplitVpnModal.svelte';
  import SplitVpnConnectModal from './SplitVpnConnectModal.svelte';
  import SplitVpnLogModal from './SplitVpnLogModal.svelte';

  const dispatch = createEventDispatcher();

  let overview: SplitVpnOverview | null = null;
  let loading = true;
  let refreshing = false;
  let installing = false;
  let showForm = false;
  let editingVpn: SplitVpn | null = null;
  let connectingVpn: SplitVpn | null = null;
  let connectManual = false;
  let logVpn: SplitVpn | null = null;
  let busyId: string | null = null;

  $: vpns = overview?.vpns || [];
  $: max = overview?.max ?? 4;
  $: atLimit = vpns.length >= max;
  $: runtimeInstalled = !!overview?.runtime?.installed;

  onMount(loadData);

  async function loadData() {
    try {
      overview = await api.getSplitVpns();
    } catch (err: any) {
      showToast(err.message || 'Failed to load split VPNs', true);
    }
    loading = false;
  }

  async function refresh() {
    refreshing = true;
    await loadData();
    refreshing = false;
  }

  function openCreate() {
    editingVpn = null;
    showForm = true;
  }

  function openEdit(vpn: SplitVpn) {
    editingVpn = vpn;
    showForm = true;
  }

  async function handleSaved() {
    showToast(editingVpn ? 'Split VPN updated' : 'Split VPN added');
    showForm = false;
    editingVpn = null;
    await loadData();
  }

  function openConnect(vpn: SplitVpn, manual = false) {
    connectManual = manual || !vpn.has_totp;
    connectingVpn = vpn;
  }

  async function handleConnected(e: CustomEvent<SplitVpnConnectResult>) {
    const name = connectingVpn?.name || 'Split VPN';
    connectingVpn = null;
    showToast(`${name} connected${e.detail.ip ? ` (${e.detail.ip})` : ''}`);
    await loadData();
  }

  async function closeConnect() {
    connectingVpn = null;
    await loadData();
  }

  async function disconnect(vpn: SplitVpn) {
    busyId = vpn.id;
    try {
      await api.disconnectSplitVpn(vpn.id);
      showToast(`${vpn.name} disconnected`);
    } catch (err: any) {
      showToast(err.message || 'Failed to disconnect', true);
    }
    await loadData();
    busyId = null;
  }

  async function remove(vpn: SplitVpn) {
    if (!confirm(`Delete split VPN "${vpn.name}"? It will be disconnected and its stored credentials removed.`)) return;
    busyId = vpn.id;
    try {
      await api.deleteSplitVpn(vpn.id);
      showToast('Split VPN deleted');
    } catch (err: any) {
      showToast(err.message || 'Failed to delete', true);
    }
    await loadData();
    busyId = null;
  }

  async function installRuntime() {
    installing = true;
    try {
      const runtime = await api.installSplitVpnRuntime();
      if (overview) overview = { ...overview, runtime };
      showToast(runtime.installed ? 'VPN client runtime installed' : 'Runtime install incomplete', !runtime.installed);
    } catch (err: any) {
      showToast(err.message || 'Runtime install failed', true);
    }
    installing = false;
    await loadData();
  }

  function groupFor(id: string, list: Profile[]): Profile | null {
    return list.find(p => p.id === id) || null;
  }

  function routeSummary(vpn: SplitVpn): string {
    const parts: string[] = [];
    const d = vpn.domains?.length || 0;
    const c = vpn.cidrs?.length || 0;
    if (d) parts.push(`${d} domain${d > 1 ? 's' : ''}`);
    if (c) parts.push(`${c} IP range${c > 1 ? 's' : ''}`);
    if (vpn.use_pushed_routes) parts.push('server-pushed networks');
    return parts.join(' · ') || 'No destinations';
  }

  function connectBlockedReason(vpn: SplitVpn): string {
    if (!runtimeInstalled) return 'Install the VPN client runtime first';
    if (!vpn.has_password) return 'No password stored — edit this VPN and enter it';
    return '';
  }
</script>

<div class="split-page">
  <div class="page-header">
    <button class="back-btn" on:click={() => dispatch('back')}>&larr; Back</button>
    <h2>Split VPNs</h2>
  </div>
  <p class="page-desc">
    Connect a third-party VPN (for example a company VPN) on the router and send only selected work domains and IP ranges
    through it, for the groups you choose. Those groups keep their normal Proton VPN for everything else.
    One-time codes are generated automatically from a stored TOTP secret.
  </p>

  {#if overview && !runtimeInstalled}
    <div class="warning-banner">
      <span>
        The router needs the <strong>VPN client runtime</strong>: the x86 Barracuda client run under emulation
        (about 70&nbsp;MB downloaded and uploaded to the router).
        {#if overview.runtime.error}<span class="banner-detail">{overview.runtime.error}</span>{/if}
      </span>
      <button class="btn-primary btn-sm" on:click={installRuntime} disabled={installing}>
        {#if installing}<span class="spinner-inline"></span> Installing…{:else}Install runtime{/if}
      </button>
    </div>
    {#if installing}
      <p class="install-note">Downloading and uploading the runtime. This can take a few minutes, so keep this page open.</p>
    {/if}
  {/if}

  {#if loading}
    <div class="loading"><span class="spinner-lg"></span><p>Loading…</p></div>
  {:else if overview}
    <div class="section-header">
      <h3>Split VPNs <span class="count">{vpns.length}/{max}</span></h3>
      <div class="header-btns">
        <button class="btn-outline btn-sm" on:click={refresh} disabled={refreshing}>{refreshing ? 'Refreshing…' : '↻ Refresh'}</button>
        <button class="btn-primary btn-sm" on:click={openCreate} disabled={atLimit}
          title={atLimit ? `At most ${max} split VPNs are supported` : ''}>+ Add Split VPN</button>
      </div>
    </div>

    {#if vpns.length === 0}
      <div class="empty-state">
        <p>No split VPNs yet. Add one to reach work resources through a company VPN without leaving Proton.</p>
      </div>
    {:else}
      <div class="vpn-list">
        {#each vpns as vpn (vpn.id)}
          {@const connected = !!vpn.status?.connected}
          {@const blocked = connectBlockedReason(vpn)}
          <div class="vpn-card" class:disabled={!vpn.enabled} class:connected>
            <div class="vpn-main">
              <div class="vpn-title">
                <span class="vpn-name">{vpn.name}</span>
                {#if connected}
                  <span class="status-badge status-on">● Connected</span>
                  {#if vpn.status?.ip}<span class="mono">{vpn.status.ip}</span>{/if}
                {:else if vpn.status?.error}
                  <span class="status-badge status-unknown" title={vpn.status.error}>● Unknown</span>
                {:else}
                  <span class="status-badge status-off">● Disconnected</span>
                {/if}
                {#if !vpn.enabled}<span class="tag">Disabled</span>{/if}
                {#if vpn.auto_connect}<span class="tag" title="Connects automatically and reconnects when the tunnel drops">Auto</span>{/if}
                {#if vpn.credentials_source === 'sops'}<span class="tag" title={`Credentials from SOPS entry split_vpns.${vpn.secret_ref}`}>SOPS</span>{/if}
                {#if vpn.credentials_error}<span class="tag tag-warn" title={vpn.credentials_error}>Credentials unavailable</span>
                {:else if !vpn.has_totp}<span class="tag tag-warn" title="No TOTP secret stored — a code must be entered on each connect">No TOTP secret</span>{/if}
              </div>
              <div class="vpn-meta">
                <span class="mono">{vpn.server}{vpn.port && vpn.port !== 691 ? `:${vpn.port}` : ''}</span>
                <span class="sep">·</span>
                <span>{routeSummary(vpn)}</span>
                <span class="sep">·</span>
                <span title={vpn.last_connected_at ? new Date(vpn.last_connected_at * 1000).toLocaleString() : ''}>
                  Last connected {timeAgo(unixToIso(vpn.last_connected_at))}
                </span>
              </div>
              <div class="group-chips">
                {#each vpn.group_ids as gid}
                  {@const g = groupFor(gid, $profiles)}
                  {#if g}
                    <span class="group-chip" style="--chip-color: {g.color}"><span>{g.icon}</span>{g.name}</span>
                  {:else}
                    <span class="group-chip chip-missing">(deleted group)</span>
                  {/if}
                {/each}
                {#if vpn.group_ids.length === 0}
                  <span class="no-groups">No groups assigned</span>
                {/if}
              </div>
            </div>

            <div class="vpn-actions">
              {#if connected}
                <button class="btn-outline btn-sm" on:click={() => disconnect(vpn)} disabled={busyId === vpn.id}>
                  {busyId === vpn.id ? 'Disconnecting…' : 'Disconnect'}
                </button>
              {:else}
                <button class="btn-primary btn-sm" on:click={() => openConnect(vpn)} disabled={!!blocked || busyId === vpn.id}
                  title={blocked || (vpn.has_totp ? '' : 'No TOTP secret stored — you will be asked for a code')}>Connect</button>
                {#if vpn.has_totp}
                  <button class="btn-icon" title="Connect with a code…" aria-label="Connect with a code"
                    on:click={() => openConnect(vpn, true)} disabled={!!blocked || busyId === vpn.id}>⌨</button>
                {/if}
              {/if}
              <button class="btn-icon" title="View log" aria-label="View log" on:click={() => logVpn = vpn}>☰</button>
              <button class="btn-icon" title="Edit" aria-label="Edit" on:click={() => openEdit(vpn)}>✎</button>
              <button class="btn-icon btn-icon-danger" title="Delete" aria-label="Delete" disabled={busyId === vpn.id}
                on:click={() => remove(vpn)}>✕</button>
            </div>
          </div>
        {/each}
      </div>
    {/if}
  {/if}
</div>

{#if showForm}
  <SplitVpnModal vpn={editingVpn} profiles={$profiles}
    on:saved={handleSaved} on:close={() => { showForm = false; editingVpn = null; }} />
{/if}

{#if connectingVpn}
  <SplitVpnConnectModal vpn={connectingVpn} manualCode={connectManual}
    on:connected={handleConnected} on:close={closeConnect} />
{/if}

{#if logVpn}
  <SplitVpnLogModal vpn={logVpn} on:close={() => logVpn = null} />
{/if}

<style>
  .split-page { padding: 24px 32px; max-width: 900px; margin: 0 auto; }
  .page-header { display: flex; align-items: center; gap: 16px; margin-bottom: 8px; }
  .page-header h2 { font-size: 1.5rem; font-weight: 600; color: var(--fg); margin: 0; }
  .page-desc { color: var(--fg2); margin-bottom: 24px; font-size: 0.95rem; }
  .back-btn { background: none; border: none; color: var(--accent); cursor: pointer; font-size: 1rem; padding: 4px 8px; border-radius: var(--radius-xs); text-transform: none; letter-spacing: normal; }
  .back-btn:hover { background: var(--accent-bg); }

  .warning-banner {
    display: flex; align-items: center; gap: 16px; justify-content: space-between;
    background: var(--amber-bg); border: 1px solid var(--amber); border-radius: var(--radius-sm);
    padding: 12px 16px; margin-bottom: 12px; color: var(--fg); font-size: 0.9rem;
  }
  .warning-banner button { flex-shrink: 0; }
  .banner-detail { display: block; margin-top: 4px; color: var(--fg3); font-size: .8rem; font-family: var(--font-mono); }
  .install-note { color: var(--fg2); font-size: .85rem; margin-bottom: 24px; }

  .loading { text-align: center; padding: 48px; color: var(--fg2); display: flex; flex-direction: column; align-items: center; gap: 12px; }
  .empty-state { text-align: center; padding: 32px; color: var(--fg3); background: var(--surface); border-radius: var(--radius-sm); }

  .section-header { display: flex; align-items: center; justify-content: space-between; margin: 12px 0; gap: 12px; }
  .section-header h3 { font-weight: 600; color: var(--fg); margin: 0; text-transform: uppercase; letter-spacing: 0.2px; font-size: 0.88rem; }
  .count { color: var(--fg3); font-weight: 500; margin-left: 6px; }
  .header-btns { display: flex; gap: 8px; }

  .vpn-list { display: flex; flex-direction: column; gap: 8px; }
  .vpn-card {
    background: var(--surface); border: 1px solid var(--border); border-left: 3px solid var(--border2);
    border-radius: var(--radius-sm); padding: 12px 16px;
    display: grid; grid-template-columns: 1fr auto; gap: 12px; align-items: center;
  }
  .vpn-card.connected { border-left-color: var(--green); }
  .vpn-card.disabled { opacity: 0.6; }

  .vpn-main { display: flex; flex-direction: column; gap: 6px; min-width: 0; }
  .vpn-title { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .vpn-name { font-weight: 600; color: var(--fg); }
  .vpn-meta { display: flex; flex-wrap: wrap; gap: 6px; color: var(--fg3); font-size: .82rem; }
  .sep { color: var(--border2); }
  .mono { font-family: var(--font-mono); font-size: .8rem; color: var(--fg2); }

  .status-badge { font-size: 0.72rem; font-weight: 600; padding: 2px 8px; border-radius: 10px; text-transform: uppercase; letter-spacing: 0.2px; }
  .status-on { background: var(--green-bg); color: var(--green); }
  .status-off { background: var(--bg3); color: var(--fg3); }
  .status-unknown { background: var(--amber-bg); color: var(--amber); }
  .tag { font-size: .7rem; color: var(--fg3); background: var(--bg3); padding: 1px 6px; border-radius: var(--radius-xs); text-transform: uppercase; letter-spacing: 0.2px; }
  .tag-warn { color: var(--amber); background: var(--amber-bg); }

  .group-chips { display: flex; flex-wrap: wrap; gap: 6px; }
  .group-chip {
    display: inline-flex; align-items: center; gap: 5px; padding: 2px 10px; font-size: .78rem;
    background: var(--bg3); color: var(--fg); border-radius: var(--radius-xs);
    border-left: 3px solid var(--chip-color, var(--border2));
  }
  .chip-missing { color: var(--fg3); font-style: italic; }
  .no-groups { color: var(--fg3); font-size: .8rem; }

  .vpn-actions { display: flex; align-items: center; gap: 6px; }
  .btn-icon { background: none; border: none; cursor: pointer; color: var(--fg3); font-size: 1rem; padding: 4px 6px; border-radius: var(--radius-xs); text-transform: none; letter-spacing: normal; }
  .btn-icon:hover { color: var(--fg); background: var(--bg3); }
  .btn-icon-danger { color: var(--red); }
  .btn-icon-danger:hover { color: var(--fg); background: var(--red); }

  .spinner-lg { display: inline-block; width: 28px; height: 28px; border: 3px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: spin .6s linear infinite; }
  .spinner-inline { display: inline-block; width: 12px; height: 12px; border: 2px solid var(--border2); border-top-color: var(--fg); border-radius: 50%; animation: spin .6s linear infinite; vertical-align: middle; margin-right: 4px; }
  @keyframes spin { to { transform: rotate(360deg); } }

  @media (max-width: 700px) {
    .split-page { padding: 16px; }
    .vpn-card { grid-template-columns: 1fr; }
    .warning-banner { flex-direction: column; align-items: flex-start; }
  }
</style>
