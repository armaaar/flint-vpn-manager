<script lang="ts">
  import { api } from '../../api';
  import { profiles, devices, showToast } from '../../stores/app';
  import { createEventDispatcher, onMount } from 'svelte';
  import BypassExceptionModal from './BypassExceptionModal.svelte';
  import type { BypassOverview, BypassException, BypassPreset } from '../../types';

  const dispatch = createEventDispatcher();

  let overview: BypassOverview | null = null;
  let loading = true;
  let showModal = false;
  let editingException: BypassException | null = null;
  let togglingId: string | null = null;
  let deletingId: string | null = null;
  let installingDnsmasq = false;
  let expandedId: string | null = null;
  let expandedPresetId: string | null = null;

  onMount(loadData);

  async function loadData() {
    loading = true;
    try {
      overview = await api.getBypassOverview();
    } catch (err: any) {
      showToast(err.message || 'Failed to load bypass data', true);
    }
    loading = false;
  }

  function openCreate() {
    editingException = null;
    showModal = true;
  }

  function openEdit(exc: BypassException) {
    editingException = exc;
    showModal = true;
  }

  async function handleSave(e: CustomEvent) {
    showModal = false;
    const data = e.detail;
    try {
      if (editingException) {
        await api.updateBypassException(editingException.id, data);
        showToast('Exception updated');
      } else {
        await api.addBypassException(data);
        showToast('Exception added');
      }
    } catch (err: any) {
      showToast(err.message || 'Failed to save exception', true);
    }
    await loadData();
  }

  async function toggleException(exc: BypassException) {
    togglingId = exc.id;
    try {
      await api.toggleBypassException(exc.id, !exc.enabled);
    } catch (err: any) {
      showToast(err.message || 'Failed to toggle', true);
    }
    await loadData();
    togglingId = null;
  }

  async function deleteException(exc: BypassException) {
    deletingId = exc.id;
    try {
      await api.deleteBypassException(exc.id);
      showToast('Exception removed');
    } catch (err: any) {
      showToast(err.message || 'Failed to delete', true);
    }
    await loadData();
    deletingId = null;
  }

  async function installDnsmasq() {
    installingDnsmasq = true;
    try {
      await api.installDnsmasqFull();
      showToast('dnsmasq-full installed');
    } catch (err: any) {
      showToast(err.message || 'Install failed', true);
    }
    await loadData();
    installingDnsmasq = false;
  }

  function scopeLabel(exc: BypassException): string {
    if (exc.scope === 'global') return 'Global';
    const raw = exc.scope_target;
    const targets = Array.isArray(raw) ? raw : (raw ? [raw] : []);
    const count = targets.length;
    if (exc.scope === 'group') return count === 1 ? '1 Group' : `${count} Groups`;
    if (exc.scope === 'device') return count === 1 ? '1 Device' : `${count} Devices`;
    return exc.scope;
  }

  function scopeDetails(exc: BypassException): string[] {
    const raw = exc.scope_target;
    const targets = Array.isArray(raw) ? raw : (raw ? [raw] : []);
    if (exc.scope === 'group') {
      return targets.map(t => {
        const p = $profiles.find(p => p.id === t);
        return p ? `${p.icon} ${p.name}` : '(deleted)';
      });
    }
    if (exc.scope === 'device') {
      return targets.map(t => {
        const d = $devices.find(d => d.mac === t);
        return d ? `${d.display_name} (${t})` : t;
      });
    }
    return [];
  }

  function scopeBadgeClass(scope: string): string {
    if (scope === 'global') return 'badge-global';
    if (scope === 'group') return 'badge-group';
    return 'badge-device';
  }

  function rulesSummary(exc: BypassException): string {
    const blocks = exc.rule_blocks || [];
    const counts = { cidr: 0, domain: 0, port: 0 };
    for (const b of blocks) {
      for (const r of b.rules || []) counts[r.type] = (counts[r.type] || 0) + 1;
    }
    const parts: string[] = [];
    if (counts.cidr) parts.push(`${counts.cidr} IP`);
    if (counts.domain) parts.push(`${counts.domain} domain`);
    if (counts.port) parts.push(`${counts.port} port`);
    const blockCount = blocks.length;
    const suffix = blockCount > 1 ? ` in ${blockCount} blocks` : '';
    return (parts.join(', ') || 'No rules') + suffix;
  }
</script>

<div class="bypass-page">
  <div class="page-header">
    <button class="back-btn" on:click={() => dispatch('back')}>&larr; Back</button>
    <h2>VPN Bypass</h2>
  </div>
  <p class="page-desc">Route specific traffic directly via WAN, bypassing VPN tunnels. Add exceptions by app preset, IP range, domain, or port.</p>

  {#if overview && !overview.dnsmasq_full_installed}
    <div class="warning-banner">
      <span>Domain-based bypass rules require <strong>dnsmasq-full</strong> on the router. IP and port rules work without it.</span>
      <button class="btn-sm btn-accent" on:click={installDnsmasq} disabled={installingDnsmasq}>
        {installingDnsmasq ? 'Installing...' : 'Install dnsmasq-full'}
      </button>
    </div>
  {/if}

  {#if loading}
    <div class="loading"><span class="spinner-lg"></span><p>Loading...</p></div>
  {:else if overview}
    <div class="section-header">
      <h3>Exceptions</h3>
      <button class="btn-primary btn-sm" on:click={openCreate}>+ Add Exception</button>
    </div>

    {#if overview.exceptions.length === 0}
      <div class="empty-state">
        <p>No bypass exceptions yet. Add one to route specific app traffic outside VPN.</p>
      </div>
    {:else}
      <div class="exception-list">
        {#each overview.exceptions as exc (exc.id)}
          <div class="exception-card" class:disabled={!exc.enabled}>
            <div class="exc-header" on:click={() => expandedId = expandedId === exc.id ? null : exc.id}>
              <div class="exc-info">
                <span class="exc-name">{exc.name}</span>
                <span class="scope-badge {scopeBadgeClass(exc.scope)}">{scopeLabel(exc)}</span>
                {#if exc.preset_id}
                  <span class="preset-tag">Preset</span>
                {/if}
              </div>
              <div class="exc-meta">
                <span class="rule-count">{rulesSummary(exc)}</span>
                <span class="expand-icon">{expandedId === exc.id ? '▾' : '▸'}</span>
              </div>
            </div>
            <div class="exc-actions">
              <label class="toggle" title={exc.enabled ? 'Disable' : 'Enable'}>
                <input type="checkbox" checked={exc.enabled} disabled={togglingId === exc.id}
                  on:change={() => toggleException(exc)} />
                <span class="toggle-slider"></span>
              </label>
              <button class="btn-icon" title="Edit" on:click={() => openEdit(exc)}>✎</button>
              <button class="btn-icon btn-danger" title="Delete" disabled={deletingId === exc.id}
                on:click={() => deleteException(exc)}>✕</button>
            </div>

            {#if expandedId === exc.id}
              <div class="exc-details">
                {#if exc.scope !== 'global'}
                  <div class="scope-detail-list">
                    <span class="scope-detail-label">{exc.scope === 'group' ? 'Groups' : 'Devices'}:</span>
                    {#each scopeDetails(exc) as item}
                      <span class="scope-detail-item">{item}</span>
                    {/each}
                  </div>
                {/if}
                {#each (exc.rule_blocks || []) as block, bi}
                  {#if bi > 0}<div class="block-divider"><span>OR</span></div>{/if}
                  <div class="rule-block">
                    {#if block.label}<div class="block-label">{block.label}</div>{/if}
                    {#each block.rules as rule}
                      <div class="rule-row">
                        <span class="rule-type">{rule.type.toUpperCase()}</span>
                        <span class="rule-value">{rule.value}</span>
                        {#if rule.protocol}
                          <span class="rule-proto">{rule.protocol}</span>
                        {/if}
                      </div>
                    {/each}
                  </div>
                {/each}
              </div>
            {/if}
          </div>
        {/each}
      </div>
    {/if}

    <!-- Presets Section -->
    <div class="section-header" style="margin-top: 32px;">
      <h3>Presets</h3>
    </div>
    <div class="preset-list">
      {#each Object.entries(overview.presets) as [id, preset]}
        <div class="preset-card" class:preset-expanded={expandedPresetId === id}>
          <div class="preset-header" on:click={() => expandedPresetId = expandedPresetId === id ? null : id}>
            <div>
              <div class="preset-name">{preset.name}</div>
              <div class="preset-meta">{(preset.rule_blocks || []).reduce((n, b) => n + (b.rules?.length || 0), 0)} rules in {(preset.rule_blocks || []).length} blocks {preset.builtin ? '' : '(custom)'}</div>
            </div>
            <span class="expand-icon">{expandedPresetId === id ? '▾' : '▸'}</span>
          </div>
          {#if expandedPresetId === id}
            <div class="preset-details">
              {#each (preset.rule_blocks || []) as block, bi}
                {#if bi > 0}<div class="block-divider"><span>OR</span></div>{/if}
                <div class="rule-block">
                  {#if block.label}<div class="block-label">{block.label}</div>{/if}
                  {#each block.rules as rule}
                    <div class="rule-row">
                      <span class="rule-type">{rule.type.toUpperCase()}</span>
                      <span class="rule-value">{rule.value}</span>
                      {#if rule.protocol}
                        <span class="rule-proto">{rule.protocol}</span>
                      {/if}
                    </div>
                  {/each}
                </div>
              {/each}
            </div>
          {/if}
          {#if !preset.builtin}
            <button class="btn-icon btn-danger btn-xs" title="Delete preset"
              on:click|stopPropagation={async () => { await api.deleteCustomPreset(id); showToast('Preset deleted'); await loadData(); }}>✕</button>
          {/if}
        </div>
      {/each}
    </div>
  {/if}
</div>

{#if showModal}
  <BypassExceptionModal
    exception={editingException}
    presets={overview?.presets || {}}
    profiles={$profiles}
    devices={$devices}
    on:save={handleSave}
    on:close={() => showModal = false}
  />
{/if}

<style>
  .bypass-page { padding: 24px 32px; max-width: 900px; margin: 0 auto; }
  .page-header { display: flex; align-items: center; gap: 16px; margin-bottom: 8px; }
  .page-header h2 { font-size: 1.5rem; font-weight: 600; color: var(--fg); margin: 0; }
  .page-desc { color: var(--fg2); margin-bottom: 24px; font-size: 0.95rem; }
  .back-btn { background: none; border: none; color: var(--accent); cursor: pointer; font-size: 1rem; padding: 4px 8px; border-radius: 6px; }
  .back-btn:hover { background: var(--accent-bg); }

  .warning-banner {
    display: flex; align-items: center; gap: 16px; justify-content: space-between;
    background: var(--amber-bg); border: 1px solid var(--amber); border-radius: 8px;
    padding: 12px 16px; margin-bottom: 24px; color: var(--fg); font-size: 0.9rem;
  }

  .loading { text-align: center; padding: 48px; color: var(--fg2); }
  .empty-state { text-align: center; padding: 32px; color: var(--fg3); background: var(--surface); border-radius: 8px; }

  .section-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; }
  .section-header h3 { font-size: 1.1rem; font-weight: 600; color: var(--fg); margin: 0; text-transform: uppercase; letter-spacing: 0.2px; font-size: 0.88rem; }

  .btn-primary { background: var(--accent); color: #fff; border: none; padding: 6px 14px; border-radius: 8px; cursor: pointer; font-weight: 600; text-transform: uppercase; letter-spacing: 0.2px; font-size: 0.82rem; }
  .btn-primary:hover { background: var(--accent2); }
  .btn-sm { font-size: 0.82rem; padding: 5px 12px; }
  .btn-accent { background: var(--accent); color: #fff; border: none; border-radius: 6px; cursor: pointer; font-weight: 500; }
  .btn-accent:hover { background: var(--accent2); }
  .btn-accent:disabled { opacity: 0.5; cursor: default; }

  .exception-list { display: flex; flex-direction: column; gap: 8px; }

  .exception-card {
    background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
    padding: 12px 16px; display: grid; grid-template-columns: 1fr auto; gap: 8px; align-items: center;
  }
  .exception-card.disabled { opacity: 0.5; }

  .exc-header { cursor: pointer; display: flex; flex-direction: column; gap: 4px; }
  .exc-info { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .exc-name { font-weight: 600; color: var(--fg); }
  .exc-meta { display: flex; align-items: center; gap: 8px; }
  .rule-count { color: var(--fg3); font-size: 0.85rem; }
  .expand-icon { color: var(--fg3); font-size: 0.8rem; }

  .scope-badge {
    font-size: 0.75rem; font-weight: 600; padding: 2px 8px; border-radius: 10px;
    text-transform: uppercase; letter-spacing: 0.2px;
  }
  .badge-global { background: var(--accent-bg); color: var(--accent); }
  .badge-group { background: var(--green-bg); color: var(--green); }
  .badge-device { background: var(--amber-bg); color: var(--amber); }
  .preset-tag { font-size: 0.7rem; color: var(--fg3); background: var(--bg3); padding: 1px 6px; border-radius: 4px; }

  .exc-actions { display: flex; align-items: center; gap: 8px; }
  .btn-icon { background: none; border: none; cursor: pointer; color: var(--fg3); font-size: 1rem; padding: 4px; border-radius: 4px; }
  .btn-icon:hover { color: var(--fg); background: var(--bg3); }
  .btn-danger { color: var(--red); }
  .btn-danger:hover { color: #fff; background: var(--red); }
  .btn-danger:disabled { opacity: 0.4; cursor: default; }

  /* Toggle switch */
  .toggle { position: relative; display: inline-block; width: 36px; height: 20px; }
  .toggle input { opacity: 0; width: 0; height: 0; }
  .toggle-slider {
    position: absolute; cursor: pointer; inset: 0; background: var(--bg3);
    border-radius: 20px; transition: 0.2s;
  }
  .toggle-slider::before {
    content: ''; position: absolute; height: 14px; width: 14px; left: 3px; bottom: 3px;
    background: var(--fg3); border-radius: 50%; transition: 0.2s;
  }
  .toggle input:checked + .toggle-slider { background: var(--green); }
  .toggle input:checked + .toggle-slider::before { transform: translateX(16px); background: #fff; }

  /* Expanded rule details */
  .exc-details { grid-column: 1 / -1; padding-top: 8px; border-top: 1px solid var(--border); margin-top: 4px; }
  .rule-row { display: flex; gap: 8px; align-items: center; padding: 4px 0; font-size: 0.85rem; font-family: var(--font-mono); }
  .rule-type { font-weight: 700; color: var(--accent); min-width: 60px; font-size: 0.75rem; text-transform: uppercase; }
  .rule-value { color: var(--fg); }
  .rule-proto { color: var(--fg3); font-size: 0.8rem; }
  .scope-detail-list { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; margin-bottom: 10px; padding-bottom: 8px; border-bottom: 1px solid var(--border); }
  .scope-detail-label { color: var(--fg2); font-size: 0.8rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.2px; }
  .scope-detail-item { background: var(--accent-bg); color: var(--accent); font-size: 0.82rem; padding: 2px 10px; border-radius: 10px; }
  .rule-block { padding: 4px 0; }
  .block-label { color: var(--fg2); font-size: 0.8rem; font-weight: 600; margin-bottom: 4px; text-transform: uppercase; letter-spacing: 0.2px; }
  .block-divider { text-align: center; padding: 4px 0; }
  .block-divider span { color: var(--amber); font-size: 0.75rem; font-weight: 700; background: var(--surface); padding: 2px 10px; border-radius: 4px; }

  /* Presets */
  .preset-list { display: flex; flex-direction: column; gap: 8px; }
  .preset-card {
    background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
    padding: 12px 16px; position: relative;
  }
  .preset-header { display: flex; justify-content: space-between; align-items: center; cursor: pointer; }
  .preset-name { font-weight: 600; color: var(--fg); font-size: 0.95rem; }
  .preset-meta { color: var(--fg3); font-size: 0.8rem; }
  .preset-details { margin-top: 10px; padding-top: 10px; border-top: 1px solid var(--border); }
  .preset-card .btn-xs { position: absolute; top: 8px; right: 8px; font-size: 0.75rem; padding: 2px 4px; }
</style>
