<script lang="ts">
  import { api } from '../../api';
  import { showToast } from '../../stores/app';
  import { onMount } from 'svelte';

  let blocklistSources: string[] = [];
  let blocklistLastUpdated = '';
  let blocklistDomainCount = 0;
  let presets: Record<string, { name: string; description: string; info_url?: string }> = {};
  let customUrl = '';
  let updatingBlocklist = false;
  let customDomains: string[] = [];
  let newCustomDomain = '';
  let showDomainViewer = false;
  let domainSearch = '';
  let domains: string[] = [];
  let domainTotal = 0;
  let domainPage = 1;
  let domainHasMore = false;
  let domainsLoading = false;
  let addingUrl = false;
  let urlError = '';

  onMount(loadAdblockSettings);

  async function loadAdblockSettings() {
    try {
      const ab = await api.getAdblockSettings();
      blocklistSources = ab.blocklist_sources || [];
      blocklistLastUpdated = ab.last_updated || '';
      blocklistDomainCount = ab.domain_count || 0;
      presets = ab.presets || {};
      customDomains = ab.custom_domains || [];
    } catch (e) { /* ignore */ }
  }

  function togglePreset(id: string) {
    if (blocklistSources.includes(id)) {
      blocklistSources = blocklistSources.filter(s => s !== id);
    } else {
      blocklistSources = [...blocklistSources, id];
    }
  }

  async function addCustomUrl() {
    urlError = '';
    const url = customUrl.trim();
    if (!url) return;
    if (blocklistSources.includes(url)) { urlError = 'Already added'; return; }
    if (!/^https?:\/\/.+\..+/.test(url)) { urlError = 'Must be a valid http:// or https:// URL'; return; }

    addingUrl = true;
    try {
      const resp = await fetch(url, { method: 'HEAD', mode: 'no-cors', signal: AbortSignal.timeout(10000) });
    } catch (e) {
      // HEAD with no-cors may fail for CORS reasons but the URL could still be valid server-side.
    }
    blocklistSources = [...blocklistSources, url];
    customUrl = '';
    addingUrl = false;
  }

  function removeSource(source: string) {
    blocklistSources = blocklistSources.filter(s => s !== source);
  }

  async function updateBlocklistNow() {
    updatingBlocklist = true;
    try {
      await api.updateAdblockSettings({ blocklist_sources: blocklistSources, custom_domains: customDomains });
      const res = await api.updateBlocklistNow();
      if (res.error) { showToast(res.error, true); }
      else {
        blocklistLastUpdated = res.last_updated || '';
        blocklistDomainCount = res.entries || 0;
        let msg = `Blocklist updated: ${res.entries.toLocaleString()} domains`;
        if (res.failed_sources?.length) msg += ` (${res.failed_sources.length} source(s) failed)`;
        showToast(msg, !!res.failed_sources?.length);
      }
    } catch (e) { showToast('Update failed', true); }
    updatingBlocklist = false;
  }

  async function loadDomains(reset = false) {
    if (reset) { domainPage = 1; domains = []; }
    domainsLoading = true;
    try {
      const res = await api.getBlockedDomains(domainSearch, domainPage, 100);
      if (reset) { domains = res.domains; }
      else { domains = [...domains, ...res.domains]; }
      domainTotal = res.total;
      domainHasMore = res.has_more;
    } catch (e) { /* ignore */ }
    domainsLoading = false;
  }

  function addCustomDomain() {
    const d = newCustomDomain.trim().toLowerCase();
    if (!d || !d.includes('.') || customDomains.includes(d)) return;
    customDomains = [...customDomains, d];
    newCustomDomain = '';
  }

  function removeCustomDomain(domain: string) {
    customDomains = customDomains.filter(d => d !== domain);
  }

  function searchDomains() {
    domainPage = 1;
    loadDomains(true);
  }

  function loadMoreDomains() {
    domainPage += 1;
    loadDomains(false);
  }
</script>

<div class="settings-section">
  <h3 class="section-title">Blocklist Sources</h3>
  <span class="hint" style="display:block;margin-bottom:12px">
    Select one or more blocklists. Lists are merged and deduplicated.
    Enable per-group in the group edit modal.
  </span>

  <div class="preset-grid">
    {#each Object.entries(presets) as [id, preset]}
      <div class="preset-row">
        <button class="preset-card" class:selected={blocklistSources.includes(id)}
                on:click={() => togglePreset(id)}>
          <span class="preset-check">{blocklistSources.includes(id) ? '✓' : ''}</span>
          <div class="preset-info">
            <span class="preset-name">{preset.name}</span>
            <span class="preset-desc">{preset.description}</span>
          </div>
        </button>
        {#if preset.info_url}
          <a href={preset.info_url} target="_blank" rel="noopener" class="preset-link" title="View blocklist source">↗</a>
        {/if}
      </div>
    {/each}
  </div>

  <h4 class="subsection-title" style="margin-top:16px">Custom Blocklist URLs</h4>
  <div class="custom-url-row">
    <input bind:value={customUrl} placeholder="https://example.com/blocklist.txt"
           on:keydown={(e) => { urlError = ''; if (e.key === 'Enter') addCustomUrl(); }}
           class:input-error={urlError}
           style="flex:1">
    <button class="btn-outline btn-sm" on:click={addCustomUrl} disabled={!customUrl.trim() || addingUrl}>
      {#if addingUrl}Adding...{:else}Add{/if}
    </button>
  </div>
  {#if urlError}<div class="url-error">{urlError}</div>{/if}

  {#if blocklistSources.filter(s => !presets[s]).length > 0}
    <div class="custom-sources" style="margin-top:8px">
      {#each blocklistSources.filter(s => !presets[s]) as url}
        <div class="custom-source-chip">
          <a href={url} target="_blank" rel="noopener" class="custom-source-url" title={url}>{url}</a>
          <button class="chip-remove" on:click={() => removeSource(url)}>&times;</button>
        </div>
      {/each}
    </div>
  {/if}

  <h4 class="subsection-title" style="margin-top:16px">Custom Blocked Domains</h4>
  <span class="hint" style="display:block;margin-bottom:8px">Add individual domains to block (e.g. ads.example.com).</span>
  <div class="custom-url-row">
    <input bind:value={newCustomDomain} placeholder="ads.example.com"
           on:keydown={(e) => e.key === 'Enter' && addCustomDomain()}
           style="flex:1">
    <button class="btn-outline btn-sm" on:click={addCustomDomain} disabled={!newCustomDomain.trim()}>Add</button>
  </div>
  {#if customDomains.length > 0}
    <div class="custom-sources" style="margin-top:8px">
      {#each customDomains as domain}
        <div class="custom-source-chip">
          <span class="custom-source-url">{domain}</span>
          <button class="chip-remove" on:click={() => removeCustomDomain(domain)}>&times;</button>
        </div>
      {/each}
    </div>
  {/if}
</div>

<div class="settings-section">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
    <div>
      {#if blocklistDomainCount > 0}
        <span style="font-size:.9rem;font-weight:600;color:var(--fg)">{blocklistDomainCount.toLocaleString()} domains blocked</span>
      {/if}
      {#if blocklistLastUpdated}
        <span class="hint" style="margin-left:8px">Updated {new Date(blocklistLastUpdated).toLocaleString()}</span>
      {:else}
        <span class="hint">Not yet downloaded</span>
      {/if}
    </div>
  </div>
  <div style="display:flex;gap:8px">
    <button class="btn-primary btn-sm" on:click={updateBlocklistNow} disabled={updatingBlocklist || blocklistSources.length === 0}>
      {#if updatingBlocklist}Saving & Downloading...{:else}Save & Apply{/if}
    </button>
    <button class="btn-outline btn-sm" on:click={() => { showDomainViewer = !showDomainViewer; if (showDomainViewer && domains.length === 0) loadDomains(true); }}>
      {showDomainViewer ? 'Hide' : 'View'} Blocked Domains
    </button>
  </div>
</div>

{#if showDomainViewer}
  <div class="settings-section">
    <div class="domain-search-row">
      <input bind:value={domainSearch} placeholder="Search domains..."
             on:keydown={(e) => e.key === 'Enter' && searchDomains()}
             style="flex:1">
      <button class="btn-outline btn-sm" on:click={searchDomains}>Search</button>
    </div>
    <div class="domain-count hint" style="margin:8px 0">
      {domainTotal.toLocaleString()} domain{domainTotal !== 1 ? 's' : ''}{domainSearch ? ` matching "${domainSearch}"` : ''}
    </div>
    {#if domainsLoading && domains.length === 0}
      <div style="text-align:center;padding:16px"><span class="spinner-sm"></span></div>
    {:else}
      <div class="domain-list">
        {#each domains as domain}
          <div class="domain-row">{domain}</div>
        {/each}
      </div>
      {#if domainHasMore}
        <button class="btn-outline btn-sm" style="margin-top:8px;width:100%" on:click={loadMoreDomains} disabled={domainsLoading}>
          {#if domainsLoading}Loading...{:else}Load More{/if}
        </button>
      {/if}
    {/if}
  </div>
{/if}

<style>
  .settings-section { background: var(--surface); border-radius: var(--radius); padding: 20px 24px; margin-bottom: 16px; }
  .section-title { font-size: .95rem; color: var(--fg2); margin: 0 0 12px 0; }
  .subsection-title { font-size: .85rem; color: var(--fg3); margin: 0 0 8px 0; font-weight: 600; }
  .spinner-sm { display: inline-block; width: 14px; height: 14px; border: 2px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: spin .6s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* Preset cards */
  .preset-grid { display: flex; flex-direction: column; gap: 6px; }
  .preset-row { display: flex; align-items: stretch; gap: 6px; }
  .preset-card { display: flex; align-items: center; gap: 10px; padding: 10px 14px; background: var(--bg3); border: 1.5px solid var(--border); border-radius: var(--radius-sm, 6px); cursor: pointer; transition: var(--transition); text-align: left; color: var(--fg); flex: 1; }
  .preset-link { display: flex; align-items: center; justify-content: center; width: 36px; background: var(--bg3); border: 1.5px solid var(--border); border-radius: var(--radius-sm, 6px); color: var(--fg3); text-decoration: none; font-size: 1rem; transition: var(--transition); flex-shrink: 0; }
  .preset-link:hover { color: var(--accent); border-color: var(--accent); }
  .preset-card:hover { border-color: var(--accent); }
  .preset-card.selected { border-color: var(--accent); background: var(--accent-bg); }
  .preset-check { width: 20px; height: 20px; display: flex; align-items: center; justify-content: center; border: 2px solid var(--border); border-radius: 4px; font-size: .75rem; font-weight: 700; color: var(--accent); flex-shrink: 0; }
  .preset-card.selected .preset-check { background: var(--accent); color: #fff; border-color: var(--accent); }
  .preset-info { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
  .preset-name { font-size: .85rem; font-weight: 600; }
  .preset-desc { font-size: .75rem; color: var(--fg3); }

  /* Custom URL */
  .custom-url-row { display: flex; gap: 8px; align-items: center; }
  .input-error { border-color: var(--red) !important; }
  .url-error { color: var(--red); font-size: .78rem; margin-top: 4px; }
  .custom-sources { display: flex; flex-wrap: wrap; gap: 6px; }
  .custom-source-chip { display: inline-flex; align-items: center; gap: 4px; padding: 4px 8px; background: var(--bg3); border-radius: 4px; font-size: .78rem; max-width: 100%; }
  .custom-source-url { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--fg2); text-decoration: none; }
  a.custom-source-url:hover { color: var(--accent); }
  .chip-remove { background: none; border: none; color: var(--fg3); cursor: pointer; font-size: 1rem; padding: 0 2px; line-height: 1; }
  .chip-remove:hover { color: var(--red); }

  /* Domain viewer */
  .domain-search-row { display: flex; gap: 8px; }
  .domain-list { max-height: 400px; overflow-y: auto; border: 1px solid var(--border); border-radius: var(--radius-sm, 6px); }
  .domain-row { padding: 4px 10px; font-family: var(--font-mono); font-size: .78rem; color: var(--fg2); border-bottom: 1px solid var(--border); }
  .domain-row:last-child { border-bottom: none; }
  .domain-row:nth-child(even) { background: var(--bg3); }
</style>
