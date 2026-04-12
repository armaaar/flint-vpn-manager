<script>
  import { api } from '../api.js';
  import { showToast } from '../stores/app.js';
  import { createEventDispatcher, onMount } from 'svelte';

  const dispatch = createEventDispatcher();

  export let initialTab = '';

  const tabs = [
    { id: 'general', label: 'General', icon: '⚙' },
    { id: 'servers', label: 'Servers', icon: '🌐' },
    { id: 'adblock', label: 'DNS Ad Blocker', icon: '🚫' },
    { id: 'sessions', label: 'Sessions', icon: '🔗' },
    { id: 'security', label: 'Security', icon: '🔒' },
  ];
  let activeTab = (initialTab && tabs.some(t => t.id === initialTab)) ? initialTab : 'general';

  function switchTab(id) {
    activeTab = id;
    dispatch('tabchange', id);
  }

  // ── State ──────────────────────────────────────────────────────────────
  let routerIp = '';
  let savingRouter = false;
  let altRouting = true, savingAltRouting = false;
  let autoOptEnabled = false, autoOptTime = '04:00', savingAutoOpt = false;
  let blacklistCount = 0, favouritesCount = 0, clearingPrefs = false;
  let blocklistSources = [], blocklistLastUpdated = '', blocklistDomainCount = 0;
  let presets = {}, customUrl = '', updatingBlocklist = false;
  let customDomains = [], newCustomDomain = '';
  let showDomainViewer = false, domainSearch = '', domains = [], domainTotal = 0, domainPage = 1, domainHasMore = false, domainsLoading = false;
  let sessions = [], maxConnections = 10, sessionsLoading = false;
  let protonUser = '', protonPass = '', routerPass = '', masterPass = '', savingCreds = false;
  let oldMasterPass = '', newMasterPass = '', confirmMasterPass = '', masterError = '', savingMaster = false;

  // ── Load ───────────────────────────────────────────────────────────────
  onMount(loadSettings);

  async function loadSettings() {
    const s = await api.getSettings();
    routerIp = s.router_ip || '';
    const ao = s.auto_optimize || {};
    autoOptEnabled = ao.enabled || false;
    autoOptTime = ao.time || '04:00';
    blacklistCount = (s.server_blacklist || []).length;
    favouritesCount = (s.server_favourites || []).length;
    altRouting = s.alternative_routing !== false;
    loadAdblockSettings();
    loadSessions();
  }

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

  // ── General ────────────────────────────────────────────────────────────
  async function saveRouter() {
    savingRouter = true;
    await api.updateSettings({ router_ip: routerIp });
    savingRouter = false;
    showToast('Router IP saved');
  }

  async function saveAltRouting() {
    savingAltRouting = true;
    await api.updateSettings({ alternative_routing: altRouting });
    savingAltRouting = false;
    showToast('Alternative routing ' + (altRouting ? 'enabled' : 'disabled'));
  }

  // ── Servers ────────────────────────────────────────────────────────────
  async function saveAutoOpt() {
    savingAutoOpt = true;
    await api.updateSettings({ auto_optimize: { enabled: autoOptEnabled, time: autoOptTime } });
    savingAutoOpt = false;
    showToast('Auto-optimize settings saved');
  }

  async function clearServerPreferences() {
    clearingPrefs = true;
    await api.updateServerPreferences({ blacklist: [], favourites: [] });
    blacklistCount = 0;
    favouritesCount = 0;
    clearingPrefs = false;
    showToast('Server preferences cleared');
  }

  // ── DNS Ad Blocker ─────────────────────────────────────────────────────
  function togglePreset(id) {
    if (blocklistSources.includes(id)) {
      blocklistSources = blocklistSources.filter(s => s !== id);
    } else {
      blocklistSources = [...blocklistSources, id];
    }
  }

  let addingUrl = false, urlError = '';

  async function addCustomUrl() {
    urlError = '';
    const url = customUrl.trim();
    if (!url) return;
    if (blocklistSources.includes(url)) { urlError = 'Already added'; return; }
    if (!/^https?:\/\/.+\..+/.test(url)) { urlError = 'Must be a valid http:// or https:// URL'; return; }

    addingUrl = true;
    try {
      const resp = await fetch(url, { method: 'HEAD', mode: 'no-cors', signal: AbortSignal.timeout(10000) });
      // no-cors means we can't read status, but if it doesn't throw, the server responded
    } catch (e) {
      // HEAD with no-cors may fail for CORS reasons but the URL could still be valid server-side.
      // Only reject if it looks like a network error (not CORS).
      // Since the backend will do the actual download, we just validate format here.
    }
    blocklistSources = [...blocklistSources, url];
    customUrl = '';
    addingUrl = false;
  }

  function removeSource(source) {
    blocklistSources = blocklistSources.filter(s => s !== source);
  }

  async function updateBlocklistNow() {
    updatingBlocklist = true;
    try {
      // Save first, then update
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

  function removeCustomDomain(domain) {
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

  // ── Sessions ───────────────────────────────────────────────────────────
  async function loadSessions() {
    sessionsLoading = true;
    try {
      const resp = await api.getSessions();
      sessions = resp.sessions || [];
      maxConnections = resp.max_connections || 10;
    } catch { sessions = []; }
    sessionsLoading = false;
  }

  // ── Security ───────────────────────────────────────────────────────────
  async function saveCreds() {
    if (!masterPass) { showToast('Master password required', true); return; }
    savingCreds = true;
    const body = { master_password: masterPass };
    if (protonUser) body.proton_user = protonUser;
    if (protonPass) body.proton_pass = protonPass;
    if (routerPass) body.router_pass = routerPass;
    const res = await api.updateCredentials(body);
    savingCreds = false;
    if (res.error) { showToast(res.error, true); return; }
    showToast('Credentials updated');
    protonUser = protonPass = routerPass = masterPass = '';
  }

  async function changeMasterPassword() {
    masterError = '';
    if (!oldMasterPass) { masterError = 'Current password required'; return; }
    if (!newMasterPass) { masterError = 'New password required'; return; }
    if (newMasterPass.length < 4) { masterError = 'New password too short'; return; }
    if (newMasterPass !== confirmMasterPass) { masterError = 'Passwords do not match'; return; }

    savingMaster = true;
    try {
      const resp = await fetch('/api/settings/master-password', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ old_password: oldMasterPass, new_password: newMasterPass }),
      });
      const data = await resp.json();
      if (data.error) { masterError = data.error; return; }
      showToast('Master password changed');
      oldMasterPass = newMasterPass = confirmMasterPass = '';
    } catch (e) {
      masterError = 'Failed to change password';
    } finally {
      savingMaster = false;
    }
  }
</script>

<div class="settings-page">
  <div class="settings-header">
    <button class="back-btn" on:click={() => dispatch('back')} title="Back to Dashboard">
      ← Back
    </button>
    <h2>Settings</h2>
  </div>

  <div class="tab-bar">
    {#each tabs as tab}
      <button class="tab" class:active={activeTab === tab.id}
              on:click={() => switchTab(tab.id)}>
        <span class="tab-icon">{tab.icon}</span>
        {tab.label}
      </button>
    {/each}
  </div>

  <div class="tab-content">
    <!-- General -->
    {#if activeTab === 'general'}
      <div class="settings-section">
        <h3 class="section-title">Router Connection</h3>
        <div class="form-group">
          <label for="sr-ip">Router IP Address</label>
          <input id="sr-ip" bind:value={routerIp}>
          <span class="hint">Default: 192.168.8.1</span>
        </div>
        <button class="btn-primary btn-sm" on:click={saveRouter} disabled={savingRouter}>
          {#if savingRouter}Saving...{:else}Save Router IP{/if}
        </button>
      </div>

      <div class="settings-section">
        <h3 class="section-title">Alternative Routing</h3>
        <span class="hint" style="display:block;margin-bottom:12px">
          When enabled, API calls are routed through third-party infrastructure (DNS-over-HTTPS) when Proton
          servers are directly blocked. Useful in censored networks.
        </span>
        <div class="ao-row">
          <input type="checkbox" id="alt-routing" bind:checked={altRouting}>
          <label for="alt-routing">Enable alternative routing</label>
        </div>
        <button class="btn-primary btn-sm" on:click={saveAltRouting} disabled={savingAltRouting} style="margin-top:8px">
          {#if savingAltRouting}Saving...{:else}Save{/if}
        </button>
      </div>

    <!-- Servers -->
    {:else if activeTab === 'servers'}
      <div class="settings-section">
        <h3 class="section-title">Server Auto-Optimize</h3>
        <span class="hint" style="display:block;margin-bottom:12px">
          Automatically switch connected VPN groups to faster servers at a scheduled time.
          Only applies to groups where you selected "Fastest", a country, or a city — groups
          with a specific server chosen are never changed.
        </span>
        <div class="ao-row">
          <input type="checkbox" id="ao-enabled" bind:checked={autoOptEnabled}>
          <label for="ao-enabled">Enable auto-optimize</label>
        </div>
        {#if autoOptEnabled}
          <div class="form-group" style="margin-top:8px;max-width:180px">
            <label for="ao-time">Time of day</label>
            <input id="ao-time" type="time" bind:value={autoOptTime}>
          </div>
        {/if}
        <button class="btn-primary btn-sm" on:click={saveAutoOpt} disabled={savingAutoOpt} style="margin-top:8px">
          {#if savingAutoOpt}Saving...{:else}Save{/if}
        </button>
      </div>

      <div class="settings-section">
        <h3 class="section-title">Server Preferences</h3>
        <span class="hint" style="display:block;margin-bottom:12px">
          Manage server blacklist and favourites. Use the star and block buttons in the
          Server Picker (when changing a group's server) to add individual servers.
        </span>
        <div class="pref-counts">
          <span class="pref-count">Favourites: <strong>{favouritesCount}</strong></span>
          <span class="pref-count">Blacklisted: <strong>{blacklistCount}</strong></span>
        </div>
        {#if blacklistCount > 0 || favouritesCount > 0}
          <button class="btn-outline btn-sm" on:click={clearServerPreferences}
                  disabled={clearingPrefs} style="margin-top:8px">
            {#if clearingPrefs}Clearing...{:else}Clear All{/if}
          </button>
        {/if}
      </div>

    <!-- DNS Ad Blocker -->
    {:else if activeTab === 'adblock'}
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

    <!-- Sessions -->
    {:else if activeTab === 'sessions'}
      <div class="settings-section">
        <h3 class="section-title">Active VPN Sessions</h3>
        <span class="hint" style="display:block;margin-bottom:12px">
          Currently active VPN connections on your Proton account ({sessions.length}/{maxConnections} slots used).
        </span>
        {#if sessionsLoading}
          <div style="text-align:center;padding:12px"><span class="spinner-sm"></span></div>
        {:else if sessions.length === 0}
          <div class="hint">No active VPN sessions.</div>
        {:else}
          <div class="sessions-list">
            {#each sessions as s}
              <div class="session-row">
                <span class="session-ip" title="Exit IP">{s.exit_ip || '—'}</span>
                <span class="session-proto">{s.protocol || 'unknown'}</span>
              </div>
            {/each}
          </div>
        {/if}
        <button class="btn-outline btn-sm" on:click={loadSessions} style="margin-top:8px">
          Refresh
        </button>
      </div>

    <!-- Security -->
    {:else if activeTab === 'security'}
      <div class="settings-section">
        <h3 class="section-title">Update Credentials</h3>
        <div class="form-group">
          <label for="sc-pu">ProtonVPN Username</label>
          <input id="sc-pu" bind:value={protonUser} placeholder="Leave blank to keep current">
        </div>
        <div class="form-group">
          <label for="sc-pp">ProtonVPN Password</label>
          <input id="sc-pp" type="password" bind:value={protonPass} placeholder="Leave blank to keep current">
        </div>
        <div class="form-group">
          <label for="sc-rp">Router Admin Password</label>
          <input id="sc-rp" type="password" bind:value={routerPass} placeholder="Leave blank to keep current">
        </div>
        <div class="form-group">
          <label for="sc-mp" class="required">Current Master Password</label>
          <input id="sc-mp" type="password" bind:value={masterPass}>
          <span class="hint">Required to update credentials</span>
        </div>
        <button class="btn-primary btn-sm" on:click={saveCreds} disabled={savingCreds}>
          {#if savingCreds}Updating...{:else}Update Credentials{/if}
        </button>
      </div>

      <div class="settings-section">
        <h3 class="section-title">Change Master Password</h3>
        <div class="form-group">
          <label for="cm-old" class="required">Current Master Password</label>
          <input id="cm-old" type="password" bind:value={oldMasterPass}>
        </div>
        <div class="form-group">
          <label for="cm-new" class="required">New Master Password</label>
          <input id="cm-new" type="password" bind:value={newMasterPass}>
        </div>
        <div class="form-group">
          <label for="cm-confirm" class="required">Confirm New Password</label>
          <input id="cm-confirm" type="password" bind:value={confirmMasterPass}>
        </div>
        {#if masterError}<div class="error-msg">{masterError}</div>{/if}
        <button class="btn-primary btn-sm" on:click={changeMasterPassword} disabled={savingMaster}>
          {#if savingMaster}Changing...{:else}Change Master Password{/if}
        </button>
      </div>
    {/if}
  </div>
</div>

<style>
  .settings-page { max-width: 800px; margin: 0 auto; padding: 20px; }
  .settings-header { display: flex; align-items: center; gap: 16px; margin-bottom: 24px; }
  .settings-header h2 { margin: 0; font-size: 1.3rem; color: var(--fg); }
  .back-btn { background: none; border: 1px solid var(--border); color: var(--fg2); padding: 6px 14px; border-radius: var(--radius-sm); cursor: pointer; font-size: .85rem; transition: var(--transition); }
  .back-btn:hover { border-color: var(--accent); color: var(--accent); }

  .tab-bar { display: flex; gap: 2px; border-bottom: 2px solid var(--border); margin-bottom: 24px; flex-wrap: wrap; }
  .tab { background: none; border: none; border-bottom: 2px solid transparent; margin-bottom: -2px; padding: 10px 16px; color: var(--fg3); font-size: .85rem; font-weight: 500; cursor: pointer; transition: var(--transition); white-space: nowrap; display: flex; align-items: center; gap: 6px; }
  .tab:hover { color: var(--fg); }
  .tab.active { color: var(--accent); border-bottom-color: var(--accent); }
  .tab-icon { font-size: .9rem; }

  .tab-content { min-height: 300px; }
  .settings-section { background: var(--surface); border-radius: var(--radius); padding: 20px 24px; margin-bottom: 16px; }
  .section-title { font-size: .95rem; color: var(--fg2); margin: 0 0 12px 0; }
  .ao-row { display: flex; align-items: center; gap: 8px; padding: 4px 0; }
  .ao-row input[type="checkbox"] { width: 18px; height: 18px; accent-color: var(--accent); cursor: pointer; }
  .ao-row label { font-size: .85rem; cursor: pointer; }
  .pref-counts { display: flex; gap: 16px; font-size: .85rem; color: var(--fg2); }
  .pref-count strong { color: var(--fg); }
  .sessions-list { display: flex; flex-direction: column; gap: 4px; }
  .session-row { display: flex; align-items: center; gap: 10px; padding: 6px 10px; background: var(--bg3); border-radius: var(--radius-xs, 4px); font-size: .82rem; }
  .session-ip { font-family: var(--font-mono); color: var(--fg); flex: 1; }
  .session-proto { font-size: .7rem; padding: 2px 6px; border-radius: 3px; background: var(--accent-bg); color: var(--accent); font-weight: 500; text-transform: uppercase; letter-spacing: .2px; }
  .spinner-sm { display: inline-block; width: 14px; height: 14px; border: 2px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: spin .6s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }

  .subsection-title { font-size: .85rem; color: var(--fg3); margin: 0 0 8px 0; font-weight: 600; }

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
