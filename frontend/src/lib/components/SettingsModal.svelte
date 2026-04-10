<script>
  import { api } from '../api.js';
  import { showToast } from '../stores/app.js';
  import { createEventDispatcher, onMount } from 'svelte';

  export let visible = false;
  const dispatch = createEventDispatcher();

  let routerIp = '';
  let protonUser = '', protonPass = '', routerPass = '', masterPass = '';
  let oldMasterPass = '', newMasterPass = '', confirmMasterPass = '';
  let masterError = '';
  let savingRouter = false, savingCreds = false, savingMaster = false;
  let autoOptEnabled = false, autoOptTime = '04:00', savingAutoOpt = false;
  let blacklistCount = 0, favouritesCount = 0, clearingPrefs = false;
  let altRouting = true;
  let savingAltRouting = false;
  let sessions = [];
  let maxConnections = 10;
  let sessionsLoading = false;

  $: if (visible) loadSettings();

  async function loadSettings() {
    const s = await api.getSettings();
    routerIp = s.router_ip || '';
    const ao = s.auto_optimize || {};
    autoOptEnabled = ao.enabled || false;
    autoOptTime = ao.time || '04:00';
    blacklistCount = (s.server_blacklist || []).length;
    favouritesCount = (s.server_favourites || []).length;
    altRouting = s.alternative_routing !== false;
    loadSessions();
  }

  async function loadSessions() {
    sessionsLoading = true;
    try {
      const resp = await api.getSessions();
      sessions = resp.sessions || [];
      maxConnections = resp.max_connections || 10;
    } catch {
      sessions = [];
    }
    sessionsLoading = false;
  }

  async function clearServerPreferences() {
    clearingPrefs = true;
    await api.updateServerPreferences({ blacklist: [], favourites: [] });
    blacklistCount = 0;
    favouritesCount = 0;
    clearingPrefs = false;
    showToast('Server preferences cleared');
  }

  async function saveAltRouting() {
    savingAltRouting = true;
    await api.updateSettings({ alternative_routing: altRouting });
    savingAltRouting = false;
    showToast('Alternative routing ' + (altRouting ? 'enabled' : 'disabled'));
  }

  async function saveAutoOpt() {
    savingAutoOpt = true;
    await api.updateSettings({ auto_optimize: { enabled: autoOptEnabled, time: autoOptTime } });
    savingAutoOpt = false;
    showToast('Auto-optimize settings saved');
  }

  async function saveRouter() {
    savingRouter = true;
    await api.updateSettings({ router_ip: routerIp });
    savingRouter = false;
    showToast('Router IP saved');
  }

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
    close();
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

  function close() { visible = false; dispatch('close'); }
</script>

{#if visible}
<div class="modal-overlay active" on:click|self={close}>
  <div class="modal">
    <div class="modal-header">
      <h2>Settings</h2>
      <button class="modal-close" on:click={close}>&times;</button>
    </div>
    <div class="modal-body">
      <div style="margin-bottom:20px">
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
      <div style="border-top:1px solid var(--border);padding-top:20px;margin-bottom:20px">
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
      <div style="border-top:1px solid var(--border);padding-top:20px;margin-bottom:20px">
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
      <div style="border-top:1px solid var(--border);padding-top:20px;margin-bottom:20px">
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
      <div style="border-top:1px solid var(--border);padding-top:20px;margin-bottom:20px">
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
      <div style="border-top:1px solid var(--border);padding-top:20px">
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
      <div style="border-top:1px solid var(--border);padding-top:20px">
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
    </div>
  </div>
</div>
{/if}

<style>
  .section-title { font-size: .9rem; color: var(--fg2); margin-bottom: 10px; }
  .ao-row { display: flex; align-items: center; gap: 8px; padding: 4px 0; }
  .ao-row input[type="checkbox"] { width: 18px; height: 18px; accent-color: var(--accent); cursor: pointer; }
  .ao-row label { font-size: .85rem; cursor: pointer; }
  .pref-counts { display: flex; gap: 16px; font-size: .85rem; color: var(--fg2); }
  .pref-count strong { color: var(--fg); }
  .sessions-list { display: flex; flex-direction: column; gap: 4px; }
  .session-row { display: flex; align-items: center; gap: 10px; padding: 6px 10px; background: var(--bg3); border-radius: var(--radius-xs); font-size: .82rem; }
  .session-ip { font-family: ui-monospace, "SF Mono", Menlo, monospace; color: var(--fg); flex: 1; }
  .session-proto { font-size: .7rem; padding: 2px 6px; border-radius: 3px; background: rgba(0,180,216,.15); color: var(--accent); font-weight: 500; text-transform: uppercase; }
  .spinner-sm { display: inline-block; width: 14px; height: 14px; border: 2px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: spin .6s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
