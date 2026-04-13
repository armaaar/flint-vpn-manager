<script lang="ts">
  import { api } from '../../api';
  import { showToast } from '../../stores/app';
  import { onMount } from 'svelte';

  let autoOptEnabled = false;
  let autoOptTime = '04:00';
  let savingAutoOpt = false;
  let blacklistCount = 0;
  let favouritesCount = 0;
  let clearingPrefs = false;

  onMount(async () => {
    const s = await api.getSettings();
    const ao = s.auto_optimize || {};
    autoOptEnabled = ao.enabled || false;
    autoOptTime = ao.time || '04:00';
    blacklistCount = (s.server_blacklist || []).length;
    favouritesCount = (s.server_favourites || []).length;
  });

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
</script>

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

<style>
  .settings-section { background: var(--surface); border-radius: var(--radius); padding: 20px 24px; margin-bottom: 16px; }
  .section-title { font-size: .95rem; color: var(--fg2); margin: 0 0 12px 0; }
  .ao-row { display: flex; align-items: center; gap: 8px; padding: 4px 0; }
  .ao-row input[type="checkbox"] { width: 18px; height: 18px; accent-color: var(--accent); cursor: pointer; }
  .ao-row label { font-size: .85rem; cursor: pointer; }
  .pref-counts { display: flex; gap: 16px; font-size: .85rem; color: var(--fg2); }
  .pref-count strong { color: var(--fg); }
</style>
