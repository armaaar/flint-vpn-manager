<script lang="ts">
  import { api } from '../../api';
  import { showToast } from '../../stores/app';
  import { onMount } from 'svelte';

  let routerIp = '';
  let savingRouter = false;
  let altRouting = true;
  let savingAltRouting = false;

  onMount(async () => {
    const s = await api.getSettings();
    routerIp = s.router_ip || '';
    altRouting = s.alternative_routing !== false;
  });

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
</script>

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

<style>
  .settings-section { background: var(--surface); border-radius: var(--radius); padding: 20px 24px; margin-bottom: 16px; }
  .section-title { font-size: .95rem; color: var(--fg2); margin: 0 0 12px 0; }
  .ao-row { display: flex; align-items: center; gap: 8px; padding: 4px 0; }
  .ao-row input[type="checkbox"] { width: 18px; height: 18px; accent-color: var(--accent); cursor: pointer; }
  .ao-row label { font-size: .85rem; cursor: pointer; }
</style>
