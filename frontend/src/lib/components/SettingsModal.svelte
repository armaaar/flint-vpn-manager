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

  $: if (visible) loadSettings();

  async function loadSettings() {
    const s = await api.getSettings();
    routerIp = s.router_ip || '';
    const ao = s.auto_optimize || {};
    autoOptEnabled = ao.enabled || false;
    autoOptTime = ao.time || '04:00';
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
</style>
