<script lang="ts">
  import { api } from '../../api';
  import { showToast } from '../../stores/app';

  let protonUser = '';
  let protonPass = '';
  let routerPass = '';
  let masterPass = '';
  let savingCreds = false;
  let oldMasterPass = '';
  let newMasterPass = '';
  let confirmMasterPass = '';
  let masterError = '';
  let savingMaster = false;

  async function saveCreds() {
    if (!masterPass) { showToast('Master password required', true); return; }
    savingCreds = true;
    const body: Record<string, string> = { master_password: masterPass };
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

<style>
  .settings-section { background: var(--surface); border-radius: var(--radius); padding: 20px 24px; margin-bottom: 16px; }
  .section-title { font-size: .95rem; color: var(--fg2); margin: 0 0 12px 0; }
</style>
