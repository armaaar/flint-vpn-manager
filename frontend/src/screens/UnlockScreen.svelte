<script lang="ts">
  import { api } from '../lib/api';
  import { appStatus, protonLoggedIn, startSSE, reloadData } from '../lib/stores/app';

  let password = '';
  let error = '';
  let unlocking = false;

  async function doUnlock() {
    if (unlocking) return;
    error = '';
    unlocking = true;
    try {
      await api.unlock(password);
      appStatus.set('unlocked');
      // Load initial data
      await reloadData();
      const st = await api.getStatus();
      protonLoggedIn.set(st.proton_logged_in || false);
      startSSE();
    } catch (e: unknown) {
      error = e instanceof Error ? e.message : 'Unlock failed';
      unlocking = false;
    }
  }

  function onKeydown(e: KeyboardEvent) {
    if (e.key === 'Enter') doUnlock();
  }
</script>

<div class="auth-screen">
  <div class="auth-card">
    <h2>Flint VPN Manager</h2>
    <p class="subtitle">Enter your master password to unlock</p>

    <div class="form-group">
      <label for="u-pass" class="required">Master Password</label>
      <input id="u-pass" type="password" bind:value={password} on:keydown={onKeydown} disabled={unlocking}>
    </div>

    {#if error}<div class="error-msg">{error}</div>{/if}

    <button class="btn-primary btn-lg" on:click={doUnlock} disabled={unlocking}>
      {#if unlocking}<span class="spinner-inline"></span>Unlocking…{:else}Unlock{/if}
    </button>
  </div>
</div>

<style>
  .spinner-inline { display: inline-block; width: 14px; height: 14px; border: 2px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: spin .6s linear infinite; vertical-align: middle; margin-right: 8px; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
