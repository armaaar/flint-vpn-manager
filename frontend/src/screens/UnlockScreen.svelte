<script lang="ts">
  import { api } from '../lib/api';
  import { appStatus, protonLoggedIn, startSSE, reloadData } from '../lib/stores/app';

  let password = '';
  let error = '';

  async function doUnlock() {
    error = '';
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
    }
  }

  function onKeydown(e: KeyboardEvent) {
    if (e.key === 'Enter') doUnlock();
  }
</script>

<div class="auth-screen">
  <div class="auth-card">
    <h2>FlintVPN Manager</h2>
    <p class="subtitle">Enter your master password to unlock</p>

    <div class="form-group">
      <label for="u-pass" class="required">Master Password</label>
      <input id="u-pass" type="password" bind:value={password} on:keydown={onKeydown}>
    </div>

    {#if error}<div class="error-msg">{error}</div>{/if}

    <button class="btn-primary btn-lg" on:click={doUnlock}>Unlock</button>
  </div>
</div>
