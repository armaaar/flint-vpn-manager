<script>
  import { api } from '../api.js';
  import { appStatus, profiles, devices, protonLoggedIn, startSSE, showToast } from '../stores/app.js';

  let password = '';
  let error = '';

  async function doUnlock() {
    error = '';
    const res = await api.unlock(password);
    if (res.error) { error = res.error; return; }
    appStatus.set('unlocked');
    // Load initial data
    const [p, d, st] = await Promise.all([api.getProfiles(), api.getDevices(), api.getStatus()]);
    profiles.set(p);
    devices.set(d);
    protonLoggedIn.set(st.proton_logged_in || false);
    startSSE();
  }

  function onKeydown(e) {
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
