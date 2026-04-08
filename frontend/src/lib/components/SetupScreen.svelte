<script>
  import { api } from '../api.js';
  import { appStatus, showToast } from '../stores/app.js';

  let protonUser = '', protonPass = '', totp = '';
  let routerPass = '', routerIp = '192.168.8.1';
  let master = '', masterConfirm = '';
  let error = '';

  async function doSetup() {
    if (master !== masterConfirm) { error = 'Passwords do not match'; return; }
    if (master.length < 4) { error = 'Password too short'; return; }
    error = '';
    const res = await api.setup({
      proton_user: protonUser, proton_pass: protonPass,
      router_pass: routerPass, router_ip: routerIp,
      master_password: master,
    });
    if (res.error) { error = res.error; return; }
    showToast('Setup complete!');
    appStatus.set('locked');
  }
</script>

<div class="auth-screen">
  <div class="auth-card">
    <h2>FlintVPN Setup</h2>
    <p class="subtitle">Connect your ProtonVPN account and router</p>

    <div class="form-group">
      <label for="s-user" class="required">ProtonVPN Username</label>
      <input id="s-user" bind:value={protonUser} placeholder="user@protonmail.com">
    </div>
    <div class="form-group">
      <label for="s-pass" class="required">ProtonVPN Password</label>
      <input id="s-pass" type="password" bind:value={protonPass}>
    </div>
    <div class="form-group">
      <label for="s-totp">2FA Code</label>
      <input id="s-totp" bind:value={totp} placeholder="Leave blank if not enabled">
      <span class="hint">From your authenticator app (if 2FA is enabled)</span>
    </div>
    <div class="form-group">
      <label for="s-rpass" class="required">Router Admin Password</label>
      <input id="s-rpass" type="password" bind:value={routerPass}>
      <span class="hint">Your GL.iNet Flint 2 admin password</span>
    </div>
    <div class="form-group">
      <label for="s-rip">Router IP</label>
      <input id="s-rip" bind:value={routerIp}>
    </div>
    <div class="form-group">
      <label for="s-master" class="required">Master Password</label>
      <input id="s-master" type="password" bind:value={master}>
      <span class="hint">Encrypts all credentials locally. You'll need this each time you open the dashboard.</span>
    </div>
    <div class="form-group">
      <label for="s-confirm" class="required">Confirm Master Password</label>
      <input id="s-confirm" type="password" bind:value={masterConfirm}>
    </div>

    {#if error}<div class="error-msg">{error}</div>{/if}

    <button class="btn-primary btn-lg" on:click={doSetup}>Complete Setup</button>
  </div>
</div>
