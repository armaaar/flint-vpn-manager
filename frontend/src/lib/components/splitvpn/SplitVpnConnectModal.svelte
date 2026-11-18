<script lang="ts">
  import { createEventDispatcher, onDestroy, onMount, tick } from 'svelte';
  import { api } from '../../api';
  import type { SplitVpn, SplitVpnConnectResult } from '../../types';

  export let vpn: SplitVpn;
  /** true → ask for a one-time code; false → the backend generates it from the stored TOTP secret. */
  export let manualCode = false;

  const dispatch = createEventDispatcher<{ connected: SplitVpnConnectResult; close: void }>();

  let otp = '';
  let connecting = false;
  let error = '';
  let log = '';
  let elapsed = 0;
  let timer: ReturnType<typeof setInterval> | null = null;
  let otpInput: HTMLInputElement;

  function focusOnMount(node: HTMLInputElement) {
    node.focus();
  }

  function startTimer() {
    elapsed = 0;
    timer = setInterval(() => { elapsed += 1; }, 1000);
  }

  function stopTimer() {
    if (timer) clearInterval(timer);
    timer = null;
  }

  onMount(() => {
    if (!manualCode) connect();
  });
  onDestroy(stopTimer);

  async function connect() {
    const code = otp.replace(/\s+/g, '');
    if (connecting || (manualCode && !code)) return;
    connecting = true;
    error = '';
    log = '';
    startTimer();
    try {
      const result = manualCode
        ? await api.connectSplitVpn(vpn.id, code)
        : await api.connectSplitVpn(vpn.id);
      if (result.connected) {
        dispatch('connected', result);
        return;
      }
      error = result.error || `Connection failed (state: ${result.state || 'unknown'})`;
      log = result.log || '';
    } catch (err: any) {
      error = err?.message || 'Connection failed';
      try {
        log = (await api.getSplitVpnLog(vpn.id)).log || '';
      } catch {
        log = '';
      }
    } finally {
      stopTimer();
      connecting = false;
    }
    // A failed attempt burns the code — clear it for the next one.
    otp = '';
    if (manualCode) setTimeout(() => otpInput?.focus(), 0);
  }

  async function switchToManual() {
    manualCode = true;
    error = '';
    log = '';
    await tick();
    otpInput?.focus();
  }

  function close() {
    if (connecting) return;
    dispatch('close');
  }
</script>

<!-- svelte-ignore a11y-click-events-have-key-events a11y-no-static-element-interactions -->
<div class="modal-overlay active" on:click|self={close}>
  <div class="modal connect-modal" role="dialog" aria-label="Connect {vpn.name}">
    <div class="modal-header">
      <h2>Connect {vpn.name}</h2>
      <button class="modal-close" title="Close" on:click={close} disabled={connecting}>✕</button>
    </div>

    <form on:submit|preventDefault={connect}>
      <div class="modal-body">
        {#if manualCode}
          <div class="form-group">
            <label for="split-otp">One-time code</label>
            <input id="split-otp" class="otp-input" type="text" inputmode="numeric" pattern="[0-9 ]*"
              autocomplete="one-time-code" placeholder="123456"
              bind:value={otp} bind:this={otpInput} use:focusOnMount disabled={connecting} />
            <span class="hint">
              {#if vpn.has_totp}
                Use a code from your authenticator instead of the one generated from the stored secret. It is used once and never stored.
              {:else}
                No TOTP secret is stored for this VPN, so enter the current code from your authenticator. It is used once and never stored. Add the secret in Edit to connect automatically.
              {/if}
            </span>
          </div>
        {:else if !connecting && !error}
          <p class="auto-note">The one-time code is generated automatically from the stored TOTP secret.</p>
        {/if}

        {#if connecting}
          <div class="progress" role="status">
            <span class="spinner"></span>
            <span>Connecting… this can take up to a minute ({elapsed}s)</span>
          </div>
        {/if}

        {#if error}
          <div class="connect-error" role="alert">{error}</div>
          {#if log}
            <details class="log-details">
              <summary>Client log</summary>
              <pre class="log-tail">{log}</pre>
            </details>
          {/if}
          {#if !manualCode}
            <button type="button" class="link-btn" on:click={switchToManual}>Connect with a code…</button>
          {/if}
        {/if}
      </div>

      <div class="modal-footer">
        <button type="button" class="btn-outline btn-sm" on:click={close} disabled={connecting}>
          {error || manualCode ? 'Cancel' : 'Close'}
        </button>
        {#if manualCode}
          <button type="submit" class="btn-primary btn-sm" disabled={connecting || !otp.trim()}>
            {connecting ? 'Connecting…' : 'Connect'}
          </button>
        {:else}
          <button type="submit" class="btn-primary btn-sm" disabled={connecting}>
            {connecting ? 'Connecting…' : 'Retry'}
          </button>
        {/if}
      </div>
    </form>
  </div>
</div>

<style>
  .connect-modal { max-width: 460px; }
  .auto-note { color: var(--fg2); font-size: .85rem; margin-bottom: 12px; }
  .otp-input {
    font-family: var(--font-mono); font-size: 1.25rem; letter-spacing: 0.25em; text-align: center;
  }
  .progress {
    display: flex; align-items: center; gap: 10px; padding: 10px 12px;
    background: var(--accent-bg); color: var(--fg2); border-radius: var(--radius-xs); font-size: .85rem;
  }
  .spinner {
    display: inline-block; width: 16px; height: 16px; flex-shrink: 0;
    border: 2px solid var(--border2); border-top-color: var(--accent); border-radius: 50%;
    animation: spin .6s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  .connect-error {
    color: var(--red); background: var(--red-bg); border-radius: var(--radius-xs);
    padding: 10px 12px; font-size: .85rem; margin-top: 4px;
  }
  .log-details { margin-top: 10px; }
  .log-details summary {
    cursor: pointer; color: var(--fg2); font-size: .8rem; font-weight: 500;
    text-transform: uppercase; letter-spacing: 0.2px;
  }
  .log-tail {
    margin-top: 8px; max-height: 240px; overflow: auto; padding: 10px 12px;
    background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius-xs);
    font-family: var(--font-mono); font-size: .75rem; color: var(--fg2);
    white-space: pre-wrap; word-break: break-all;
  }
  .link-btn {
    background: none; border: none; padding: 10px 0 0; color: var(--accent); font-size: .75rem;
    font-weight: 500; text-transform: uppercase; letter-spacing: 0.2px;
  }
  .link-btn:hover { color: var(--fg); }
</style>
