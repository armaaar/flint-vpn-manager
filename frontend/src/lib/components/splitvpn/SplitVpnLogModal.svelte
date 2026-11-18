<script lang="ts">
  import { createEventDispatcher, onMount, tick } from 'svelte';
  import { api } from '../../api';
  import type { SplitVpn } from '../../types';

  export let vpn: SplitVpn;

  const dispatch = createEventDispatcher<{ close: void }>();

  let log = '';
  let loading = false;
  let error = '';
  let pre: HTMLPreElement;

  onMount(load);

  async function load() {
    loading = true;
    error = '';
    try {
      log = (await api.getSplitVpnLog(vpn.id)).log || '';
    } catch (err: any) {
      error = err?.message || 'Failed to load log';
    }
    loading = false;
    await tick();
    if (pre) pre.scrollTop = pre.scrollHeight;
  }
</script>

<!-- svelte-ignore a11y-click-events-have-key-events a11y-no-static-element-interactions -->
<div class="modal-overlay active" on:click|self={() => dispatch('close')}>
  <div class="modal log-modal" role="dialog" aria-label="{vpn.name} client log">
    <div class="modal-header">
      <h2>{vpn.name} — client log</h2>
      <button class="modal-close" title="Close" on:click={() => dispatch('close')}>✕</button>
    </div>
    <div class="modal-body">
      {#if error}
        <div class="error-msg">{error}</div>
      {:else if loading && !log}
        <div class="log-empty">Loading…</div>
      {:else if !log.trim()}
        <div class="log-empty">The log is empty. It fills in when you connect.</div>
      {:else}
        <pre class="log-tail" bind:this={pre}>{log}</pre>
      {/if}
    </div>
    <div class="modal-footer">
      <button class="btn-outline btn-sm" on:click={load} disabled={loading}>{loading ? 'Loading…' : '↻ Refresh'}</button>
      <button class="btn-primary btn-sm" on:click={() => dispatch('close')}>Close</button>
    </div>
  </div>
</div>

<style>
  .log-modal { max-width: 820px; }
  .log-empty { color: var(--fg3); font-size: .85rem; text-align: center; padding: 24px; }
  .log-tail {
    max-height: 60vh; overflow: auto; padding: 12px 14px;
    background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius-xs);
    font-family: var(--font-mono); font-size: .75rem; color: var(--fg2);
    white-space: pre-wrap; word-break: break-all;
  }
</style>
