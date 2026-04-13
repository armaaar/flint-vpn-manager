<script lang="ts">
  import { api } from '../../api';
  import { onMount } from 'svelte';
  import type { VpnSession } from '../../types';

  let sessions: VpnSession[] = [];
  let maxConnections = 10;
  let sessionsLoading = false;

  onMount(loadSessions);

  async function loadSessions() {
    sessionsLoading = true;
    try {
      const resp = await api.getSessions();
      sessions = resp.sessions || [];
      maxConnections = resp.max_connections || 10;
    } catch { sessions = []; }
    sessionsLoading = false;
  }
</script>

<div class="settings-section">
  <h3 class="section-title">Active VPN Sessions</h3>
  <span class="hint" style="display:block;margin-bottom:12px">
    Currently active VPN connections on your Proton account ({sessions.length}/{maxConnections} slots used).
  </span>
  {#if sessionsLoading}
    <div style="text-align:center;padding:12px"><span class="spinner-sm"></span></div>
  {:else if sessions.length === 0}
    <div class="hint">No active VPN sessions.</div>
  {:else}
    <div class="sessions-list">
      {#each sessions as s}
        <div class="session-row">
          <span class="session-ip" title="Exit IP">{s.exit_ip || '—'}</span>
          <span class="session-proto">{s.protocol || 'unknown'}</span>
        </div>
      {/each}
    </div>
  {/if}
  <button class="btn-outline btn-sm" on:click={loadSessions} style="margin-top:8px">
    Refresh
  </button>
</div>

<style>
  .settings-section { background: var(--surface); border-radius: var(--radius); padding: 20px 24px; margin-bottom: 16px; }
  .section-title { font-size: .95rem; color: var(--fg2); margin: 0 0 12px 0; }
  .sessions-list { display: flex; flex-direction: column; gap: 4px; }
  .session-row { display: flex; align-items: center; gap: 10px; padding: 6px 10px; background: var(--bg3); border-radius: var(--radius-xs, 4px); font-size: .82rem; }
  .session-ip { font-family: var(--font-mono); color: var(--fg); flex: 1; }
  .session-proto { font-size: .7rem; padding: 2px 6px; border-radius: 3px; background: var(--accent-bg); color: var(--accent); font-weight: 500; text-transform: uppercase; letter-spacing: .2px; }
  .spinner-sm { display: inline-block; width: 14px; height: 14px; border: 2px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: spin .6s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
