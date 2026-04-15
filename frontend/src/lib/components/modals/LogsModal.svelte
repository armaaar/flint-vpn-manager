<script>
  import { api } from '../../api';
  import { showToast } from '../../stores/app';
  import { createEventDispatcher } from 'svelte';

  export let visible = false;
  const dispatch = createEventDispatcher();

  let logFiles = [];
  let selectedLog = 'app.log';
  let lines = [];
  let totalLines = 0;
  let loading = false;

  $: if (visible) loadLogList();

  async function loadLogList() {
    const res = await fetch('/api/logs');
    logFiles = await res.json();
    if (logFiles.length) await loadLog(selectedLog);
  }

  async function loadLog(name) {
    selectedLog = name;
    loading = true;
    const res = await fetch(`/api/logs/${name}?lines=300`);
    const data = await res.json();
    lines = data.lines || [];
    totalLines = data.total_lines || 0;
    loading = false;
    // Auto-scroll to bottom
    setTimeout(() => {
      const el = document.getElementById('log-content');
      if (el) el.scrollTop = el.scrollHeight;
    }, 50);
  }

  async function clearLog() {
    if (!confirm(`Clear ${selectedLog}?`)) return;
    await fetch(`/api/logs/${selectedLog}`, { method: 'DELETE' });
    showToast(`${selectedLog} cleared`);
    await loadLog(selectedLog);
  }

  async function refresh() {
    await loadLog(selectedLog);
  }

  function close() { visible = false; dispatch('close'); }

  function lineClass(line) {
    if (line.includes('[ERROR]')) return 'log-error';
    if (line.includes('[WARNING]')) return 'log-warn';
    if (line.includes('[INFO]')) return 'log-info';
    return '';
  }
</script>

{#if visible}
<div class="modal-overlay active">
  <div class="modal logs-modal">
    <div class="modal-header">
      <h2>Logs</h2>
      <button class="modal-close" on:click={close}>&times;</button>
    </div>
    <div class="modal-body">
      <div class="log-tabs">
        {#each logFiles as f}
          <button class="log-tab" class:active={selectedLog === f.name}
                  on:click={() => loadLog(f.name)}>
            {f.name.replace('.log', '')}
            <span class="log-size">{(f.size / 1024).toFixed(0)}KB</span>
          </button>
        {/each}
        <div class="log-actions">
          <button class="btn-outline btn-sm" on:click={refresh}>↻</button>
          <button class="btn-outline btn-sm" on:click={clearLog}>Clear</button>
        </div>
      </div>

      <div class="log-info-bar">
        {selectedLog} — {totalLines} lines
      </div>

      <div class="log-content" id="log-content">
        {#if loading}
          <div class="log-loading"><span class="spinner"></span></div>
        {:else if lines.length === 0}
          <div class="log-empty">No log entries</div>
        {:else}
          {#each lines as line}
            <div class="log-line {lineClass(line)}">{line}</div>
          {/each}
        {/if}
      </div>
    </div>
  </div>
</div>
{/if}

<style>
  .logs-modal { max-width: 800px; width: 95%; }
  .log-tabs { display: flex; gap: 4px; margin-bottom: 8px; align-items: center; flex-wrap: wrap; }
  .log-tab { padding: 6px 12px; font-size: .8rem; background: var(--bg); color: var(--fg2); border: 1px solid var(--border); border-radius: 4px; cursor: pointer; transition: var(--transition); display: flex; align-items: center; gap: 6px; }
  .log-tab.active { background: var(--accent); color: #fff; border-color: var(--accent); }
  .log-size { font-size: .65rem; opacity: .7; }
  .log-actions { margin-left: auto; display: flex; gap: 4px; }
  .log-info-bar { font-size: .75rem; color: var(--fg3); margin-bottom: 6px; }
  .log-content { background: var(--bg2); border: 1px solid var(--border); border-radius: var(--radius-xs); padding: 10px; font-family: var(--font-mono); font-size: .78rem; line-height: 1.6; max-height: 400px; overflow-y: auto; white-space: pre-wrap; word-break: break-all; }
  .log-line { padding: 1px 0; }
  .log-error { color: var(--red); }
  .log-warn { color: var(--amber); }
  .log-info { color: var(--fg2); }
  .log-loading, .log-empty { padding: 24px; text-align: center; color: var(--fg3); }
  .spinner { display: inline-block; width: 18px; height: 18px; border: 2.5px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: spin .6s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
