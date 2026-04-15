<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import GeneralTab from './GeneralTab.svelte';
  import ServersTab from './ServersTab.svelte';
  import AdblockTab from './AdblockTab.svelte';
  import SecurityTab from './SecurityTab.svelte';

  const dispatch = createEventDispatcher();

  export let initialTab = '';

  const tabs = [
    { id: 'general', label: 'General', icon: '⚙' },
    { id: 'servers', label: 'Servers', icon: '🌐' },
    { id: 'adblock', label: 'DNS Ad Blocker', icon: '🚫' },
    { id: 'security', label: 'Security', icon: '🔒' },
  ];
  let activeTab = (initialTab && tabs.some(t => t.id === initialTab)) ? initialTab : 'general';

  function switchTab(id: string) {
    activeTab = id;
    dispatch('tabchange', id);
  }
</script>

<div class="settings-page">
  <div class="settings-header">
    <button class="back-btn" on:click={() => dispatch('back')} title="Back to Dashboard">
      ← Back
    </button>
    <h2>Settings</h2>
  </div>

  <div class="tab-bar">
    {#each tabs as tab}
      <button class="tab" class:active={activeTab === tab.id}
              on:click={() => switchTab(tab.id)}>
        <span class="tab-icon">{tab.icon}</span>
        {tab.label}
      </button>
    {/each}
  </div>

  <div class="tab-content">
    {#if activeTab === 'general'}
      <GeneralTab />
    {:else if activeTab === 'servers'}
      <ServersTab />
    {:else if activeTab === 'adblock'}
      <AdblockTab />
    {:else if activeTab === 'security'}
      <SecurityTab />
    {/if}
  </div>
</div>

<style>
  .settings-page { max-width: 800px; margin: 0 auto; padding: 20px; }
  .settings-header { display: flex; align-items: center; gap: 16px; margin-bottom: 24px; }
  .settings-header h2 { margin: 0; font-size: 1.3rem; color: var(--fg); }
  .back-btn { background: none; border: none; color: var(--accent); cursor: pointer; font-size: 1rem; padding: 4px 8px; border-radius: 6px; }
  .back-btn:hover { background: var(--accent-bg); }

  .tab-bar { display: flex; gap: 2px; border-bottom: 2px solid var(--border); margin-bottom: 24px; flex-wrap: wrap; }
  .tab { background: none; border: none; border-bottom: 2px solid transparent; margin-bottom: -2px; padding: 10px 16px; color: var(--fg3); font-size: .85rem; font-weight: 500; cursor: pointer; transition: var(--transition); white-space: nowrap; display: flex; align-items: center; gap: 6px; }
  .tab:hover { color: var(--fg); }
  .tab.active { color: var(--accent); border-bottom-color: var(--accent); }
  .tab-icon { font-size: .9rem; }

  .tab-content { min-height: 300px; }
</style>
