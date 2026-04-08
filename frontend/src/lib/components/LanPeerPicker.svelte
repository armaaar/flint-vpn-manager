<script>
  import { profiles, devices } from '../stores/app.js';
  import { createEventDispatcher } from 'svelte';

  /** Array of entry objects: {value, type: 'mac'|'profile', source?: 'group'|'device'}.
   * Inherited entries (source === 'group') are rendered greyed out and are
   * non-removable from this picker. The picker only emits changes for
   * device-source entries; the parent diffs against the inherited list to
   * derive the device-only allow list to send to the API. */
  export let value = [];
  /** Profile ID to exclude from the picker (the current group, so it's not
   * selectable as its own exception). */
  export let excludeProfileId = null;
  /** Hide the picker entirely (e.g. when state is 'allowed'). */
  export let disabled = false;

  const dispatch = createEventDispatcher();

  let open = false;
  let search = '';

  $: deviceList = $devices || [];
  $: profileList = $profiles || [];

  $: selectedKeys = new Set((value || []).map(e => `${e.type}:${e.value}`));

  $: profileOptions = profileList
    .filter(p => p.id !== excludeProfileId)
    .filter(p => !search || (p.name || '').toLowerCase().includes(search.toLowerCase()))
    .map(p => ({
      key: `profile:${p.id}`,
      type: 'profile',
      value: p.id,
      label: `${p.icon || '📦'} ${p.name}`,
    }));

  $: deviceOptions = deviceList
    .filter(d => {
      if (!search) return true;
      const s = search.toLowerCase();
      return (d.display_name || '').toLowerCase().includes(s) ||
             (d.mac || '').toLowerCase().includes(s);
    })
    .map(d => ({
      key: `mac:${d.mac}`,
      type: 'mac',
      value: d.mac,
      label: d.display_name || d.mac,
      sub: d.mac,
    }));

  function labelFor(entry) {
    if (entry.type === 'profile') {
      const p = profileList.find(x => x.id === entry.value);
      return p ? `${p.icon || '📦'} ${p.name}` : `(deleted group)`;
    }
    const d = deviceList.find(x => (x.mac || '').toLowerCase() === entry.value.toLowerCase());
    return d ? (d.display_name || d.mac) : entry.value;
  }

  function add(opt) {
    if (selectedKeys.has(opt.key)) return;
    value = [...value, { value: opt.value, type: opt.type, source: 'device' }];
    dispatch('change', value);
    open = false;
    search = '';
  }

  function remove(entry) {
    if (entry.source === 'group') return; // can't remove inherited
    value = value.filter(e => !(e.type === entry.type && e.value === entry.value));
    dispatch('change', value);
  }

  function toggleOpen() {
    if (disabled) return;
    open = !open;
    if (open) search = '';
  }
</script>

{#if !disabled}
  <div class="picker">
    <div class="chips">
      {#each value as entry (entry.type + ':' + entry.value)}
        <span class="chip" class:inherited={entry.source === 'group'}
              title={entry.source === 'group' ? 'Inherited from group — edit on the group to remove' : ''}>
          <span class="chip-label">{labelFor(entry)}</span>
          {#if entry.source !== 'group'}
            <button class="chip-x" on:click={() => remove(entry)} aria-label="Remove">&times;</button>
          {/if}
        </span>
      {/each}
      <button class="add-btn" on:click={toggleOpen}>+ Add</button>
    </div>

    {#if open}
      <div class="dropdown">
        <input class="search" type="text" placeholder="Search devices and groups…"
               bind:value={search} autofocus />
        <div class="section-title">Groups</div>
        <div class="opt-list">
          {#each profileOptions as opt (opt.key)}
            <button class="opt" class:taken={selectedKeys.has(opt.key)}
                    disabled={selectedKeys.has(opt.key)} on:click={() => add(opt)}>
              {opt.label}
            </button>
          {:else}
            <div class="empty">No matching groups</div>
          {/each}
        </div>
        <div class="section-title">Devices</div>
        <div class="opt-list">
          {#each deviceOptions as opt (opt.key)}
            <button class="opt" class:taken={selectedKeys.has(opt.key)}
                    disabled={selectedKeys.has(opt.key)} on:click={() => add(opt)}>
              <span>{opt.label}</span><span class="sub">{opt.sub}</span>
            </button>
          {:else}
            <div class="empty">No matching devices</div>
          {/each}
        </div>
      </div>
    {/if}
  </div>
{/if}

<style>
  .picker { position: relative; }
  .chips { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; padding: 4px 0; }
  .chip {
    display: inline-flex; align-items: center; gap: 4px;
    background: var(--bg3); border: 1px solid var(--border2);
    border-radius: 999px; padding: 3px 10px; font-size: .78rem; color: var(--fg);
  }
  .chip.inherited { opacity: .55; font-style: italic; }
  .chip-label { white-space: nowrap; }
  .chip-x {
    background: transparent; border: none; color: var(--fg3);
    cursor: pointer; font-size: 1rem; line-height: 1; padding: 0 0 0 2px;
  }
  .chip-x:hover { color: var(--fg); }
  .add-btn {
    background: transparent; border: 1px dashed var(--border2);
    color: var(--fg3); border-radius: 999px; padding: 3px 10px;
    font-size: .75rem; cursor: pointer;
  }
  .add-btn:hover { color: var(--accent); border-color: var(--accent); }
  .dropdown {
    position: absolute; top: 100%; left: 0; right: 0; z-index: 100;
    margin-top: 4px; background: var(--bg2); border: 1px solid var(--border2);
    border-radius: var(--radius-xs); padding: 8px; max-height: 280px;
    overflow-y: auto; box-shadow: 0 4px 12px rgba(0,0,0,.4);
  }
  .search {
    width: 100%; padding: 6px 8px; background: var(--bg3);
    border: 1px solid var(--border2); border-radius: var(--radius-xs);
    color: var(--fg); font-size: .8rem; margin-bottom: 6px;
  }
  .section-title {
    font-size: .68rem; text-transform: uppercase; letter-spacing: .05em;
    color: var(--fg3); margin: 6px 0 2px 4px;
  }
  .opt-list { display: flex; flex-direction: column; gap: 2px; }
  .opt {
    display: flex; justify-content: space-between; align-items: center;
    background: transparent; border: none; color: var(--fg);
    padding: 6px 8px; font-size: .8rem; text-align: left; cursor: pointer;
    border-radius: var(--radius-xs);
  }
  .opt:hover:not(:disabled) { background: var(--bg3); }
  .opt.taken { opacity: .4; cursor: default; }
  .sub { font-size: .68rem; color: var(--fg3); font-family: monospace; }
  .empty { font-size: .75rem; color: var(--fg3); padding: 4px 8px; }
</style>
