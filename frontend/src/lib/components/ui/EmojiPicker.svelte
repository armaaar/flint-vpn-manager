<script>
  import { EMOJI_CATEGORIES } from '../../emojiData';
  import { createEventDispatcher, tick } from 'svelte';

  export let value = '🔒';
  let open = false;
  let search = '';
  let searchInput;
  let btnEl;
  let dropdownStyle = '';
  const dispatch = createEventDispatcher();

  // Flatten for search — each entry has emoji, keywords, and category
  const allEmojis = EMOJI_CATEGORIES.flatMap(c =>
    c.emojis.map(item => ({ emoji: item.e, keywords: `${c.name} ${item.k}`.toLowerCase() }))
  );

  $: filtered = search.trim()
    ? allEmojis.filter(item => {
        const q = search.toLowerCase();
        return q.split(/\s+/).every(word => item.keywords.includes(word));
      })
    : null;

  function pick(emoji) {
    value = emoji;
    open = false;
    search = '';
    dispatch('change', emoji);
  }

  async function toggle() {
    open = !open;
    if (open) {
      search = '';
      await tick();
      // Position dropdown above the button using fixed positioning
      if (btnEl) {
        const rect = btnEl.getBoundingClientRect();
        const dropW = 300, dropH = 340;
        let left = rect.left;
        let top = rect.top - dropH - 4;
        // If it would go off the top, show below instead
        if (top < 8) top = rect.bottom + 4;
        // Keep within viewport horizontally
        if (left + dropW > window.innerWidth - 8) left = window.innerWidth - dropW - 8;
        dropdownStyle = `top:${top}px;left:${left}px`;
      }
      setTimeout(() => searchInput?.focus(), 50);
    }
  }

  function handleClickOutside(e) {
    if (!e.target.closest('.emoji-picker-wrap') && !e.target.closest('.emoji-dropdown')) {
      open = false;
      search = '';
    }
  }
</script>

<svelte:window on:click={handleClickOutside} />

<div class="emoji-picker-wrap">
  <button bind:this={btnEl} type="button" class="emoji-btn" on:click|stopPropagation={toggle}>
    {value}
  </button>
  {#if open}
    <div class="emoji-dropdown" style={dropdownStyle} on:click|stopPropagation>
      <div class="emoji-search">
        <input bind:this={searchInput} bind:value={search}
               placeholder="Search category..." type="text">
      </div>
      <div class="emoji-scroll">
        {#if filtered}
          <div class="emoji-grid">
            {#each filtered as item}
              <button type="button" class="emoji-item" title={item.keywords} on:click={() => pick(item.emoji)}>{item.emoji}</button>
            {/each}
          </div>
          {#if filtered.length === 0}
            <div class="emoji-empty">No matches</div>
          {/if}
        {:else}
          {#each EMOJI_CATEGORIES as cat}
            <div class="emoji-cat-label">{cat.name}</div>
            <div class="emoji-grid">
              {#each cat.emojis as item}
                <button type="button" class="emoji-item" title={item.k} on:click={() => pick(item.e)}>{item.e}</button>
              {/each}
            </div>
          {/each}
        {/if}
      </div>
    </div>
  {/if}
</div>

<style>
  .emoji-picker-wrap { position: relative; }
  .emoji-btn {
    display: flex; align-items: center; justify-content: center;
    width: 50px; height: 42px; font-size: 1.4rem;
    background: var(--bg); border: 1.5px solid var(--border);
    border-radius: var(--radius-xs); cursor: pointer; transition: var(--transition);
  }
  .emoji-btn:hover { border-color: var(--accent); }
  .emoji-dropdown {
    position: fixed;
    background: var(--bg2); border: 1px solid var(--border2);
    border-radius: var(--radius-sm); width: 300px;
    z-index: 1000; box-shadow: var(--shadow-lg);
    display: flex; flex-direction: column;
    max-height: 340px;
  }
  .emoji-search {
    padding: 8px 8px 4px;
    flex-shrink: 0;
  }
  .emoji-search input {
    width: 100%; padding: 6px 10px; font-size: .82rem;
    background: var(--bg); border: 1px solid var(--border);
    border-radius: var(--radius-xs); color: var(--fg);
    outline: none; box-sizing: border-box;
  }
  .emoji-search input:focus { border-color: var(--accent); }
  .emoji-scroll {
    overflow-y: auto; overflow-x: hidden; padding: 4px 8px 8px;
    flex: 1; min-height: 0;
  }
  .emoji-cat-label {
    font-size: .65rem; text-transform: uppercase; letter-spacing: .06em;
    color: var(--fg3); padding: 6px 2px 3px; font-weight: 600;
  }
  .emoji-grid {
    display: grid; grid-template-columns: repeat(8, 1fr); gap: 1px;
  }
  .emoji-item {
    font-size: 1.2rem; padding: 4px 0; cursor: pointer;
    border-radius: 4px; text-align: center; border: none;
    background: none; line-height: 1;
  }
  .emoji-item:hover { background: var(--bg3); }
  .emoji-empty {
    padding: 20px; text-align: center; color: var(--fg3); font-size: .85rem;
  }
</style>
