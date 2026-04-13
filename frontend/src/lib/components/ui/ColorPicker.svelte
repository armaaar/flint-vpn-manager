<script>
  import { tick } from 'svelte';

  export let value = '#00aaff';

  const PALETTE = [
    '#00aaff', '#0077cc', '#2980b9', '#00b4d8', '#0096c7', '#48cae4',
    '#2ecc71', '#27ae60', '#1abc9c', '#16a085', '#a8e063', '#6bc950',
    '#e74c3c', '#c0392b', '#e84393', '#fd79a8', '#ff6b6b', '#d63031',
    '#9b59b6', '#8e44ad', '#6c5ce7', '#a29bfe', '#7c3aed', '#c084fc',
    '#f39c12', '#e67e22', '#d35400', '#f1c40f', '#fdcb6e', '#ff9f43',
    '#95a5a6', '#7f8c8d', '#636e72', '#dfe6e9', '#b2bec3', '#2d3436',
  ];

  let open = false;
  let showCustom = false;
  let btnEl;
  let dropStyle = '';

  async function toggle() {
    open = !open;
    showCustom = false;
    if (open) {
      await tick();
      if (btnEl) {
        const rect = btnEl.getBoundingClientRect();
        const dropW = 214, dropH = 280;
        let left = rect.left;
        let top = rect.bottom + 4;
        if (top + dropH > window.innerHeight - 8) top = rect.top - dropH - 4;
        if (left + dropW > window.innerWidth - 8) left = window.innerWidth - dropW - 8;
        dropStyle = `top:${top}px;left:${left}px`;
      }
    }
  }

  function pick(c) {
    value = c;
    open = false;
  }

  function handleClickOutside(e) {
    if (!e.target.closest('.color-picker-wrap') && !e.target.closest('.color-dropdown')) {
      open = false;
    }
  }
</script>

<svelte:window on:click={handleClickOutside} />

<div class="color-picker-wrap">
  <button bind:this={btnEl} type="button" class="color-btn" on:click|stopPropagation={toggle}>
    <span class="color-preview" style="background:{value}"></span>
    <span class="color-hex">{value}</span>
  </button>
  {#if open}
    <div class="color-dropdown" style={dropStyle} on:click|stopPropagation>
      <div class="swatches">
        {#each PALETTE as c}
          <button type="button" class="swatch" class:selected={value === c}
                  style="background:{c}" on:click={() => pick(c)}></button>
        {/each}
        <button type="button" class="swatch custom-swatch" class:active={showCustom}
                on:click={() => showCustom = !showCustom}>
          {#if showCustom}✕{:else}…{/if}
        </button>
      </div>
      {#if showCustom}
        <div class="custom-row">
          <input type="color" bind:value style="width:32px;height:26px;padding:1px;border:1px solid var(--border);border-radius:4px;cursor:pointer">
          <input type="text" bind:value placeholder="#hex"
                 style="flex:1;padding:4px 8px;font-size:.78rem;background:var(--bg);border:1px solid var(--border);border-radius:4px;color:var(--fg);font-family:monospace">
        </div>
      {/if}
    </div>
  {/if}
</div>

<style>
  .color-picker-wrap { position: relative; display: inline-block; }
  .color-btn {
    display: flex; align-items: center; gap: 8px;
    padding: 6px 12px; height: 42px; box-sizing: border-box;
    background: var(--bg); border: 1.5px solid var(--border);
    border-radius: var(--radius-xs); cursor: pointer; transition: var(--transition);
  }
  .color-btn:hover { border-color: var(--accent); }
  .color-preview { width: 20px; height: 20px; border-radius: 4px; flex-shrink: 0; }
  .color-hex { font-size: .8rem; color: var(--fg2); font-family: var(--font-mono); }

  .color-dropdown {
    position: fixed; width: 214px;
    background: var(--bg2); border: 1px solid var(--border2);
    border-radius: var(--radius-sm); padding: 10px;
    z-index: 1000; box-shadow: var(--shadow-lg);
  }
  .swatches { display: grid; grid-template-columns: repeat(6, 28px); gap: 4px; justify-content: center; }
  .swatch {
    width: 28px; height: 28px; border-radius: 5px; border: 2px solid transparent;
    cursor: pointer; transition: transform .1s, border-color .15s; padding: 0;
  }
  .swatch:hover { transform: scale(1.15); z-index: 1; }
  .swatch.selected { border-color: #fff; box-shadow: 0 0 0 1px rgba(0,0,0,.3); }
  .custom-swatch {
    background: conic-gradient(red, yellow, lime, aqua, blue, magenta, red) !important;
    font-size: .6rem; color: #fff; font-weight: 700;
    display: flex; align-items: center; justify-content: center;
    text-shadow: 0 1px 2px rgba(0,0,0,.5);
  }
  .custom-swatch.active { border-color: #fff; }
  .custom-row { display: flex; gap: 6px; align-items: center; margin-top: 8px; }
</style>
