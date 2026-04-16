<script lang="ts">
  import type { Device } from '../../types';
  import { deviceIcon, isOnline } from '../../utils/device';

  export let device: Device;
  export let showIp = false;
  export let showMac = true;
  export let showArrow = false;
  export let showCheckbox = false;
  export let selected = false;
  export let interactive = true;
</script>

<!-- svelte-ignore a11y-click-events-have-key-events -->
<!-- svelte-ignore a11y-no-static-element-interactions -->
{#if interactive}
  <button class="dli" class:selected on:click>
    {#if showCheckbox}<input type="checkbox" checked={selected} class="dli-checkbox" tabindex="-1" />{/if}
    <span class="dli-icon">{deviceIcon(device)}</span>
    <span class="dli-dot" class:online={isOnline(device)}></span>
    <span class="dli-name">{device.display_name}</span>
    {#if showIp && device.ip}<span class="dli-meta">{device.ip}</span>{/if}
    {#if showMac}<span class="dli-mac">{device.mac}</span>{/if}
    {#if showArrow}<span class="dli-arrow">›</span>{/if}
  </button>
{:else}
  <div class="dli">
    <span class="dli-icon">{deviceIcon(device)}</span>
    <span class="dli-dot" class:online={isOnline(device)}></span>
    <span class="dli-name">{device.display_name}</span>
    {#if showIp && device.ip}<span class="dli-meta">{device.ip}</span>{/if}
    {#if showMac}<span class="dli-mac">{device.mac}</span>{/if}
  </div>
{/if}

<style>
  .dli {
    display: flex; align-items: center; gap: 8px; padding: 6px 10px;
    background: none; border: 1px solid transparent; border-radius: 6px;
    font-size: 0.88rem; width: 100%; text-align: left; color: var(--fg);
    font-family: inherit;
  }
  button.dli { cursor: pointer; }
  div.dli { cursor: default; }
  .dli:hover { background: var(--bg3); }
  .dli.selected { background: var(--accent-bg); border-color: var(--accent); }
  .dli-checkbox { accent-color: var(--accent); width: 16px; height: 16px; margin: 0; flex-shrink: 0; pointer-events: none; }
  .dli-icon { flex-shrink: 0; font-size: 0.95rem; line-height: 1; }
  .dli-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--fg3); flex-shrink: 0; }
  .dli-dot.online { background: var(--green); }
  .dli-name { font-weight: 500; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .dli-meta { color: var(--fg3); font-size: 0.78rem; font-family: var(--font-mono); }
  .dli-mac { color: var(--fg3); font-size: 0.78rem; font-family: var(--font-mono); flex-shrink: 0; }
  .dli-arrow { color: var(--fg3); font-size: 1.1rem; flex-shrink: 0; }
</style>
