<script lang="ts">
  import { deviceIcon, isOnline, isStale, isRandomMac } from '../../utils/device';
  import { timeAgo, formatSpeed } from '../../utils/format';
  import { movingDevices } from '../../stores/app';
  import { createEventDispatcher } from 'svelte';
  import type { Device } from '../../types';

  export let device: Device;
  const dispatch = createEventDispatcher();

  $: online = isOnline(device);
  $: stale = isStale(device);
  $: moving = $movingDevices.has(device.mac);
</script>

<div class="device-row" class:offline={!online} class:stale class:moving
     on:click={() => dispatch('select', device)} role="button" tabindex="0">
  <span class="device-icon">{deviceIcon(device)}</span>
  <div class="device-info">
    <div class="device-name">
      <span class="online-dot" class:on={online} class:off={!online}
            title={online ? 'Online' : device.last_seen ? 'Offline — last seen ' + timeAgo(device.last_seen) : 'Offline'}></span>
      {device.display_name}
      {#if !device.label && device.hostname}
        <span class="auto-tag">(auto)</span>
      {/if}
    </div>
    <div class="device-meta">
      {device.ip || device.mac.toUpperCase()}
      {#if device.iface}&middot; {device.iface}{/if}
      {#if online && (device.rx_speed || device.tx_speed)}
        &middot; ↓{formatSpeed(device.rx_speed)} ↑{formatSpeed(device.tx_speed)}
      {/if}
      {#if !online && device.last_seen}
        &middot; {timeAgo(device.last_seen)}
      {/if}
    </div>
  </div>
  <div class="device-badges">
    {#if isRandomMac(device.mac)}
      <span class="badge badge-random"
            title="Private/randomized MAC. This device may get a new MAC when it reconnects, losing its group assignment. Disable MAC randomization in the device WiFi settings for reliable routing.">⚠</span>
    {/if}
  </div>
  <span class="device-chevron">›</span>
</div>

<style>
  .device-row { display: flex; align-items: center; padding: 10px 16px; gap: 10px; transition: var(--transition); cursor: pointer; border-bottom: 1px solid var(--border); }
  .device-row:last-child { border-bottom: none; }
  .device-row:hover { background: var(--bg3); }
  .device-row.offline { opacity: .6; }
  .device-row.stale { opacity: .35; }
  .device-row.moving { opacity: .5; animation: shimmer 1.2s ease-in-out infinite; pointer-events: none; }
  @keyframes shimmer { 0%, 100% { opacity: .5; } 50% { opacity: .3; } }
  .device-icon { font-size: 1.1rem; width: 24px; text-align: center; }
  .device-info { flex: 1; min-width: 0; }
  .device-name { font-size: .875rem; font-weight: 500; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .device-meta { font-size: .75rem; color: var(--fg3); }
  .auto-tag { color: var(--fg3); font-size: .75rem; }
  .online-dot { display: inline-block; width: 7px; height: 7px; border-radius: 50%; margin-right: 3px; vertical-align: middle; }
  .online-dot.on { background: var(--green); box-shadow: 0 0 4px var(--green); }
  .online-dot.off { background: var(--fg3); }
  .device-badges { display: flex; gap: 4px; }
  .badge-random { font-size: .65rem; padding: 2px 6px; border-radius: 3px; font-weight: 600; background: rgba(243,156,18,.12); color: var(--amber); }
  .device-chevron { color: var(--fg3); font-size: .9rem; }
</style>
