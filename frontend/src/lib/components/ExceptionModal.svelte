<script>
  import { createEventDispatcher } from 'svelte';

  export let networks = [];
  export let networkDevices = {};

  const dispatch = createEventDispatcher();

  let fromType = 'device'; // 'device' | 'network'
  let fromZone = '';
  let fromDevice = null;
  let toType = 'device';
  let toZone = '';
  let toDevice = null;
  let direction = 'both';
  let saving = false;

  // Load devices for selected zone
  $: if (fromZone && !networkDevices[fromZone]) dispatch('loadDevices', fromZone);
  $: if (toZone && !networkDevices[toZone]) dispatch('loadDevices', toZone);

  $: fromDevices = fromZone ? (networkDevices[fromZone] || []) : [];
  $: toDevices = toZone ? (networkDevices[toZone] || []) : [];

  $: canSave = (() => {
    const hasFrom = fromType === 'network' ? !!fromZone : !!fromDevice;
    const hasTo = toType === 'network' ? !!toZone : !!toDevice;
    return hasFrom && hasTo;
  })();

  const buildLabel = () => {
    const fromLabel = fromType === 'network'
      ? networks.find(n => n.id === fromZone)?.ssids?.[0]?.name || fromZone
      : fromDevice?.display_name || '';
    const toLabel = toType === 'network'
      ? networks.find(n => n.id === toZone)?.ssids?.[0]?.name || toZone
      : toDevice?.display_name || '';
    const arrow = direction === 'both' ? '⟷' : direction === 'outbound' ? '→' : '←';
    return `${fromLabel} ${arrow} ${toLabel}`;
  };

  const save = () => {
    if (!canSave || saving) return;
    saving = true;

    const fromIp = fromType === 'device' ? fromDevice?.ip : '';
    const fromMac = fromType === 'device' ? fromDevice?.mac : '';
    const toIp = toType === 'device' ? toDevice?.ip : '';
    const toMac = toType === 'device' ? toDevice?.mac : '';

    // For network targets, use subnet (router will handle it)
    const targetNet = toType === 'network' ? networks.find(n => n.id === toZone) : null;
    const sourceNet = fromType === 'network' ? networks.find(n => n.id === fromZone) : null;

    dispatch('save', {
      from_ip: fromIp || (sourceNet?.subnet || ''),
      from_mac: fromMac,
      to_ip: toIp || (targetNet?.subnet || ''),
      to_mac: toMac,
      direction,
      label: buildLabel(),
    });
  };

  const close = () => dispatch('close');
</script>

<div class="modal-overlay active" on:click|self={close}>
  <div class="modal">
    <div class="modal-header">
      <h2>Add Exception</h2>
      <button class="modal-close" on:click={close}>&times;</button>
    </div>
    <div class="modal-body">
      <!-- From -->
      <div class="form-group">
        <label>From</label>
        <div class="picker-row">
          <select bind:value={fromType} on:change={() => { fromDevice = null; }}>
            <option value="device">Device</option>
            <option value="network">Entire Network</option>
          </select>
          <select bind:value={fromZone} on:change={() => { fromDevice = null; }}>
            <option value="">Select network...</option>
            {#each networks as n}
              <option value={n.id}>{n.ssids?.[0]?.name || n.zone}</option>
            {/each}
          </select>
        </div>
        {#if fromType === 'device' && fromZone}
          <select bind:value={fromDevice} class="device-select">
            <option value={null}>Select device...</option>
            {#each fromDevices as d}
              <option value={d}>{d.display_name} ({d.ip})</option>
            {/each}
          </select>
        {/if}
      </div>

      <!-- To -->
      <div class="form-group">
        <label>To</label>
        <div class="picker-row">
          <select bind:value={toType} on:change={() => { toDevice = null; }}>
            <option value="device">Device</option>
            <option value="network">Entire Network</option>
          </select>
          <select bind:value={toZone} on:change={() => { toDevice = null; }}>
            <option value="">Select network...</option>
            {#each networks as n}
              <option value={n.id}>{n.ssids?.[0]?.name || n.zone}</option>
            {/each}
          </select>
        </div>
        {#if toType === 'device' && toZone}
          <select bind:value={toDevice} class="device-select">
            <option value={null}>Select device...</option>
            {#each toDevices as d}
              <option value={d}>{d.display_name} ({d.ip})</option>
            {/each}
          </select>
        {/if}
      </div>

      <!-- Direction -->
      <div class="form-group">
        <label>Direction</label>
        <select bind:value={direction}>
          <option value="both">⟷ Both directions</option>
          <option value="outbound">→ From → To only</option>
          <option value="inbound">← To → From only</option>
        </select>
      </div>
    </div>
    <div class="modal-footer">
      <button class="btn-outline" on:click={close}>Cancel</button>
      <button class="btn-primary" on:click={save} disabled={!canSave || saving}>
        {saving ? 'Adding...' : 'Add Exception'}
      </button>
    </div>
  </div>
</div>

<style>
  .picker-row { display: flex; gap: 8px; }
  .picker-row select { flex: 1; }
  .device-select { width: 100%; margin-top: 6px; }
</style>
