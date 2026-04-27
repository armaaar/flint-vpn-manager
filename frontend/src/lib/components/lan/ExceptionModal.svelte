<script>
  import { createEventDispatcher } from 'svelte';

  export let networks = [];
  export let networkDevices = {};
  /** @type {{ from_ip?: string, to_ip?: string, direction?: string } | null} */
  export let exception = null; // existing exception for edit mode

  const dispatch = createEventDispatcher();

  let fromType = 'device';
  let fromZone = '';
  let fromMac = '';  // track by MAC, not object ref
  let toType = 'device';
  let toZone = '';
  let toMac = '';
  let direction = 'both';
  let saving = false;
  let initialized = false;

  function findZoneByIp(ip) {
    if (!ip) return '';
    for (const [zone, devs] of Object.entries(networkDevices)) {
      if (devs.some(d => d.ip === ip)) return zone;
    }
    return '';
  }

  function findZoneBySubnet(subnet) {
    if (!subnet) return '';
    const net = networks.find(n => n.subnet === subnet);
    return net?.id || '';
  }

  function findMacByIp(zone, ip) {
    if (!zone || !ip) return '';
    return (networkDevices[zone] || []).find(d => d.ip === ip)?.mac || '';
  }

  // Pre-fill once when editing. The device-vs-network distinction is
  // encoded in the IP shape (CIDR = network, single IP = device).
  $: if (exception && !initialized && Object.keys(networkDevices).length > 0) {
    initialized = true;
    direction = exception.direction || 'both';

    const fromIsSubnet = (exception.from_ip || '').includes('/');
    if (fromIsSubnet) {
      fromType = 'network';
      fromZone = findZoneBySubnet(exception.from_ip);
    } else {
      fromType = 'device';
      fromZone = findZoneByIp(exception.from_ip);
      fromMac = findMacByIp(fromZone, exception.from_ip);
    }

    const toIsSubnet = (exception.to_ip || '').includes('/');
    if (toIsSubnet) {
      toType = 'network';
      toZone = findZoneBySubnet(exception.to_ip);
    } else {
      toType = 'device';
      toZone = findZoneByIp(exception.to_ip);
      toMac = findMacByIp(toZone, exception.to_ip);
    }
  }

  $: fromDevices = fromZone ? (networkDevices[fromZone] || []) : [];
  $: toDevices = toZone ? (networkDevices[toZone] || []) : [];
  // Resolve MAC → device object (survives SSE updates)
  $: fromDevice = fromMac ? fromDevices.find(d => d.mac === fromMac) || null : null;
  $: toDevice = toMac ? toDevices.find(d => d.mac === toMac) || null : null;

  $: sameNetwork = !!(fromZone && toZone && fromZone === toZone);

  $: canSave = (() => {
    const hasFrom = fromType === 'network' ? !!fromZone : !!fromMac;
    const hasTo = toType === 'network' ? !!toZone : !!toMac;
    return hasFrom && hasTo && !sameNetwork;
  })();

  const save = () => {
    if (!canSave || saving) return;
    saving = true;

    const sourceNet = fromType === 'network' ? networks.find(n => n.id === fromZone) : null;
    const targetNet = toType === 'network' ? networks.find(n => n.id === toZone) : null;

    dispatch('save', {
      from_ip: fromType === 'device' ? (fromDevice?.ip || '') : (sourceNet?.subnet || ''),
      to_ip: toType === 'device' ? (toDevice?.ip || '') : (targetNet?.subnet || ''),
      direction,
    });
  };

  const close = () => dispatch('close');
</script>

<div class="modal-overlay active">
  <div class="modal">
    <div class="modal-header">
      <h2>{exception ? 'Edit' : 'Add'} Exception</h2>
      <button class="modal-close" on:click={close}>&times;</button>
    </div>
    <div class="modal-body">
      <!-- From -->
      <div class="form-group">
        <label>From</label>
        <div class="picker-row">
          <select bind:value={fromType} on:change={() => { fromMac = ''; }}>
            <option value="device">Device</option>
            <option value="network">Entire Network</option>
          </select>
          <select bind:value={fromZone} on:change={() => { fromMac = ''; }}>
            <option value="">Select network...</option>
            {#each networks as n}
              <option value={n.id}>{n.ssids?.[0]?.name || n.zone}</option>
            {/each}
          </select>
        </div>
        {#if fromType === 'device' && fromZone}
          <select bind:value={fromMac} class="device-select">
            <option value="">Select device...</option>
            {#each fromDevices as d}
              <option value={d.mac}>{d.display_name} ({d.ip})</option>
            {/each}
          </select>
        {/if}
      </div>

      <!-- To -->
      <div class="form-group">
        <label>To</label>
        <div class="picker-row">
          <select bind:value={toType} on:change={() => { toMac = ''; }}>
            <option value="device">Device</option>
            <option value="network">Entire Network</option>
          </select>
          <select bind:value={toZone} on:change={() => { toMac = ''; }}>
            <option value="">Select network...</option>
            {#each networks as n}
              <option value={n.id}>{n.ssids?.[0]?.name || n.zone}</option>
            {/each}
          </select>
        </div>
        {#if toType === 'device' && toZone}
          <select bind:value={toMac} class="device-select">
            <option value="">Select device...</option>
            {#each toDevices as d}
              <option value={d.mac}>{d.display_name} ({d.ip})</option>
            {/each}
          </select>
        {/if}
      </div>

      {#if sameNetwork}
        <p class="same-net-warning">Exceptions only apply between different networks. Use device isolation for same-network blocking.</p>
      {/if}

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
        {saving ? 'Saving...' : exception ? 'Save' : 'Add Exception'}
      </button>
    </div>
  </div>
</div>

<style>
  .picker-row { display: flex; gap: 8px; }
  .picker-row select { flex: 1; }
  .device-select { width: 100%; margin-top: 6px; }
  .same-net-warning { color: var(--amber); font-size: .82rem; margin: 8px 0 0; padding: 8px 12px; background: rgba(243,156,18,.08); border-radius: var(--radius-xs); }
</style>
