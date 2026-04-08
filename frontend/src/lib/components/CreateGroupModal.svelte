<script>
  import { api } from '../api.js';
  import { profiles, showToast } from '../stores/app.js';
  import EmojiPicker from './EmojiPicker.svelte';
  import ColorPicker from './ColorPicker.svelte';
  import { createEventDispatcher } from 'svelte';

  export let visible = false;
  const dispatch = createEventDispatcher();

  const MAX_WG_GROUPS = 5;
  const MAX_OVPN_GROUPS = 5;

  let type = 'vpn', name = '', icon = '🔒', color = '#00aaff', isGuest = false;
  let vpnProtocol = 'wireguard'; // 'wireguard' or 'openvpn'
  let ovpnProtocol = 'udp'; // 'udp' or 'tcp'
  let lanOutbound = 'allowed', lanInbound = 'allowed';
  let error = '';

  // When creating VPN profile, we need the server picker
  export let onNeedServer;

  $: wgCount = $profiles.filter(p => p.type === 'vpn' && p.router_info?.vpn_protocol !== 'openvpn').length;
  $: ovpnCount = $profiles.filter(p => p.router_info?.vpn_protocol === 'openvpn').length;
  $: currentLimitReached = type === 'vpn' && (
    (vpnProtocol === 'wireguard' && wgCount >= MAX_WG_GROUPS) ||
    (vpnProtocol === 'openvpn' && ovpnCount >= MAX_OVPN_GROUPS)
  );
  $: currentCount = vpnProtocol === 'wireguard' ? wgCount : ovpnCount;
  $: currentMax = vpnProtocol === 'wireguard' ? MAX_WG_GROUPS : MAX_OVPN_GROUPS;

  // Reset form when modal opens
  $: if (visible) resetForm();

  function resetForm() {
    type = 'vpn';
    name = '';
    icon = '🔒';
    color = '#00aaff';
    isGuest = false;
    vpnProtocol = 'wireguard';
    ovpnProtocol = 'udp';
    lanOutbound = 'allowed';
    lanInbound = 'allowed';
    error = '';
  }

  function applyPreset(preset) {
    if (preset === 'open') { lanOutbound = 'allowed'; lanInbound = 'allowed'; }
    else if (preset === 'isolated') { lanOutbound = 'group_only'; lanInbound = 'group_only'; }
    else if (preset === 'locked') { lanOutbound = 'blocked'; lanInbound = 'blocked'; }
  }

  function onTypeChange() {
    const icons = { vpn: '🔒', no_vpn: '🌐', no_internet: '🚫' };
    icon = icons[type] || '🔒';
    error = '';
  }

  async function create() {
    if (!name.trim()) { error = 'Name required'; return; }
    if (type === 'vpn' && currentLimitReached) {
      const otherProto = vpnProtocol === 'wireguard' ? 'OpenVPN' : 'WireGuard';
      error = `${vpnProtocol === 'wireguard' ? 'WireGuard' : 'OpenVPN'} limit reached (${currentCount}/${currentMax}). Try ${otherProto} instead, or delete an existing group.`;
      return;
    }
    error = '';

    if (type === 'vpn') {
      visible = false;
      if (onNeedServer) {
        const savedLanOut = lanOutbound, savedLanIn = lanInbound;
        onNeedServer(async (serverId, options, scope) => {
          const body = {
            name, type, color, icon, is_guest: isGuest,
            server_id: serverId, options,
            vpn_protocol: vpnProtocol,
            ovpn_protocol: ovpnProtocol,
            server_scope: scope,
          };
          const res = await api.createProfile(body);
          if (res.error) { showToast(res.error, true); return; }
          if (savedLanOut !== 'allowed' || savedLanIn !== 'allowed') {
            await api.setProfileLanAccess(res.id, { outbound: savedLanOut, inbound: savedLanIn });
          }
          showToast(`Created ${icon} ${name}`);
          dispatch('reload');
        }, vpnProtocol);
      }
      return;
    }

    const res = await api.createProfile({ name, type, color, icon, is_guest: isGuest });
    if (res.error) { error = res.error; return; }
    if (lanOutbound !== 'allowed' || lanInbound !== 'allowed') {
      await api.setProfileLanAccess(res.id, { outbound: lanOutbound, inbound: lanInbound });
    }
    visible = false;
    showToast(`Created ${icon} ${name}`);
    dispatch('reload');
  }

  function close() { visible = false; dispatch('close'); }
</script>

{#if visible}
<div class="modal-overlay active" on:click|self={close}>
  <div class="modal">
    <div class="modal-header">
      <h2>Create Group</h2>
      <button class="modal-close" on:click={close}>&times;</button>
    </div>
    <div class="modal-body">
      <div class="form-group">
        <label for="cg-type" class="required">Group Type</label>
        <select id="cg-type" bind:value={type} on:change={onTypeChange}>
          <option value="vpn">VPN — Route through ProtonVPN tunnel</option>
          <option value="no_vpn">No VPN — Direct internet (no tunnel)</option>
          <option value="no_internet">No Internet — LAN only, block WAN</option>
        </select>
        <div class="type-descriptions">
          {#if type === 'vpn'}
            <span class="hint">All device traffic routes through a ProtonVPN tunnel. You can choose the server location, enable NetShield ad blocking, and configure kill switch.</span>
          {:else if type === 'no_vpn'}
            <span class="hint">Devices route through your ISP directly with no VPN tunnel. Useful for devices that break under VPN (banking apps, some smart home hubs). No tunnel limit applies.</span>
          {:else}
            <span class="hint">Devices get a LAN IP and can communicate on the local network, but all internet access is blocked. Ideal for printers, local-only sensors, or IoT devices that shouldn't reach the internet. No tunnel limit applies.</span>
          {/if}
        </div>
      </div>

      {#if type === 'vpn'}
      <div class="form-group">
        <label class="required">VPN Protocol</label>
        <div class="protocol-cards">
          <button type="button" class="protocol-card" class:selected={vpnProtocol === 'wireguard'}
                  on:click={() => vpnProtocol = 'wireguard'}>
            <div class="proto-name">WireGuard</div>
            <div class="proto-desc">Fastest speeds, lowest latency, modern encryption. Best for most users.</div>
            <div class="proto-slots">{wgCount}/{MAX_WG_GROUPS} used</div>
          </button>
          <button type="button" class="protocol-card" class:selected={vpnProtocol === 'openvpn'}
                  on:click={() => vpnProtocol = 'openvpn'}>
            <div class="proto-name">OpenVPN</div>
            <div class="proto-desc">More compatible, works on restricted networks, TCP option bypasses firewalls.</div>
            <div class="proto-slots">{ovpnCount}/{MAX_OVPN_GROUPS} used</div>
          </button>
        </div>
        {#if currentLimitReached}
          <div class="limit-error">{vpnProtocol === 'wireguard' ? 'WireGuard' : 'OpenVPN'} limit reached. Try the other protocol or delete an existing group.</div>
        {/if}
      </div>

      {#if vpnProtocol === 'openvpn'}
      <div class="form-group">
        <label>OpenVPN Transport</label>
        <select bind:value={ovpnProtocol}>
          <option value="udp">UDP (faster, recommended)</option>
          <option value="tcp">TCP (bypasses firewalls, slower)</option>
        </select>
        <span class="hint">Use TCP if your network blocks VPN traffic or if UDP connections are unstable.</span>
      </div>
      {/if}

      <details class="protocol-help">
        <summary>When to use which protocol?</summary>
        <div class="help-content">
          <h4>WireGuard (Recommended)</h4>
          <ul>
            <li><strong>Speed:</strong> 2-4x faster than OpenVPN, runs in the kernel</li>
            <li><strong>Latency:</strong> Lower latency, ideal for gaming and video calls</li>
            <li><strong>Battery/CPU:</strong> Much lower resource usage on the router</li>
            <li><strong>Features:</strong> Moderate NAT, NAT-PMP (port forwarding), VPN Accelerator</li>
            <li><strong>Reconnection:</strong> Reconnects almost instantly after network changes</li>
          </ul>
          <h4>OpenVPN</h4>
          <ul>
            <li><strong>Compatibility:</strong> Works on networks that block WireGuard (hotels, offices, restrictive countries)</li>
            <li><strong>TCP mode:</strong> Can run on port 443 (HTTPS port), making it nearly impossible to block</li>
            <li><strong>Maturity:</strong> Older protocol, more widely audited and documented</li>
            <li><strong>Fallback:</strong> Use when WireGuard doesn't connect</li>
          </ul>
          <h4>Quick Guide</h4>
          <ul>
            <li><strong>Home use / streaming / gaming:</strong> WireGuard</li>
            <li><strong>Hotel / office / restricted WiFi:</strong> OpenVPN TCP</li>
            <li><strong>Maximum privacy:</strong> Either works, WireGuard for speed</li>
            <li><strong>WireGuard not connecting:</strong> Try OpenVPN UDP, then TCP</li>
          </ul>
        </div>
      </details>
      {/if}

      <div class="form-group">
        <label for="cg-name" class="required">Group Name</label>
        <input id="cg-name" bind:value={name} placeholder="e.g. Streaming, Gaming, Printers">
      </div>
      <div style="display:flex;gap:12px;align-items:flex-end">
        <div class="form-group" style="width:auto">
          <label>Icon</label>
          <EmojiPicker bind:value={icon} />
        </div>
        <div class="form-group" style="width:auto">
          <label>Card Color</label>
          <ColorPicker bind:value={color} />
        </div>
      </div>
      <div class="option-item" style="margin-top:4px">
        <input type="checkbox" id="cg-guest" bind:checked={isGuest}>
        <label for="cg-guest">Set as Guest group</label>
        <span class="tooltip-trigger" title="New devices joining the network will be automatically assigned to this group. Only one group can be the Guest group at a time.">?</span>
      </div>
      <!-- LAN Access -->
      <div class="lan-section">
        <div class="lan-header">
          <span class="lan-title">LAN Access</span>
          <div class="lan-presets">
            <button type="button" class="preset-btn" class:active={lanOutbound === 'allowed' && lanInbound === 'allowed'}
                    on:click={() => applyPreset('open')} title="Full LAN access">Open</button>
            <button type="button" class="preset-btn" class:active={lanOutbound === 'group_only' && lanInbound === 'group_only'}
                    on:click={() => applyPreset('isolated')} title="Devices only talk within this group">Isolated</button>
            <button type="button" class="preset-btn" class:active={lanOutbound === 'blocked' && lanInbound === 'blocked'}
                    on:click={() => applyPreset('locked')} title="No LAN access, internet only">Locked Down</button>
          </div>
        </div>
        <div class="lan-controls">
          <div class="lan-control">
            <label for="cg-lan-out">Outbound</label>
            <select id="cg-lan-out" bind:value={lanOutbound}>
              <option value="allowed">Allowed</option>
              <option value="group_only">Group Only</option>
              <option value="blocked">Blocked</option>
            </select>
          </div>
          <div class="lan-control">
            <label for="cg-lan-in">Inbound</label>
            <select id="cg-lan-in" bind:value={lanInbound}>
              <option value="allowed">Allowed</option>
              <option value="group_only">Group Only</option>
              <option value="blocked">Blocked</option>
            </select>
          </div>
        </div>
        <div class="lan-hint">Controls whether devices in this group can communicate with devices in other groups on the local network.</div>
      </div>

      {#if error}<div class="error-msg">{error}</div>{/if}
    </div>
    <div class="modal-footer">
      <button class="btn-outline" on:click={close}>Cancel</button>
      <button class="btn-primary" on:click={create}
              disabled={type === 'vpn' && currentLimitReached}>Create Group</button>
    </div>
  </div>
</div>
{/if}

<style>
  .option-item { display: flex; align-items: center; gap: 8px; padding: 8px 10px; border-radius: var(--radius-xs); }
  .option-item input[type="checkbox"] { width: 18px; height: 18px; accent-color: var(--accent); cursor: pointer; }
  .option-item label { font-size: .85rem; cursor: pointer; }
  .tooltip-trigger { display: inline-flex; align-items: center; justify-content: center; width: 16px; height: 16px; border-radius: 50%; background: var(--border); color: var(--fg3); font-size: .65rem; font-weight: 700; cursor: help; }
  .type-descriptions { margin-top: 6px; }
  .limit-error { font-size: .82rem; color: var(--red); background: var(--red-bg); padding: 8px 10px; border-radius: var(--radius-xs); margin-top: 6px; }
  button:disabled { opacity: 0.5; cursor: not-allowed; }

  .protocol-cards { display: flex; gap: 10px; }
  .protocol-card { flex: 1; padding: 12px; border: 2px solid var(--border); border-radius: var(--radius-xs); background: var(--bg); cursor: pointer; text-align: left; transition: var(--transition); }
  .protocol-card:hover { border-color: var(--fg3); }
  .protocol-card.selected { border-color: var(--accent); background: rgba(0,180,216,.08); }
  .proto-name { font-size: .9rem; font-weight: 600; margin-bottom: 4px; color: var(--fg); }
  .proto-desc { font-size: .75rem; color: var(--fg2); line-height: 1.4; }
  .proto-slots { font-size: .7rem; color: var(--fg3); margin-top: 6px; }

  .protocol-help { margin-top: 8px; }
  .protocol-help summary { font-size: .82rem; color: var(--accent); cursor: pointer; padding: 6px 0; }
  .protocol-help summary:hover { text-decoration: underline; }
  .help-content { font-size: .8rem; color: var(--fg2); line-height: 1.5; padding: 10px; background: var(--bg); border-radius: var(--radius-xs); margin-top: 4px; }
  .help-content h4 { font-size: .85rem; color: var(--fg); margin: 8px 0 4px; }
  .help-content h4:first-child { margin-top: 0; }
  .help-content ul { margin: 0 0 0 16px; padding: 0; }
  .help-content li { margin-bottom: 3px; }

  .lan-section { margin-top: 16px; padding-top: 16px; border-top: 1px solid var(--border); }
  .lan-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; }
  .lan-title { font-size: .9rem; font-weight: 600; color: var(--fg); }
  .lan-presets { display: flex; gap: 4px; }
  .preset-btn { padding: 4px 10px; font-size: .7rem; border-radius: var(--radius-xs); border: 1px solid var(--border2); background: var(--bg3); color: var(--fg2); cursor: pointer; font-weight: 500; transition: var(--transition); }
  .preset-btn:hover { border-color: var(--accent); color: var(--accent); }
  .preset-btn.active { background: var(--accent); color: #fff; border-color: var(--accent); }
  .lan-controls { display: flex; gap: 12px; }
  .lan-control { flex: 1; }
  .lan-control label { display: block; font-size: .75rem; color: var(--fg3); margin-bottom: 4px; text-transform: uppercase; letter-spacing: .05em; }
  .lan-control select { width: 100%; padding: 8px; background: var(--bg3); border: 1px solid var(--border2); border-radius: var(--radius-xs); color: var(--fg); font-size: .85rem; }
  .lan-hint { font-size: .75rem; color: var(--fg3); margin-top: 8px; line-height: 1.4; }
</style>
