<script>
  import { api } from '../api.js';
  import { profiles, showToast } from '../stores/app.js';
  import EmojiPicker from './EmojiPicker.svelte';
  import ColorPicker from './ColorPicker.svelte';
  import LanPeerPicker from './LanPeerPicker.svelte';
  import HelpTooltip from './HelpTooltip.svelte';
  import { createEventDispatcher } from 'svelte';

  // The parent passes a profile reference via bind:profile, but we
  // re-resolve it from the live store so we always read the freshest
  // router-pushed values (kill_switch, etc.).
  export let profile = null;
  const dispatch = createEventDispatcher();

  // Always derive from the LIVE store by id, so SSE pushes propagate.
  $: liveProfile = profile ? ($profiles.find(p => p.id === profile.id) || profile) : null;

  let name = '', icon = '🔒', color = '#00aaff', isGuest = false;
  let lanOutbound = 'allowed', lanInbound = 'allowed';
  // Allow lists for the group itself. Plain entries: [{value, type}]
  // (no source tag — at the group layer everything IS the source).
  let lanOutboundAllow = [];
  let lanInboundAllow = [];

  // Detect if a string looks like a MAC.
  const MAC_RE = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i;
  function rawListToEntries(raw) {
    return (raw || []).map(v => ({
      value: v,
      type: MAC_RE.test(v) ? 'mac' : 'profile',
    }));
  }
  function entriesToRawList(entries) {
    return (entries || []).map(e => e.value);
  }
  // VPN options
  let killSwitch = false;
  let netshield = '0';
  let accelerator = true;
  let moderateNat = false;
  let natPmp = false;
  // Snapshots for change detection
  let initial = {
    killSwitch: false, netshield: '0',
    accelerator: true, moderateNat: false, natPmp: false,
  };
  let lastLoadedId = null;

  $: isWireGuard = liveProfile?.router_info?.vpn_protocol !== 'openvpn';

  // Re-read whenever we open a different profile (or the user reopens after close).
  $: if (liveProfile && liveProfile.id !== lastLoadedId) {
    lastLoadedId = liveProfile.id;
    name = liveProfile.name;
    icon = liveProfile.icon;
    color = liveProfile.color;
    isGuest = liveProfile.is_guest || false;
    lanOutbound = liveProfile.lan_access?.outbound || 'allowed';
    lanInbound = liveProfile.lan_access?.inbound || 'allowed';
    lanOutboundAllow = rawListToEntries(liveProfile.lan_access?.outbound_allow);
    lanInboundAllow = rawListToEntries(liveProfile.lan_access?.inbound_allow);
    // Router-canonical kill_switch — defaults to false when undefined.
    killSwitch = liveProfile.kill_switch === true;
    const opts = liveProfile.options || {};
    netshield = String(opts.netshield ?? '0');
    accelerator = opts.vpn_accelerator !== false;
    moderateNat = !!opts.moderate_nat;
    natPmp = !!opts.nat_pmp;
    initial = { killSwitch, netshield, accelerator, moderateNat, natPmp };
  }
  $: if (!profile) lastLoadedId = null;

  // Options other than kill_switch require regenerating the WG/OVPN config.
  $: optionsChanged = (
    netshield !== initial.netshield ||
    accelerator !== initial.accelerator ||
    moderateNat !== initial.moderateNat ||
    natPmp !== initial.natPmp
  );

  function applyPreset(preset) {
    if (preset === 'open') { lanOutbound = 'allowed'; lanInbound = 'allowed'; }
    else if (preset === 'isolated') { lanOutbound = 'group_only'; lanInbound = 'group_only'; }
    else if (preset === 'locked') { lanOutbound = 'blocked'; lanInbound = 'blocked'; }
  }

  let saving = false, deleting = false;

  async function save() {
    if (!liveProfile || saving) return;
    saving = true;
    try {
      const update = { name, icon, color };
      if (liveProfile.type === 'vpn' && killSwitch !== initial.killSwitch) {
        update.kill_switch = killSwitch;
      }
      await api.updateProfile(liveProfile.id, update);
      if (isGuest) await api.setGuestProfile(liveProfile.id);
      await api.setProfileLanAccess(liveProfile.id, {
        outbound: lanOutbound,
        inbound: lanInbound,
        outbound_allow: entriesToRawList(lanOutboundAllow),
        inbound_allow: entriesToRawList(lanInboundAllow),
      });

      // NetShield / Accelerator / Moderate NAT / NAT-PMP are baked into the
      // generated WG/OVPN config — changing them requires regenerating the
      // tunnel via api.changeServer with the same server.
      if (liveProfile.type === 'vpn' && optionsChanged && liveProfile.server?.id) {
        const newOptions = {
          netshield: parseInt(netshield),
          vpn_accelerator: accelerator,
          moderate_nat: moderateNat,
          nat_pmp: natPmp,
        };
        showToast('Regenerating tunnel with new options…');
        const res = await api.changeServer(liveProfile.id, {
          server_id: liveProfile.server.id,
          options: newOptions,
          server_scope: liveProfile.server_scope,
        });
        if (res?.error) {
          showToast(res.error, true);
          return;
        }
      }
      close();
      showToast('Group updated');
      dispatch('reload');
    } finally {
      saving = false;
    }
  }

  async function deleteGroup() {
    if (!confirm(`Delete "${name}"? All devices will be unassigned.`)) return;
    deleting = true;
    await api.deleteProfile(profile.id);
    deleting = false;
    close();
    showToast('Group deleted');
    dispatch('reload');
  }

  function close() { profile = null; dispatch('close'); }
</script>

{#if profile}
<div class="modal-overlay active" on:click|self={close}>
  <div class="modal">
    <div class="modal-header">
      <h2>Edit Group</h2>
      <button class="modal-close" on:click={close}>&times;</button>
    </div>
    <div class="modal-body">
      <div class="form-group">
        <label for="eg-name" class="required">Name</label>
        <input id="eg-name" bind:value={name}>
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
        <input type="checkbox" id="eg-guest" bind:checked={isGuest}>
        <label for="eg-guest">Set as Guest group</label>
      </div>

      {#if liveProfile?.type === 'vpn'}
        <div class="vpn-options-section">
          <div class="lan-header">
            <span class="lan-title">VPN Options</span>
            {#if !isWireGuard}<span class="proto-note">OpenVPN</span>{/if}
          </div>
          <div class="form-group">
            <label for="eg-netshield" class="opt-label-with-help">
              NetShield
              <HelpTooltip title="NetShield">
                <p>Blocks ads, trackers, and malware at the DNS level for every device in this group. Use the highest level by default; drop to Malware only if a site breaks.</p>
              </HelpTooltip>
            </label>
            <select id="eg-netshield" bind:value={netshield}>
              <option value="0">Off</option>
              <option value="1">Malware</option>
              <option value="2">Malware + Ads + Trackers</option>
            </select>
          </div>
          <div class="option-item">
            <input type="checkbox" id="eg-killswitch" bind:checked={killSwitch}>
            <label for="eg-killswitch">
              Kill Switch
              <span class="opt-hint">— block traffic if the tunnel drops</span>
            </label>
            <HelpTooltip title="Kill Switch">
              <p>If the VPN drops, devices lose all internet instead of leaking through your ISP. Turn on for torrenting, work, or anything privacy-sensitive.</p>
            </HelpTooltip>
          </div>
          {#if isWireGuard}
            <div class="option-item">
              <input type="checkbox" id="eg-acc" bind:checked={accelerator}>
              <label for="eg-acc">
                VPN Accelerator
                <span class="opt-hint">— up to 400% faster (recommended)</span>
              </label>
              <HelpTooltip title="VPN Accelerator">
                <p>Proton's speed-tuning tweaks — same encryption, just faster. Leave on unless you're troubleshooting connection issues.</p>
              </HelpTooltip>
            </div>
            <div class="option-item">
              <input type="checkbox" id="eg-mn" bind:checked={moderateNat}>
              <label for="eg-mn">
                Moderate NAT
                <span class="opt-hint">— better for gaming/P2P</span>
              </label>
              <HelpTooltip title="Moderate NAT">
                <p>Fixes "Strict NAT" issues with gaming consoles, voice/video calls, and P2P apps. Slightly less anonymous; turn on if you have an Xbox/PlayStation or use Discord voice chat.</p>
              </HelpTooltip>
            </div>
            <div class="option-item">
              <input type="checkbox" id="eg-nm" bind:checked={natPmp}>
              <label for="eg-nm">
                NAT-PMP
                <span class="opt-hint">— UPnP-style port forwarding</span>
              </label>
              <HelpTooltip title="NAT-PMP (Port Forwarding)">
                <p>Lets apps inside the tunnel accept incoming connections. Turn on for torrent seeding or hosting; leave off otherwise.</p>
              </HelpTooltip>
            </div>
          {/if}
          {#if optionsChanged}
            <div class="opt-warning">
              ⚠ Changing NetShield, Accelerator, Moderate NAT, or NAT-PMP will
              regenerate the tunnel and briefly disconnect.
            </div>
          {/if}
        </div>
      {/if}

      <!-- LAN Access Control -->
      <div class="lan-section">
        <div class="lan-header">
          <span class="lan-title">LAN Access</span>
          <div class="lan-presets">
            <button class="preset-btn" class:active={lanOutbound === 'allowed' && lanInbound === 'allowed'}
                    on:click={() => applyPreset('open')} title="Full LAN access">Open</button>
            <button class="preset-btn" class:active={lanOutbound === 'group_only' && lanInbound === 'group_only'}
                    on:click={() => applyPreset('isolated')} title="Devices only talk within this group">Isolated</button>
            <button class="preset-btn" class:active={lanOutbound === 'blocked' && lanInbound === 'blocked'}
                    on:click={() => applyPreset('locked')} title="No LAN access, internet only">Locked Down</button>
          </div>
        </div>
        <div class="lan-controls">
          <div class="lan-control">
            <label for="eg-lan-out">Outbound</label>
            <select id="eg-lan-out" bind:value={lanOutbound}>
              <option value="allowed">Allowed</option>
              <option value="group_only">Group Only</option>
              <option value="blocked">Blocked</option>
            </select>
            {#if lanOutbound !== 'allowed'}
              <div class="exc-label">Exceptions (always allowed):</div>
              <LanPeerPicker bind:value={lanOutboundAllow} excludeProfileId={liveProfile?.id} />
            {/if}
          </div>
          <div class="lan-control">
            <label for="eg-lan-in">Inbound</label>
            <select id="eg-lan-in" bind:value={lanInbound}>
              <option value="allowed">Allowed</option>
              <option value="group_only">Group Only</option>
              <option value="blocked">Blocked</option>
            </select>
            {#if lanInbound !== 'allowed'}
              <div class="exc-label">Exceptions (always allowed):</div>
              <LanPeerPicker bind:value={lanInboundAllow} excludeProfileId={liveProfile?.id} />
            {/if}
          </div>
        </div>
        <div class="lan-hint">Controls whether devices in this group can communicate with devices in other groups on the local network. Exceptions pierce a Group Only or Blocked posture for specific peers without weakening it for everyone else.</div>
      </div>

      <div style="margin-top:16px;padding-top:16px;border-top:1px solid var(--border)">
        <button class="btn-danger btn-sm" on:click={deleteGroup} disabled={deleting || saving}>
          {#if deleting}Deleting...{:else}Delete Group{/if}
        </button>
      </div>
    </div>
    <div class="modal-footer">
      <button class="btn-outline" on:click={close}>Cancel</button>
      <button class="btn-primary" on:click={save} disabled={saving || deleting}>
        {#if saving}Saving...{:else}Save{/if}
      </button>
    </div>
  </div>
</div>
{/if}

<style>
  .option-item { display: flex; align-items: center; gap: 8px; padding: 8px 10px; }
  .opt-label-with-help { display: flex; align-items: center; }
  .option-item input[type="checkbox"] { width: 18px; height: 18px; accent-color: var(--accent); cursor: pointer; }
  .option-item label { font-size: .85rem; cursor: pointer; }
  .opt-hint { color: var(--fg3); font-weight: 400; font-size: .78rem; }
  .vpn-options-section { margin-top: 16px; padding-top: 16px; border-top: 1px solid var(--border); }
  .vpn-options-section .form-group { margin-bottom: 8px; }
  .proto-note { font-size: .7rem; color: var(--fg3); font-weight: 400; }
  .opt-warning {
    margin-top: 8px; padding: 8px 10px; background: rgba(243,156,18,.15);
    border-radius: var(--radius-xs); font-size: .75rem; color: #f39c12;
    line-height: 1.4;
  }

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
  .exc-label { font-size: .68rem; color: var(--fg3); margin-top: 8px; text-transform: uppercase; letter-spacing: .04em; }
</style>
