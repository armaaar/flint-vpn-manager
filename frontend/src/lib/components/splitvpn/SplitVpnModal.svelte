<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import { api } from '../../api';
  import type { Profile, SplitVpn } from '../../types';
  import {
    SPLIT_VPN_DEFAULT_PORT, SPLIT_VPN_TUNNEL_MODES,
    initialSplitVpnForm, buildSplitVpnPayload, splitVpnEligibleGroups, settingSecret,
  } from '../../utils/splitVpn';

  export let vpn: SplitVpn | null = null;
  export let profiles: Profile[] = [];

  const dispatch = createEventDispatcher<{ saved: SplitVpn; close: void }>();

  let form = initialSplitVpnForm(vpn);
  let showAdvanced = !!vpn && (vpn.port !== SPLIT_VPN_DEFAULT_PORT || vpn.tunnel_mode !== 'TCP');
  let saving = false;
  let error = '';

  $: groups = splitVpnEligibleGroups(profiles);
  $: needsMaster = settingSecret(form);
  $: canSave =
    !!form.name.trim() && !!form.server.trim() && !!form.username.trim() &&
    (vpn ? true : (!!form.password && !!form.totp_secret.trim())) &&
    (!needsMaster || !!form.master_password);

  function toggleGroup(id: string) {
    form.group_ids = form.group_ids.includes(id)
      ? form.group_ids.filter(g => g !== id)
      : [...form.group_ids, id];
  }

  async function save() {
    if (!canSave || saving) return;
    saving = true;
    error = '';
    try {
      const data = buildSplitVpnPayload(form);
      const result = vpn ? await api.updateSplitVpn(vpn.id, data) : await api.createSplitVpn(data);
      dispatch('saved', result);
    } catch (err: any) {
      error = err?.message || 'Failed to save split VPN';
    }
    saving = false;
  }

  function close() {
    if (!saving) dispatch('close');
  }
</script>

<!-- svelte-ignore a11y-click-events-have-key-events a11y-no-static-element-interactions -->
<div class="modal-overlay active" on:click|self={close}>
  <div class="modal split-modal" role="dialog" aria-label={vpn ? 'Edit split VPN' : 'Add split VPN'}>
    <div class="modal-header">
      <h2>{vpn ? 'Edit Split VPN' : 'Add Split VPN'}</h2>
      <button class="modal-close" title="Close" on:click={close}>✕</button>
    </div>

    <form on:submit|preventDefault={save}>
      <div class="modal-body">
        <div class="type-note">
          <span class="type-badge">Barracuda CloudGen</span>
          <span>Runs on the router and carries only the destinations below for the selected groups. Everything else keeps using the group's normal route.</span>
        </div>

        <div class="form-group">
          <label for="sv-name" class="required">Name</label>
          <input id="sv-name" type="text" bind:value={form.name} placeholder="e.g. Work VPN" maxlength="64" />
        </div>

        <div class="form-group">
          <label for="sv-server" class="required">Server</label>
          <input id="sv-server" type="text" bind:value={form.server} placeholder="vpn.example.com" autocomplete="off" />
          <button type="button" class="link-btn" on:click={() => showAdvanced = !showAdvanced}>
            {showAdvanced ? '▾' : '▸'} Advanced (port {form.port || SPLIT_VPN_DEFAULT_PORT}, {form.tunnel_mode})
          </button>
        </div>

        {#if showAdvanced}
          <div class="form-row">
            <div class="form-group">
              <label for="sv-port">Port</label>
              <input id="sv-port" type="number" min="1" max="65535" bind:value={form.port} />
            </div>
            <div class="form-group">
              <label for="sv-mode">Tunnel mode</label>
              <select id="sv-mode" bind:value={form.tunnel_mode}>
                {#each SPLIT_VPN_TUNNEL_MODES as m}
                  <option value={m}>{m}</option>
                {/each}
              </select>
            </div>
          </div>
        {/if}

        <div class="form-row">
          <div class="form-group">
            <label for="sv-user" class="required">Username</label>
            <input id="sv-user" type="text" bind:value={form.username} autocomplete="off" />
          </div>
          <div class="form-group">
            <label for="sv-pass" class:required={!vpn}>Password</label>
            <input id="sv-pass" type="password" bind:value={form.password} autocomplete="new-password"
              placeholder={vpn ? (vpn.has_password ? 'unchanged' : 'not set — enter password') : ''} />
          </div>
        </div>

        <div class="form-group">
          <label for="sv-totp" class:required={!vpn}>TOTP secret</label>
          <input id="sv-totp" type="password" bind:value={form.totp_secret} autocomplete="off" spellcheck="false"
            placeholder={vpn ? (vpn.has_totp ? 'unchanged' : 'not set — enter secret') : 'Base32 secret or otpauth://totp/… URI'} />
          <span class="hint">The secret behind your authenticator's code (the base32 key or the full otpauth:// link from the QR code). One-time codes are generated automatically from it on every connect.</span>
        </div>

        {#if needsMaster}
          <div class="form-group">
            <label for="sv-master" class="required">Master password</label>
            <input id="sv-master" type="password" bind:value={form.master_password} autocomplete="current-password" />
            <span class="hint">The password and TOTP secret are stored encrypted. Enter this app's master password to save them.</span>
          </div>
        {/if}

        <div class="form-group">
          <span class="field-label">Groups</span>
          <span class="hint hint-top">Devices in these groups reach the work destinations through this VPN.</span>
          <div class="group-chips">
            {#each groups as g (g.id)}
              <button type="button" class="group-chip" class:selected={form.group_ids.includes(g.id)}
                style="--chip-color: {g.color}" aria-pressed={form.group_ids.includes(g.id)}
                on:click={() => toggleGroup(g.id)}>
                <span class="chip-icon">{g.icon}</span>
                <span>{g.name}</span>
              </button>
            {/each}
            {#if groups.length === 0}
              <span class="hint">No groups with internet access yet.</span>
            {/if}
          </div>
        </div>

        <div class="form-row">
          <div class="form-group">
            <label for="sv-domains">Work domains</label>
            <textarea id="sv-domains" rows="5" bind:value={form.domainsText} placeholder={'corp.example.com\nintranet.example.org'}></textarea>
            <span class="hint">One per line. Subdomains are included.</span>
          </div>
          <div class="form-group">
            <label for="sv-cidrs">Extra IP ranges</label>
            <textarea id="sv-cidrs" rows="5" bind:value={form.cidrsText} placeholder={'10.20.0.0/16\n192.168.50.10'}></textarea>
            <span class="hint">One IPv4 address or CIDR per line.</span>
          </div>
        </div>

        <label class="toggle-row">
          <span class="toggle">
            <input type="checkbox" bind:checked={form.use_pushed_routes} />
            <span class="toggle-slider"></span>
          </span>
          <span>Also route networks pushed by the VPN server</span>
        </label>

        <label class="toggle-row">
          <span class="toggle">
            <input type="checkbox" bind:checked={form.auto_connect} />
            <span class="toggle-slider"></span>
          </span>
          <span>Connect automatically and reconnect when the tunnel drops</span>
        </label>

        <label class="toggle-row">
          <span class="toggle">
            <input type="checkbox" bind:checked={form.enabled} />
            <span class="toggle-slider"></span>
          </span>
          <span>Enabled</span>
        </label>

        {#if vpn && ((vpn.pushed_routes || []).length || (vpn.pushed_dns || []).length)}
          <div class="learned">
            <div class="field-label">Learned from server</div>
            {#if vpn.pushed_routes?.length}
              <div class="learned-row">
                <span class="learned-key">Routes</span>
                <span class="learned-vals">{#each vpn.pushed_routes as r}<code>{r}</code>{/each}</span>
              </div>
            {/if}
            {#if vpn.pushed_dns?.length}
              <div class="learned-row">
                <span class="learned-key">DNS</span>
                <span class="learned-vals">{#each vpn.pushed_dns as d}<code>{d}</code>{/each}</span>
              </div>
            {/if}
          </div>
        {/if}

        {#if error}
          <div class="error-msg" role="alert">{error}</div>
        {/if}
      </div>

      <div class="modal-footer">
        <button type="button" class="btn-outline btn-sm" on:click={close} disabled={saving}>Cancel</button>
        <button type="submit" class="btn-primary btn-sm" disabled={!canSave || saving}>
          {saving ? 'Saving…' : (vpn ? 'Save Changes' : 'Create Split VPN')}
        </button>
      </div>
    </form>
  </div>
</div>

<style>
  .split-modal { max-width: 680px; }

  .type-note {
    display: flex; gap: 10px; align-items: flex-start; margin-bottom: 18px; padding: 10px 12px;
    background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-sm);
    color: var(--fg2); font-size: .8rem;
  }
  .type-badge {
    flex-shrink: 0; font-size: .7rem; font-weight: 600; padding: 2px 8px; border-radius: var(--radius-xs);
    background: var(--accent-bg); color: var(--accent); text-transform: uppercase; letter-spacing: 0.2px;
  }

  .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  .field-label { display: block; margin-bottom: 5px; font-size: .825rem; font-weight: 500; color: var(--fg2); }
  .hint-top { margin: -2px 0 8px; }

  textarea {
    width: 100%; resize: vertical; background: var(--bg); color: var(--fg);
    border: 1.5px solid var(--border); border-radius: var(--radius-xs); padding: 10px 14px;
    font-family: var(--font-mono); font-size: .8rem; transition: var(--transition);
  }
  textarea:focus { outline: none; border-color: var(--accent); box-shadow: var(--focus-ring); }
  textarea::placeholder, input::placeholder { color: var(--fg3); }

  .link-btn {
    background: none; border: none; padding: 6px 0 0; color: var(--accent); font-size: .75rem;
    font-weight: 500; text-transform: uppercase; letter-spacing: 0.2px;
  }
  .link-btn:hover { color: var(--fg); }

  .group-chips { display: flex; flex-wrap: wrap; gap: 6px; }
  .group-chip {
    display: inline-flex; align-items: center; gap: 6px; padding: 6px 12px;
    background: var(--surface); color: var(--fg2); border: 1.5px solid var(--border);
    border-left: 4px solid var(--chip-color, var(--border2)); border-radius: var(--radius-xs);
    font-size: .8rem; text-transform: none; letter-spacing: normal;
  }
  .group-chip:hover { border-color: var(--accent); border-left-color: var(--chip-color, var(--accent)); }
  .group-chip.selected { background: var(--accent-bg); color: var(--fg); border-color: var(--accent); border-left-color: var(--chip-color, var(--accent)); font-weight: 600; }
  .chip-icon { font-size: .95rem; line-height: 1; }

  .toggle-row { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; color: var(--fg); font-size: .875rem; cursor: pointer; }
  .toggle { position: relative; display: inline-block; width: 36px; height: 20px; flex-shrink: 0; }
  .toggle input { opacity: 0; width: 0; height: 0; padding: 0; border: none; }
  .toggle-slider { position: absolute; inset: 0; background: var(--bg3); border: 1px solid var(--border2); border-radius: 20px; transition: var(--transition); }
  .toggle-slider::before {
    content: ''; position: absolute; height: 14px; width: 14px; left: 2px; top: 2px;
    background: var(--fg3); border-radius: 50%; transition: var(--transition);
  }
  .toggle input:checked + .toggle-slider { background: var(--green); border-color: var(--green); }
  .toggle input:checked + .toggle-slider::before { transform: translateX(16px); background: var(--fg); }
  .toggle input:focus-visible + .toggle-slider { box-shadow: var(--focus-ring); }

  .learned {
    margin-top: 6px; padding: 12px; background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius-sm);
  }
  .learned-row { display: flex; gap: 10px; align-items: baseline; padding: 3px 0; }
  .learned-key { min-width: 56px; color: var(--fg3); font-size: .75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.2px; }
  .learned-vals { display: flex; flex-wrap: wrap; gap: 6px; }
  .learned-vals code { font-family: var(--font-mono); font-size: .75rem; color: var(--fg); background: var(--bg3); padding: 1px 6px; border-radius: var(--radius-xs); }

  @media (max-width: 600px) {
    .form-row { grid-template-columns: 1fr; }
  }
</style>
