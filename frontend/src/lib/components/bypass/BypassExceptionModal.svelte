<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import type { BypassException, BypassPreset, BypassRule, BypassRuleBlock, Profile, Device } from '../../types';
  import { deviceIcon, isOnline } from '../../utils/device';

  export let exception: BypassException | null = null;
  export let presets: Record<string, BypassPreset> = {};
  export let profiles: Profile[] = [];
  export let devices: Device[] = [];

  const dispatch = createEventDispatcher();

  // Form state
  let step = exception ? 2 : 1;
  let name = exception?.name || '';
  let scope: string = exception?.scope || 'global';
  let scopeTargets: string[] = Array.isArray(exception?.scope_target) ? exception.scope_target : (exception?.scope_target ? [exception.scope_target] : []);
  let ruleBlocks: BypassRuleBlock[] = exception?.rule_blocks
    ? exception.rule_blocks.map(b => ({ label: b.label || '', rules: b.rules.map(r => ({...r})) }))
    : [];
  let presetId: string | null = exception?.preset_id || null;

  function selectPreset(id: string) {
    const preset = presets[id];
    if (!preset) return;
    name = preset.name;
    presetId = id;
    ruleBlocks = (preset.rule_blocks || []).map(b => ({
      label: b.label || '',
      rules: (b.rules || []).map(r => ({...r})),
    }));
    step = 2;
  }

  function startCustom() {
    name = '';
    presetId = null;
    ruleBlocks = [{ label: '', rules: [] }];
    step = 2;
  }

  function addBlock() {
    ruleBlocks = [...ruleBlocks, { label: '', rules: [] }];
  }

  function removeBlock(bi: number) {
    ruleBlocks = ruleBlocks.filter((_, i) => i !== bi);
  }

  function addRule(bi: number) {
    ruleBlocks[bi].rules = [...ruleBlocks[bi].rules, { type: 'cidr', value: '' }];
    ruleBlocks = ruleBlocks;
  }

  function removeRule(bi: number, ri: number) {
    ruleBlocks[bi].rules = ruleBlocks[bi].rules.filter((_, i) => i !== ri);
    ruleBlocks = ruleBlocks;
  }

  function save() {
    if (!name.trim()) name = 'Untitled';
    // Filter out empty rules and empty blocks
    const cleanBlocks = ruleBlocks
      .map(b => ({
        label: b.label,
        rules: b.rules.filter(r => r.value.trim()),
      }))
      .filter(b => b.rules.length > 0);

    const data: Record<string, unknown> = {
      name,
      scope,
      scope_target: scope === 'global' ? null : scopeTargets,
      preset_id: presetId,
      rule_blocks: cleanBlocks,
    };
    dispatch('save', data);
  }

  $: vpnProfiles = profiles.filter(p => p.type === 'vpn');

  let targetSearch = '';
  // Groups: keep dashboard order (already sorted by display_order), then filter
  $: filteredGroups = vpnProfiles.filter(p =>
    !targetSearch || p.name.toLowerCase().includes(targetSearch.toLowerCase())
  );
  // Devices: sort alphabetically by display_name, then filter
  $: filteredDevices = [...devices]
    .sort((a, b) => a.display_name.localeCompare(b.display_name))
    .filter(d =>
      !targetSearch ||
      d.display_name.toLowerCase().includes(targetSearch.toLowerCase()) ||
      d.mac.toLowerCase().includes(targetSearch.toLowerCase())
    );
  // Reset search and clear targets when scope changes
  let prevScope = scope;
  $: if (scope !== prevScope) {
    targetSearch = '';
    scopeTargets = [];
    prevScope = scope;
  }

  const CIDR_RE = /^[0-9a-fA-F.:]+(\/(3[0-2]|[12]?\d))?$/;
  const DOMAIN_RE = /^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$/;
  const PORT_RE = /^[0-9]+(:[0-9]+)?(,[0-9]+(:[0-9]+)?)*$/;

  function isValidRule(rule: BypassRule): boolean {
    const v = rule.value.trim();
    if (!v) return true;
    if (rule.type === 'cidr') return CIDR_RE.test(v);
    if (rule.type === 'domain') return DOMAIN_RE.test(v);
    if (rule.type === 'port') return PORT_RE.test(v);
    return false;
  }

  $: hasValidRules = ruleBlocks.some(b => b.rules.some(r => r.value.trim()));
  $: scopeValid = scope === 'global' || (scope === 'custom' && scopeTargets.length > 0);

  function toggleTarget(value: string) {
    if (scopeTargets.includes(value)) {
      scopeTargets = scopeTargets.filter(t => t !== value);
    } else {
      scopeTargets = [...scopeTargets, value];
    }
  }
</script>

<!-- svelte-ignore a11y-click-events-have-key-events -->
<div class="modal-overlay" on:click|self={() => dispatch('close')}>
  <div class="modal">
    <div class="modal-header">
      <h3>{exception ? 'Edit Exception' : 'Add Bypass Exception'}</h3>
      <button class="close-btn" on:click={() => dispatch('close')}>✕</button>
    </div>

    {#if step === 1}
      <div class="modal-body">
        <p class="step-label">Choose a preset or create custom rules:</p>
        <div class="preset-picker">
          {#each Object.entries(presets) as [id, preset]}
            <button class="preset-pick-card" on:click={() => selectPreset(id)}>
              <span class="pick-name">{preset.name}</span>
              <span class="pick-meta">{(preset.rule_blocks || []).length} blocks</span>
            </button>
          {/each}
          <button class="preset-pick-card custom-card" on:click={startCustom}>
            <span class="pick-name">+ Custom</span>
            <span class="pick-meta">Define your own rules</span>
          </button>
        </div>
      </div>

    {:else}
      <div class="modal-body">
        <div class="form-group">
          <label for="exc-name">Name</label>
          <input id="exc-name" type="text" bind:value={name} placeholder="e.g. League of Legends" />
        </div>

        <div class="form-group">
          <label>Scope</label>
          <div class="scope-radios">
            <label class="radio-label">
              <input type="radio" bind:group={scope} value="global" /> Global (all devices)
            </label>
            <label class="radio-label">
              <input type="radio" bind:group={scope} value="custom" /> Selected groups / devices
            </label>
          </div>
        </div>

        {#if scope === 'custom'}
          <div class="form-group">
            <label>VPN Groups</label>
            <div class="target-list">
              {#each filteredGroups as p}
                <label class="target-check">
                  <input type="checkbox" checked={scopeTargets.includes(p.id)}
                    on:change={() => toggleTarget(p.id)} />
                  <span class="target-icon">{p.icon}</span>
                  <span class="target-name">{p.name}</span>
                </label>
              {/each}
              {#if filteredGroups.length === 0}
                <span class="no-targets">No VPN groups available</span>
              {/if}
            </div>
          </div>

          <div class="form-group">
            <label>Devices</label>
            <input type="text" class="target-search" bind:value={targetSearch} placeholder="Search by name or MAC..." />
            <div class="target-list device-target-list">
              {#each filteredDevices as d}
                <button class="device-row" class:selected={scopeTargets.includes(d.mac)}
                  on:click={() => toggleTarget(d.mac)}>
                  <span class="dev-icon">{deviceIcon(d)}</span>
                  <span class="dev-dot" class:online={isOnline(d)}></span>
                  <span class="dev-name">{d.display_name}</span>
                  <span class="dev-mac">{d.mac}</span>
                </button>
              {/each}
              {#if filteredDevices.length === 0}
                <span class="no-targets">{targetSearch ? 'No matching devices' : 'No devices available'}</span>
              {/if}
            </div>
          </div>
        {/if}

        <div class="form-group">
          <label>Rule Blocks</label>
          <p class="rules-hint">
            Traffic matches a block when <strong>all conditions</strong> are met: destination matches <strong>any</strong> listed IP/domain <strong>and</strong> port matches <strong>any</strong> listed port. If a block has only IPs, all traffic to those IPs bypasses. If it has IPs + ports, only traffic on those ports to those IPs bypasses. Multiple blocks act as alternatives — matching <strong>any one</strong> block is enough. Domain rules include all subdomains.
          </p>

          {#each ruleBlocks as block, bi}
            {#if bi > 0}<div class="block-or-divider"><span>OR</span></div>{/if}
            <div class="block-editor">
              <div class="block-header">
                <input type="text" class="block-label-input" bind:value={block.label} placeholder="Block label (optional)" />
                {#if ruleBlocks.length > 1}
                  <button class="btn-icon btn-danger" title="Remove block" on:click={() => removeBlock(bi)}>✕</button>
                {/if}
              </div>
              <div class="rules-editor">
                {#each block.rules as rule, ri}
                  {@const invalid = rule.value.trim() && !isValidRule(rule)}
                  <div class="rule-edit-row" class:rule-invalid={invalid}>
                    <select bind:value={rule.type} class="rule-type-sel">
                      <option value="cidr">IP / CIDR</option>
                      <option value="domain">Domain</option>
                      <option value="port">Port</option>
                    </select>
                    <input type="text" bind:value={rule.value} class="rule-value-input"
                      class:input-error={invalid}
                      placeholder={rule.type === 'cidr' ? '10.0.0.0/8' : rule.type === 'domain' ? 'example.com' : '5000:5500'}
                      title={rule.type === 'domain' ? 'Matches domain and all subdomains' : rule.type === 'cidr' ? 'IP address or CIDR range' : 'Port or port range (e.g. 5000:5500)'} />
                    {#if rule.type === 'port'}
                      <select bind:value={rule.protocol} class="rule-proto-sel">
                        <option value="tcp">TCP</option>
                        <option value="udp">UDP</option>
                      </select>
                    {/if}
                    <button class="btn-icon btn-danger" on:click={() => removeRule(bi, ri)}>✕</button>
                  </div>
                {/each}
                <button class="btn-add-rule" on:click={() => addRule(bi)}>+ Add Rule</button>
              </div>
            </div>
          {/each}

          <button class="btn-add-block" on:click={addBlock}>+ Add Block (OR)</button>
        </div>
      </div>

      <div class="modal-footer">
        {#if !exception}
          <button class="btn-back" on:click={() => { step = 1; }}>Back</button>
        {/if}
        <button class="btn-save" on:click={save}
          disabled={!name.trim() || !hasValidRules || !scopeValid}>
          {exception ? 'Save Changes' : 'Create Exception'}
        </button>
      </div>
    {/if}
  </div>
</div>

<style>
  .modal-overlay {
    position: fixed; inset: 0; background: rgba(0,0,0,0.6); display: flex;
    align-items: center; justify-content: center; z-index: 100;
  }
  .modal {
    background: var(--bg2); border: 1px solid var(--border); border-radius: 12px;
    width: 700px; max-width: 95vw; max-height: 85vh; overflow-y: auto;
    box-shadow: 0 10px 40px rgba(0,0,0,0.4);
  }
  .modal-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 16px 20px; border-bottom: 1px solid var(--border);
  }
  .modal-header h3 { margin: 0; font-size: 1.1rem; font-weight: 600; color: var(--fg); }
  .close-btn { background: none; border: none; color: var(--fg3); cursor: pointer; font-size: 1.2rem; padding: 4px; }
  .close-btn:hover { color: var(--fg); }

  .modal-body { padding: 20px; }
  .modal-footer { padding: 12px 20px; border-top: 1px solid var(--border); display: flex; justify-content: flex-end; gap: 8px; }

  .step-label { color: var(--fg2); margin-bottom: 16px; font-size: 0.95rem; }

  .preset-picker { display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 10px; }
  .preset-pick-card {
    background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
    padding: 14px; cursor: pointer; text-align: left; display: flex; flex-direction: column; gap: 4px;
    transition: border-color 0.15s;
  }
  .preset-pick-card:hover { border-color: var(--accent); }
  .custom-card { border-style: dashed; }
  .pick-name { font-weight: 600; color: var(--fg); font-size: 0.95rem; }
  .pick-meta { color: var(--fg3); font-size: 0.8rem; }

  .form-group { margin-bottom: 16px; }
  .form-group > label { display: block; font-weight: 500; color: var(--fg2); margin-bottom: 6px; font-size: 0.88rem; text-transform: uppercase; letter-spacing: 0.2px; }
  .form-group input[type="text"], .form-group select {
    width: 100%; padding: 8px 12px; background: var(--surface); border: 1px solid var(--border);
    border-radius: 6px; color: var(--fg); font-size: 0.95rem; font-family: var(--font-ui); box-sizing: border-box;
  }
  .form-group input:focus, .form-group select:focus { outline: none; border-color: var(--accent); }

  .scope-radios { display: flex; gap: 6px; }
  .radio-label {
    display: flex; align-items: center; justify-content: center; color: var(--fg); font-size: 0.88rem;
    cursor: pointer; padding: 10px 18px; border-radius: 8px; text-align: center;
    background: var(--surface); border: 1px solid var(--border); transition: border-color 0.15s, background 0.15s;
    flex: 1;
  }
  .radio-label:hover { border-color: var(--accent); }
  .radio-label:has(input:checked) { border-color: var(--accent); background: var(--accent-bg); color: var(--accent); font-weight: 600; }
  .radio-label input[type="radio"] { display: none; }

  .target-list {
    max-height: 200px; overflow-y: auto; background: var(--surface);
    border: 1px solid var(--border); border-radius: 8px; padding: 6px;
  }
  .target-check {
    display: grid; grid-template-columns: 20px auto 1fr; gap: 8px; align-items: center;
    color: var(--fg); font-size: 0.9rem; cursor: pointer;
    padding: 7px 10px; border-radius: 6px; border: 1px solid transparent; margin-bottom: 2px;
  }
  .target-check:hover { background: var(--bg3); }
  .target-check:has(input:checked) { background: var(--accent-bg); border-color: var(--accent); }
  .target-check input[type="checkbox"] { accent-color: var(--accent); width: 16px; height: 16px; margin: 0; }
  .target-icon { font-size: 1rem; line-height: 1; }
  .target-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .target-mac { color: var(--fg3); font-family: var(--font-mono); font-size: 0.78rem; grid-column: 3; text-align: right; }
  .target-search {
    width: 100%; padding: 7px 12px; margin-bottom: 6px; background: var(--surface);
    border: 1px solid var(--border); border-radius: 6px; color: var(--fg);
    font-size: 0.88rem; box-sizing: border-box;
  }
  .target-search:focus { outline: none; border-color: var(--accent); }
  .target-search::placeholder { color: var(--fg3); }
  /* Device rows (Networks-style) */
  .device-target-list { padding: 4px; }
  .device-row {
    display: flex; align-items: center; gap: 8px; padding: 7px 10px;
    background: none; border: 1px solid transparent; border-radius: 6px;
    font-size: 0.88rem; width: 100%; text-align: left; color: var(--fg);
    cursor: pointer; font-family: inherit; margin-bottom: 2px;
  }
  .device-row:hover { background: var(--bg3); }
  .device-row.selected { background: var(--accent-bg); border-color: var(--accent); }
  .dev-icon { flex-shrink: 0; font-size: 0.95rem; line-height: 1; }
  .dev-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--fg3); flex-shrink: 0; }
  .dev-dot.online { background: var(--green); }
  .dev-name { font-weight: 500; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .dev-mac { color: var(--fg3); font-family: var(--font-mono); font-size: 0.78rem; flex-shrink: 0; }

  .no-targets { color: var(--fg3); font-size: 0.85rem; padding: 12px; text-align: center; }

  .rules-hint { color: var(--fg3); font-size: 0.8rem; margin-bottom: 12px; margin-top: 0; }

  /* Block editor */
  .block-editor {
    background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
    padding: 12px; margin-bottom: 4px;
  }
  .block-header { display: flex; gap: 8px; align-items: center; margin-bottom: 8px; }
  .block-label-input {
    flex: 1; padding: 4px 8px; background: transparent; border: 1px solid transparent;
    border-radius: 4px; color: var(--fg2); font-size: 0.82rem; font-weight: 500;
    text-transform: uppercase; letter-spacing: 0.2px;
  }
  .block-label-input:focus { border-color: var(--border); background: var(--bg3); outline: none; }
  .block-label-input::placeholder { color: var(--fg3); text-transform: none; letter-spacing: normal; }

  .block-or-divider { text-align: center; padding: 6px 0; }
  .block-or-divider span {
    color: var(--amber); font-size: 0.75rem; font-weight: 700;
    background: var(--bg2); padding: 2px 12px; border-radius: 4px;
  }

  .rules-editor { display: flex; flex-direction: column; gap: 6px; }
  .rule-edit-row { display: grid; grid-template-columns: 110px 1fr auto auto; gap: 6px; align-items: center; }
  .rule-type-sel { padding: 6px 8px; background: var(--bg3); border: 1px solid var(--border); border-radius: 6px; color: var(--fg); font-size: 0.88rem; }
  .rule-value-input { width: 100%; padding: 6px 10px; background: var(--bg3); border: 1px solid var(--border); border-radius: 6px; color: var(--fg); font-family: var(--font-mono); font-size: 0.88rem; box-sizing: border-box; }
  .rule-proto-sel { width: 70px; padding: 6px 8px; background: var(--bg3); border: 1px solid var(--border); border-radius: 6px; color: var(--fg); font-size: 0.88rem; }
  .rule-value-input:focus, .rule-type-sel:focus, .rule-proto-sel:focus { outline: none; border-color: var(--accent); }
  .input-error { border-color: var(--red) !important; }
  .rule-invalid { opacity: 0.9; }

  .btn-add-rule {
    background: none; border: 1px dashed var(--border); border-radius: 6px;
    color: var(--fg3); padding: 6px; cursor: pointer; font-size: 0.82rem; text-align: center;
  }
  .btn-add-rule:hover { border-color: var(--accent); color: var(--accent); }

  .btn-add-block {
    background: none; border: 1px dashed var(--amber); border-radius: 8px;
    color: var(--amber); padding: 10px; cursor: pointer; font-size: 0.85rem;
    text-align: center; width: 100%; margin-top: 8px; font-weight: 500;
  }
  .btn-add-block:hover { background: var(--amber-bg); }

  .btn-icon { background: none; border: none; cursor: pointer; color: var(--fg3); font-size: 0.9rem; padding: 4px; border-radius: 4px; }
  .btn-danger { color: var(--red); }
  .btn-danger:hover { color: #fff; background: var(--red); }

  .btn-save {
    background: var(--accent); color: #fff; border: none; padding: 8px 20px;
    border-radius: 8px; cursor: pointer; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.2px; font-size: 0.85rem;
  }
  .btn-save:hover { background: var(--accent2); }
  .btn-save:disabled { opacity: 0.4; cursor: default; }

  .btn-back {
    background: var(--surface); color: var(--fg2); border: 1px solid var(--border);
    padding: 8px 16px; border-radius: 8px; cursor: pointer; font-size: 0.85rem;
  }
  .btn-back:hover { background: var(--bg3); }
</style>
