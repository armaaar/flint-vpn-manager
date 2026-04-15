<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import type { BypassException, BypassPreset, BypassRule, BypassRuleBlock, Profile, Device } from '../../types';

  export let exception: BypassException | null = null;
  export let presets: Record<string, BypassPreset> = {};
  export let profiles: Profile[] = [];
  export let devices: Device[] = [];

  const dispatch = createEventDispatcher();

  // Form state
  let step = exception ? 2 : 1;
  let name = exception?.name || '';
  let scope: string = exception?.scope || 'global';
  let scopeTarget: string = exception?.scope_target || '';
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
      scope_target: scope === 'global' ? null : scopeTarget,
      preset_id: presetId,
      rule_blocks: cleanBlocks,
    };
    dispatch('save', data);
  }

  $: vpnProfiles = profiles.filter(p => p.type === 'vpn');

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
  $: scopeValid = scope === 'global' || !!scopeTarget;
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
              <input type="radio" bind:group={scope} value="group" /> Per Group
            </label>
            <label class="radio-label">
              <input type="radio" bind:group={scope} value="device" /> Per Device
            </label>
          </div>
        </div>

        {#if scope === 'group'}
          <div class="form-group">
            <label for="scope-group">VPN Group</label>
            <select id="scope-group" bind:value={scopeTarget}>
              <option value="">Select a group...</option>
              {#each vpnProfiles as p}
                <option value={p.id}>{p.name} ({p.icon})</option>
              {/each}
            </select>
          </div>
        {/if}

        {#if scope === 'device'}
          <div class="form-group">
            <label for="scope-device">Device</label>
            <select id="scope-device" bind:value={scopeTarget}>
              <option value="">Select a device...</option>
              {#each devices as d}
                <option value={d.mac}>{d.display_name} ({d.mac})</option>
              {/each}
            </select>
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

  .scope-radios { display: flex; gap: 16px; flex-wrap: wrap; }
  .radio-label { display: flex; align-items: center; gap: 6px; color: var(--fg); font-size: 0.9rem; cursor: pointer; }
  .radio-label input[type="radio"] { accent-color: var(--accent); }

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
