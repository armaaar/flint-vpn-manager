<script>
  import { api } from '../api.js';
  import { profiles, showToast } from '../stores/app.js';
  import { loadBarColor, countryFlagUrl, countryName } from '../utils.js';
  import { createEventDispatcher } from 'svelte';

  export let profileId = null;
  export let visible = false;
  export let vpnProtocol = 'wireguard'; // 'wireguard' or 'openvpn'

  $: isWireGuard = vpnProtocol === 'wireguard';
  // Resolve the live profile from the store so options reflect router-canonical state
  $: currentProfile = profileId ? $profiles.find(p => p.id === profileId) : null;

  const dispatch = createEventDispatcher();

  let servers = [];
  let search = '';
  let featureFilter = '';
  let selectedId = null;
  let selectionScope = { type: 'server' };
  let loading = true;
  let viewLevel = 'country'; // 'country' | 'city' | 'server'
  let expandedCountry = null;
  let expandedCity = null;

  // VPN options (NetShield, Accelerator, Moderate NAT, NAT-PMP, Kill Switch)
  // are configured in EditGroupModal — not here. The server picker only
  // chooses location + scope. When changing the server, the existing options
  // are read from the current profile and passed through unchanged.
  let lastInitProfileId = null;

  $: if (visible) {
    loadServers();
    viewLevel = 'country';
    expandedCountry = null;
    expandedCity = null;
    selectedId = null;
    search = '';
    featureFilter = '';
  }

  // Carry over the existing server scope so the user can change it
  $: if (visible && currentProfile && currentProfile.id !== lastInitProfileId) {
    lastInitProfileId = currentProfile.id;
    selectionScope = currentProfile.server_scope || { type: 'server' };
  }
  $: if (!visible) lastInitProfileId = null;

  async function loadServers() {
    loading = true;
    servers = await api.getServers(profileId);
    loading = false;
  }

  // Apply filters
  $: filtered = (() => {
    let f = servers;
    if (featureFilter === 'secure_core') f = f.filter(s => s.secure_core);
    else if (featureFilter) f = f.filter(s => s.features.includes(featureFilter));
    if (search) {
      const q = search.toLowerCase();
      f = f.filter(s => s.country.toLowerCase().includes(q) || s.city.toLowerCase().includes(q) || s.name.toLowerCase().includes(q));
    }
    return f;
  })();

  // Group by country
  $: countryGroups = (() => {
    const groups = {};
    for (const s of filtered) {
      const key = s.country_code;
      if (!groups[key]) {
        groups[key] = { code: key, name: s.country, servers: [], total_load: 0 };
      }
      groups[key].servers.push(s);
      groups[key].total_load += s.load;
    }
    return Object.values(groups).map(g => {
      g.avg_load = Math.round(g.total_load / g.servers.length);
      g.best = g.servers.reduce((a, b) => a.load < b.load ? a : b);
      // Build city sub-groups
      // SC servers are grouped by city + entry country (e.g. "Sydney via CH" vs "Sydney via SE")
      const cityMap = {};
      for (const s of g.servers) {
        const issc = s.secure_core;
        const ck = issc
          ? `sc:${s.city || 'Unknown'}:${s.entry_country_code}`
          : (s.city || 'Unknown');
        if (!cityMap[ck]) {
          cityMap[ck] = {
            key: `${g.code}:${ck}`,
            city: s.city || 'Unknown',
            is_secure_core: issc,
            entry_country_code: issc ? s.entry_country_code : null,
            servers: [], total_load: 0,
          };
        }
        cityMap[ck].servers.push(s);
        cityMap[ck].total_load += s.load;
      }
      g.cities = Object.values(cityMap).map(c => {
        c.avg_load = Math.round(c.total_load / c.servers.length);
        c.best = c.servers.reduce((a, b) => a.load < b.load ? a : b);
        c.servers.sort((a, b) => a.load - b.load);
        return c;
      });
      g.cities.sort((a, b) => {
        if (a.is_secure_core !== b.is_secure_core) return a.is_secure_core ? 1 : -1;
        if (a.city !== b.city) return a.city.localeCompare(b.city);
        return (a.entry_country_code || '').localeCompare(b.entry_country_code || '');
      });
      return g;
    }).sort((a, b) => a.name.localeCompare(b.name));
  })();

  // Overall fastest server across all countries
  $: fastestServer = filtered.length > 0
    ? filtered.reduce((a, b) => a.score < b.score ? a : b)
    : null;

  // Flat server list for individual view
  $: flatServers = (() => {
    const f = [...filtered];
    f.sort((a, b) => a.load - b.load);
    return f.slice(0, 100);
  })();

  function setFilter(feat) {
    featureFilter = feat;
    expandedCountry = null;
    expandedCity = null;
  }

  function selectCountry(group) {
    selectedId = group.best.id;
    selectionScope = { type: 'country', country_code: group.code };
    expandedCountry = null;
    expandedCity = null;
  }

  function selectCityGroup(city, countryCode) {
    selectedId = city.best.id;
    selectionScope = { type: 'city', country_code: countryCode, city: city.city };
    expandedCity = null;
  }

  function toggleCountry(code) {
    expandedCountry = expandedCountry === code ? null : code;
    expandedCity = null;
  }

  function toggleCity(key) {
    expandedCity = expandedCity === key ? null : key;
  }

  function scEntryName(code) {
    return countryName(code, servers) || code;
  }

  function select() {
    if (!selectedId) { showToast('Select a location first', true); return; }
    // Pass through the existing options from the current profile so the
    // backend regenerates the tunnel with the same options.
    // For new profile creation (no currentProfile), the backend applies defaults.
    const existingOpts = currentProfile?.options || {};
    dispatch('select', {
      serverId: selectedId,
      options: {
        netshield: existingOpts.netshield ?? 2,
        vpn_accelerator: existingOpts.vpn_accelerator !== false,
        moderate_nat: !!existingOpts.moderate_nat,
        nat_pmp: !!existingOpts.nat_pmp,
      },
      scope: selectionScope,
    });
  }

  function close() { dispatch('close'); }
</script>

{#if visible}
<div class="modal-overlay active" on:click|self={close}>
  <div class="modal" style="max-width:640px">
    <div class="modal-header">
      <h2>{profileId ? 'Change Server' : 'Choose Server'}</h2>
      <button class="modal-close" on:click={close}>&times;</button>
    </div>
    <div class="modal-body">
      <div class="server-filters">
        <input placeholder="Search country, city, or server..." bind:value={search}>
        <div class="filter-chips">
          {#each [['', 'All'], ['streaming', 'Streaming'], ['p2p', 'P2P'], ['secure_core', 'Secure Core']] as [val, label]}
            <button class="filter-chip" class:active={featureFilter === val}
                    on:click={() => setFilter(val)}>{label}</button>
          {/each}
        </div>
      </div>

      <div class="view-toggle">
        <button class="toggle-btn" class:active={viewLevel === 'country'} on:click={() => { viewLevel = 'country'; expandedCountry = null; expandedCity = null; }}>Country</button>
        <button class="toggle-btn" class:active={viewLevel === 'city'} on:click={() => { viewLevel = 'city'; expandedCity = null; }}>City</button>
        <button class="toggle-btn" class:active={viewLevel === 'server'} on:click={() => viewLevel = 'server'}>Server</button>
      </div>

      <div class="server-list">
        {#if loading}
          <div class="center-pad"><span class="spinner"></span></div>

        <!-- ═══ COUNTRY VIEW ═══ -->
        {:else if viewLevel === 'country'}
          {#if countryGroups.length === 0}
            <div class="empty-msg">No servers found</div>
          {:else}
            {#if fastestServer && !search}
              <div class="row fastest-row" class:selected={selectedId === fastestServer.id}
                   on:click={() => { selectedId = fastestServer.id; selectionScope = { type: 'global' }; expandedCountry = null; }} role="button" tabindex="0">
                <span class="fastest-icon">⚡</span>
                <div class="row-info">
                  <span class="row-name">Fastest</span>
                  <span class="row-meta">
                    <img class="flag-img" src={countryFlagUrl(fastestServer.country_code)} alt="" />
                    {fastestServer.name} · {fastestServer.city || fastestServer.country}
                  </span>
                </div>
                <div class="load-bar"><div class="load-fill" style="width:{fastestServer.load}%;background:{loadBarColor(fastestServer.load)}"></div></div>
                <span class="load-pct">{fastestServer.load}%</span>
              </div>
            {/if}
            {#each countryGroups as g (g.code)}
              <div class="row" class:selected={selectedId === g.best.id && expandedCountry !== g.code}
                   on:click={() => selectCountry(g)} role="button" tabindex="0">
                <span class="flag"><img class="flag-img" src={countryFlagUrl(g.code)} alt="" /></span>
                <div class="row-info">
                  <span class="row-name">{g.name}</span>
                  <span class="row-meta">{g.servers.length} server{g.servers.length !== 1 ? 's' : ''} · {g.cities.length} {g.cities.length === 1 ? 'location' : 'locations'}</span>
                </div>
                <div class="load-bar"><div class="load-fill" style="width:{g.avg_load}%;background:{loadBarColor(g.avg_load)}"></div></div>
                <span class="load-pct">{g.avg_load}%</span>
                <button class="expand-btn" on:click|stopPropagation={() => toggleCountry(g.code)}
                        title="Show cities">{expandedCountry === g.code ? '▾' : '▸'}</button>
              </div>

              {#if expandedCountry === g.code}
                {#each g.cities as city (city.key)}
                  <div class="row sub1" class:selected={selectedId === city.best.id && expandedCity !== city.key}
                       on:click|stopPropagation={() => selectCityGroup(city, g.code)} role="button" tabindex="0">
                    <div class="row-info">
                      <span class="row-name">
                        {city.city}
                        {#if city.is_secure_core}
                          <span class="sc-badge" title="Multi-hop: traffic enters via {scEntryName(city.entry_country_code)} before exiting in {g.name}">
                            via <img class="flag-img" src={countryFlagUrl(city.entry_country_code)} alt="" /> {scEntryName(city.entry_country_code)}
                          </span>
                        {/if}
                      </span>
                      <span class="row-meta">{city.servers.length} server{city.servers.length !== 1 ? 's' : ''}</span>
                    </div>
                    <div class="load-bar"><div class="load-fill" style="width:{city.avg_load}%;background:{loadBarColor(city.avg_load)}"></div></div>
                    <span class="load-pct">{city.avg_load}%</span>
                    <button class="expand-btn" on:click|stopPropagation={() => toggleCity(city.key)}
                            title="Show servers">{expandedCity === city.key ? '▾' : '▸'}</button>
                  </div>

                  {#if expandedCity === city.key}
                    {#each city.servers as s (s.id)}
                      <div class="row sub2" class:selected={selectedId === s.id}
                           on:click|stopPropagation={() => { selectedId = s.id; selectionScope = { type: 'server' }; }} role="button" tabindex="0">
                        <span class="row-name srv-name">{s.name}</span>
                        {#if s.secure_core}
                          <span class="sc-pill" title="Secure Core: enters via {scEntryName(s.entry_country_code)}">SC</span>
                        {/if}
                        <div class="load-bar"><div class="load-fill" style="width:{s.load}%;background:{loadBarColor(s.load)}"></div></div>
                        <span class="load-pct">{s.load}%</span>
                      </div>
                    {/each}
                  {/if}
                {/each}
              {/if}
            {/each}
          {/if}

        <!-- ═══ CITY VIEW ═══ -->
        {:else if viewLevel === 'city'}
          {#if countryGroups.length === 0}
            <div class="empty-msg">No servers found</div>
          {:else}
            {#each countryGroups as g (g.code)}
              {#each g.cities as city (city.key)}
                <div class="row" class:selected={selectedId === city.best.id && expandedCity !== city.key}
                     on:click={() => selectCityGroup(city, g.code)} role="button" tabindex="0">
                  <span class="flag"><img class="flag-img" src={countryFlagUrl(g.code)} alt="" /></span>
                  <div class="row-info">
                    <span class="row-name">
                      {g.name} — {city.city}
                      {#if city.is_secure_core}
                        <span class="sc-badge" title="Multi-hop: traffic enters via {scEntryName(city.entry_country_code)} before exiting in {g.name}">
                          via <img class="flag-img" src={countryFlagUrl(city.entry_country_code)} alt="" /> {scEntryName(city.entry_country_code)}
                        </span>
                      {/if}
                    </span>
                    <span class="row-meta">{city.servers.length} server{city.servers.length !== 1 ? 's' : ''}</span>
                  </div>
                  <div class="load-bar"><div class="load-fill" style="width:{city.avg_load}%;background:{loadBarColor(city.avg_load)}"></div></div>
                  <span class="load-pct">{city.avg_load}%</span>
                  <button class="expand-btn" on:click|stopPropagation={() => toggleCity(city.key)}
                          title="Show servers">{expandedCity === city.key ? '▾' : '▸'}</button>
                </div>

                {#if expandedCity === city.key}
                  {#each city.servers as s (s.id)}
                    <div class="row sub1" class:selected={selectedId === s.id}
                         on:click|stopPropagation={() => { selectedId = s.id; selectionScope = { type: 'server' }; }} role="button" tabindex="0">
                      <span class="row-name srv-name">{s.name}</span>
                      {#if s.secure_core}
                        <span class="sc-pill" title="Secure Core: enters via {scEntryName(s.entry_country_code)}">SC</span>
                      {/if}
                      <div class="load-bar"><div class="load-fill" style="width:{s.load}%;background:{loadBarColor(s.load)}"></div></div>
                      <span class="load-pct">{s.load}%</span>
                    </div>
                  {/each}
                {/if}
              {/each}
            {/each}
          {/if}

        <!-- ═══ SERVER VIEW ═══ -->
        {:else}
          {#if flatServers.length === 0}
            <div class="empty-msg">No servers found</div>
          {:else}
            {#each flatServers as s (s.id)}
              <div class="row" class:selected={selectedId === s.id}
                   on:click={() => { selectedId = s.id; selectionScope = { type: 'server' }; }} role="button" tabindex="0">
                <span class="flag"><img class="flag-img" src={countryFlagUrl(s.country_code)} alt="" /></span>
                <span class="row-name srv-name">{s.name}</span>
                {#if s.secure_core}
                  <span class="sc-pill" title="Secure Core: {scEntryName(s.entry_country_code)} → {s.city}, {s.country}">SC</span>
                  <span class="row-meta">{s.city} via <img class="flag-img" src={countryFlagUrl(s.entry_country_code)} alt="" /> {scEntryName(s.entry_country_code)}</span>
                {:else}
                  <span class="row-meta">{s.city}</span>
                {/if}
                <div class="load-bar"><div class="load-fill" style="width:{s.load}%;background:{loadBarColor(s.load)}"></div></div>
                <span class="load-pct">{s.load}%</span>
              </div>
            {/each}
          {/if}
        {/if}
      </div>

    </div>
    <div class="modal-footer">
      <button class="btn-outline" on:click={close}>Cancel</button>
      <button class="btn-primary" on:click={select}>Connect</button>
    </div>
  </div>
</div>
{/if}

<style>
  .server-filters { display: flex; gap: 10px; margin-bottom: 14px; flex-wrap: wrap; }
  .server-filters input { max-width: 240px; }
  .filter-chips { display: flex; gap: 6px; flex-wrap: wrap; align-items: center; }
  .filter-chip { padding: 5px 12px; border-radius: 16px; font-size: .8rem; background: var(--bg); color: var(--fg2); border: 1px solid var(--border); cursor: pointer; transition: var(--transition); }
  .filter-chip:hover { border-color: var(--accent); color: var(--accent); }
  .filter-chip.active { background: var(--accent); color: #fff; border-color: var(--accent); }

  .view-toggle { display: flex; gap: 3px; margin-bottom: 10px; background: var(--bg); border-radius: var(--radius-xs); padding: 3px; }
  .toggle-btn { flex: 1; padding: 6px 12px; font-size: .8rem; background: transparent; color: var(--fg3); border: none; border-radius: 4px; cursor: pointer; transition: var(--transition); }
  .toggle-btn.active { background: var(--surface); color: var(--fg); font-weight: 500; }

  .server-list { max-height: 320px; overflow-y: auto; border: 1px solid var(--border); border-radius: var(--radius-xs); }
  .center-pad { padding: 20px; text-align: center; }
  .empty-msg { padding: 24px; text-align: center; color: var(--fg3); }

  .row { display: flex; align-items: center; padding: 10px 14px; cursor: pointer; transition: var(--transition); border-bottom: 1px solid var(--border); gap: 8px; }
  .row:last-child { border-bottom: none; }
  .row:hover { background: var(--bg3); }
  .row.selected { background: rgba(0,180,216,.12); }
  .fastest-row { border-bottom: 2px solid var(--border2); }
  .fastest-icon { font-size: 1.15rem; flex-shrink: 0; width: 26px; text-align: center; }
  .row.sub1 { padding-left: 42px; background: rgba(0,0,0,.08); }
  .row.sub2 { padding-left: 62px; background: rgba(0,0,0,.14); font-size: .82rem; }
  .row.sub1:hover, .row.sub2:hover { background: var(--bg3); }

  .flag { font-size: 1.15rem; flex-shrink: 0; width: 26px; text-align: center; display: flex; align-items: center; justify-content: center; }
  .flag-img, :global(.flag-img) { width: 20px; height: 15px; vertical-align: middle; border-radius: 2px; object-fit: cover; }
  .row-info { flex: 1; min-width: 0; }
  .row-name { font-size: .85rem; font-weight: 500; display: block; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .row-meta { font-size: .72rem; color: var(--fg3); }
  .srv-name { flex: 1; }
  .sc-badge { font-size: .72rem; color: var(--amber); font-weight: 400; }
  .sc-pill { font-size: .65rem; background: var(--amber-bg); color: var(--amber); padding: 1px 5px; border-radius: 3px; font-weight: 600; flex-shrink: 0; cursor: help; }
  .expand-btn { background: none; border: none; color: var(--fg3); font-size: .85rem; padding: 4px 6px; cursor: pointer; flex-shrink: 0; }
  .expand-btn:hover { color: var(--fg); }

  .load-bar { width: 50px; height: 6px; background: var(--border); border-radius: 3px; overflow: hidden; flex-shrink: 0; }
  .load-fill { height: 100%; border-radius: 3px; display: block; }
  .load-pct { font-size: .78rem; color: var(--fg2); min-width: 32px; text-align: right; }

  .options-section { margin-top: 18px; }
  .options-section h3 { font-size: .9rem; font-weight: 600; margin-bottom: 10px; color: var(--fg2); }
  .proto-note { font-size: .75rem; font-weight: 400; color: var(--fg3); }
  .options-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 6px; }
  .option-item { display: flex; align-items: center; gap: 8px; padding: 8px 10px; border-radius: var(--radius-xs); }
  .option-item:hover { background: var(--bg3); }
  .option-item input[type="checkbox"] { width: 18px; height: 18px; accent-color: var(--accent); cursor: pointer; }
  .option-item label { font-size: .85rem; cursor: pointer; flex: 1; }
  .tooltip-trigger { display: inline-flex; align-items: center; justify-content: center; width: 16px; height: 16px; border-radius: 50%; background: var(--border); color: var(--fg3); font-size: .65rem; font-weight: 700; cursor: help; }
  .spinner { display: inline-block; width: 18px; height: 18px; border: 2.5px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: spin .6s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
