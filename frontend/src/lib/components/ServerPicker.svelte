<script>
  import { api } from '../api.js';
  import { profiles, showToast } from '../stores/app.js';
  import { loadBarColor } from '../format.js';
  import { countryFlagUrl, countryName } from '../country.js';
  import { createEventDispatcher } from 'svelte';

  export let profileId = null;
  export let visible = false;
  export let vpnProtocol = 'wireguard';

  $: currentProfile = profileId ? $profiles.find(p => p.id === profileId) : null;

  const dispatch = createEventDispatcher();

  let allServers = [];
  let loading = true;
  let lastInitProfileId = null;

  // Three independent selects + features filter. All start as "Fastest".
  let features = { streaming: false, p2p: false, secure_core: false };
  let selCountry = null;     // null = Fastest
  let selCity = null;        // null = Fastest
  let selEntryCountry = null; // null = Fastest (only meaningful with secure_core)
  let selServerId = null;    // null = Fastest

  // Open dropdown state
  let openDropdown = null; // 'country' | 'city' | 'server' | null
  let searchCountry = '';
  let searchCity = '';
  let searchServer = '';

  $: if (visible) {
    loadServers();
    openDropdown = null;
  }

  // Hydrate selections from the existing profile's scope when opening
  $: if (visible && currentProfile && currentProfile.id !== lastInitProfileId) {
    lastInitProfileId = currentProfile.id;
    const sc = currentProfile.server_scope || {};
    features = {
      streaming: !!(sc.features && sc.features.streaming),
      p2p: !!(sc.features && sc.features.p2p),
      secure_core: !!(sc.features && sc.features.secure_core),
    };
    selCountry = sc.country_code || null;
    selCity = sc.city || null;
    selEntryCountry = sc.entry_country_code || null;
    selServerId = sc.server_id || null;
  }
  $: if (!visible) lastInitProfileId = null;

  async function loadServers() {
    loading = true;
    allServers = await api.getServers(profileId);
    loading = false;
  }

  // ── Blacklist / Favourite toggles ─────────────────────────────────────
  async function toggleBlacklist(serverId, e) {
    e.stopPropagation();
    const s = allServers.find(x => x.id === serverId);
    if (!s) return;
    try {
      if (s.blacklisted) {
        await api.removeFromBlacklist(serverId);
      } else {
        await api.addToBlacklist(serverId);
      }
      // Update local state immediately
      allServers = allServers.map(x => {
        if (x.id === serverId) {
          return { ...x, blacklisted: !x.blacklisted, favourite: false };
        }
        return x;
      });
    } catch (err) {
      showToast('Failed to update blacklist: ' + err.message, true);
    }
  }

  async function toggleFavourite(serverId, e) {
    e.stopPropagation();
    const s = allServers.find(x => x.id === serverId);
    if (!s) return;
    try {
      if (s.favourite) {
        await api.removeFromFavourites(serverId);
      } else {
        await api.addToFavourites(serverId);
      }
      allServers = allServers.map(x => {
        if (x.id === serverId) {
          return { ...x, favourite: !x.favourite, blacklisted: false };
        }
        return x;
      });
    } catch (err) {
      showToast('Failed to update favourites: ' + err.message, true);
    }
  }

  // ── Latency probing ────────────────────────────────────────────────────
  let latencies = {};  // {server_id: ms_or_null}
  let probing = false;

  async function probeVisibleServers() {
    if (probing) return;
    const ids = filteredServerOptions.map(s => s.id);
    if (ids.length === 0) return;
    probing = true;
    try {
      const resp = await api.probeLatency(ids);
      latencies = { ...latencies, ...resp.latencies };
    } catch (err) {
      showToast('Latency probe failed: ' + err.message, true);
    } finally {
      probing = false;
    }
  }

  // ── Filtering pipeline ────────────────────────────────────────────────
  // 1. Apply features (streaming/p2p/secure_core) — AND combination.
  // 2. The Country options come from this pre-filtered set.
  // 3. The City options come from servers also matching selCountry.
  // 4. The Server options come from servers also matching selCity (+ entry).

  $: featureFiltered = (() => {
    return allServers.filter(s => {
      if (features.streaming && !s.streaming) return false;
      if (features.p2p && !s.p2p) return false;
      if (features.secure_core !== !!s.secure_core) return false;
      return true;
    });
  })();

  // Country options: distinct country_codes with server counts.
  // Aggregates both avgLoad (congestion display) and avgScore (the sort
  // metric used by the optimizer + Proton's client).
  $: countryOptions = (() => {
    const map = {};
    for (const s of featureFiltered) {
      const cc = s.country_code;
      if (!map[cc]) {
        map[cc] = {
          code: cc,
          name: s.country,
          servers: 0,
          loadSum: 0,
          scoreSum: 0,
        };
      }
      map[cc].servers += 1;
      map[cc].loadSum += s.load;
      map[cc].scoreSum += (s.score ?? 0);
    }
    return Object.values(map)
      .map(c => ({
        ...c,
        avgLoad: Math.round(c.loadSum / c.servers),
        avgScore: c.scoreSum / c.servers,
      }))
      .sort((a, b) => a.name.localeCompare(b.name));
  })();

  // City options: distinct cities in the selected country (or all when
  // Country=Fastest, but the cascade rule disables the City select then,
  // so this only matters for option count display).
  $: cityOptions = (() => {
    if (!selCountry) return [];
    const inCountry = featureFiltered.filter(s => s.country_code === selCountry);
    // For SC mode, group by (city, entry_country_code) so "Sydney via CH"
    // and "Sydney via SE" appear as separate options.
    const map = {};
    for (const s of inCountry) {
      const city = s.city || 'Unknown';
      const key = features.secure_core
        ? `${city}::${s.entry_country_code}`
        : city;
      if (!map[key]) {
        map[key] = {
          city,
          entry_country_code: features.secure_core ? s.entry_country_code : null,
          servers: 0,
          loadSum: 0,
          scoreSum: 0,
        };
      }
      map[key].servers += 1;
      map[key].loadSum += s.load;
      map[key].scoreSum += (s.score ?? 0);
    }
    return Object.values(map)
      .map(c => ({
        ...c,
        avgLoad: Math.round(c.loadSum / c.servers),
        avgScore: c.scoreSum / c.servers,
      }))
      .sort((a, b) => {
        if (a.city !== b.city) return a.city.localeCompare(b.city);
        return (a.entry_country_code || '').localeCompare(b.entry_country_code || '');
      });
  })();

  // Server options: specific servers in the selected country+city.
  // Sorted by Proton's `score` (lower = better) — same metric the
  // backend's resolve_scope_to_server and the official Proton client use.
  // Load bars stay in the UI as a separate, intuitive congestion signal.
  $: serverOptions = (() => {
    if (!selCountry || !selCity) return [];
    return featureFiltered
      .filter(s => {
        if (s.country_code !== selCountry) return false;
        if (s.city !== selCity) return false;
        if (features.secure_core && selEntryCountry &&
            s.entry_country_code !== selEntryCountry) return false;
        return true;
      })
      .sort((a, b) => {
        // Favourites first, blacklisted last, then by score
        if (a.favourite !== b.favourite) return a.favourite ? -1 : 1;
        if (a.blacklisted !== b.blacklisted) return a.blacklisted ? 1 : -1;
        return (a.score ?? Infinity) - (b.score ?? Infinity);
      });
  })();

  // ── Resolved server preview ───────────────────────────────────────────
  // Mirrors backend resolve_scope_to_server logic: pick the lowest-score
  // server within the scope's filters (or the pinned server if set).
  $: resolvedServer = (() => {
    if (selServerId) {
      const exact = featureFiltered.find(s => s.id === selServerId);
      if (exact) return exact;
      // Pinned server vanished — fall back to fastest
    }
    let candidates = featureFiltered.filter(s => !s.blacklisted);
    if (selCountry) candidates = candidates.filter(s => s.country_code === selCountry);
    if (selCity) candidates = candidates.filter(s => s.city === selCity);
    if (features.secure_core && selEntryCountry) {
      candidates = candidates.filter(s => s.entry_country_code === selEntryCountry);
    }
    if (candidates.length === 0) return null;
    // Prefer favourites when score is close (within 30%)
    candidates.sort((a, b) => (a.score ?? Infinity) - (b.score ?? Infinity));
    const best = candidates[0];
    const bestScore = best.score ?? Infinity;
    const threshold = bestScore * 1.3;
    const fav = candidates.find(s => s.favourite && (s.score ?? Infinity) <= threshold);
    return fav || best;
  })();

  // ── Cascade enforcement on changes ────────────────────────────────────

  function setFeature(key) {
    features = { ...features, [key]: !features[key] };
    // Re-validate selections after the feature filter changes
    revalidate();
  }

  function setCountry(code) {
    selCountry = code;
    // Cascade reset
    selCity = null;
    selEntryCountry = null;
    selServerId = null;
    openDropdown = null;
  }

  function setCity(option) {
    if (option === null) {
      selCity = null;
      selEntryCountry = null;
      selServerId = null;
    } else {
      selCity = option.city;
      selEntryCountry = option.entry_country_code || null;
      selServerId = null;
    }
    openDropdown = null;
  }

  function setServer(id) {
    selServerId = id;
    openDropdown = null;
  }

  function revalidate() {
    // After a features change, drop selections that no longer have any
    // matching servers. Cascade naturally.
    if (selCountry && !countryOptions.find(c => c.code === selCountry)) {
      selCountry = null;
      selCity = null;
      selEntryCountry = null;
      selServerId = null;
      return;
    }
    if (selCity && !cityOptions.find(c =>
        c.city === selCity &&
        (!features.secure_core || c.entry_country_code === selEntryCountry))) {
      selCity = null;
      selEntryCountry = null;
      selServerId = null;
      return;
    }
    if (selServerId && !serverOptions.find(s => s.id === selServerId)) {
      selServerId = null;
    }
  }

  // ── Filtered option lists for the open dropdown's search ──────────────
  $: filteredCountryOptions = countryOptions.filter(c =>
    !searchCountry || c.name.toLowerCase().includes(searchCountry.toLowerCase())
  );
  $: filteredCityOptions = cityOptions.filter(c =>
    !searchCity || c.city.toLowerCase().includes(searchCity.toLowerCase())
  );
  $: filteredServerOptions = serverOptions.filter(s =>
    !searchServer || s.name.toLowerCase().includes(searchServer.toLowerCase())
  );

  function openDrop(name) {
    if (openDropdown === name) {
      openDropdown = null;
    } else {
      openDropdown = name;
      searchCountry = '';
      searchCity = '';
      searchServer = '';
    }
  }

  function handleWindowClick(e) {
    if (!openDropdown) return;
    if (!e.target.closest('.dropdown-wrap')) openDropdown = null;
  }

  function scEntryName(code) {
    return countryName(code, allServers) || code;
  }

  // Proton's `score` is a small float (typically 0.5–3.0) where lower
  // means better. Format to 2 decimals for display. Treat null/undefined
  // as "?". The picker is sorted by this metric end-to-end.
  function formatScore(s) {
    if (s === null || s === undefined || Number.isNaN(s)) return '?';
    return Number(s).toFixed(2);
  }

  // ── Display labels for the dropdown triggers ──────────────────────────
  $: countryLabel = selCountry
    ? (countryOptions.find(c => c.code === selCountry)?.name || selCountry)
    : 'Fastest';
  $: cityLabel = selCity ? selCity : 'Fastest';
  $: serverLabel = (() => {
    if (selServerId) {
      const s = featureFiltered.find(x => x.id === selServerId);
      return s ? s.name : 'Fastest';
    }
    return 'Fastest';
  })();

  $: cityDisabled = !selCountry;
  $: serverDisabled = !selCountry || !selCity;

  // ── Submit ────────────────────────────────────────────────────────────

  function connect() {
    if (!resolvedServer) {
      showToast('No server matches your filters', true);
      return;
    }
    const existingOpts = currentProfile?.options || {};
    dispatch('select', {
      serverId: resolvedServer.id,
      options: {
        netshield: existingOpts.netshield ?? 2,
        vpn_accelerator: existingOpts.vpn_accelerator !== false,
        moderate_nat: !!existingOpts.moderate_nat,
        nat_pmp: !!existingOpts.nat_pmp,
      },
      scope: {
        country_code: selCountry,
        city: selCity,
        entry_country_code: features.secure_core ? selEntryCountry : null,
        server_id: selServerId,
        features: { ...features },
      },
    });
  }

  function close() { dispatch('close'); }
</script>

<svelte:window on:click={handleWindowClick} />

{#if visible}
<div class="modal-overlay active" on:click|self={close}>
  <div class="modal" style="max-width:560px">
    <div class="modal-header">
      <h2>{profileId ? 'Change Server' : 'Choose Server'}</h2>
      <button class="modal-close" on:click={close}>&times;</button>
    </div>
    <div class="modal-body">

      {#if loading}
        <div class="center-pad"><span class="spinner"></span></div>
      {:else}

      <!-- Feature filters -->
      <div class="filter-section">
        <div class="filter-label">Filters</div>
        <div class="filter-chips">
          <button class="filter-chip" class:active={features.streaming}
                  on:click={() => setFeature('streaming')}>📺 Streaming</button>
          <button class="filter-chip" class:active={features.p2p}
                  on:click={() => setFeature('p2p')}>⇄ P2P</button>
          <button class="filter-chip" class:active={features.secure_core}
                  on:click={() => setFeature('secure_core')}>🛡 Secure Core</button>
        </div>
      </div>

      <!-- Country select -->
      <div class="form-group">
        <label>Country</label>
        <div class="dropdown-wrap">
          <button class="dropdown-trigger" on:click={() => openDrop('country')}>
            <span class="trig-content">
              {#if selCountry}
                <img class="flag-img" src={countryFlagUrl(selCountry)} alt="" />
                {countryLabel}
              {:else}
                <span class="fastest-icon">⚡</span> Fastest country
              {/if}
            </span>
            <span class="caret">▾</span>
          </button>
          {#if openDropdown === 'country'}
            <div class="dropdown-pop" on:click|stopPropagation>
              <input class="dropdown-search" placeholder="Search country..."
                     bind:value={searchCountry} autofocus>
              <div class="dropdown-list">
                <button class="dropdown-item" class:selected={selCountry === null}
                        on:click={() => setCountry(null)}>
                  <span class="fastest-icon">⚡</span>
                  <span class="item-main">Fastest</span>
                  <span class="item-meta">{countryOptions.length} {countryOptions.length === 1 ? 'country' : 'countries'}</span>
                </button>
                {#if filteredCountryOptions.length === 0}
                  <div class="empty">No countries match your filters</div>
                {:else}
                  {#each filteredCountryOptions as c (c.code)}
                    <button class="dropdown-item" class:selected={selCountry === c.code}
                            on:click={() => setCountry(c.code)}>
                      <img class="flag-img" src={countryFlagUrl(c.code)} alt="" />
                      <span class="item-main">{c.name}</span>
                      <span class="item-meta">{c.servers} server{c.servers !== 1 ? 's' : ''}</span>
                      <div class="load-bar"><div class="load-fill" style="width:{c.avgLoad}%;background:{loadBarColor(c.avgLoad)}"></div></div>
                      <span class="load-pct">{c.avgLoad}%</span>
                      <span class="score-pct" title="Average Proton score (lower = better)">{formatScore(c.avgScore)}</span>
                    </button>
                  {/each}
                {/if}
              </div>
            </div>
          {/if}
        </div>
      </div>

      <!-- City select -->
      <div class="form-group">
        <label>City</label>
        <div class="dropdown-wrap">
          <button class="dropdown-trigger" class:disabled={cityDisabled}
                  disabled={cityDisabled}
                  on:click={() => openDrop('city')}>
            <span class="trig-content">
              {#if cityDisabled}
                <span class="fastest-icon">⚡</span> Fastest city
              {:else if selCity}
                {cityLabel}
                {#if features.secure_core && selEntryCountry}
                  <span class="sc-via">via <img class="flag-img" src={countryFlagUrl(selEntryCountry)} alt="" /> {scEntryName(selEntryCountry)}</span>
                {/if}
              {:else}
                <span class="fastest-icon">⚡</span> Fastest city
              {/if}
            </span>
            {#if !cityDisabled}<span class="caret">▾</span>{/if}
          </button>
          {#if openDropdown === 'city' && !cityDisabled}
            <div class="dropdown-pop" on:click|stopPropagation>
              <input class="dropdown-search" placeholder="Search city..."
                     bind:value={searchCity} autofocus>
              <div class="dropdown-list">
                <button class="dropdown-item" class:selected={selCity === null}
                        on:click={() => setCity(null)}>
                  <span class="fastest-icon">⚡</span>
                  <span class="item-main">Fastest</span>
                  <span class="item-meta">{cityOptions.length} {cityOptions.length === 1 ? 'option' : 'options'}</span>
                </button>
                {#if filteredCityOptions.length === 0}
                  <div class="empty">No cities match your filters</div>
                {:else}
                  {#each filteredCityOptions as c (`${c.city}::${c.entry_country_code || ''}`)}
                    <button class="dropdown-item"
                            class:selected={selCity === c.city && selEntryCountry === c.entry_country_code}
                            on:click={() => setCity(c)}>
                      <span class="item-main">
                        {c.city}
                        {#if c.entry_country_code}
                          <span class="sc-via-inline">via <img class="flag-img" src={countryFlagUrl(c.entry_country_code)} alt="" /> {scEntryName(c.entry_country_code)}</span>
                        {/if}
                      </span>
                      <span class="item-meta">{c.servers} server{c.servers !== 1 ? 's' : ''}</span>
                      <div class="load-bar"><div class="load-fill" style="width:{c.avgLoad}%;background:{loadBarColor(c.avgLoad)}"></div></div>
                      <span class="load-pct">{c.avgLoad}%</span>
                      <span class="score-pct" title="Average Proton score (lower = better)">{formatScore(c.avgScore)}</span>
                    </button>
                  {/each}
                {/if}
              </div>
            </div>
          {/if}
        </div>
      </div>

      <!-- Server select -->
      <div class="form-group">
        <label class="server-label">
          Server
          {#if !serverDisabled}
            <span class="label-action" on:click|stopPropagation={probeVisibleServers}
                  role="button" tabindex="-1">
              {#if probing}testing...{:else}Test latency{/if}
            </span>
          {/if}
        </label>
        <div class="dropdown-wrap">
          <button class="dropdown-trigger" class:disabled={serverDisabled}
                  disabled={serverDisabled}
                  on:click={() => openDrop('server')}>
            <span class="trig-content">
              {#if serverDisabled}
                <span class="fastest-icon">⚡</span> Fastest server
              {:else if selServerId}
                {serverLabel}
              {:else}
                <span class="fastest-icon">⚡</span> Fastest server
              {/if}
            </span>
            {#if !serverDisabled}<span class="caret">▾</span>{/if}
          </button>
          {#if openDropdown === 'server' && !serverDisabled}
            <div class="dropdown-pop" on:click|stopPropagation>
              <input class="dropdown-search" placeholder="Search server..."
                     bind:value={searchServer} autofocus>
              <div class="dropdown-list">
                <button class="dropdown-item" class:selected={selServerId === null}
                        on:click={() => setServer(null)}>
                  <span class="fastest-icon">⚡</span>
                  <span class="item-main">Fastest</span>
                  <span class="item-meta">{serverOptions.length} server{serverOptions.length !== 1 ? 's' : ''}</span>
                </button>
                {#if filteredServerOptions.length === 0}
                  <div class="empty">No servers match</div>
                {:else}
                  {#each filteredServerOptions as s (s.id)}
                    <button class="dropdown-item" class:selected={selServerId === s.id}
                            class:blacklisted={s.blacklisted}
                            on:click={() => setServer(s.id)}>
                      <span class="pref-btn" class:active={s.favourite} role="button" tabindex="-1"
                              title={s.favourite ? 'Remove from favourites' : 'Add to favourites'}
                              on:click={(e) => toggleFavourite(s.id, e)}>&#9733;</span>
                      <span class="item-main">{s.name}</span>
                      <span class="srv-badges">
                        {#if s.streaming}<span class="srv-badge str">STR</span>{/if}
                        {#if s.p2p}<span class="srv-badge p2p">P2P</span>{/if}
                        {#if s.secure_core}<span class="srv-badge sc">SC</span>{/if}
                      </span>
                      <div class="load-bar"><div class="load-fill" style="width:{s.load}%;background:{loadBarColor(s.load)}"></div></div>
                      <span class="load-pct">{s.load}%</span>
                      <span class="score-pct" title="Proton score (lower = better)">{formatScore(s.score)}</span>
                      {#if latencies[s.id] !== undefined}
                        <span class="latency-badge" class:good={latencies[s.id] !== null && latencies[s.id] < 50}
                              class:warn={latencies[s.id] !== null && latencies[s.id] >= 50 && latencies[s.id] < 150}
                              class:bad={latencies[s.id] === null || latencies[s.id] >= 150}
                              title="TCP connect latency from router">
                          {latencies[s.id] !== null ? Math.round(latencies[s.id]) + 'ms' : 'fail'}
                        </span>
                      {/if}
                      <span class="pref-btn ban-btn" class:active={s.blacklisted} role="button" tabindex="-1"
                              title={s.blacklisted ? 'Remove from blacklist' : 'Block this server'}
                              on:click={(e) => toggleBlacklist(s.id, e)}>&#128683;</span>
                    </button>
                  {/each}
                {/if}
              </div>
            </div>
          {/if}
        </div>
      </div>

      <!-- Resolved preview -->
      <div class="preview">
        <div class="preview-label">Currently resolves to</div>
        {#if resolvedServer}
          <div class="preview-server">
            <img class="flag-img" src={countryFlagUrl(resolvedServer.country_code)} alt="" />
            <strong>{resolvedServer.name}</strong>
            <span class="preview-meta">· {resolvedServer.city || resolvedServer.country}</span>
            {#if resolvedServer.secure_core}
              <span class="srv-badge sc">SC</span>
              <span class="sc-via-inline">via <img class="flag-img" src={countryFlagUrl(resolvedServer.entry_country_code)} alt="" /> {scEntryName(resolvedServer.entry_country_code)}</span>
            {/if}
            <div class="load-bar"><div class="load-fill" style="width:{resolvedServer.load}%;background:{loadBarColor(resolvedServer.load)}"></div></div>
            <span class="load-pct">{resolvedServer.load}%</span>
            <span class="score-pct" title="Proton score (lower = better)">{formatScore(resolvedServer.score)}</span>
          </div>
        {:else}
          <div class="preview-empty">No server matches your filters. Try removing a feature or picking a different country.</div>
        {/if}
      </div>

      <details class="metric-help">
        <summary>What do load % and ⚡ score mean?</summary>
        <div class="help-content">
          <h4>Load %</h4>
          <p>How busy the server is right now. Lower means less congestion. Above ~80% the server is crowded.</p>
          <h4>⚡ Score</h4>
          <p>Proton's own "fastest server" metric — lower is better. It blends load, latency from Proton's measurement infrastructure, and tier weighting.</p>
          <p>This list and the auto-optimizer are sorted by score, exactly like Proton's official client.</p>
          <h4>When they disagree</h4>
          <p>The two usually agree. When they don't, trust the score: a lightly-loaded server with bad latency from Proton's probes will have a worse score and won't be picked.</p>
        </div>
      </details>

      {/if}

    </div>
    <div class="modal-footer">
      <button class="btn-outline" on:click={close}>Cancel</button>
      <button class="btn-primary" on:click={connect} disabled={!resolvedServer}>Connect</button>
    </div>
  </div>
</div>
{/if}

<style>
  .center-pad { padding: 40px; text-align: center; }
  .spinner { display: inline-block; width: 18px; height: 18px; border: 2.5px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: spin .6s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }

  .filter-section { margin-bottom: 14px; }
  .filter-label { font-size: .72rem; color: var(--fg3); text-transform: uppercase; letter-spacing: .05em; margin-bottom: 6px; }
  .filter-chips { display: flex; gap: 6px; flex-wrap: wrap; }
  .filter-chip { padding: 6px 12px; border-radius: 16px; font-size: .8rem; background: var(--bg); color: var(--fg2); border: 1px solid var(--border); cursor: pointer; transition: var(--transition); }
  .filter-chip:hover { border-color: var(--accent); color: var(--accent); }
  .filter-chip.active { background: var(--accent); color: #fff; border-color: var(--accent); }

  .form-group { margin-bottom: 12px; }
  .form-group label { display: flex; align-items: center; font-size: .72rem; color: var(--fg3); text-transform: uppercase; letter-spacing: .05em; margin-bottom: 4px; }
  .server-label { display: flex; align-items: center; }

  .dropdown-wrap { position: relative; }
  .dropdown-trigger {
    width: 100%; display: flex; align-items: center; justify-content: space-between;
    padding: 9px 12px; background: var(--bg); border: 1px solid var(--border2);
    border-radius: var(--radius-xs); color: var(--fg); font-size: .9rem;
    cursor: pointer; text-align: left; transition: var(--transition);
  }
  .dropdown-trigger:hover:not(.disabled) { border-color: var(--accent); }
  .dropdown-trigger.disabled { opacity: .5; cursor: not-allowed; background: var(--bg2); }
  .trig-content { display: flex; align-items: center; gap: 6px; flex: 1; min-width: 0; }
  .fastest-icon { color: #f39c12; }
  .caret { color: var(--fg3); font-size: .8rem; }
  .sc-via { font-size: .72rem; color: var(--fg3); margin-left: 4px; display: inline-flex; align-items: center; gap: 3px; }
  .sc-via-inline { font-size: .68rem; color: var(--fg3); margin-left: 4px; display: inline-flex; align-items: center; gap: 3px; }

  .dropdown-pop {
    position: absolute; top: calc(100% + 4px); left: 0; right: 0;
    z-index: 100; background: var(--surface); border: 1px solid var(--border2);
    border-radius: var(--radius-xs); box-shadow: var(--shadow-lg);
    max-height: 280px; display: flex; flex-direction: column;
  }
  .dropdown-search {
    margin: 6px; padding: 6px 8px; background: var(--bg); border: 1px solid var(--border);
    border-radius: var(--radius-xs); color: var(--fg); font-size: .82rem;
  }
  .dropdown-list { overflow-y: auto; flex: 1; }
  .dropdown-item {
    width: 100%; display: flex; align-items: center; gap: 8px;
    padding: 8px 10px; background: transparent; border: none;
    color: var(--fg); font-size: .82rem; cursor: pointer; text-align: left;
    border-bottom: 1px solid var(--border); transition: background .15s;
  }
  .dropdown-item:last-child { border-bottom: none; }
  .dropdown-item:hover { background: var(--bg3); }
  .dropdown-item.selected { background: rgba(0,180,216,.12); }

  .item-main { flex: 1; min-width: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .item-meta { font-size: .7rem; color: var(--fg3); flex-shrink: 0; }

  .srv-badges { display: flex; gap: 3px; flex-shrink: 0; }
  .srv-badge { font-size: .6rem; padding: 1px 4px; border-radius: 3px; font-weight: 600; }
  .srv-badge.str { background: rgba(155, 89, 182, .2); color: #b07cd6; }
  .srv-badge.p2p { background: rgba(46, 204, 113, .2); color: #2ecc71; }
  .srv-badge.sc { background: rgba(243, 156, 18, .2); color: #f39c12; }

  .load-bar { width: 50px; height: 6px; background: var(--border); border-radius: 3px; overflow: hidden; flex-shrink: 0; }
  .load-fill { height: 100%; }
  .load-pct { font-size: .76rem; color: var(--fg2); min-width: 32px; text-align: right; flex-shrink: 0; }
  /* Proton score: the actual sort key. Visually distinct from load%
     so users don't confuse the two metrics — smaller, monospaced,
     dimmer, with a leading bolt to echo the "Fastest" iconography. */
  .score-pct {
    font-size: .68rem; color: var(--fg3);
    font-family: ui-monospace, "SF Mono", Menlo, monospace;
    min-width: 38px; text-align: right; flex-shrink: 0;
  }
  .score-pct::before { content: "⚡ "; opacity: .55; }

  /* Blacklisted server rows — dimmed, strikethrough name */
  .dropdown-item.blacklisted { opacity: .45; }
  .dropdown-item.blacklisted .item-main { text-decoration: line-through; }

  /* Star (favourite) and ban (blacklist) toggle buttons inline in server rows */
  .pref-btn {
    background: none; border: none; cursor: pointer; padding: 0 2px;
    font-size: .85rem; color: var(--fg3); opacity: .35;
    transition: opacity .15s, color .15s; flex-shrink: 0; line-height: 1;
  }
  .pref-btn:hover { opacity: 1; }
  .pref-btn.active { opacity: 1; color: #f1c40f; }
  .ban-btn.active { opacity: 1; color: #e74c3c; }

  /* "Test latency" action link in the Server label */
  .label-action {
    margin-left: auto; font-size: .7rem; color: var(--accent);
    cursor: pointer; text-transform: none; letter-spacing: 0;
    font-weight: normal;
  }
  .label-action:hover { text-decoration: underline; }

  /* Latency badges on server items */
  .latency-badge {
    font-size: .65rem; padding: 1px 5px; border-radius: 3px;
    font-weight: 600; flex-shrink: 0; font-family: ui-monospace, monospace;
  }
  .latency-badge.good { background: rgba(46, 204, 113, .15); color: #2ecc71; }
  .latency-badge.warn { background: rgba(243, 156, 18, .15); color: #f39c12; }
  .latency-badge.bad { background: rgba(231, 76, 60, .15); color: #e74c3c; }

  .empty { padding: 16px; text-align: center; color: var(--fg3); font-size: .82rem; }

  .preview {
    margin-top: 16px; padding: 12px;
    background: var(--bg); border: 1px solid var(--border);
    border-radius: var(--radius-xs);
  }
  .preview-label { font-size: .68rem; color: var(--fg3); text-transform: uppercase; letter-spacing: .05em; margin-bottom: 6px; }
  .preview-server { display: flex; align-items: center; gap: 6px; font-size: .85rem; color: var(--fg); }
  .preview-meta { color: var(--fg3); font-size: .78rem; }
  .preview-empty { font-size: .78rem; color: var(--fg3); line-height: 1.4; }

  /* Collapsible "What do load % and score mean?" — mirrors the
     `.protocol-help` pattern in CreateGroupModal so the two collapsibles
     feel consistent. */
  .metric-help { margin-top: 12px; }
  .metric-help summary { font-size: .82rem; color: var(--accent); cursor: pointer; padding: 6px 0; }
  .metric-help summary:hover { text-decoration: underline; }
  .help-content { font-size: .8rem; color: var(--fg2); line-height: 1.5; padding: 10px; background: var(--bg); border-radius: var(--radius-xs); margin-top: 4px; }
  .help-content h4 { font-size: .85rem; color: var(--fg); margin: 8px 0 4px; }
  .help-content h4:first-child { margin-top: 0; }
  .help-content p { margin: 0 0 6px; }
  .help-content p:last-child { margin-bottom: 0; }

  :global(.flag-img) { width: 20px; height: 15px; vertical-align: middle; border-radius: 2px; object-fit: cover; }
</style>
