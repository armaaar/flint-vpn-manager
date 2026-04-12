/** API client — all fetch calls to the Flask backend. */

const BASE = '';

async function request(path, opts = {}) {
  const res = await fetch(BASE + path, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data?.error || `Request failed: ${res.status}`);
  return data;
}

export const api = {
  // Auth
  getStatus: () => request('/api/status'),
  setup: (data) => request('/api/setup', { method: 'POST', body: data }),
  unlock: (masterPassword) => request('/api/unlock', { method: 'POST', body: { master_password: masterPassword } }),

  // Profiles
  getProfiles: () => request('/api/profiles'),
  createProfile: (data) => request('/api/profiles', { method: 'POST', body: data }),
  updateProfile: (id, data) => request(`/api/profiles/${id}`, { method: 'PUT', body: data }),
  reorderProfiles: (profileIds) => request('/api/profiles/reorder', { method: 'PUT', body: { profile_ids: profileIds } }),
  deleteProfile: (id) => request(`/api/profiles/${id}`, { method: 'DELETE' }),
  connectProfile: (id) => request(`/api/profiles/${id}/connect`, { method: 'POST' }),
  disconnectProfile: (id) => request(`/api/profiles/${id}/disconnect`, { method: 'POST' }),
  setGuestProfile: (id) => request(`/api/profiles/${id}/guest`, { method: 'PUT' }),
  changeServer: (id, data) => request(`/api/profiles/${id}/server`, { method: 'PUT', body: data }),
  changeType: (id, data) => request(`/api/profiles/${id}/type`, { method: 'PUT', body: data }),
  changeProtocol: (id, data) => request(`/api/profiles/${id}/protocol`, { method: 'PUT', body: data }),
  // Servers
  getServers: (profileId) => request(`/api/profiles/${profileId || 'none'}/servers`),

  // Devices
  getDevices: () => request('/api/devices'),
  assignDevice: (mac, profileId) => request(`/api/devices/${encodeURIComponent(mac)}/profile`, { method: 'PUT', body: { profile_id: profileId } }),
  setDeviceLabel: (mac, label, deviceClass) => request(`/api/devices/${encodeURIComponent(mac)}/label`, { method: 'PUT', body: { label, device_class: deviceClass } }),
  // Settings
  getSettings: () => request('/api/settings'),
  updateSettings: (data) => request('/api/settings', { method: 'PUT', body: data }),
  updateCredentials: (data) => request('/api/settings/credentials', { method: 'PUT', body: data }),

  // Server Preferences (Blacklist / Favourites)
  getServerPreferences: () => request('/api/settings/server-preferences'),
  updateServerPreferences: (data) => request('/api/settings/server-preferences', { method: 'PUT', body: data }),
  addToBlacklist: (serverId) => request(`/api/settings/server-preferences/blacklist/${encodeURIComponent(serverId)}`, { method: 'POST' }),
  removeFromBlacklist: (serverId) => request(`/api/settings/server-preferences/blacklist/${encodeURIComponent(serverId)}`, { method: 'DELETE' }),
  addToFavourites: (serverId) => request(`/api/settings/server-preferences/favourites/${encodeURIComponent(serverId)}`, { method: 'POST' }),
  removeFromFavourites: (serverId) => request(`/api/settings/server-preferences/favourites/${encodeURIComponent(serverId)}`, { method: 'DELETE' }),

  // DNS Ad Blocker
  getAdblockSettings: () => request('/api/settings/adblock'),
  updateAdblockSettings: (data) => request('/api/settings/adblock', { method: 'PUT', body: data }),
  updateBlocklistNow: () => request('/api/settings/adblock/update-now', { method: 'POST' }),
  getBlockedDomains: (search = '', page = 1, limit = 100) =>
    request(`/api/settings/adblock/domains?search=${encodeURIComponent(search)}&page=${page}&limit=${limit}`),

  // Ports
  getAvailablePorts: () => request('/api/available-ports'),

  // Latency Probing
  probeLatency: (serverIds) => request('/api/probe-latency', { method: 'POST', body: { server_ids: serverIds } }),

  // Location & Sessions
  getLocation: () => request('/api/location'),
  getSessions: () => request('/api/sessions'),

  // Networks (LAN Access)
  getNetworks: () => request('/api/lan-access/networks'),
  createNetwork: (data) => request('/api/lan-access/networks', { method: 'POST', body: data }),
  updateNetwork: (zoneId, data) => request(`/api/lan-access/networks/${zoneId}`, { method: 'PUT', body: data }),
  deleteNetwork: (zoneId) => request(`/api/lan-access/networks/${zoneId}`, { method: 'DELETE' }),
  getNetworkDevices: (zoneId) => request(`/api/lan-access/networks/${zoneId}/devices`),
  updateAccessRules: (rules) => request('/api/lan-access/rules', { method: 'PUT', body: { rules } }),
  setIsolation: (zoneId, enabled) => request(`/api/lan-access/isolation/${zoneId}`, { method: 'PUT', body: { enabled } }),
  getExceptions: () => request('/api/lan-access/exceptions'),
  addException: (data) => request('/api/lan-access/exceptions', { method: 'POST', body: data }),
  removeException: (id) => request(`/api/lan-access/exceptions/${id}`, { method: 'DELETE' }),

  // Refresh
  refresh: () => request('/api/refresh', { method: 'POST' }),
};
