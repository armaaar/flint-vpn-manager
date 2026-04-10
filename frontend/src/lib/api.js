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
  connectProfile: (id, opts) => request(`/api/profiles/${id}/connect`, { method: 'POST', body: opts || {} }),
  disconnectProfile: (id) => request(`/api/profiles/${id}/disconnect`, { method: 'POST' }),
  setGuestProfile: (id) => request(`/api/profiles/${id}/guest`, { method: 'PUT' }),
  changeServer: (id, data) => request(`/api/profiles/${id}/server`, { method: 'PUT', body: data }),
  changeType: (id, data) => request(`/api/profiles/${id}/type`, { method: 'PUT', body: data }),
  changeProtocol: (id, data) => request(`/api/profiles/${id}/protocol`, { method: 'PUT', body: data }),
  setProfileLanAccess: (id, data) => request(`/api/profiles/${id}/lan-access`, { method: 'PUT', body: data }),

  // Servers
  getServers: (profileId) => request(`/api/profiles/${profileId || 'none'}/servers`),

  // Devices
  getDevices: () => request('/api/devices'),
  assignDevice: (mac, profileId) => request(`/api/devices/${encodeURIComponent(mac)}/profile`, { method: 'PUT', body: { profile_id: profileId } }),
  setDeviceLabel: (mac, label, deviceClass) => request(`/api/devices/${encodeURIComponent(mac)}/label`, { method: 'PUT', body: { label, device_class: deviceClass } }),
  setDeviceLanAccess: (mac, data) => request(`/api/devices/${encodeURIComponent(mac)}/lan-access`, { method: 'PUT', body: data }),

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

  // Ports
  getAvailablePorts: () => request('/api/available-ports'),

  // Latency Probing
  probeLatency: (serverIds) => request('/api/probe-latency', { method: 'POST', body: { server_ids: serverIds } }),

  // Location & Sessions
  getLocation: () => request('/api/location'),
  getSessions: () => request('/api/sessions'),

  // Refresh
  refresh: () => request('/api/refresh', { method: 'POST' }),
};
