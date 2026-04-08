/** API client — all fetch calls to the Flask backend. */

const BASE = '';

async function request(path, opts = {}) {
  const res = await fetch(BASE + path, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  return res.json();
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

  // Refresh
  refresh: () => request('/api/refresh', { method: 'POST' }),
};
