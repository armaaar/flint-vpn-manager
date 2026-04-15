/** API client — all fetch calls to the Flask backend. */

import type {
  Profile, Device, ServerInfo, AppSettings, AdblockSettings,
  LanNetwork, LanException, AccessRule,
} from './types';

const BASE = '';

interface RequestOptions {
  method?: string;
  body?: unknown;
  headers?: Record<string, string>;
}

async function request<T = unknown>(path: string, opts: RequestOptions = {}): Promise<T> {
  const res = await fetch(BASE + path, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data?.error || `Request failed: ${res.status}`);
  return data as T;
}

export const api = {
  // Auth
  getStatus: () => request<{ status: string; proton_logged_in?: boolean }>('/api/status'),
  setup: (data: Record<string, string>) => request('/api/setup', { method: 'POST', body: data }),
  unlock: (masterPassword: string) => request('/api/unlock', { method: 'POST', body: { master_password: masterPassword } }),

  // Profiles
  getProfiles: () => request<Profile[]>('/api/profiles'),
  createProfile: (data: Record<string, unknown>) => request<Profile>('/api/profiles', { method: 'POST', body: data }),
  updateProfile: (id: string, data: Record<string, unknown>) => request<Profile>(`/api/profiles/${id}`, { method: 'PUT', body: data }),
  reorderProfiles: (profileIds: string[]) => request('/api/profiles/reorder', { method: 'PUT', body: { profile_ids: profileIds } }),
  deleteProfile: (id: string) => request(`/api/profiles/${id}`, { method: 'DELETE' }),
  connectProfile: (id: string) => request<{ success: boolean; health: string }>(`/api/profiles/${id}/connect`, { method: 'POST' }),
  disconnectProfile: (id: string) => request<{ success: boolean; health: string }>(`/api/profiles/${id}/disconnect`, { method: 'POST' }),
  setGuestProfile: (id: string) => request(`/api/profiles/${id}/guest`, { method: 'PUT' }),
  changeServer: (id: string, data: Record<string, unknown>) => request<Profile>(`/api/profiles/${id}/server`, { method: 'PUT', body: data }),
  changeType: (id: string, data: Record<string, unknown>) => request<Profile>(`/api/profiles/${id}/type`, { method: 'PUT', body: data }),
  changeProtocol: (id: string, data: Record<string, unknown>) => request<Profile>(`/api/profiles/${id}/protocol`, { method: 'PUT', body: data }),

  // Servers
  getServers: (profileId?: string) => request<ServerInfo[]>(`/api/profiles/${profileId || 'none'}/servers`),

  // Devices
  getDevices: () => request<Device[]>('/api/devices'),
  assignDevice: (mac: string, profileId: string | null) => request(`/api/devices/${encodeURIComponent(mac)}/profile`, { method: 'PUT', body: { profile_id: profileId } }),
  setDeviceLabel: (mac: string, label: string, deviceClass: string) => request(`/api/devices/${encodeURIComponent(mac)}/label`, { method: 'PUT', body: { label, device_class: deviceClass } }),

  // Settings
  getSettings: () => request<AppSettings>('/api/settings'),
  updateSettings: (data: Record<string, unknown>) => request<AppSettings>('/api/settings', { method: 'PUT', body: data }),
  updateCredentials: (data: Record<string, string>) => request('/api/settings/credentials', { method: 'PUT', body: data }),

  // Server Preferences (Blacklist / Favourites)
  getServerPreferences: () => request<{ blacklist: string[]; favourites: string[] }>('/api/settings/server-preferences'),
  updateServerPreferences: (data: Record<string, unknown>) => request('/api/settings/server-preferences', { method: 'PUT', body: data }),
  addToBlacklist: (serverId: string) => request(`/api/settings/server-preferences/blacklist/${encodeURIComponent(serverId)}`, { method: 'POST' }),
  removeFromBlacklist: (serverId: string) => request(`/api/settings/server-preferences/blacklist/${encodeURIComponent(serverId)}`, { method: 'DELETE' }),
  addToFavourites: (serverId: string) => request(`/api/settings/server-preferences/favourites/${encodeURIComponent(serverId)}`, { method: 'POST' }),
  removeFromFavourites: (serverId: string) => request(`/api/settings/server-preferences/favourites/${encodeURIComponent(serverId)}`, { method: 'DELETE' }),

  // DNS Ad Blocker
  getAdblockSettings: () => request<AdblockSettings & { presets: Record<string, unknown> }>('/api/settings/adblock'),
  updateAdblockSettings: (data: Record<string, unknown>) => request<AdblockSettings>('/api/settings/adblock', { method: 'PUT', body: data }),
  updateBlocklistNow: () => request<{ success: boolean; entries: number; last_updated: string; failed_sources?: string[] }>('/api/settings/adblock/update-now', { method: 'POST' }),
  getBlockedDomains: (search = '', page = 1, limit = 100) =>
    request<{ domains: string[]; total: number; page: number; has_more: boolean }>(`/api/settings/adblock/domains?search=${encodeURIComponent(search)}&page=${page}&limit=${limit}`),

  // Ports
  getAvailablePorts: () => request<Record<string, number[]>>('/api/available-ports'),

  // Latency Probing
  probeLatency: (serverIds: string[]) => request<{ latencies: Record<string, number | null> }>('/api/probe-latency', { method: 'POST', body: { server_ids: serverIds } }),

  // Location
  getLocation: () => request<{ ip: string; country: string; isp: string }>('/api/location'),

  // Networks (LAN Access)
  getNetworks: () => request<LanNetwork[]>('/api/lan-access/networks'),
  createNetwork: (data: Record<string, unknown>) => request<LanNetwork>('/api/lan-access/networks', { method: 'POST', body: data }),
  updateNetwork: (zoneId: string, data: Record<string, unknown>) => request<LanNetwork>(`/api/lan-access/networks/${zoneId}`, { method: 'PUT', body: data }),
  deleteNetwork: (zoneId: string) => request(`/api/lan-access/networks/${zoneId}`, { method: 'DELETE' }),
  getNetworkDevices: (zoneId: string) => request<{ devices: Device[] }>(`/api/lan-access/networks/${zoneId}/devices`),
  updateAccessRules: (rules: AccessRule[]) => request('/api/lan-access/rules', { method: 'PUT', body: { rules } }),
  setIsolation: (zoneId: string, enabled: boolean) => request(`/api/lan-access/isolation/${zoneId}`, { method: 'PUT', body: { enabled } }),
  setIpv6: (zoneId: string, enabled: boolean) => request(`/api/lan-access/ipv6/${zoneId}`, { method: 'PUT', body: { enabled } }),
  getExceptions: () => request<{ exceptions: LanException[] }>('/api/lan-access/exceptions'),
  addException: (data: Record<string, unknown>) => request<LanException>('/api/lan-access/exceptions', { method: 'POST', body: data }),
  removeException: (id: string) => request(`/api/lan-access/exceptions/${id}`, { method: 'DELETE' }),

  // Refresh
  refresh: () => request('/api/refresh', { method: 'POST' }),
};
