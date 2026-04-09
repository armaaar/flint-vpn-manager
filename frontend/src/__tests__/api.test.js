import { describe, it, expect, vi, beforeEach } from 'vitest';
import { api } from '../lib/api.js';

// Mock fetch globally
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

function mockResponse(data, ok = true) {
  mockFetch.mockResolvedValueOnce({ json: () => Promise.resolve(data), ok });
}

beforeEach(() => {
  mockFetch.mockReset();
});

describe('api.getStatus', () => {
  it('calls GET /api/status', async () => {
    mockResponse({ status: 'locked' });
    const result = await api.getStatus();
    expect(result.status).toBe('locked');
    expect(mockFetch).toHaveBeenCalledWith('/api/status', expect.objectContaining({ headers: expect.any(Object) }));
  });
});

describe('api.unlock', () => {
  it('calls POST /api/unlock with master password', async () => {
    mockResponse({ success: true });
    const result = await api.unlock('mypassword');
    expect(result.success).toBe(true);
    const call = mockFetch.mock.calls[0];
    expect(call[0]).toBe('/api/unlock');
    expect(call[1].method).toBe('POST');
    expect(JSON.parse(call[1].body)).toEqual({ master_password: 'mypassword' });
  });
});

describe('api.setup', () => {
  it('calls POST /api/setup with credentials', async () => {
    mockResponse({ success: true });
    const data = { proton_user: 'u', proton_pass: 'p', router_pass: 'r', master_password: 'm' };
    await api.setup(data);
    const call = mockFetch.mock.calls[0];
    expect(call[0]).toBe('/api/setup');
    expect(JSON.parse(call[1].body)).toEqual(data);
  });
});

describe('api.getProfiles', () => {
  it('calls GET /api/profiles', async () => {
    const profiles = [{ id: '1', name: 'Test', type: 'vpn' }];
    mockResponse(profiles);
    const result = await api.getProfiles();
    expect(result).toEqual(profiles);
  });
});

describe('api.createProfile', () => {
  it('calls POST /api/profiles', async () => {
    const profile = { name: 'Gaming', type: 'vpn' };
    mockResponse({ ...profile, id: '123' });
    const result = await api.createProfile(profile);
    expect(result.id).toBe('123');
    const call = mockFetch.mock.calls[0];
    expect(call[1].method).toBe('POST');
  });
});

describe('api.assignDevice', () => {
  it('calls PUT /api/devices/:mac/profile', async () => {
    mockResponse({ success: true });
    await api.assignDevice('aa:bb:cc:dd:ee:ff', 'profile-1');
    const call = mockFetch.mock.calls[0];
    expect(call[0]).toBe('/api/devices/aa%3Abb%3Acc%3Add%3Aee%3Aff/profile');
    expect(call[1].method).toBe('PUT');
    expect(JSON.parse(call[1].body)).toEqual({ profile_id: 'profile-1' });
  });

  it('sends null profile_id for unassign', async () => {
    mockResponse({ success: true });
    await api.assignDevice('aa:bb:cc:dd:ee:ff', null);
    const call = mockFetch.mock.calls[0];
    expect(JSON.parse(call[1].body)).toEqual({ profile_id: null });
  });
});

describe('api.setDeviceLabel', () => {
  it('calls PUT /api/devices/:mac/label with label and device_class', async () => {
    mockResponse({ success: true });
    await api.setDeviceLabel('aa:bb:cc:dd:ee:ff', 'Living Room TV', 'tv');
    const call = mockFetch.mock.calls[0];
    expect(call[0]).toBe('/api/devices/aa%3Abb%3Acc%3Add%3Aee%3Aff/label');
    expect(JSON.parse(call[1].body)).toEqual({ label: 'Living Room TV', device_class: 'tv' });
  });
});

describe('api.getServers', () => {
  it('calls GET /api/profiles/:id/servers', async () => {
    mockResponse([{ id: 's1', name: 'UK#1' }]);
    const result = await api.getServers('profile-1');
    expect(result[0].name).toBe('UK#1');
    expect(mockFetch.mock.calls[0][0]).toBe('/api/profiles/profile-1/servers');
  });

  it('uses "none" when no profile ID', async () => {
    mockResponse([]);
    await api.getServers(null);
    expect(mockFetch.mock.calls[0][0]).toBe('/api/profiles/none/servers');
  });
});

describe('api.connectProfile', () => {
  it('calls POST /api/profiles/:id/connect', async () => {
    mockResponse({ success: true });
    await api.connectProfile('p1');
    expect(mockFetch.mock.calls[0][0]).toBe('/api/profiles/p1/connect');
    expect(mockFetch.mock.calls[0][1].method).toBe('POST');
  });
});

describe('api.changeServer', () => {
  it('calls PUT /api/profiles/:id/server', async () => {
    mockResponse({ success: true });
    await api.changeServer('p1', { server_id: 's1', options: {} });
    const call = mockFetch.mock.calls[0];
    expect(call[0]).toBe('/api/profiles/p1/server');
    expect(call[1].method).toBe('PUT');
  });
});

describe('api.reorderProfiles', () => {
  it('calls PUT /api/profiles/reorder with profile IDs', async () => {
    mockResponse({ success: true });
    await api.reorderProfiles(['id1', 'id2', 'id3']);
    const call = mockFetch.mock.calls[0];
    expect(call[0]).toBe('/api/profiles/reorder');
    expect(call[1].method).toBe('PUT');
    expect(JSON.parse(call[1].body)).toEqual({ profile_ids: ['id1', 'id2', 'id3'] });
  });
});

describe('api.refresh', () => {
  it('calls POST /api/refresh', async () => {
    mockResponse({ success: true });
    await api.refresh();
    expect(mockFetch.mock.calls[0][0]).toBe('/api/refresh');
    expect(mockFetch.mock.calls[0][1].method).toBe('POST');
  });
});

describe('error handling', () => {
  it('throws on HTTP error with backend message', async () => {
    mockResponse({ error: 'Session locked' }, false);
    await expect(api.getStatus()).rejects.toThrow('Session locked');
  });

  it('throws generic message when no error field', async () => {
    mockResponse({}, false);
    await expect(api.getStatus()).rejects.toThrow('Request failed');
  });
});
