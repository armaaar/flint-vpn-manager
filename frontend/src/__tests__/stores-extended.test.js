import { describe, it, expect, vi, beforeEach } from 'vitest';
import { get } from 'svelte/store';
import {
  profiles, devices, smartProtocolStatus, movingDevices,
  devicesForProfile, reloadData, startSSE, stopSSE,
} from '../lib/stores/app';

// Mock api module
vi.mock('../lib/api', () => ({
  api: {
    getProfiles: vi.fn(),
    getDevices: vi.fn(),
  },
}));
import { api } from '../lib/api';

beforeEach(() => {
  profiles.set([]);
  devices.set([]);
  smartProtocolStatus.set({});
  movingDevices.set(new Set());
  vi.restoreAllMocks();
});

describe('devicesForProfile', () => {
  it('returns devices matching profile_id', () => {
    devices.set([
      { mac: 'aa:bb:cc:dd:ee:ff', profile_id: 'p1' },
      { mac: '11:22:33:44:55:66', profile_id: 'p2' },
      { mac: '77:88:99:aa:bb:cc', profile_id: 'p1' },
    ]);
    const result = devicesForProfile('p1');
    expect(result).toHaveLength(2);
    expect(result[0].mac).toBe('aa:bb:cc:dd:ee:ff');
    expect(result[1].mac).toBe('77:88:99:aa:bb:cc');
  });

  it('returns empty for non-existent profile', () => {
    devices.set([
      { mac: 'aa:bb:cc:dd:ee:ff', profile_id: 'p1' },
    ]);
    expect(devicesForProfile('nonexistent')).toHaveLength(0);
  });

  it('returns empty when no devices', () => {
    expect(devicesForProfile('p1')).toHaveLength(0);
  });
});

describe('reloadData', () => {
  it('fetches profiles and devices in parallel', async () => {
    const mockProfiles = [{ id: 'p1', name: 'US' }];
    const mockDevices = [{ mac: 'aa:bb:cc:dd:ee:ff' }];
    api.getProfiles.mockResolvedValue(mockProfiles);
    api.getDevices.mockResolvedValue(mockDevices);

    await reloadData();

    expect(api.getProfiles).toHaveBeenCalledOnce();
    expect(api.getDevices).toHaveBeenCalledOnce();
    expect(get(profiles)).toEqual(mockProfiles);
    expect(get(devices)).toEqual(mockDevices);
  });
});

describe('startSSE / stopSSE', () => {
  let mockEventSource;

  beforeEach(() => {
    mockEventSource = {
      close: vi.fn(),
      onmessage: null,
    };
    vi.stubGlobal('EventSource', function(url) {
      mockEventSource._url = url;
      return mockEventSource;
    });
  });

  it('creates an EventSource on /api/stream', () => {
    startSSE();
    expect(mockEventSource._url).toBe('/api/stream');
  });

  it('closes previous SSE before starting new one', () => {
    startSSE();
    startSSE();
    expect(mockEventSource.close).toHaveBeenCalled();
  });

  it('stopSSE closes the connection', () => {
    startSSE();
    stopSSE();
    expect(mockEventSource.close).toHaveBeenCalled();
  });

  it('handles tunnel_health SSE messages', () => {
    profiles.set([
      { id: 'p1', name: 'US', health: 'red' },
      { id: 'p2', name: 'UK', health: 'green' },
    ]);

    startSSE();
    // Simulate SSE message
    mockEventSource.onmessage({
      data: JSON.stringify({
        tunnel_health: { p1: 'green' },
      }),
    });

    const updated = get(profiles);
    expect(updated.find(p => p.id === 'p1').health).toBe('green');
    expect(updated.find(p => p.id === 'p2').health).toBe('green'); // unchanged
  });

  it('handles kill_switch SSE messages', () => {
    profiles.set([{ id: 'p1', kill_switch: true }]);
    startSSE();
    mockEventSource.onmessage({
      data: JSON.stringify({ kill_switch: { p1: false } }),
    });
    expect(get(profiles).find(p => p.id === 'p1').kill_switch).toBe(false);
  });

  it('handles devices SSE messages', () => {
    startSSE();
    const newDevices = [{ mac: 'aa:bb:cc:dd:ee:ff', name: 'Phone' }];
    mockEventSource.onmessage({
      data: JSON.stringify({ devices: newDevices }),
    });
    expect(get(devices)).toEqual(newDevices);
  });

  it('handles smart_protocol_status SSE messages', () => {
    startSSE();
    const status = { p1: { attempting: 'wireguard-tcp', attempt: 2, total: 5 } };
    mockEventSource.onmessage({
      data: JSON.stringify({ smart_protocol_status: status }),
    });
    expect(get(smartProtocolStatus)).toEqual(status);
  });

  it('handles profile_names SSE messages', () => {
    profiles.set([{ id: 'p1', name: 'Old Name' }]);
    startSSE();
    mockEventSource.onmessage({
      data: JSON.stringify({ profile_names: { p1: 'New Name' } }),
    });
    expect(get(profiles).find(p => p.id === 'p1').name).toBe('New Name');
  });

  it('handles server_info SSE messages', () => {
    profiles.set([{ id: 'p1', server: null, health: 'green' }]);
    startSSE();
    const srv = { name: 'US#42', country: 'US' };
    // server_info is only processed when tunnel_health/kill_switch/profile_names is also present
    mockEventSource.onmessage({
      data: JSON.stringify({ tunnel_health: { p1: 'green' }, server_info: { p1: srv } }),
    });
    expect(get(profiles).find(p => p.id === 'p1').server).toEqual(srv);
  });

  it('ignores malformed SSE data', () => {
    profiles.set([{ id: 'p1', health: 'green' }]);
    startSSE();
    // Should not throw
    mockEventSource.onmessage({ data: 'not json' });
    expect(get(profiles)[0].health).toBe('green');
  });
});
