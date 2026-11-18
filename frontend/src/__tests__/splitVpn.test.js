import { describe, it, expect, vi, beforeEach } from 'vitest';
import { api } from '../lib/api';
import {
  parseList, initialSplitVpnForm, buildSplitVpnPayload, settingSecret,
  splitVpnEligibleGroups, unixToIso,
} from '../lib/utils/splitVpn';

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

function mockResponse(data, ok = true) {
  mockFetch.mockResolvedValueOnce({ json: () => Promise.resolve(data), ok });
}

function lastCall() {
  const [url, opts] = mockFetch.mock.calls[mockFetch.mock.calls.length - 1];
  return { url, method: opts.method || 'GET', body: opts.body ? JSON.parse(opts.body) : undefined };
}

beforeEach(() => {
  mockFetch.mockReset();
});

const VPN = {
  id: 'sv_1', type: 'barracuda', slot: 0, name: 'Work', server: 'vpn.corp.com', port: 691,
  tunnel_mode: 'TCP', username: 'alice', group_ids: ['g1'], domains: ['corp.com'], cidrs: ['10.0.0.0/8'],
  use_pushed_routes: true, auto_connect: true, enabled: true, pushed_routes: [], pushed_dns: [],
  has_password: true, has_totp: true,
};

describe('split VPN API client', () => {
  it('getSplitVpns calls GET /api/split-vpns?live=1', async () => {
    mockResponse({ vpns: [], runtime: { installed: true }, max: 4 });
    const res = await api.getSplitVpns();
    expect(res.max).toBe(4);
    expect(lastCall()).toMatchObject({ url: '/api/split-vpns?live=1', method: 'GET' });
  });

  it('getSplitVpns(false) asks for live=0', async () => {
    mockResponse({ vpns: [], runtime: { installed: true }, max: 4 });
    await api.getSplitVpns(false);
    expect(lastCall().url).toBe('/api/split-vpns?live=0');
  });

  it('createSplitVpn POSTs the body', async () => {
    mockResponse(VPN);
    await api.createSplitVpn({ name: 'Work' });
    expect(lastCall()).toEqual({ url: '/api/split-vpns', method: 'POST', body: { name: 'Work' } });
  });

  it('updateSplitVpn PUTs to /api/split-vpns/:id', async () => {
    mockResponse(VPN);
    await api.updateSplitVpn('sv_1', { enabled: false });
    expect(lastCall()).toEqual({ url: '/api/split-vpns/sv_1', method: 'PUT', body: { enabled: false } });
  });

  it('deleteSplitVpn DELETEs /api/split-vpns/:id', async () => {
    mockResponse({ success: true });
    await api.deleteSplitVpn('sv_1');
    expect(lastCall()).toMatchObject({ url: '/api/split-vpns/sv_1', method: 'DELETE' });
  });

  it('connectSplitVpn without a code sends an empty body', async () => {
    mockResponse({ connected: true, state: 'CONNECTED' });
    await api.connectSplitVpn('sv_1');
    expect(lastCall()).toEqual({ url: '/api/split-vpns/sv_1/connect', method: 'POST', body: {} });
  });

  it('connectSplitVpn with a code sends {otp}', async () => {
    mockResponse({ connected: true, state: 'CONNECTED' });
    await api.connectSplitVpn('sv_1', '123456');
    expect(lastCall()).toEqual({ url: '/api/split-vpns/sv_1/connect', method: 'POST', body: { otp: '123456' } });
  });

  it('disconnectSplitVpn POSTs /disconnect', async () => {
    mockResponse({ success: true });
    await api.disconnectSplitVpn('sv_1');
    expect(lastCall()).toMatchObject({ url: '/api/split-vpns/sv_1/disconnect', method: 'POST' });
  });

  it('getSplitVpnLog GETs /log', async () => {
    mockResponse({ log: 'hello' });
    const res = await api.getSplitVpnLog('sv_1');
    expect(res.log).toBe('hello');
    expect(lastCall()).toMatchObject({ url: '/api/split-vpns/sv_1/log', method: 'GET' });
  });

  it('runtime status and install hit the runtime endpoints', async () => {
    mockResponse({ installed: false });
    await api.getSplitVpnRuntime();
    expect(lastCall()).toMatchObject({ url: '/api/split-vpns/runtime', method: 'GET' });
    mockResponse({ installed: true });
    const res = await api.installSplitVpnRuntime();
    expect(res.installed).toBe(true);
    expect(lastCall()).toMatchObject({ url: '/api/split-vpns/runtime/install', method: 'POST' });
  });

  it('surfaces backend error messages', async () => {
    mockResponse({ error: 'Wrong master password' }, false);
    await expect(api.createSplitVpn({})).rejects.toThrow('Wrong master password');
  });
});

describe('split VPN form helpers', () => {
  it('parseList splits on newlines/commas/spaces, trims and dedupes', () => {
    expect(parseList(' a.com\nb.com, a.com  c.com\n\n')).toEqual(['a.com', 'b.com', 'c.com']);
    expect(parseList('')).toEqual([]);
  });

  it('initial form for create has defaults', () => {
    const f = initialSplitVpnForm(null);
    expect(f.port).toBe(691);
    expect(f.tunnel_mode).toBe('TCP');
    expect(f.use_pushed_routes).toBe(true);
    expect(f.auto_connect).toBe(true);
    expect(f.enabled).toBe(true);
  });

  it('edit payload omits password, totp_secret and master_password when unchanged', () => {
    const f = initialSplitVpnForm(VPN);
    f.master_password = 'typed-but-irrelevant';
    const data = buildSplitVpnPayload(f);
    expect(data).not.toHaveProperty('password');
    expect(data).not.toHaveProperty('totp_secret');
    expect(data).not.toHaveProperty('master_password');
    expect(data).toMatchObject({
      name: 'Work', server: 'vpn.corp.com', port: 691, tunnel_mode: 'TCP', username: 'alice',
      group_ids: ['g1'], domains: ['corp.com'], cidrs: ['10.0.0.0/8'],
      use_pushed_routes: true, auto_connect: true, enabled: true,
    });
  });

  it('payload includes the master password with a new password', () => {
    const f = initialSplitVpnForm(VPN);
    f.password = 'secret';
    f.master_password = 'mp';
    expect(settingSecret(f)).toBe(true);
    const data = buildSplitVpnPayload(f);
    expect(data.password).toBe('secret');
    expect(data.master_password).toBe('mp');
    expect(data).not.toHaveProperty('totp_secret');
  });

  it('payload includes the master password with a new TOTP secret only', () => {
    const f = initialSplitVpnForm(VPN);
    f.totp_secret = '  JBSWY3DPEHPK3PXP ';
    f.master_password = 'mp';
    const data = buildSplitVpnPayload(f);
    expect(data.totp_secret).toBe('JBSWY3DPEHPK3PXP');
    expect(data.master_password).toBe('mp');
    expect(data).not.toHaveProperty('password');
  });

  it('only vpn and no_vpn groups are eligible', () => {
    const groups = splitVpnEligibleGroups([
      { id: 'a', type: 'vpn' }, { id: 'b', type: 'no_vpn' }, { id: 'c', type: 'no_internet' },
    ]);
    expect(groups.map(g => g.id)).toEqual(['a', 'b']);
  });

  it('unixToIso converts seconds and handles missing values', () => {
    expect(unixToIso(0)).toBeNull();
    expect(unixToIso(undefined)).toBeNull();
    expect(unixToIso(1700000000)).toBe('2023-11-14T22:13:20.000Z');
  });
});

describe('split VPN SOPS credentials', () => {
  it('sends only secret_ref (no secrets, no master password) for SOPS credentials', async () => {
    const { initialSplitVpnForm, buildSplitVpnPayload } = await import('../lib/utils/splitVpn');
    const form = { ...initialSplitVpnForm(null), name: 'W', server: 'vpn.example.com',
      cred_source: 'sops', secret_ref: ' work ', password: 'x', totp_secret: 'y', master_password: 'z' };
    const body = buildSplitVpnPayload(form);
    expect(body.secret_ref).toBe('work');
    expect(body).not.toHaveProperty('password');
    expect(body).not.toHaveProperty('totp_secret');
    expect(body).not.toHaveProperty('master_password');
  });

  it('pre-selects SOPS for a VPN with a secret_ref and clears it when switching back', async () => {
    const { initialSplitVpnForm, buildSplitVpnPayload } = await import('../lib/utils/splitVpn');
    const form = initialSplitVpnForm({ id: 'sv_1', name: 'W', server: 's', secret_ref: 'work' });
    expect(form.cred_source).toBe('sops');
    form.cred_source = 'app';
    expect(buildSplitVpnPayload(form).secret_ref).toBe('');
  });
});
