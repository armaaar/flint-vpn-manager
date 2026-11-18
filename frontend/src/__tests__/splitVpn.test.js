import { describe, it, expect, vi, beforeEach } from 'vitest';
import { api } from '../lib/api';
import {
  parseList, initialSplitVpnForm, buildSplitVpnPayload, settingSecret,
  splitVpnEligibleGroups, unixToIso, splitVpnAutoStatus, deviceName, parseGraceMinutes,
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

describe('split VPN presence payload', () => {
  it('defaults to always mode and sends only connect_mode', () => {
    const f = initialSplitVpnForm(null);
    expect(f.connect_mode).toBe('always');
    expect(f.presence_grace_min).toBe(5);
    expect(f.yield_to_device_tunnel).toBe(true);
    f.presence_macs = ['AA:BB:CC:DD:EE:FF'];
    const data = buildSplitVpnPayload(f);
    expect(data.connect_mode).toBe('always');
    expect(data).not.toHaveProperty('presence_macs');
    expect(data).not.toHaveProperty('presence_grace_min');
    expect(data).not.toHaveProperty('yield_to_device_tunnel');
  });

  it('includes presence fields (lowercased, deduped) in presence mode', () => {
    const f = initialSplitVpnForm(VPN);
    f.connect_mode = 'presence';
    f.presence_macs = ['AA:BB:CC:DD:EE:FF', 'aa:bb:cc:dd:ee:ff', '11:22:33:44:55:66'];
    f.presence_grace_min = '15';
    f.yield_to_device_tunnel = false;
    const data = buildSplitVpnPayload(f);
    expect(data).toMatchObject({
      connect_mode: 'presence',
      presence_macs: ['aa:bb:cc:dd:ee:ff', '11:22:33:44:55:66'],
      presence_grace_min: 15,
      yield_to_device_tunnel: false,
    });
  });

  it('falls back to 5 minutes for an out-of-range grace value', () => {
    const f = { ...initialSplitVpnForm(VPN), connect_mode: 'presence', presence_macs: ['aa:bb:cc:dd:ee:ff'], presence_grace_min: 500 };
    expect(buildSplitVpnPayload(f).presence_grace_min).toBe(5);
    expect(parseGraceMinutes(0)).toBeNull();
    expect(parseGraceMinutes('121')).toBeNull();
    expect(parseGraceMinutes('2.5')).toBeNull();
    expect(parseGraceMinutes('120')).toBe(120);
  });

  it('keeps presence fields with SOPS credentials', () => {
    const f = { ...initialSplitVpnForm(null), cred_source: 'sops', secret_ref: 'x',
      connect_mode: 'presence', presence_macs: ['aa:bb:cc:dd:ee:ff'] };
    const data = buildSplitVpnPayload(f);
    expect(data.secret_ref).toBe('x');
    expect(data.presence_macs).toEqual(['aa:bb:cc:dd:ee:ff']);
    expect(data.yield_to_device_tunnel).toBe(true);
  });

  it('pre-fills presence settings from the VPN on edit', () => {
    const f = initialSplitVpnForm({ ...VPN, connect_mode: 'presence', presence_macs: ['AA:BB:CC:DD:EE:FF'],
      presence_grace_min: 10, yield_to_device_tunnel: false });
    expect(f).toMatchObject({ connect_mode: 'presence', presence_macs: ['aa:bb:cc:dd:ee:ff'],
      presence_grace_min: 10, yield_to_device_tunnel: false });
  });
});

describe('split VPN auto-state status line', () => {
  const LAPTOP = 'aa:bb:cc:dd:ee:ff';
  const PHONE = '11:22:33:44:55:66';
  const DEVICES = [
    { mac: LAPTOP, label: 'Work laptop', hostname: 'wl-123' },
    { mac: PHONE, label: '', hostname: 'pixel' },
  ];
  const NOW = 1_800_000_000;
  const vpnWith = (auto_state, extra = {}) => ({
    ...VPN, connect_mode: 'presence', presence_macs: [LAPTOP], auto_state, ...extra,
  });
  const st = (state, code, more = {}) => ({ state, code, devices: [LAPTOP], since: null, release_at: null, ...more });
  const text = (vpn) => splitVpnAutoStatus(vpn, DEVICES, NOW)?.text;

  it('resolves device names: label, then hostname, then MAC', () => {
    expect(deviceName('AA:BB:CC:DD:EE:FF', DEVICES)).toBe('Work laptop');
    expect(deviceName(PHONE, DEVICES)).toBe('pixel');
    expect(deviceName('de:ad:be:ef:00:01', DEVICES)).toBe('de:ad:be:ef:00:01');
  });

  it('returns null without auto_state', () => {
    expect(splitVpnAutoStatus({ ...VPN }, DEVICES, NOW)).toBeNull();
    expect(splitVpnAutoStatus({ ...VPN, auto_state: null }, DEVICES, NOW)).toBeNull();
  });

  it('connected at home', () => {
    const r = splitVpnAutoStatus(vpnWith(st('connected', 'home')), DEVICES, NOW);
    expect(r).toEqual({ text: '🟢 Connected — Work laptop at home', tone: 'on' });
  });

  it('standing by while away, with and without since', () => {
    expect(text(vpnWith(st('standby', 'away')))).toBe('⏸️ Standing by — Work laptop away');
    const since = Math.floor(Date.now() / 1000) - 7 * 60;
    expect(text(vpnWith(st('standby', 'away', { since })))).toBe('⏸️ Standing by — Work laptop away (released 7m ago)');
  });

  it('falls back to presence_macs when devices is empty', () => {
    expect(text(vpnWith(st('standby', 'away', { devices: [] })))).toBe('⏸️ Standing by — Work laptop away');
  });

  it('standing by while the device runs its own VPN', () => {
    expect(text(vpnWith(st('standby', 'own_tunnel')))).toBe('⏸️ Standing by — Work laptop is using its own VPN');
    expect(text(vpnWith(st('standby', 'own_tunnel', { devices: [LAPTOP, PHONE] }))))
      .toBe('⏸️ Standing by — Work laptop and pixel are using their own VPN');
  });

  it('releasing countdown rounds up minutes', () => {
    expect(text(vpnWith(st('releasing', 'away', { release_at: NOW + 4 * 60 + 1 })))).toBe('⏳ Releasing in 5 min — Work laptop left');
    expect(text(vpnWith(st('releasing', 'away', { release_at: NOW + 60 })))).toBe('⏳ Releasing in 1 min — Work laptop left');
    expect(text(vpnWith(st('releasing', 'away', { release_at: NOW - 30 })))).toBe('⏳ Releasing in 1 min — Work laptop left');
    expect(splitVpnAutoStatus(vpnWith(st('releasing', 'away', { release_at: NOW + 120 })), DEVICES, NOW).tone).toBe('pending');
  });

  it('connecting, paused, off and always', () => {
    expect(text(vpnWith(st('connecting', 'home')))).toBe('Connecting…');
    expect(text(vpnWith(st('paused', 'manual')))).toBe('Paused — reconnects on next manual connect');
    expect(text(vpnWith(st('off', 'disabled')))).toBe('Auto-connect off');
    expect(text(vpnWith(st('connected', 'always', { devices: [] }), { connect_mode: 'always' })))
      .toBe('Always connected (auto-reconnect)');
  });
});
