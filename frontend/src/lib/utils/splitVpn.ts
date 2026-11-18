/** Split VPN form helpers (pure — unit-tested in __tests__/splitVpn.test.js). */

import type { Device, Profile, SplitVpn, SplitVpnConnectMode, SplitVpnTunnelMode } from '../types';
import { timeAgo } from './format';

export const SPLIT_VPN_DEFAULT_PORT = 691;
export const SPLIT_VPN_TUNNEL_MODES: SplitVpnTunnelMode[] = ['TCP', 'UDP', 'HYBRID'];
export const SPLIT_VPN_DEFAULT_GRACE_MIN = 5;
export const SPLIT_VPN_MIN_GRACE_MIN = 1;
export const SPLIT_VPN_MAX_GRACE_MIN = 120;

export interface SplitVpnForm {
  name: string;
  server: string;
  port: number | string;
  tunnel_mode: SplitVpnTunnelMode;
  username: string;
  /** Where credentials come from: encrypted in this app, or the SOPS secrets file. */
  cred_source: 'app' | 'sops';
  secret_ref: string;
  password: string;
  totp_secret: string;
  master_password: string;
  group_ids: string[];
  domainsText: string;
  cidrsText: string;
  use_pushed_routes: boolean;
  auto_connect: boolean;
  enabled: boolean;
  /** "always" holds the session; "presence" only while presence_macs are home. */
  connect_mode: SplitVpnConnectMode;
  presence_macs: string[];
  presence_grace_min: number | string;
  yield_to_device_tunnel: boolean;
}

/** Split a free-text list (newlines, commas or whitespace) into unique, trimmed entries. */
export function parseList(text: string): string[] {
  const out: string[] = [];
  for (const raw of (text || '').split(/[\s,;]+/)) {
    const v = raw.trim();
    if (v && !out.includes(v)) out.push(v);
  }
  return out;
}

/** Initial form state — blank for create, pre-filled (minus secrets) for edit. */
export function initialSplitVpnForm(vpn: SplitVpn | null): SplitVpnForm {
  return {
    name: vpn?.name || '',
    server: vpn?.server || '',
    port: vpn?.port || SPLIT_VPN_DEFAULT_PORT,
    tunnel_mode: vpn?.tunnel_mode || 'TCP',
    username: vpn?.username || '',
    cred_source: vpn?.secret_ref ? 'sops' : 'app',
    secret_ref: vpn?.secret_ref || '',
    password: '',
    totp_secret: '',
    master_password: '',
    group_ids: [...(vpn?.group_ids || [])],
    domainsText: (vpn?.domains || []).join('\n'),
    cidrsText: (vpn?.cidrs || []).join('\n'),
    use_pushed_routes: vpn ? vpn.use_pushed_routes !== false : true,
    auto_connect: vpn ? vpn.auto_connect !== false : true,
    enabled: vpn ? vpn.enabled !== false : true,
    connect_mode: vpn?.connect_mode === 'presence' ? 'presence' : 'always',
    presence_macs: (vpn?.presence_macs || []).map(m => m.toLowerCase()),
    presence_grace_min: vpn?.presence_grace_min || SPLIT_VPN_DEFAULT_GRACE_MIN,
    yield_to_device_tunnel: vpn ? vpn.yield_to_device_tunnel !== false : true,
  };
}

/** Grace minutes as an integer, or null when outside 1–120. */
export function parseGraceMinutes(value: number | string): number | null {
  const n = Number(value);
  if (!Number.isInteger(n) || n < SPLIT_VPN_MIN_GRACE_MIN || n > SPLIT_VPN_MAX_GRACE_MIN) return null;
  return n;
}

/** True when the form will store a secret (password or TOTP secret), which needs the master password. */
export function settingSecret(form: SplitVpnForm): boolean {
  if (form.cred_source === 'sops') return false;
  return !!form.password || !!form.totp_secret.trim();
}

/**
 * Build the POST/PUT body. The password / TOTP secret are only sent when typed
 * (on edit, an empty field means "unchanged"); the master password is only sent
 * alongside one of them.
 */
export function buildSplitVpnPayload(form: SplitVpnForm): Record<string, unknown> {
  const data: Record<string, unknown> = {
    name: form.name.trim(),
    server: form.server.trim(),
    port: Number(form.port) || SPLIT_VPN_DEFAULT_PORT,
    tunnel_mode: form.tunnel_mode || 'TCP',
    username: form.username.trim(),
    group_ids: [...form.group_ids],
    domains: parseList(form.domainsText),
    cidrs: parseList(form.cidrsText),
    use_pushed_routes: !!form.use_pushed_routes,
    auto_connect: !!form.auto_connect,
    enabled: !!form.enabled,
    connect_mode: form.connect_mode === 'presence' ? 'presence' : 'always',
  };
  if (data.connect_mode === 'presence') {
    data.presence_macs = [...new Set(form.presence_macs.map(m => m.toLowerCase()))];
    data.presence_grace_min = parseGraceMinutes(form.presence_grace_min) ?? SPLIT_VPN_DEFAULT_GRACE_MIN;
    data.yield_to_device_tunnel = !!form.yield_to_device_tunnel;
  }
  if (form.cred_source === 'sops') {
    data.secret_ref = form.secret_ref.trim();
    return data;
  }
  data.secret_ref = '';
  if (form.password) data.password = form.password;
  if (form.totp_secret.trim()) data.totp_secret = form.totp_secret.trim();
  if (settingSecret(form)) data.master_password = form.master_password;
  return data;
}

/** Groups that may carry a split VPN — only ones with internet access. */
export function splitVpnEligibleGroups(profiles: Profile[]): Profile[] {
  return profiles.filter(p => p.type === 'vpn' || p.type === 'no_vpn');
}

/** Unix seconds → ISO string (for timeAgo), or null. */
export function unixToIso(sec: number | null | undefined): string | null {
  if (!sec) return null;
  return new Date(sec * 1000).toISOString();
}

// ── Presence-based connect ────────────────────────────────────────────────

/** Friendly device name for a MAC: label, then hostname, then the MAC itself. */
export function deviceName(mac: string, devices: Device[]): string {
  const m = (mac || '').toLowerCase();
  const d = devices.find(x => (x.mac || '').toLowerCase() === m);
  return d?.label || d?.hostname || mac;
}

/** "A", "A and B", "A, B and C". */
function joinNames(names: string[]): string {
  if (names.length <= 1) return names[0] || '';
  return `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`;
}

export type SplitVpnAutoTone = 'on' | 'standby' | 'pending' | 'off';

export interface SplitVpnAutoStatus {
  text: string;
  tone: SplitVpnAutoTone;
}

/**
 * One-line explanation of the backend's auto-connect state, with device names
 * resolved. Returns null when the backend reports no auto_state.
 * `nowSec` (unix seconds) drives the "Releasing in N min" countdown.
 */
export function splitVpnAutoStatus(
  vpn: SplitVpn, devices: Device[], nowSec: number = Date.now() / 1000,
): SplitVpnAutoStatus | null {
  const a = vpn.auto_state;
  if (!a) return null;
  const macs = a.devices?.length ? a.devices : (vpn.presence_macs || []);
  const names = macs.map(m => deviceName(m, devices));
  const who = joinNames(names) || 'the devices';
  const plural = names.length !== 1;

  switch (a.state) {
    case 'connecting':
      return { text: 'Connecting…', tone: 'pending' };
    case 'paused':
      return { text: 'Paused — reconnects on next manual connect', tone: 'off' };
    case 'off':
      return { text: 'Auto-connect off', tone: 'off' };
    case 'releasing': {
      if (!a.release_at) return { text: `⏳ Releasing soon — ${who} left`, tone: 'pending' };
      const min = Math.max(1, Math.ceil((a.release_at - nowSec) / 60));
      return { text: `⏳ Releasing in ${min} min — ${who} left`, tone: 'pending' };
    }
    case 'standby': {
      if (a.code === 'own_tunnel') {
        const verb = plural ? 'are using their own VPN' : 'is using its own VPN';
        return { text: `⏸️ Standing by — ${who} ${verb}`, tone: 'standby' };
      }
      if (a.code === 'no_devices') return { text: '⏸️ Standing by — no presence devices chosen', tone: 'standby' };
      const released = a.since ? ` (released ${timeAgo(unixToIso(a.since)).toLowerCase()})` : '';
      return { text: `⏸️ Standing by — ${who} away${released}`, tone: 'standby' };
    }
    case 'connected':
      if (a.code === 'home') return { text: `🟢 Connected — ${who} at home`, tone: 'on' };
      break;
  }
  if (a.code === 'always' || vpn.connect_mode !== 'presence') {
    return { text: 'Always connected (auto-reconnect)', tone: 'on' };
  }
  return null;
}
