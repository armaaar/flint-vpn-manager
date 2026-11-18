/** Split VPN form helpers (pure — unit-tested in __tests__/splitVpn.test.js). */

import type { Profile, SplitVpn, SplitVpnTunnelMode } from '../types';

export const SPLIT_VPN_DEFAULT_PORT = 691;
export const SPLIT_VPN_TUNNEL_MODES: SplitVpnTunnelMode[] = ['TCP', 'UDP', 'HYBRID'];

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
  };
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
  };
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
