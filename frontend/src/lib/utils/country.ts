/** Country code, flag, and name utility functions. */

import type { ServerInfo } from './types';

const FLAG_OVERRIDES: Record<string, string> = { 'UK': 'GB' };

export function countryFlag(code: string): string {
  if (!code || code.length !== 2) return '';
  const upper = FLAG_OVERRIDES[code.toUpperCase()] || code.toUpperCase();
  const emoji = String.fromCodePoint(
    ...upper.split('').map(c => 0x1F1E6 + c.charCodeAt(0) - 65)
  );
  return emoji;
}

export function countryFlagUrl(code: string): string {
  if (!code || code.length !== 2) return '';
  const lower = (FLAG_OVERRIDES[code.toUpperCase()] || code).toLowerCase();
  return `https://flagcdn.com/20x15/${lower}.png`;
}

export function countryName(code: string, servers: ServerInfo[]): string {
  if (!code || !servers) return code || '';
  const s = servers.find(s => s.country_code === code || s.entry_country_code === code);
  return s ? s.country : code;
}
