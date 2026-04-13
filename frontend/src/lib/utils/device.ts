/** Device-related utility functions and constants. */

import { parseUTC } from './format';
import type { Device } from './types';

export function isOnline(d: Device): boolean {
  // Use router's online status (source of truth) if available
  if (d.router_online !== undefined) return d.router_online;
  // Fallback to timestamp
  const t = parseUTC(d.last_seen);
  if (!t) return false;
  return (Date.now() - t.getTime()) / 1000 < 300;
}

export function isStale(d: Device): boolean {
  const t = parseUTC(d.last_seen);
  if (!t) return false;
  return (Date.now() - t.getTime()) / 1000 > 86400 * 30;
}

export function isRandomMac(mac: string): boolean {
  return !!mac && mac.length >= 2 && '26ae'.includes(mac[1].toLowerCase());
}

/**
 * GL.iNet router device class -> icon + label mapping.
 * These match the router dashboard's device type dropdown exactly.
 */
export const DEVICE_TYPES: Record<string, { icon: string; label: string }> = {
  computer:         { icon: '🖥️', label: 'Desktop' },
  phone:            { icon: '📱', label: 'Phone' },
  pad:              { icon: '📱', label: 'Tablet PC' },
  camera:           { icon: '📷', label: 'Camera' },
  watch:            { icon: '⌚', label: 'Wearable device' },
  laptop:           { icon: '💻', label: 'Laptop' },
  printer:          { icon: '🖨️', label: 'Printer' },
  sound:            { icon: '🔊', label: 'Sound' },
  television:       { icon: '📺', label: 'Television' },
  smartappliances:  { icon: '💡', label: 'Smart Appliances' },
  games:            { icon: '🎮', label: 'Games' },
  gateway:          { icon: '🌐', label: 'Gateway' },
  nas:              { icon: '💾', label: 'NAS' },
  server:           { icon: '🖥️', label: 'Server' },
  switch:           { icon: '🔌', label: 'Switch' },
};

export function deviceIcon(d: Device | string): string {
  const cls = typeof d === 'object' ? d.device_class : '';
  if (cls && DEVICE_TYPES[cls]) return DEVICE_TYPES[cls].icon;
  // Fallback: guess from hostname
  const h = (typeof d === 'string' ? d : d?.display_name || '').toLowerCase();
  if (/phone|pixel|iphone|android|galaxy/.test(h)) return '📱';
  if (/tv|roku|fire|chromecast/.test(h)) return '📺';
  if (/printer|laser|hp/.test(h)) return '🖨️';
  if (/ipad|tab|surface/.test(h)) return '📱';
  if (/nas|synology|qnap/.test(h)) return '💾';
  return '💻';
}

export function deviceTypeLabel(cls: string): string {
  if (cls && DEVICE_TYPES[cls]) return DEVICE_TYPES[cls].label;
  return '';
}
