/** Device-related utility functions and constants. */

import { parseUTC } from './format.js';

export function isOnline(d) {
  // Use router's online status (source of truth) if available
  if (d.router_online !== undefined) return d.router_online;
  // Fallback to timestamp
  const t = parseUTC(d.last_seen);
  if (!t) return false;
  return (Date.now() - t.getTime()) / 1000 < 300;
}

export function isStale(d) {
  // Stage 8: last_seen is no longer tracked. The "stale" concept (>30d
  // since last seen) is not meaningful anymore — gl-clients shows
  // currently-known devices and that's the canonical present-tense view.
  const t = parseUTC(d.last_seen);
  if (!t) return false;
  return (Date.now() - t.getTime()) / 1000 > 86400 * 30;
}

export function isRandomMac(mac) {
  return mac && mac.length >= 2 && '26ae'.includes(mac[1].toLowerCase());
}

/**
 * GL.iNet router device class -> icon + label mapping.
 * These match the router dashboard's device type dropdown exactly.
 * The UCI config stores the `class` field (e.g. 'computer', 'phone', 'pad').
 */
export const DEVICE_TYPES = {
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

export function deviceIcon(d) {
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

export function deviceTypeLabel(cls) {
  if (cls && DEVICE_TYPES[cls]) return DEVICE_TYPES[cls].label;
  return '';
}
