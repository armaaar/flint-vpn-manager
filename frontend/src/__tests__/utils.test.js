import { describe, it, expect } from 'vitest';
import {
  timeAgo, isOnline, isStale, isRandomMac,
  formatBytes, formatSpeed, deviceIcon, loadBarColor,
  DEVICE_TYPES, deviceTypeLabel, countryFlag, countryName,
} from '../lib/utils/index';

describe('timeAgo', () => {
  it('returns "never" for null', () => {
    expect(timeAgo(null)).toBe('never');
  });

  it('returns "Just now" for recent timestamp', () => {
    const now = new Date().toISOString();
    expect(timeAgo(now)).toBe('Just now');
  });

  it('returns minutes ago', () => {
    const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    expect(timeAgo(fiveMinAgo)).toBe('5m ago');
  });

  it('returns hours ago', () => {
    const twoHoursAgo = new Date(Date.now() - 2 * 3600 * 1000).toISOString();
    expect(timeAgo(twoHoursAgo)).toBe('2h ago');
  });

  it('returns days ago', () => {
    const threeDaysAgo = new Date(Date.now() - 3 * 86400 * 1000).toISOString();
    expect(timeAgo(threeDaysAgo)).toBe('3d ago');
  });
});

describe('isOnline', () => {
  it('returns true for device seen within 5 minutes', () => {
    const d = { last_seen: new Date().toISOString() };
    expect(isOnline(d)).toBe(true);
  });

  it('returns false for device seen 10 minutes ago', () => {
    const d = { last_seen: new Date(Date.now() - 10 * 60 * 1000).toISOString() };
    expect(isOnline(d)).toBe(false);
  });

  it('returns false for null last_seen', () => {
    expect(isOnline({ last_seen: null })).toBe(false);
  });
});

describe('isStale', () => {
  it('returns false for recently seen device', () => {
    const d = { last_seen: new Date().toISOString() };
    expect(isStale(d)).toBe(false);
  });

  it('returns true for device not seen in 31 days', () => {
    const d = { last_seen: new Date(Date.now() - 31 * 86400 * 1000).toISOString() };
    expect(isStale(d)).toBe(true);
  });

  it('returns false for null last_seen (Stage 8: not tracked)', () => {
    expect(isStale({ last_seen: null })).toBe(false);
  });
});

describe('isRandomMac', () => {
  it('detects randomized MACs (2nd char is 2, 6, a, or e)', () => {
    expect(isRandomMac('42:00:00:00:00:01')).toBe(true);  // '2'
    expect(isRandomMac('d6:ab:cd:ef:12:34')).toBe(true);  // '6'
    expect(isRandomMac('fa:bb:cc:dd:ee:ff')).toBe(true);  // 'a'
    expect(isRandomMac('de:ad:be:ef:12:34')).toBe(true);  // 'e'
  });

  it('returns false for non-random MACs', () => {
    expect(isRandomMac('a4:00:00:00:00:01')).toBe(false); // '4'
    expect(isRandomMac('00:11:22:33:44:55')).toBe(false);  // '0'
    expect(isRandomMac('d8:ab:cd:ef:12:34')).toBe(false);  // '8'
  });

  it('handles edge cases', () => {
    expect(isRandomMac(null)).toBeFalsy();
    expect(isRandomMac('')).toBeFalsy();
    expect(isRandomMac('a')).toBeFalsy();
  });
});

describe('formatBytes', () => {
  it('formats zero', () => {
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(null)).toBe('0 B');
  });

  it('formats bytes', () => {
    expect(formatBytes(500)).toBe('500 B');
  });

  it('formats kilobytes', () => {
    expect(formatBytes(2048)).toBe('2.0 KB');
  });

  it('formats megabytes', () => {
    expect(formatBytes(5242880)).toBe('5.0 MB');
  });

  it('formats gigabytes', () => {
    expect(formatBytes(2147483648)).toBe('2.0 GB');
  });
});

describe('formatSpeed', () => {
  it('returns empty for zero', () => {
    expect(formatSpeed(0)).toBe('');
    expect(formatSpeed(null)).toBe('');
  });

  it('formats bytes/s', () => {
    expect(formatSpeed(500)).toBe('500 B/s');
  });

  it('formats KB/s', () => {
    expect(formatSpeed(15360)).toBe('15 KB/s');
  });

  it('formats MB/s', () => {
    expect(formatSpeed(5242880)).toBe('5.0 MB/s');
  });
});

describe('DEVICE_TYPES', () => {
  it('has all 15 GL.iNet router device types', () => {
    const types = ['computer','phone','pad','camera','watch','laptop','printer',
                   'sound','television','smartappliances','games','gateway','nas','server','switch'];
    types.forEach(t => {
      expect(DEVICE_TYPES[t]).toBeDefined();
      expect(DEVICE_TYPES[t].icon).toBeTruthy();
      expect(DEVICE_TYPES[t].label).toBeTruthy();
    });
  });
});

describe('deviceIcon', () => {
  it('returns correct icon for router device classes', () => {
    expect(deviceIcon({ device_class: 'phone' })).toBe('📱');
    expect(deviceIcon({ device_class: 'computer' })).toBe('🖥️');
    expect(deviceIcon({ device_class: 'laptop' })).toBe('💻');
    expect(deviceIcon({ device_class: 'television' })).toBe('📺');
    expect(deviceIcon({ device_class: 'printer' })).toBe('🖨️');
    expect(deviceIcon({ device_class: 'games' })).toBe('🎮');
    expect(deviceIcon({ device_class: 'nas' })).toBe('💾');
  });

  it('falls back to hostname matching', () => {
    expect(deviceIcon({ display_name: 'Samsung-TV', device_class: '' })).toBe('📺');
    expect(deviceIcon({ display_name: 'iPhone-12', device_class: '' })).toBe('📱');
  });

  it('defaults to computer', () => {
    expect(deviceIcon({ display_name: 'unknown', device_class: '' })).toBe('💻');
    expect(deviceIcon('something')).toBe('💻');
  });
});

describe('deviceTypeLabel', () => {
  it('returns label for known types', () => {
    expect(deviceTypeLabel('computer')).toBe('Desktop');
    expect(deviceTypeLabel('phone')).toBe('Phone');
    expect(deviceTypeLabel('pad')).toBe('Tablet PC');
    expect(deviceTypeLabel('television')).toBe('Television');
  });

  it('returns empty for unknown types', () => {
    expect(deviceTypeLabel('')).toBe('');
    expect(deviceTypeLabel('unknown')).toBe('');
  });
});

describe('countryFlag', () => {
  it('converts 2-letter codes to flag emoji', () => {
    expect(countryFlag('US')).toBe('🇺🇸');
    expect(countryFlag('GB')).toBe('🇬🇧');
    expect(countryFlag('DE')).toBe('🇩🇪');
    expect(countryFlag('JP')).toBe('🇯🇵');
  });

  it('handles lowercase', () => {
    expect(countryFlag('us')).toBe('🇺🇸');
  });

  it('returns empty for invalid input', () => {
    expect(countryFlag('')).toBe('');
    expect(countryFlag(null)).toBe('');
    expect(countryFlag('ABC')).toBe('');
  });

  // ProtonVPN uses "UK" not "GB" — we remap to GB for proper flag
  it('handles UK code by mapping to GB', () => {
    expect(countryFlag('UK')).toBe('🇬🇧');
    expect(countryFlag('GB')).toBe('🇬🇧');
  });
});

describe('loadBarColor', () => {
  it('returns green for low load', () => {
    expect(loadBarColor(20)).toBe('var(--green)');
  });

  it('returns amber for medium load', () => {
    expect(loadBarColor(55)).toBe('var(--amber)');
  });

  it('returns red for high load', () => {
    expect(loadBarColor(85)).toBe('var(--red)');
  });
});

// ── New tests for features added after initial release ──

describe('isOnline - router_online', () => {
  it('uses router_online when available (true)', () => {
    expect(isOnline({ router_online: true, last_seen: null })).toBe(true);
  });

  it('uses router_online when available (false)', () => {
    expect(isOnline({ router_online: false, last_seen: new Date().toISOString() })).toBe(false);
  });

  it('falls back to timestamp when router_online undefined', () => {
    const recent = new Date().toISOString();
    expect(isOnline({ last_seen: recent })).toBe(true);
  });
});

describe('timeAgo - UTC handling', () => {
  it('handles timestamp without Z suffix as UTC', () => {
    // A UTC timestamp without Z should still be parsed correctly
    const now = new Date();
    const utcStr = now.toISOString().replace('Z', '');
    const result = timeAgo(utcStr);
    expect(result).toBe('Just now');
  });

  it('handles timestamp with Z suffix', () => {
    const now = new Date().toISOString();
    expect(timeAgo(now)).toBe('Just now');
  });
});

describe('countryName', () => {
  const servers = [
    { country_code: 'CH', entry_country_code: 'CH', country: 'Switzerland' },
    { country_code: 'DE', entry_country_code: 'CH', country: 'Germany' },
  ];

  it('finds country name by code', () => {
    expect(countryName('CH', servers)).toBe('Switzerland');
    expect(countryName('DE', servers)).toBe('Germany');
  });

  it('finds by entry_country_code', () => {
    expect(countryName('CH', servers)).toBe('Switzerland');
  });

  it('returns code for unknown', () => {
    expect(countryName('XX', servers)).toBe('XX');
  });

  it('handles null/empty', () => {
    expect(countryName(null, servers)).toBe('');
    expect(countryName('', servers)).toBe('');
  });
});

describe('deviceIcon - all router types', () => {
  it('maps all DEVICE_TYPES correctly', () => {
    for (const [cls, { icon }] of Object.entries(DEVICE_TYPES)) {
      expect(deviceIcon({ device_class: cls })).toBe(icon);
    }
  });

  it('handles NAS from hostname', () => {
    expect(deviceIcon({ display_name: 'synology-nas', device_class: '' })).toBe('💾');
  });
});
