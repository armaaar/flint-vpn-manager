import { describe, it, expect } from 'vitest';
import { hexToHSL, buildGradient } from '../lib/utils/color';

describe('hexToHSL', () => {
  it('converts pure red', () => {
    const [h, s, l] = hexToHSL('#ff0000');
    expect(h).toBe(0);
    expect(s).toBe(100);
    expect(l).toBe(50);
  });

  it('converts pure green', () => {
    const [h, s, l] = hexToHSL('#00ff00');
    expect(h).toBe(120);
    expect(s).toBe(100);
    expect(l).toBe(50);
  });

  it('converts pure blue', () => {
    const [h, s, l] = hexToHSL('#0000ff');
    expect(h).toBe(240);
    expect(s).toBe(100);
    expect(l).toBe(50);
  });

  it('converts black', () => {
    const [h, s, l] = hexToHSL('#000000');
    expect(h).toBe(0);
    expect(s).toBe(0);
    expect(l).toBe(0);
  });

  it('converts white', () => {
    const [h, s, l] = hexToHSL('#ffffff');
    expect(h).toBe(0);
    expect(s).toBe(0);
    expect(l).toBe(100);
  });

  it('converts mid gray', () => {
    const [h, s, l] = hexToHSL('#808080');
    expect(h).toBe(0);
    expect(s).toBe(0);
    expect(l).toBe(50);
  });

  it('handles hex without #', () => {
    const [h, s, l] = hexToHSL('ff0000');
    expect(h).toBe(0);
    expect(s).toBe(100);
  });

  it('converts a typical profile color', () => {
    const [h, s, l] = hexToHSL('#3498db');
    // Cerulean blue: ~204deg
    expect(h).toBeGreaterThan(200);
    expect(h).toBeLessThan(210);
    expect(s).toBeGreaterThan(50);
  });
});

describe('buildGradient', () => {
  const profile = { color: '#3498db' };

  it('returns connected gradient', () => {
    const g = buildGradient(profile, 'connected');
    expect(g).toMatch(/^linear-gradient\(135deg/);
    expect(g).toContain('50%');
    expect(g).toContain('100%)');
  });

  it('returns transitioning gradient', () => {
    const g = buildGradient(profile, 'transitioning');
    expect(g).toMatch(/^linear-gradient/);
  });

  it('returns no_vpn gradient', () => {
    const g = buildGradient(profile, 'no_vpn');
    expect(g).toMatch(/^linear-gradient/);
  });

  it('returns no_internet gradient (desaturated)', () => {
    const g = buildGradient(profile, 'no_internet');
    expect(g).toMatch(/^linear-gradient/);
  });

  it('returns disconnected gradient (fallback)', () => {
    const g = buildGradient(profile, 'disconnected');
    expect(g).toMatch(/^linear-gradient/);
  });

  it('uses default color when profile.color is null', () => {
    const g = buildGradient({ color: null }, 'connected');
    expect(g).toMatch(/^linear-gradient/);
  });

  it('connected is more saturated than disconnected', () => {
    const connected = buildGradient(profile, 'connected');
    const disconnected = buildGradient(profile, 'disconnected');
    // Connected gradient reaches 50% lightness, disconnected caps at 30%
    expect(connected).toContain('50%)');
    expect(disconnected).toContain('30%)');
  });
});
