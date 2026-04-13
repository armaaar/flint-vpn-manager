/** Color conversion and gradient utilities. Extracted from GroupCard. */

import type { Profile } from '../types';

export function hexToHSL(hex: string): [number, number, number] {
  hex = hex.replace('#', '');
  const r = parseInt(hex.substring(0, 2), 16) / 255;
  const g = parseInt(hex.substring(2, 4), 16) / 255;
  const b = parseInt(hex.substring(4, 6), 16) / 255;
  const max = Math.max(r, g, b), min = Math.min(r, g, b);
  let h = 0, s = 0;
  const l = (max + min) / 2;
  if (max !== min) {
    const d = max - min;
    s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
    if (max === r) h = ((g - b) / d + (g < b ? 6 : 0)) / 6;
    else if (max === g) h = ((b - r) / d + 2) / 6;
    else h = ((r - g) / d + 4) / 6;
  }
  return [Math.round(h * 360), Math.round(s * 100), Math.round(l * 100)];
}

export function buildGradient(p: Profile, connState: string): string {
  const [h, s] = hexToHSL(p.color || '#00aaff');
  if (connState === 'connected') return `linear-gradient(135deg, hsl(${h},${Math.min(s,50)}%,18%) 0%, hsl(${h},${Math.min(s+10,85)}%,35%) 50%, hsl(${h},${Math.min(s+15,90)}%,50%) 100%)`;
  if (connState === 'transitioning') return `linear-gradient(135deg, hsl(${h},${Math.min(s,30)}%,20%) 0%, hsl(${h},${Math.min(s,50)}%,32%) 50%, hsl(${h},${Math.min(s,55)}%,42%) 100%)`;
  if (connState === 'no_vpn') return `linear-gradient(135deg, hsl(${h},${Math.min(s,40)}%,16%) 0%, hsl(${h},${Math.min(s,60)}%,30%) 50%, hsl(${h},${Math.min(s+10,70)}%,45%) 100%)`;
  if (connState === 'no_internet') return `linear-gradient(135deg, hsl(${h},${Math.max(s-30,8)}%,14%) 0%, hsl(${h},${Math.max(s-20,12)}%,22%) 50%, hsl(${h},${Math.max(s-10,15)}%,30%) 100%)`;
  // disconnected — desaturated
  return `linear-gradient(135deg, hsl(${h},${Math.max(s-30,5)}%,14%) 0%, hsl(${h},${Math.max(s-20,8)}%,22%) 50%, hsl(${h},${Math.max(s-10,12)}%,30%) 100%)`;
}
