/** Profile status derivation utilities. Extracted from GroupCard. */

import type { Profile } from '../types';

export type ConnState = 'connected' | 'transitioning' | 'disconnected' | 'no_vpn' | 'no_internet';

export function derivedConnState(p: Profile): ConnState {
  if (p.type !== 'vpn') return p.type as ConnState;
  const h = p.health;
  if (h === 'green' || h === 'amber') return 'connected';
  if (h === 'connecting' || h === 'loading') return 'transitioning';
  return 'disconnected';
}

export function getStatusBorderColor(p: Profile): string {
  if (p.type !== 'vpn') return '#636e72';
  const cs = derivedConnState(p);
  if (cs === 'connected') return '#2ecc71';
  if (cs === 'transitioning') return '#f1c40f';
  return '#636e72';
}

export function getStatusClass(p: Profile): string {
  if (p.type === 'vpn') {
    const cs = derivedConnState(p);
    if (cs === 'connected') return 'connected';
    if (cs === 'transitioning') return 'reconnecting';
    return 'disconnected';
  }
  if (p.type === 'no_vpn') return 'novpn';
  return 'nointernet';
}

export function getStatusLabel(p: Profile): string {
  if (p.type === 'vpn') {
    const h = p.health;
    if (h === 'green' || h === 'amber') return 'CONNECTED';
    if (h === 'connecting') return 'CONNECTING...';
    if (h === 'loading') return 'CHECKING...';
    return 'NOT CONNECTED';
  }
  if (p.type === 'no_vpn') return 'NO VPN';
  return 'NO INTERNET';
}
