import { describe, it, expect } from 'vitest';
import { derivedConnState, getStatusBorderColor, getStatusClass, getStatusLabel } from '../lib/utils/profile';

describe('derivedConnState', () => {
  it('returns no_vpn for no_vpn type', () => {
    expect(derivedConnState({ type: 'no_vpn' })).toBe('no_vpn');
  });

  it('returns no_internet for no_internet type', () => {
    expect(derivedConnState({ type: 'no_internet' })).toBe('no_internet');
  });

  it('returns connected for green health', () => {
    expect(derivedConnState({ type: 'vpn', health: 'green' })).toBe('connected');
  });

  it('returns connected for amber health', () => {
    expect(derivedConnState({ type: 'vpn', health: 'amber' })).toBe('connected');
  });

  it('returns transitioning for connecting health', () => {
    expect(derivedConnState({ type: 'vpn', health: 'connecting' })).toBe('transitioning');
  });

  it('returns transitioning for loading health', () => {
    expect(derivedConnState({ type: 'vpn', health: 'loading' })).toBe('transitioning');
  });

  it('returns disconnected for red health', () => {
    expect(derivedConnState({ type: 'vpn', health: 'red' })).toBe('disconnected');
  });

  it('returns disconnected for undefined health', () => {
    expect(derivedConnState({ type: 'vpn' })).toBe('disconnected');
  });
});

describe('getStatusBorderColor', () => {
  it('returns green for connected VPN', () => {
    expect(getStatusBorderColor({ type: 'vpn', health: 'green' })).toBe('#2ecc71');
  });

  it('returns yellow for transitioning VPN', () => {
    expect(getStatusBorderColor({ type: 'vpn', health: 'connecting' })).toBe('#f1c40f');
  });

  it('returns gray for disconnected VPN', () => {
    expect(getStatusBorderColor({ type: 'vpn', health: 'red' })).toBe('#636e72');
  });

  it('returns gray for non-VPN types', () => {
    expect(getStatusBorderColor({ type: 'no_vpn' })).toBe('#636e72');
    expect(getStatusBorderColor({ type: 'no_internet' })).toBe('#636e72');
  });
});

describe('getStatusClass', () => {
  it('returns connected for green VPN', () => {
    expect(getStatusClass({ type: 'vpn', health: 'green' })).toBe('connected');
  });

  it('returns reconnecting for connecting VPN', () => {
    expect(getStatusClass({ type: 'vpn', health: 'connecting' })).toBe('reconnecting');
  });

  it('returns disconnected for red VPN', () => {
    expect(getStatusClass({ type: 'vpn', health: 'red' })).toBe('disconnected');
  });

  it('returns novpn for no_vpn type', () => {
    expect(getStatusClass({ type: 'no_vpn' })).toBe('novpn');
  });

  it('returns nointernet for no_internet type', () => {
    expect(getStatusClass({ type: 'no_internet' })).toBe('nointernet');
  });
});

describe('getStatusLabel', () => {
  it('returns CONNECTED for green', () => {
    expect(getStatusLabel({ type: 'vpn', health: 'green' })).toBe('CONNECTED');
  });

  it('returns CONNECTED for amber', () => {
    expect(getStatusLabel({ type: 'vpn', health: 'amber' })).toBe('CONNECTED');
  });

  it('returns CONNECTING... for connecting', () => {
    expect(getStatusLabel({ type: 'vpn', health: 'connecting' })).toBe('CONNECTING...');
  });

  it('returns CHECKING... for loading', () => {
    expect(getStatusLabel({ type: 'vpn', health: 'loading' })).toBe('CHECKING...');
  });

  it('returns NOT CONNECTED for red', () => {
    expect(getStatusLabel({ type: 'vpn', health: 'red' })).toBe('NOT CONNECTED');
  });

  it('returns NO VPN for no_vpn', () => {
    expect(getStatusLabel({ type: 'no_vpn' })).toBe('NO VPN');
  });

  it('returns NO INTERNET for no_internet', () => {
    expect(getStatusLabel({ type: 'no_internet' })).toBe('NO INTERNET');
  });
});
