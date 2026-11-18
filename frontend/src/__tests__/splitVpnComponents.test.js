import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/svelte';

vi.mock('../lib/api', () => ({
  api: {
    connectSplitVpn: vi.fn(),
    getSplitVpnLog: vi.fn(),
    createSplitVpn: vi.fn(),
    updateSplitVpn: vi.fn(),
  },
}));
import { api } from '../lib/api';
import SplitVpnConnectModal from '../lib/components/splitvpn/SplitVpnConnectModal.svelte';
import SplitVpnModal from '../lib/components/splitvpn/SplitVpnModal.svelte';

const VPN = {
  id: 'sv_1', type: 'barracuda', slot: 0, name: 'Work', server: 'vpn.corp.com', port: 691,
  tunnel_mode: 'TCP', username: 'alice', group_ids: ['g1'], domains: ['corp.com'], cidrs: [],
  use_pushed_routes: true, auto_connect: true, enabled: true,
  pushed_routes: ['10.1.0.0/16'], pushed_dns: ['10.1.0.53'],
  has_password: true, has_totp: true,
};

const PROFILES = [
  { id: 'g1', type: 'vpn', name: 'Laptops', icon: '💻', color: '#336699' },
  { id: 'g2', type: 'no_internet', name: 'IoT', icon: '🔌', color: '#663399' },
];

beforeEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe('SplitVpnConnectModal', () => {
  it('connects automatically with an empty body when not in manual mode', async () => {
    api.connectSplitVpn.mockResolvedValue({ connected: true, state: 'CONNECTED', ip: '10.9.0.2' });
    const onConnected = vi.fn();
    render(SplitVpnConnectModal, { props: { vpn: VPN }, events: { connected: onConnected } });
    await waitFor(() => expect(onConnected).toHaveBeenCalled());
    expect(api.connectSplitVpn).toHaveBeenCalledWith('sv_1');
  });

  it('manual mode autofocuses the code field and submits the OTP on Enter', async () => {
    api.connectSplitVpn.mockResolvedValue({ connected: true, state: 'CONNECTED' });
    const onConnected = vi.fn();
    render(SplitVpnConnectModal, { props: { vpn: VPN, manualCode: true }, events: { connected: onConnected } });
    const input = screen.getByLabelText('One-time code');
    expect(document.activeElement).toBe(input);
    expect(api.connectSplitVpn).not.toHaveBeenCalled();
    await fireEvent.input(input, { target: { value: '123 456' } });
    await fireEvent.submit(input.closest('form'));
    await waitFor(() => expect(onConnected).toHaveBeenCalled());
    expect(api.connectSplitVpn).toHaveBeenCalledWith('sv_1', '123456');
  });

  it('shows the error and log tail when the connection fails', async () => {
    api.connectSplitVpn.mockResolvedValue({ connected: false, state: 'FAILED', error: 'Auth rejected', log: 'line1\nline2' });
    render(SplitVpnConnectModal, { props: { vpn: VPN } });
    expect((await screen.findByRole('alert')).textContent).toContain('Auth rejected');
    expect(screen.getByText('Client log')).toBeTruthy();
    expect(screen.getByText(/line1/)).toBeTruthy();
    // Offers the manual-code fallback
    await fireEvent.click(screen.getByText('Connect with a code…'));
    expect(screen.getByLabelText('One-time code')).toBeTruthy();
  });
});

describe('SplitVpnModal', () => {
  it('on edit, omits password/totp_secret/master_password when unchanged', async () => {
    api.updateSplitVpn.mockResolvedValue(VPN);
    const onSaved = vi.fn();
    render(SplitVpnModal, { props: { vpn: VPN, profiles: PROFILES }, events: { saved: onSaved } });
    expect(screen.queryByLabelText('Master password')).toBeNull();
    expect(screen.getByLabelText('Password').getAttribute('placeholder')).toBe('unchanged');
    expect(screen.getByLabelText('TOTP secret').getAttribute('placeholder')).toBe('unchanged');
    await fireEvent.click(screen.getByText('Save Changes'));
    await waitFor(() => expect(onSaved).toHaveBeenCalled());
    const [id, body] = api.updateSplitVpn.mock.calls[0];
    expect(id).toBe('sv_1');
    expect(body).not.toHaveProperty('password');
    expect(body).not.toHaveProperty('totp_secret');
    expect(body).not.toHaveProperty('master_password');
    expect(body.group_ids).toEqual(['g1']);
  });

  it('requires the master password once a new password is typed', async () => {
    api.updateSplitVpn.mockResolvedValue(VPN);
    render(SplitVpnModal, { props: { vpn: VPN, profiles: PROFILES } });
    await fireEvent.input(screen.getByLabelText('Password'), { target: { value: 'newpass' } });
    const master = screen.getByLabelText('Master password');
    const save = screen.getByText('Save Changes');
    expect(save.disabled).toBe(true);
    await fireEvent.input(master, { target: { value: 'mp' } });
    expect(save.disabled).toBe(false);
    await fireEvent.click(save);
    await waitFor(() => expect(api.updateSplitVpn).toHaveBeenCalled());
    const body = api.updateSplitVpn.mock.calls[0][1];
    expect(body.password).toBe('newpass');
    expect(body.master_password).toBe('mp');
  });

  it('only offers groups with internet access', () => {
    render(SplitVpnModal, { props: { vpn: null, profiles: PROFILES } });
    expect(screen.getByText('Laptops')).toBeTruthy();
    expect(screen.queryByText('IoT')).toBeNull();
  });

  it('shows the backend error inline and keeps the form open', async () => {
    api.updateSplitVpn.mockRejectedValue(new Error('Wrong master password'));
    const onSaved = vi.fn();
    render(SplitVpnModal, { props: { vpn: VPN, profiles: PROFILES }, events: { saved: onSaved } });
    await fireEvent.click(screen.getByText('Save Changes'));
    expect((await screen.findByRole('alert')).textContent).toContain('Wrong master password');
    expect(onSaved).not.toHaveBeenCalled();
  });
});

describe('SplitVpnModal presence settings', () => {
  const DEVICES = [
    { mac: 'aa:bb:cc:dd:ee:ff', label: 'Work laptop', hostname: 'wl' },
    { mac: '11:22:33:44:55:66', label: '', hostname: 'pixel' },
  ];

  it('hides presence fields in always mode and sends connect_mode', async () => {
    api.updateSplitVpn.mockResolvedValue(VPN);
    render(SplitVpnModal, { props: { vpn: VPN, profiles: PROFILES, devices: DEVICES } });
    expect(screen.getByLabelText('Always').checked).toBe(true);
    expect(screen.queryByLabelText('Release after')).toBeNull();
    await fireEvent.click(screen.getByText('Save Changes'));
    await waitFor(() => expect(api.updateSplitVpn).toHaveBeenCalled());
    const body = api.updateSplitVpn.mock.calls[0][1];
    expect(body.connect_mode).toBe('always');
    expect(body).not.toHaveProperty('presence_macs');
  });

  it('picks presence devices and sends them', async () => {
    api.updateSplitVpn.mockResolvedValue(VPN);
    render(SplitVpnModal, { props: { vpn: VPN, profiles: PROFILES, devices: DEVICES } });
    await fireEvent.click(screen.getByLabelText('Only while these devices are home'));
    const save = screen.getByText('Save Changes');
    expect(save.disabled).toBe(true); // no device picked yet
    await fireEvent.click(screen.getByText('Work laptop'));
    expect(save.disabled).toBe(false);
    await fireEvent.input(screen.getByLabelText('Release after'), { target: { value: '10' } });
    await fireEvent.click(save);
    await waitFor(() => expect(api.updateSplitVpn).toHaveBeenCalled());
    expect(api.updateSplitVpn.mock.calls[0][1]).toMatchObject({
      connect_mode: 'presence', presence_macs: ['aa:bb:cc:dd:ee:ff'], presence_grace_min: 10, yield_to_device_tunnel: true,
    });
  });
});
