import { test, expect } from '@playwright/test';
import { unlockApp, uniqueName, API_BASE, MASTER_PASSWORD } from './helpers';

let vpnProfileId: string;

test.describe('VPN Group Card Details', () => {
  test.beforeAll(async ({ request }) => {
    // Ensure unlocked
    const status = await request.get(`${API_BASE}/api/status`);
    const data = await status.json();
    if (data.status === 'locked') {
      await request.post(`${API_BASE}/api/unlock`, {
        data: { master_password: MASTER_PASSWORD },
      });
    }

    const serversRes = await request.get(`${API_BASE}/api/profiles/none/servers`);
    const servers = await serversRes.json();
    const serverId = servers[0]?.id;

    const res = await request.post(`${API_BASE}/api/profiles`, {
      data: {
        name: uniqueName('E2E-Card'),
        type: 'vpn',
        vpn_protocol: 'wireguard',
        server_id: serverId,
        color: '#9b59b6',
        icon: '🟣',
        kill_switch: true,
      },
    });
    const profile = await res.json();
    vpnProfileId = profile.id;
  });

  test.afterAll(async ({ request }) => {
    if (vpnProfileId) {
      await request.delete(`${API_BASE}/api/profiles/${vpnProfileId}`);
    }
  });

  test.beforeEach(async ({ page }) => {
    await unlockApp(page);
    await expect(page.locator('.loading-groups')).not.toBeVisible({ timeout: 15_000 });
    await expect(page.locator('.group-card').first()).toBeVisible({ timeout: 10_000 });
  });

  test('VPN group card shows status label', async ({ page }) => {
    const card = page.locator('.group-card').first();
    await expect(card.locator('.group-status-label')).toBeVisible();
    const statusText = await card.locator('.group-status-label').textContent();
    expect(statusText?.toUpperCase()).toMatch(/NOT CONNECTED|CONNECTED|CONNECTING/);
  });

  test('VPN group card shows connection type badge', async ({ page }) => {
    const card = page.locator('.group-card').first();
    await expect(card.locator('.conn-type')).toBeVisible();
    const connType = await card.locator('.conn-type').textContent();
    expect(connType?.trim()).toMatch(/WG|OVPN|Stealth|Direct|LAN Only/);
  });

  test('VPN group card shows server name', async ({ page }) => {
    const card = page.locator('.group-card').first();
    await expect(card.locator('.group-server-name')).toBeVisible();
  });

  test('VPN group card shows connect button', async ({ page }) => {
    const card = page.locator('.group-card').first();
    await expect(card.locator('.btn-connect')).toBeVisible();
    await expect(card.locator('.btn-connect')).toContainText('Connect');
  });

  test('VPN options toggle expands and collapses', async ({ page }) => {
    const card = page.locator('.group-card').first();
    const toggle = card.locator('.vpn-options-toggle');
    await expect(toggle).toBeVisible();

    await toggle.click();
    await expect(card.locator('.vpn-options')).toBeVisible();
    await expect(card.locator('.opt-row').first()).toBeVisible();

    await toggle.click();
    await expect(card.locator('.vpn-options')).not.toBeVisible();
  });

  test('expanded VPN options shows kill switch and netshield', async ({ page }) => {
    const card = page.locator('.group-card').first();
    await card.locator('.vpn-options-toggle').click();
    await expect(card.locator('.vpn-options')).toBeVisible();

    const optText = await card.locator('.vpn-options').textContent();
    expect(optText).toContain('Kill Switch');
    expect(optText).toContain('NetShield');
  });

  test('VPN options toggle shows KS pill in summary', async ({ page }) => {
    const card = page.locator('.group-card').first();
    await expect(card.locator('.opt-summary .opt-pill')).toBeVisible();
  });

  test('device count badge shows on group card', async ({ page }) => {
    const card = page.locator('.group-card').first();
    await expect(card.locator('.device-count-badge')).toBeVisible();
    const badge = await card.locator('.device-count-badge').textContent();
    expect(badge).toMatch(/\d+\/\d+/);
  });

  test('group card shows "Drop devices here" when empty', async ({ page }) => {
    const card = page.locator('.group-card').first();
    await expect(card.locator('.no-devices')).toBeVisible();
    await expect(card.locator('.no-devices')).toContainText('Drop devices here');
  });

  test('server change button is visible', async ({ page }) => {
    const card = page.locator('.group-card').first();
    await expect(card.locator('.group-server-menu')).toBeVisible();
  });
});
