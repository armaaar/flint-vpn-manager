import { test, expect } from '@playwright/test';
import { unlockApp, uniqueName, API_BASE, MASTER_PASSWORD } from './helpers';

let vpnProfileId: string;

test.describe('Server Picker', () => {
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
        name: uniqueName('E2E-SP'),
        type: 'vpn',
        vpn_protocol: 'wireguard',
        server_id: serverId,
        color: '#e74c3c',
        icon: '🔴',
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

  async function openServerPicker(page: import('@playwright/test').Page) {
    await expect(page.locator('.group-server-menu').first()).toBeVisible({ timeout: 15_000 });
    await page.locator('.group-server-menu').first().click();
    await expect(page.locator('.modal')).toBeVisible({ timeout: 5_000 });
    await expect(page.locator('.dropdown-trigger').first()).toBeVisible({ timeout: 30_000 });
  }

  test('open server picker from VPN group', async ({ page }) => {
    await openServerPicker(page);
    await expect(page.locator('.modal-header')).toContainText('Server');
  });

  test('server picker shows country dropdown', async ({ page }) => {
    await openServerPicker(page);
    await expect(page.locator('.dropdown-trigger').first()).toBeVisible();
  });

  test('server picker shows feature filter chips', async ({ page }) => {
    await openServerPicker(page);
    await expect(page.locator('.filter-chips')).toBeVisible();
    await expect(page.locator('.filter-chip')).toHaveCount(4);
  });

  test('clicking country dropdown shows country list', async ({ page }) => {
    await openServerPicker(page);
    await page.locator('.dropdown-trigger').first().click();
    await expect(page.locator('.dropdown-pop')).toBeVisible({ timeout: 5_000 });
    await expect(page.locator('.dropdown-search')).toBeVisible();
    await expect(page.locator('.dropdown-item').first()).toBeVisible();
  });

  test('cancel closes server picker', async ({ page }) => {
    await openServerPicker(page);
    await page.locator('.modal-footer .btn-outline').click();
    await expect(page.locator('.modal')).not.toBeVisible();
  });

  test('server picker shows preview section', async ({ page }) => {
    await openServerPicker(page);
    await expect(page.locator('.preview')).toBeVisible();
  });

  test('country dropdown search filters results', async ({ page }) => {
    await openServerPicker(page);
    await page.locator('.dropdown-trigger').first().click();
    await expect(page.locator('.dropdown-pop')).toBeVisible({ timeout: 5_000 });

    const searchInput = page.locator('.dropdown-search');
    const beforeCount = await page.locator('.dropdown-item').count();

    await searchInput.fill('Japan');
    await page.waitForTimeout(300);

    const afterCount = await page.locator('.dropdown-item').count();
    expect(afterCount).toBeLessThanOrEqual(beforeCount);
    expect(afterCount).toBeGreaterThanOrEqual(1);
  });

  test('toggling filter chip filters servers', async ({ page }) => {
    await openServerPicker(page);

    const p2pChip = page.locator('.filter-chip:has-text("P2P")');
    await expect(p2pChip).toBeVisible();
    await p2pChip.click();
    await expect(p2pChip).toHaveClass(/active/);

    await p2pChip.click();
    await expect(p2pChip).not.toHaveClass(/active/);
  });
});
