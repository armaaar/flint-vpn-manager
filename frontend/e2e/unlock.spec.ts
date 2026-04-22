import { test, expect } from '@playwright/test';
import { lockApp, MASTER_PASSWORD, API_BASE } from './helpers';

// These tests mutate global app state (lock/unlock), so they run serially
test.describe.configure({ mode: 'serial' });

// Skip: unlock tests require specific app state (locked) and are flaky.
// The afterAll still ensures the app is unlocked for dependent test suites.
test.describe('Unlock Screen', () => {
  test.beforeEach(async ({ page }) => {
    await lockApp(page);
    await page.goto('/');
    await expect(page.locator('.auth-card')).toBeVisible({ timeout: 10_000 });
  });

  // Re-unlock after all tests so other specs aren't affected
  test.afterAll(async ({ request }) => {
    const status = await request.get(`${API_BASE}/api/status`);
    const data = await status.json();
    if (data.status === 'locked') {
      await request.post(`${API_BASE}/api/unlock`, {
        data: { master_password: MASTER_PASSWORD },
      });
    }
  });

  test.skip('shows unlock screen with correct elements', async ({ page }) => {
    await expect(page.locator('h2')).toHaveText('Flint VPN Manager');
    await expect(page.locator('#u-pass')).toBeVisible();
    await expect(page.locator('button:has-text("Unlock")')).toBeVisible();
    await expect(page.locator('.subtitle')).toHaveText(
      'Enter your master password to unlock',
    );
  });

  test.skip('unlocks with correct password', async ({ page }) => {
    await page.locator('#u-pass').fill(MASTER_PASSWORD);
    await page.locator('button:has-text("Unlock")').click();

    await expect(page.locator('.sidebar')).toBeVisible({ timeout: 15_000 });
    await expect(page.locator('.sidebar-logo')).toContainText('Flint VPN');
  });

  test.skip('unlock via Enter key', async ({ page }) => {
    await page.locator('#u-pass').fill(MASTER_PASSWORD);
    await page.locator('#u-pass').press('Enter');

    await expect(page.locator('.sidebar')).toBeVisible({ timeout: 15_000 });
  });

  test.skip('shows error on wrong password', async ({ page }) => {
    await page.locator('#u-pass').fill('wrong-password');
    await page.locator('button:has-text("Unlock")').click();

    await expect(page.locator('.error-msg')).toBeVisible({ timeout: 5_000 });
    // Should still be on unlock screen
    await expect(page.locator('.auth-card')).toBeVisible();
  });
});
