import { test, expect } from '@playwright/test';
import { unlockApp } from './helpers';

test.describe('Location Widget', () => {
  test.beforeEach(async ({ page }) => {
    await unlockApp(page);
  });

  test('shows IP location or check IP link in sidebar', async ({ page }) => {
    const sidebarBottom = page.locator('.sidebar-bottom');
    // Should show either location info, loading state, error, or "Check IP" link
    await expect(
      sidebarBottom.locator(':has-text("Check IP"), :has-text("Checking IP"), .location-info, :has-text("IP check failed")'),
    ).toBeVisible({ timeout: 10_000 });
  });

  test('clicking Check IP triggers location fetch', async ({ page }) => {
    const checkIpLink = page.locator('.sidebar-bottom a:has-text("Check IP")');

    // If location is already loaded, the "Check IP" link won't be visible
    if ((await checkIpLink.count()) === 0) {
      // Location already loaded — verify it shows info
      await expect(page.locator('.location-info')).toBeVisible();
      return;
    }

    await checkIpLink.click();
    // Should show loading or result
    await expect(
      page.locator('.sidebar-bottom').locator(':has-text("Checking IP"), .location-info'),
    ).toBeVisible({ timeout: 5_000 });
  });

  test('shows Proton API connection status', async ({ page }) => {
    await expect(page.locator('.sidebar-bottom')).toContainText('Proton API');
    // Should show Ready or Not logged in
    const protonText = await page.locator('.sidebar-bottom a:has-text("Proton API")').textContent();
    expect(protonText).toMatch(/Ready|Not logged in/);
  });

  test('shows router device count', async ({ page }) => {
    const routerText = await page.locator('.sidebar-bottom a:has-text("Router")').textContent();
    expect(routerText).toMatch(/\d+ devices|No data/);
  });
});
