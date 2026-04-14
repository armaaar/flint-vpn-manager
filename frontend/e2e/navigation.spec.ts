import { test, expect } from '@playwright/test';
import { unlockApp } from './helpers';

test.describe('Navigation', () => {
  test.beforeEach(async ({ page }) => {
    await unlockApp(page);
  });

  test('navigate to Settings page', async ({ page }) => {
    await page.locator('.sidebar-nav a:has-text("Settings")').click();
    await expect(page).toHaveURL(/#settings/);
    await expect(page.locator('.settings-page')).toBeVisible();
  });

  test('navigate to Networks page', async ({ page }) => {
    await page.locator('.sidebar-nav a:has-text("Networks")').click();
    await expect(page).toHaveURL(/#networks/);
    await expect(page.locator('.lan-page')).toBeVisible();
  });

  test('navigate back to Dashboard from Settings', async ({ page }) => {
    await page.locator('.sidebar-nav a:has-text("Settings")').click();
    await expect(page.locator('.settings-page')).toBeVisible();

    await page.locator('.sidebar-nav a:has-text("Dashboard")').click();
    await expect(page.locator('.content-header h2')).toHaveText('Dashboard');
  });

  test('navigate back to Dashboard from Networks', async ({ page }) => {
    await page.locator('.sidebar-nav a:has-text("Networks")').click();
    await expect(page.locator('.lan-page')).toBeVisible();

    await page.locator('.sidebar-nav a:has-text("Dashboard")').click();
    await expect(page.locator('.content-header h2')).toHaveText('Dashboard');
  });

  test('opens Logs modal', async ({ page }) => {
    await page.locator('.sidebar-nav a:has-text("Logs")').click();
    await expect(page.locator('.logs-modal')).toBeVisible({ timeout: 5_000 });
  });

  test('close Logs modal via close button', async ({ page }) => {
    await page.locator('.sidebar-nav a:has-text("Logs")').click();
    await expect(page.locator('.logs-modal')).toBeVisible({ timeout: 5_000 });

    await page.locator('.logs-modal .modal-close').click();
    await expect(page.locator('.logs-modal')).not.toBeVisible();
  });
});
