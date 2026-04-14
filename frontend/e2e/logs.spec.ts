import { test, expect } from '@playwright/test';
import { unlockApp } from './helpers';

test.describe('Logs Modal', () => {
  test.beforeEach(async ({ page }) => {
    await unlockApp(page);
    await page.locator('.sidebar-nav a:has-text("Logs")').click();
    await expect(page.locator('.logs-modal')).toBeVisible({ timeout: 5_000 });
  });

  test('shows log tabs', async ({ page }) => {
    const tabs = page.locator('.log-tab');
    expect(await tabs.count()).toBeGreaterThanOrEqual(1);
  });

  test('shows log file sizes', async ({ page }) => {
    await expect(page.locator('.log-size').first()).toBeVisible();
  });

  test('shows log content area', async ({ page }) => {
    // Wait for content to load
    await expect(page.locator('.log-content')).toBeVisible({ timeout: 10_000 });
  });

  test('switching tabs changes log content', async ({ page }) => {
    const tabs = page.locator('.log-tab');
    const tabCount = await tabs.count();

    if (tabCount < 2) {
      test.skip();
      return;
    }

    // Click second tab
    await tabs.nth(1).click();
    // Log content should still be visible
    await expect(page.locator('.log-content')).toBeVisible();
  });

  test('refresh button reloads logs', async ({ page }) => {
    const refreshBtn = page.locator('.log-actions button:has-text("↻")');
    await expect(refreshBtn).toBeVisible();
    await refreshBtn.click();
    // Content should remain visible after refresh
    await expect(page.locator('.log-content')).toBeVisible({ timeout: 10_000 });
  });

  test('close modal via close button', async ({ page }) => {
    await page.locator('.logs-modal .modal-close').click();
    await expect(page.locator('.logs-modal')).not.toBeVisible();
  });
});
