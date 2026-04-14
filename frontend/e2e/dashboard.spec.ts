import { test, expect } from '@playwright/test';
import { unlockApp } from './helpers';

test.describe('Dashboard', () => {
  test.beforeEach(async ({ page }) => {
    await unlockApp(page);
  });

  test('shows sidebar navigation links', async ({ page }) => {
    await expect(page.locator('.sidebar-nav')).toBeVisible();
    await expect(page.locator('.sidebar-nav a:has-text("Dashboard")')).toBeVisible();
    await expect(page.locator('.sidebar-nav a:has-text("Networks")')).toBeVisible();
    await expect(page.locator('.sidebar-nav a:has-text("Settings")')).toBeVisible();
    await expect(page.locator('.sidebar-nav a:has-text("Logs")')).toBeVisible();
  });

  test('shows dashboard content header with refresh button', async ({ page }) => {
    await expect(page.locator('.content-header h2')).toHaveText('Dashboard');
    await expect(page.locator('button:has-text("Refresh")')).toBeVisible();
  });

  test('shows Proton API status in sidebar', async ({ page }) => {
    await expect(page.locator('.sidebar-bottom')).toContainText('Proton API');
  });

  test('shows router device count in sidebar', async ({ page }) => {
    await expect(page.locator('.sidebar-bottom')).toContainText('Router');
  });

  test('displays group cards or add-group button', async ({ page }) => {
    // Wait for loading to finish
    await expect(page.locator('.loading-groups')).not.toBeVisible({ timeout: 15_000 });
    // Either group cards exist or the add-group button is visible
    const groupCards = page.locator('.group-card');
    const addButton = page.locator('.add-group-btn');
    const hasGroups = (await groupCards.count()) > 0;
    const hasAddButton = await addButton.isVisible();
    expect(hasGroups || hasAddButton).toBeTruthy();
  });

  test('shows unassigned devices section', async ({ page }) => {
    await expect(page.locator('.loading-groups')).not.toBeVisible({ timeout: 15_000 });
    await expect(page.locator('.unassigned-section')).toBeVisible();
    await expect(page.locator('.unassigned-title')).toContainText('Unassigned Devices');
  });

  test('refresh button is clickable and completes', async ({ page }) => {
    await expect(page.locator('.loading-groups')).not.toBeVisible({ timeout: 15_000 });
    const refreshBtn = page.locator('button:has-text("Refresh")');
    await refreshBtn.click();
    // Wait for refresh to complete — button re-enables with text
    await expect(refreshBtn).toBeEnabled({ timeout: 30_000 });
    await expect(refreshBtn).toContainText('Refresh', { timeout: 30_000 });
  });
});
