import { test, expect } from '@playwright/test';
import { unlockApp } from './helpers';

test.describe('Device Management', () => {
  test.beforeEach(async ({ page }) => {
    await unlockApp(page);
    await expect(page.locator('.loading-groups')).not.toBeVisible({ timeout: 15_000 });
  });

  test('clicking an unassigned device opens the device modal', async ({ page }) => {
    const deviceChip = page.locator('.unassigned-chip').first();
    await expect(deviceChip).toBeVisible({ timeout: 10_000 });

    await deviceChip.click();
    await expect(page.locator('.modal')).toBeVisible({ timeout: 5_000 });
    await expect(page.locator('.modal-header')).toBeVisible();
    // Should have info grid with device details
    await expect(page.locator('.info-grid')).toBeVisible();
  });

  test('device modal shows MAC address and IP', async ({ page }) => {
    await page.locator('.unassigned-chip').first().click();
    await expect(page.locator('.modal')).toBeVisible({ timeout: 5_000 });

    await expect(page.locator('.info-grid')).toContainText('MAC');
    await expect(page.locator('.info-grid')).toContainText('IP');
  });

  test('device modal has label and type edit fields', async ({ page }) => {
    await page.locator('.unassigned-chip').first().click();
    await expect(page.locator('.modal')).toBeVisible({ timeout: 5_000 });

    await expect(page.locator('#dl')).toBeVisible();
    await expect(page.locator('#dc')).toBeVisible();
    await expect(page.locator('#dg')).toBeVisible();
  });

  test('device modal has save and cancel buttons', async ({ page }) => {
    await page.locator('.unassigned-chip').first().click();
    await expect(page.locator('.modal')).toBeVisible({ timeout: 5_000 });

    await expect(page.locator('.modal-footer .btn-primary')).toBeVisible();
    await expect(page.locator('.modal-footer .btn-outline')).toBeVisible();
  });

  test('cancel device modal closes without changes', async ({ page }) => {
    await page.locator('.unassigned-chip').first().click();
    await expect(page.locator('.modal')).toBeVisible({ timeout: 5_000 });

    await page.locator('.modal-footer .btn-outline').click();
    await expect(page.locator('.modal')).not.toBeVisible();
  });

  test('device modal group select lists available profiles', async ({ page }) => {
    await page.locator('.unassigned-chip').first().click();
    await expect(page.locator('.modal')).toBeVisible({ timeout: 5_000 });

    // Group select should at minimum have "Unassigned" option
    const groupSelect = page.locator('#dg');
    await expect(groupSelect).toBeVisible();
    const options = await groupSelect.locator('option').allTextContents();
    expect(options.some(o => o.includes('Unassigned'))).toBeTruthy();
  });

  test('private MAC badge is shown for randomized MACs', async ({ page }) => {
    // Several devices have private MACs based on the snapshot
    const privateBadge = page.locator('.badge-random').first();
    await expect(privateBadge).toBeVisible({ timeout: 10_000 });
    await expect(privateBadge).toContainText('Private MAC');
  });

  test('unassigned section shows device count', async ({ page }) => {
    const title = page.locator('.unassigned-title');
    await expect(title).toBeVisible();
    const text = await title.textContent();
    expect(text).toMatch(/Unassigned Devices \(\d+\)/);
  });
});
