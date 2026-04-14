import { test, expect } from '@playwright/test';
import { unlockApp } from './helpers';

test.describe('DNS Ad Blocker Settings', () => {
  test.beforeEach(async ({ page }) => {
    await unlockApp(page);
    await page.locator('.sidebar-nav a:has-text("Settings")').click();
    await expect(page.locator('.settings-page')).toBeVisible({ timeout: 5_000 });
    await page.locator('.tab:has-text("DNS Ad Blocker")').click();
  });

  test('shows blocklist sources heading', async ({ page }) => {
    await expect(page.locator('h3:has-text("Blocklist Sources")')).toBeVisible({ timeout: 5_000 });
  });

  test('shows preset blocklist cards', async ({ page }) => {
    const presetCards = page.locator('.preset-card');
    await expect(presetCards.first()).toBeVisible({ timeout: 10_000 });
    expect(await presetCards.count()).toBeGreaterThanOrEqual(1);
  });

  test('shows custom URL input', async ({ page }) => {
    await expect(page.locator('h4:has-text("Custom Blocklist URLs")')).toBeVisible();
    await expect(page.locator('input[placeholder*="blocklist"]')).toBeVisible();
  });

  test('shows custom domains input', async ({ page }) => {
    await expect(page.locator('h4:has-text("Custom Blocked Domains")')).toBeVisible();
    await expect(page.locator('input[placeholder="ads.example.com"]')).toBeVisible();
  });

  test('shows domain count and last updated', async ({ page }) => {
    // Should show "X domains blocked" or similar
    await expect(page.locator('text=/\\d+.*domains blocked/')).toBeVisible({ timeout: 10_000 });
  });

  test('shows Save & Apply button', async ({ page }) => {
    await expect(page.locator('button:has-text("Save & Apply")')).toBeVisible();
  });

  test('shows View Blocked Domains button', async ({ page }) => {
    await expect(page.locator('button:has-text("View Blocked Domains")')).toBeVisible();
  });

  test('preset cards are toggleable', async ({ page }) => {
    const firstPreset = page.locator('.preset-card').first();
    const wasSelected = await firstPreset.evaluate(el => el.classList.contains('selected'));

    // Click to toggle
    await firstPreset.click();
    const isSelected = await firstPreset.evaluate(el => el.classList.contains('selected'));
    expect(isSelected).not.toBe(wasSelected);

    // Toggle back to restore original state
    await firstPreset.click();
  });
});
