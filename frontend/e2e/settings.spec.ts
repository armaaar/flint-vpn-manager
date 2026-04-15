import { test, expect } from '@playwright/test';
import { unlockApp } from './helpers';

test.describe('Settings Page', () => {
  test.beforeEach(async ({ page }) => {
    await unlockApp(page);
    await page.locator('.sidebar-nav a:has-text("Settings")').click();
    await expect(page.locator('.settings-page')).toBeVisible({ timeout: 5_000 });
  });

  test('shows settings header with back button', async ({ page }) => {
    await expect(page.locator('.settings-header')).toBeVisible();
    await expect(page.locator('.back-btn')).toBeVisible();
  });

  test('shows tab bar with all tabs', async ({ page }) => {
    await expect(page.locator('.tab-bar')).toBeVisible();
    await expect(page.locator('.tab:has-text("General")')).toBeVisible();
    await expect(page.locator('.tab:has-text("Servers")')).toBeVisible();
    await expect(page.locator('.tab:has-text("DNS Ad Blocker")')).toBeVisible();
    await expect(page.locator('.tab:has-text("Security")')).toBeVisible();
    // Sessions tab was removed
    await expect(page.locator('.tab:has-text("Sessions")')).not.toBeVisible();
  });

  test('General tab shows router IP field', async ({ page }) => {
    await page.locator('.tab:has-text("General")').click();
    await expect(page.locator('#sr-ip')).toBeVisible();
  });

  test('General tab shows alternative routing toggle', async ({ page }) => {
    await page.locator('.tab:has-text("General")').click();
    await expect(page.locator('#alt-routing')).toBeVisible();
  });

  test('General tab shows IPv6 toggle', async ({ page }) => {
    await page.locator('.tab:has-text("General")').click();
    await expect(page.locator('#ipv6-global')).toBeVisible();
    await expect(page.locator('label[for="ipv6-global"]')).toContainText('Enable IPv6');
  });

  test('Servers tab shows auto-optimize controls', async ({ page }) => {
    await page.locator('.tab:has-text("Servers")').click();
    await expect(page.locator('#ao-enabled')).toBeVisible();
  });

  test('DNS Ad Blocker tab is navigable', async ({ page }) => {
    await page.locator('.tab:has-text("DNS Ad Blocker")').click();
    await expect(page).toHaveURL(/#settings\/adblock/);
  });

  test('Security tab shows credential forms', async ({ page }) => {
    await page.locator('.tab:has-text("Security")').click();
    await expect(page.locator('#sc-pu')).toBeVisible();
    await expect(page.locator('#sc-pp')).toBeVisible();
    await expect(page.locator('#sc-rp')).toBeVisible();
  });

  test('Security tab shows change master password form', async ({ page }) => {
    await page.locator('.tab:has-text("Security")').click();
    await expect(page.locator('#cm-old')).toBeVisible();
    await expect(page.locator('#cm-new')).toBeVisible();
    await expect(page.locator('#cm-confirm')).toBeVisible();
  });

  test('back button returns to dashboard', async ({ page }) => {
    await page.locator('.back-btn').click();
    await expect(page.locator('.content-header h2')).toHaveText('Dashboard');
  });

  test('navigating between tabs updates URL hash', async ({ page }) => {
    await page.locator('.tab:has-text("Security")').click();
    await expect(page).toHaveURL(/#settings\/security/);

    await page.locator('.tab:has-text("General")').click();
    await expect(page).toHaveURL(/#settings\/general/);
  });
});
