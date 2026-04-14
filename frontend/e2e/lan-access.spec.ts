import { test, expect } from '@playwright/test';
import { unlockApp } from './helpers';

test.describe('LAN Access Page', () => {
  test.beforeEach(async ({ page }) => {
    await unlockApp(page);
    await page.locator('.sidebar-nav a:has-text("Networks")').click();
    await expect(page.locator('.lan-page')).toBeVisible({ timeout: 5_000 });
    // Wait for networks to load from router (SSH can be slow)
    await expect(page.locator('text=Loading networks')).not.toBeVisible({ timeout: 30_000 });
  });

  test('shows page header with back and refresh buttons', async ({ page }) => {
    await expect(page.locator('.page-header')).toBeVisible();
    await expect(page.locator('.btn-back')).toBeVisible();
    await expect(page.locator('button:has-text("Refresh")')).toBeVisible();
  });

  test('shows network cards for discovered networks', async ({ page }) => {
    const cards = page.locator('.network-card');
    await expect(cards.first()).toBeVisible({ timeout: 10_000 });
    // Router has at least the main LAN network
    expect(await cards.count()).toBeGreaterThanOrEqual(1);
  });

  test('network card shows SSID names and subnet', async ({ page }) => {
    const firstCard = page.locator('.network-card').first();
    await expect(firstCard.locator('.network-header')).toBeVisible();
    // Should show subnet like 192.168.x.0/24
    const headerText = await firstCard.locator('.network-header').textContent();
    expect(headerText).toMatch(/192\.168\.\d+\.\d+\/\d+/);
  });

  test('network card shows device count badge', async ({ page }) => {
    const firstCard = page.locator('.network-card').first();
    const headerText = await firstCard.locator('.network-header').textContent();
    expect(headerText).toMatch(/\d+ devices?/);
  });

  test('network card shows isolation status badge', async ({ page }) => {
    // At least one network should have Free talk or Isolated badge
    const badges = page.locator('.network-header .badge');
    await expect(badges.first()).toBeVisible();
  });

  test('clicking network card expands it', async ({ page }) => {
    const firstCard = page.locator('.network-card').first();
    await firstCard.locator('.network-header').click();
    await expect(firstCard.locator('.network-body')).toBeVisible({ timeout: 10_000 });
  });

  test('expanded network shows device isolation toggle', async ({ page }) => {
    const firstCard = page.locator('.network-card').first();
    await firstCard.locator('.network-header').click();
    await expect(firstCard.locator('.network-body')).toBeVisible({ timeout: 10_000 });

    // Isolation toggle checkbox
    await expect(firstCard.locator('.network-body input[type="checkbox"]').first()).toBeVisible();
  });

  test('expanded network shows access rules table', async ({ page }) => {
    const firstCard = page.locator('.network-card').first();
    await firstCard.locator('.network-header').click();
    await expect(firstCard.locator('.network-body')).toBeVisible({ timeout: 10_000 });

    // Access rules section with table
    await expect(firstCard.locator('.rules-section, table').first()).toBeVisible();
    // Table headers: Network, Inbound, Outbound
    const tableText = await firstCard.locator('.network-body').textContent();
    expect(tableText).toContain('Inbound');
    expect(tableText).toContain('Outbound');
  });

  test('expanded network shows devices list', async ({ page }) => {
    const firstCard = page.locator('.network-card').first();
    await firstCard.locator('.network-header').click();
    await expect(firstCard.locator('.network-body')).toBeVisible({ timeout: 10_000 });

    // Devices heading
    await expect(firstCard.locator('h4:has-text("Devices")')).toBeVisible();
  });

  test('expanded network shows WiFi Settings section', async ({ page }) => {
    const firstCard = page.locator('.network-card').first();
    await firstCard.locator('.network-header').click();
    await expect(firstCard.locator('.network-body')).toBeVisible({ timeout: 10_000 });

    await expect(firstCard.locator('text=WiFi Settings')).toBeVisible();
  });

  test('shows create network button', async ({ page }) => {
    await expect(page.locator('button:has-text("Create Network")')).toBeVisible();
  });

  test('shows exceptions section heading', async ({ page }) => {
    await expect(page.locator('.exceptions-section h3')).toBeVisible();
    const heading = await page.locator('.exceptions-section h3').textContent();
    expect(heading).toMatch(/Exceptions/);
  });

  test('shows add exception button', async ({ page }) => {
    await expect(page.locator('button:has-text("Add Exception")')).toBeVisible();
  });

  test('access rules table shows lock/unlock toggles', async ({ page }) => {
    const firstCard = page.locator('.network-card').first();
    await firstCard.locator('.network-header').click();
    await expect(firstCard.locator('.network-body')).toBeVisible({ timeout: 10_000 });

    // Rule toggles are buttons with lock or check icons
    const ruleToggles = firstCard.locator('.rule-toggle, button:has-text("🔒"), button:has-text("✅")');
    await expect(ruleToggles.first()).toBeVisible();
  });

  test('back button returns to dashboard', async ({ page }) => {
    await page.locator('.btn-back').click();
    await expect(page.locator('.content-header h2')).toHaveText('Dashboard');
  });
});
