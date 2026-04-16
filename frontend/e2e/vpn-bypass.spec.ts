import { test, expect } from '@playwright/test';
import { unlockApp, API_BASE } from './helpers';

test.describe.configure({ mode: 'serial' });

test.describe('VPN Bypass Page', () => {
  test.beforeEach(async ({ page }) => {
    await unlockApp(page);
    // Clean up any leftover exceptions from previous test runs
    const res = await page.request.get(`${API_BASE}/api/vpn-bypass`);
    const data = await res.json();
    for (const exc of data.exceptions || []) {
      await page.request.delete(`${API_BASE}/api/vpn-bypass/exceptions/${exc.id}`);
    }
    // Navigate to bypass page
    await page.locator('.sidebar-nav a:has-text("VPN Bypass")').click();
    await expect(page.locator('.bypass-page')).toBeVisible({ timeout: 10_000 });
  });

  test('navigate to bypass page via sidebar', async ({ page }) => {
    await expect(page).toHaveURL(/#bypass/);
    await expect(page.locator('h2:has-text("VPN Bypass")')).toBeVisible();
  });

  test('shows empty state when no exceptions', async ({ page }) => {
    await expect(page.locator('text=No bypass exceptions yet')).toBeVisible();
  });

  test('shows preset cards', async ({ page }) => {
    await expect(page.locator('text=League of Legends')).toBeVisible();
    await expect(page.locator('text=Valorant')).toBeVisible();
  });

  test('back button navigates to dashboard', async ({ page }) => {
    await page.locator('button:has-text("Back")'). click();
    await expect(page.locator('.content-header h2')).toHaveText('Dashboard');
  });

  test('add exception from preset — shows preset picker', async ({ page }) => {
    await page.locator('button:has-text("Add Exception")').click();
    await expect(page.locator('h3:has-text("Add Bypass Exception")')).toBeVisible();
    // Should show preset picker as step 1
    await expect(page.locator('text=Choose a preset or create custom rules')).toBeVisible();
    await expect(page.locator('button:has-text("League of Legends")')).toBeVisible();
    await expect(page.locator('button:has-text("Valorant")')).toBeVisible();
    await expect(page.locator('button:has-text("Custom")')).toBeVisible();
  });

  test('select preset shows step 2 with pre-filled rules', async ({ page }) => {
    await page.locator('button:has-text("Add Exception")').click();
    await page.locator('button:has-text("League of Legends")').first().click();

    // Step 2: name should be pre-filled
    const nameInput = page.locator('input[placeholder="e.g. League of Legends"]');
    await expect(nameInput).toHaveValue('League of Legends');

    // Scope radios should be visible
    await expect(page.locator('text=Global (all devices)')).toBeVisible();
    await expect(page.locator('text=Selected groups / devices')).toBeVisible();

    // Rules should be populated (check that rule rows exist with domain values)
    await expect(page.locator('.rule-edit-row').first()).toBeVisible();
    // At least one input should contain a domain value
    await expect(page.locator('.rule-value-input').first()).not.toHaveValue('');

    // Create button should be visible
    await expect(page.locator('button:has-text("Create Exception")')).toBeVisible();
  });

  test('create global exception from LoL preset', async ({ page }) => {
    await page.locator('button:has-text("Add Exception")').click();
    await page.locator('button:has-text("League of Legends")').first().click();
    await page.locator('button:has-text("Create Exception")').click();

    // Modal should close and exception should appear
    await expect(page.locator('h3:has-text("Add Bypass Exception")')).not.toBeVisible();
    // Exception card should show
    await expect(page.locator('.exception-card').first()).toBeVisible({ timeout: 5_000 });
    await expect(page.locator('.exc-name:has-text("League of Legends")')).toBeVisible();
    await expect(page.locator('.scope-badge:has-text("Global")').first()).toBeVisible();
    await expect(page.locator('.preset-tag:has-text("Preset")').first()).toBeVisible();
  });

  test('expand exception shows rule details', async ({ page }) => {
    // Create an exception first
    await page.request.post(`${API_BASE}/api/vpn-bypass/exceptions`, {
      data: { name: 'Test Expand', preset_id: 'lol', scope: 'global' },
    });
    await page.reload();
    await expect(page.locator('.bypass-page')).toBeVisible({ timeout: 5_000 });

    // Click to expand
    await page.locator('.exc-header').first().click();
    // Should show rule details
    await expect(page.locator('.exc-details')).toBeVisible();
    await expect(page.locator('.rule-type:has-text("CIDR")').first()).toBeVisible();
    await expect(page.locator('.rule-type:has-text("DOMAIN")').first()).toBeVisible();
    await expect(page.locator('.rule-value:has-text("riotgames.com")').first()).toBeVisible();
  });

  test('toggle exception disables it', async ({ page }) => {
    // Create an exception
    await page.request.post(`${API_BASE}/api/vpn-bypass/exceptions`, {
      data: { name: 'Toggle Test', preset_id: 'lol', scope: 'global' },
    });
    await page.reload();
    await expect(page.locator('.bypass-page')).toBeVisible({ timeout: 5_000 });

    // Exception should not be dimmed (enabled)
    await expect(page.locator('.exception-card').first()).toBeVisible();

    // Toggle off by clicking the toggle label
    await page.locator('.exception-card .toggle').first().click();
    // After toggle, the page reloads data — wait for the card to become disabled
    await expect(page.locator('.exception-card.disabled').first()).toBeVisible({ timeout: 10_000 });
  });

  test('delete exception removes it', async ({ page }) => {
    // Create an exception
    await page.request.post(`${API_BASE}/api/vpn-bypass/exceptions`, {
      data: { name: 'Delete Test', preset_id: 'lol', scope: 'global' },
    });
    await page.reload();
    await expect(page.locator('.bypass-page')).toBeVisible({ timeout: 5_000 });
    await expect(page.locator('.exc-name:has-text("Delete Test")')).toBeVisible();

    // Delete it specifically
    const card = page.locator('.exception-card', { has: page.locator('.exc-name:has-text("Delete Test")') });
    await card.locator('.btn-danger:has-text("✕")').click();

    // "Delete Test" should disappear
    await expect(page.locator('.exc-name:has-text("Delete Test")')).not.toBeVisible({ timeout: 5_000 });
  });

  test('edit exception opens modal with existing data', async ({ page }) => {
    // Create an exception via API
    await page.request.post(`${API_BASE}/api/vpn-bypass/exceptions`, {
      data: { name: 'Edit Test', preset_id: 'lol', scope: 'global' },
    });
    // Reload to pick up the new exception (already on #bypass from beforeEach)
    await page.reload();
    await expect(page.locator('.bypass-page')).toBeVisible({ timeout: 10_000 });
    await expect(page.locator('.exc-name:has-text("Edit Test")')).toBeVisible({ timeout: 10_000 });

    // Click edit button on the Edit Test card
    const card = page.locator('.exception-card', { has: page.locator('.exc-name:has-text("Edit Test")') });
    await card.locator('button:has-text("✎")').click();

    // Modal should open in step 2 (no preset picker) with existing name
    await expect(page.locator('h3:has-text("Edit Exception")')).toBeVisible();
    const nameInput = page.locator('input[placeholder="e.g. League of Legends"]');
    await expect(nameInput).toHaveValue('Edit Test');
    // Rules should be populated
    await expect(page.locator('.rule-edit-row').first()).toBeVisible();
  });

  test('close modal via X button', async ({ page }) => {
    await page.locator('button:has-text("Add Exception")').click();
    await expect(page.locator('.modal')).toBeVisible();

    await page.locator('.close-btn:has-text("✕")').click();
    await expect(page.locator('.modal')).not.toBeVisible();
  });

  test('close modal via overlay click', async ({ page }) => {
    await page.locator('button:has-text("Add Exception")').click();
    await expect(page.locator('.modal')).toBeVisible();

    // Click on overlay (outside modal)
    await page.locator('.modal-overlay').click({ position: { x: 10, y: 10 } });
    await expect(page.locator('.modal')).not.toBeVisible();
  });

  test('custom exception with manual rules', async ({ page }) => {
    await page.locator('button:has-text("Add Exception")').click();
    // Pick custom
    await page.locator('button:has-text("Custom")').click();

    // Fill name
    await page.locator('input[placeholder="e.g. League of Legends"]').fill('My Custom Rule');

    // Add a CIDR rule
    await page.locator('button:has-text("Add Rule")').click();
    // Fill the first (and only) rule value input
    await page.locator('.rule-value-input').first().fill('10.0.0.0/8');

    // Create button should now be enabled
    const createBtn = page.locator('button:has-text("Create Exception")');
    await expect(createBtn).toBeEnabled();
    await createBtn.click();

    // Should appear in the list
    await expect(page.locator('.exc-name:has-text("My Custom Rule")')).toBeVisible({ timeout: 5_000 });
  });

  test('custom scope shows both groups and devices', async ({ page }) => {
    await page.locator('button:has-text("Add Exception")').click();
    await page.locator('button:has-text("Custom")').click();

    // Select custom scope
    await page.locator('text=Selected groups / devices').click();
    // Both groups and devices lists should appear
    await expect(page.locator('label:has-text("VPN Groups")')).toBeVisible();
    await expect(page.locator('label:has-text("Devices")')).toBeVisible();
    // Device rows should be visible
    await expect(page.locator('.device-row').first()).toBeVisible();
  });

  test('multiple exceptions can coexist', async ({ page }) => {
    // Create two exceptions via API
    await page.request.post(`${API_BASE}/api/vpn-bypass/exceptions`, {
      data: { name: 'Exception 1', preset_id: 'lol', scope: 'global' },
    });
    await page.request.post(`${API_BASE}/api/vpn-bypass/exceptions`, {
      data: { name: 'Exception 2', preset_id: 'valorant', scope: 'global' },
    });
    await page.reload();
    await expect(page.locator('.bypass-page')).toBeVisible({ timeout: 10_000 });

    await expect(page.locator('.exc-name:has-text("Exception 1")')).toBeVisible({ timeout: 10_000 });
    await expect(page.locator('.exc-name:has-text("Exception 2")')).toBeVisible();
    const cards = page.locator('.exception-card');
    expect(await cards.count()).toBe(2);
  });
});
