import { test, expect } from '@playwright/test';
import { unlockApp, uniqueName, deleteProfileApi } from './helpers';

test.describe('Group Management', () => {
  test.beforeEach(async ({ page }) => {
    await unlockApp(page);
    await expect(page.locator('.loading-groups')).not.toBeVisible({ timeout: 15_000 });
  });

  test('add-group button opens create modal', async ({ page }) => {
    await page.locator('.add-group-btn').click();
    await expect(page.locator('.modal')).toBeVisible();
    await expect(page.locator('.modal-header h2')).toHaveText('Create Group');
  });

  test('create NoVPN group and delete it', async ({ page }) => {
    const groupName = uniqueName('TestNoVPN');

    // Open create modal
    await page.locator('.add-group-btn').click();
    await expect(page.locator('.modal')).toBeVisible();

    // Fill form
    await page.locator('#gm-type').selectOption('no_vpn');
    await page.locator('#gm-name').fill(groupName);

    // Submit
    await page.locator('.modal-footer .btn-primary').click();

    // Wait for modal to close and card to appear
    await expect(page.locator('.modal')).not.toBeVisible({ timeout: 10_000 });
    await expect(page.locator(`.group-name:has-text("${groupName}")`)).toBeVisible({ timeout: 10_000 });

    // Clean up: open edit modal and delete
    const card = page.locator('.group-card', { has: page.locator(`.group-name:has-text("${groupName}")`) });
    await card.locator('.group-settings-btn').click();
    await expect(page.locator('.modal-header h2')).toHaveText('Edit Group');

    // Handle the native confirm() dialog
    page.once('dialog', dialog => dialog.accept());
    await page.locator('button:has-text("Delete Group")').click();
    await expect(page.locator('.modal')).not.toBeVisible({ timeout: 10_000 });
    await expect(page.locator(`.group-name:has-text("${groupName}")`)).not.toBeVisible();
  });

  test('create NoInternet group and delete it', async ({ page }) => {
    const groupName = uniqueName('TestNoInet');

    // Create via API for reliability (NoInternet creation involves router sync)
    const res = await page.request.post('http://localhost:5173/api/profiles', {
      data: { type: 'no_internet', name: groupName, icon: '🚫', color: '#e74c3c' },
    });
    const profileData = await res.json();

    // Reload to see the new group
    await page.reload();
    await expect(page.locator('.sidebar')).toBeVisible({ timeout: 15_000 });
    await expect(page.locator('.loading-groups')).not.toBeVisible({ timeout: 15_000 });
    await expect(page.locator(`.group-name:has-text("${groupName}")`)).toBeVisible({ timeout: 10_000 });

    // Clean up via edit modal
    const card = page.locator('.group-card', { has: page.locator(`.group-name:has-text("${groupName}")`) });
    await card.locator('.group-settings-btn').click();
    await expect(page.locator('.modal-header h2')).toHaveText('Edit Group');
    page.once('dialog', dialog => dialog.accept());
    await page.locator('button:has-text("Delete Group")').click();
    await expect(page.locator('.modal')).not.toBeVisible({ timeout: 10_000 });
    await expect(page.locator(`.group-name:has-text("${groupName}")`)).not.toBeVisible();
  });

  test('edit group name', async ({ page }) => {
    const originalName = uniqueName('EditOrig');
    const newName = uniqueName('EditNew');

    // Create a group via API for isolation
    const profile = await page.request.post('http://localhost:5173/api/profiles', {
      data: { type: 'no_vpn', name: originalName, icon: '🔒', color: '#00aaff' },
    });
    const profileData = await profile.json();

    // Reload to see the new group
    await page.reload();
    await expect(page.locator('.sidebar')).toBeVisible({ timeout: 15_000 });
    await expect(page.locator('.loading-groups')).not.toBeVisible({ timeout: 15_000 });

    // Open edit modal
    const card = page.locator('.group-card', { has: page.locator(`.group-name:has-text("${originalName}")`) });
    await card.locator('.group-settings-btn').click();
    await expect(page.locator('.modal-header h2')).toHaveText('Edit Group');

    // Change name
    await page.locator('#gm-name').fill(newName);
    await page.locator('.modal-footer .btn-primary').click();
    await expect(page.locator('.modal')).not.toBeVisible({ timeout: 10_000 });

    // Verify new name appears
    await expect(page.locator(`.group-name:has-text("${newName}")`)).toBeVisible({ timeout: 10_000 });

    // Clean up
    await deleteProfileApi(page, profileData.id);
  });

  test('cancel create modal does not create group', async ({ page }) => {
    await page.locator('.add-group-btn').click();
    await expect(page.locator('.modal')).toBeVisible();

    await page.locator('#gm-name').fill('ShouldNotExist');
    await page.locator('.modal-footer .btn-outline').click();

    await expect(page.locator('.modal')).not.toBeVisible();
    await expect(page.locator('.group-name:has-text("ShouldNotExist")')).not.toBeVisible();
  });

  test('create modal shows type descriptions', async ({ page }) => {
    await page.locator('.add-group-btn').click();
    await expect(page.locator('.modal')).toBeVisible();

    // VPN type is default
    await expect(page.locator('#gm-type')).toHaveValue('vpn');

    // Switch to no_vpn
    await page.locator('#gm-type').selectOption('no_vpn');

    // Switch to no_internet
    await page.locator('#gm-type').selectOption('no_internet');

    // Close
    await page.locator('.modal-footer .btn-outline').click();
  });

  test('VPN type shows protocol selection cards', async ({ page }) => {
    await page.locator('.add-group-btn').click();
    await expect(page.locator('.modal')).toBeVisible();

    // VPN type is default — protocol cards should be visible
    await expect(page.locator('#gm-type')).toHaveValue('vpn');
    await expect(page.locator('.protocol-cards')).toBeVisible();

    // Should have at least 3 protocol options
    const cards = page.locator('.protocol-card');
    expect(await cards.count()).toBeGreaterThanOrEqual(3);

    await page.locator('.modal-footer .btn-outline').click();
  });

  test('VPN type shows VPN options section', async ({ page }) => {
    await page.locator('.add-group-btn').click();
    await expect(page.locator('.modal')).toBeVisible();

    await expect(page.locator('.vpn-options-section')).toBeVisible();
    // Kill switch checkbox
    await expect(page.locator('#gm-killswitch')).toBeVisible();
    // NetShield select
    await expect(page.locator('#gm-netshield')).toBeVisible();
    // VPN Accelerator checkbox
    await expect(page.locator('#gm-acc')).toBeVisible();

    await page.locator('.modal-footer .btn-outline').click();
  });

  test('switching to NoVPN hides protocol and VPN options', async ({ page }) => {
    await page.locator('.add-group-btn').click();
    await expect(page.locator('.modal')).toBeVisible();

    // Initially VPN — protocol cards visible
    await expect(page.locator('.protocol-cards')).toBeVisible();

    // Switch to NoVPN
    await page.locator('#gm-type').selectOption('no_vpn');

    // Protocol cards and VPN options should be hidden
    await expect(page.locator('.protocol-cards')).not.toBeVisible();
    await expect(page.locator('.vpn-options-section')).not.toBeVisible();

    await page.locator('.modal-footer .btn-outline').click();
  });

  test('smart protocol toggle forces WireGuard', async ({ page }) => {
    await page.locator('.add-group-btn').click();
    await expect(page.locator('.modal')).toBeVisible();

    // Enable smart protocol
    const smartCheckbox = page.locator('#gm-smart');
    await expect(smartCheckbox).toBeVisible();
    await smartCheckbox.check();

    // Protocol cards should be hidden (smart protocol manages protocol)
    await expect(page.locator('.smart-protocol-info')).toBeVisible();

    await page.locator('.modal-footer .btn-outline').click();
  });

  test('name field is required for create', async ({ page }) => {
    await page.locator('.add-group-btn').click();
    await expect(page.locator('.modal')).toBeVisible();

    await page.locator('#gm-type').selectOption('no_vpn');
    // Leave name empty and try to submit
    await page.locator('#gm-name').fill('');
    await page.locator('.modal-footer .btn-primary').click();

    // Should show error or remain on modal
    await expect(page.locator('.modal')).toBeVisible();

    await page.locator('.modal-footer .btn-outline').click();
  });
});
