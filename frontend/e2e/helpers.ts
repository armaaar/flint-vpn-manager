import { type Page, expect } from '@playwright/test';

const MASTER_PASSWORD = 'claudy';
const API_BASE = 'http://localhost:5173';

/**
 * Lock the app via the backend API.
 */
export async function lockApp(page: Page) {
  await page.request.post(`${API_BASE}/api/lock`);
}

/**
 * Unlock the app. Handles both locked and already-unlocked states.
 */
export async function unlockApp(page: Page) {
  // Ensure app is unlocked via API first (fast path)
  const status = await page.request.get(`${API_BASE}/api/status`);
  const data = await status.json();
  if (data.status === 'locked') {
    await page.request.post(`${API_BASE}/api/unlock`, {
      data: { master_password: MASTER_PASSWORD },
    });
  }

  await page.goto('/');
  // Wait for sidebar (dashboard) to appear
  await expect(page.locator('.sidebar')).toBeVisible({ timeout: 15_000 });
}

/**
 * Create a unique name for test resources to avoid parallel collisions.
 */
export function uniqueName(prefix: string): string {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
}

/**
 * Delete a profile by ID via API (for cleanup).
 */
export async function deleteProfileApi(page: Page, profileId: string) {
  await page.request.delete(`${API_BASE}/api/profiles/${profileId}`);
}

/**
 * Create a profile via API and return it.
 */
export async function createProfileApi(
  page: Page,
  data: Record<string, unknown>,
): Promise<{ id: string; [key: string]: unknown }> {
  const res = await page.request.post(`${API_BASE}/api/profiles`, { data });
  return res.json();
}

export { MASTER_PASSWORD, API_BASE };
