import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: 'html',
  use: {
    baseURL: 'http://localhost:5173',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
  },
  projects: [
    // Unlock tests run first and serially (they lock/unlock global app state)
    {
      name: 'unlock',
      testMatch: 'unlock.spec.ts',
    },
    // VPN-dependent tests run serially (share router WG slots)
    {
      name: 'vpn',
      testMatch: ['server-picker.spec.ts', 'vpn-group-card.spec.ts'],
      dependencies: ['unlock'],
      fullyParallel: false,
      timeout: 60_000,
    },
    // LAN access tests run after VPN tests (SSH-heavy, avoid contention)
    {
      name: 'lan',
      testMatch: 'lan-access.spec.ts',
      dependencies: ['vpn'],
      timeout: 60_000,
    },
    // All other tests run in parallel after unlock tests finish
    {
      name: 'default',
      testIgnore: ['unlock.spec.ts', 'server-picker.spec.ts', 'vpn-group-card.spec.ts', 'lan-access.spec.ts'],
      dependencies: ['unlock'],
    },
  ],
  webServer: {
    command: 'npm run dev',
    url: 'http://localhost:5173',
    reuseExistingServer: true,
    timeout: 10_000,
  },
});
