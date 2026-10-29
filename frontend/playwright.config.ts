import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: './e2e',
  testMatch: '**/*.spec.ts',
  fullyParallel: false,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: 'list',
  ...(process.env.CYBERLENS_BASE_URL ? {} : {
    webServer: {
      command: 'npm run dev -- --host 127.0.0.1',
      url: 'http://127.0.0.1:5173',
      reuseExistingServer: !process.env.CI,
      timeout: 30_000,
    },
  }),
  use: {
    baseURL: process.env.CYBERLENS_BASE_URL ?? 'http://127.0.0.1:5173',
    browserName: 'chromium',
    ...(process.env.CYBERLENS_BROWSER_CHANNEL
      ? { channel: process.env.CYBERLENS_BROWSER_CHANNEL as 'chrome' | 'msedge' }
      : {}),
    headless: true,
    ignoreHTTPSErrors: true,
    trace: 'retain-on-failure',
  },
})
