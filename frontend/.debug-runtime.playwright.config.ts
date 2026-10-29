import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: 'list',
  outputDir: './test-results/runtime-debug',
  use: {
    baseURL: 'http://localhost:15173',
    browserName: 'chromium',
    headless: true,
    trace: 'retain-on-failure',
  },
})
