import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: './tests',
  timeout: 240000,
  expect: { timeout: 10000 },
  retries: 0,
  use: {
    browserName: 'chromium',
    video: 'on',
    viewport: { width: 1440, height: 900 },
    trace: 'off'
  },
  reporter: [['list']]
})
