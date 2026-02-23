import { test, expect } from '@playwright/test'
import { execSync } from 'child_process'
import path from 'path'
import { fileURLToPath } from 'url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..')

test('axiomos payment flow demo', async ({ page }) => {
  test.setTimeout(240000)
  await page.setViewportSize({ width: 1440, height: 900 })
  const env = {
    ...process.env,
    BASE: 'http://localhost:8080',
    POLICY: 'http://localhost:8082',
    STATE: 'http://localhost:8083'
  }
  execSync('bash ./scripts/demo-seed.sh', { cwd: root, stdio: 'inherit', env })

  await page.goto('http://localhost:5173', { waitUntil: 'networkidle' })
  await page.getByText('Escrow Queue').waitFor()
  const masks = [
    page.locator('.stat-grid'),
    page.locator('.stepper'),
    page.locator('.timeline'),
    page.locator('.list'),
    page.locator('.muted'),
    page.locator('.sidebar-footer')
  ]
  await expect(page).toHaveScreenshot('console-overview.png', { fullPage: false, mask: masks, maxDiffPixelRatio: 0.03 })

  const approveBtn = page.getByRole('button', { name: 'Approve' }).first()
  await expect(approveBtn).toBeVisible({ timeout: 20000 })
  await approveBtn.click()

  await page.waitForTimeout(3000)
  await expect(page.locator('.list-title', { hasText: 'CLOSED' }).first()).toBeVisible({ timeout: 20000 })
  await expect(page).toHaveScreenshot('console-post-approval.png', { fullPage: false, mask: masks, maxDiffPixelRatio: 0.03 })

  await page.waitForTimeout(180000)
})
