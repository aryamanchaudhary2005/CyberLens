import { expect, test, type Page } from '@playwright/test'

async function signIn(page: Page) {
  const username = process.env.CYBERLENS_SMOKE_USERNAME ?? 'admin'
  const password = process.env.CYBERLENS_E2E_ADMIN_PASSWORD ?? 'CyberLens-Smoke-Changed-Password-2026!'
  await page.goto('/')
  await page.getByLabel('Username').fill(username)
  await page.getByLabel('Password').fill(password)
  const pendingLogin = page.waitForResponse((response) => response.url().endsWith('/api/v1/auth/login') && response.request().method() === 'POST')
  await page.getByRole('button', { name: 'Sign in' }).click()
  const response = await pendingLogin
  expect(response.ok()).toBeTruthy()
  const payload = await response.json() as { user: { must_change_password: boolean } }
  if (payload.user.must_change_password) {
    await expect(page.getByRole('heading', { name: 'Change your temporary password' })).toBeVisible()
    await page.getByLabel('Current password').fill(password)
    await page.getByLabel('New password').fill('CyberLens-OSV-Smoke-2026!')
    await page.getByRole('button', { name: 'Update password' }).click()
  }
  await expect(page.getByRole('heading', { name: 'Investigation workspace' })).toBeVisible()
}

test('Demo package inventory shows an evidence-linked OSV candidate without network access', async ({ page }) => {
  await signIn(page)
  await page.getByRole('navigation', { name: 'Workspace', exact: true }).getByRole('button', { name: 'Assets', exact: true }).click()
  await page.getByLabel('Type').selectOption('application')
  await page.getByLabel('Identifier').fill(`OSV fixture application ${Date.now()}`)
  await page.getByRole('button', { name: 'Add asset' }).click()
  await expect(page.getByText(/Asset registered/)).toBeVisible()

  await page.getByLabel('Vendor').fill('CyberLens Demo')
  await page.getByLabel('Product').fill('Package fixture')
  await page.getByLabel('Version (required)').fill('1.0.0')
  await page.getByLabel('Package ecosystem (optional)').selectOption('npm')
  await page.getByLabel('Exact npm package name').fill('cyberlens-demo-widget')
  await page.getByRole('button', { name: 'Add software' }).click()
  await expect(page.getByText(/OSV npm: cyberlens-demo-widget@1.0.0/)).toBeVisible()

  await page.getByLabel('Demo scenario').selectOption('vulnerable_application')
  await page.getByRole('button', { name: 'Run investigation' }).click()
  await expect(page.getByRole('heading', { name: 'OSV package advisory' })).toBeVisible({ timeout: 30_000 })
  const advisory = page.getByRole('region', { name: 'OSV package advisory', exact: true })
  await expect(advisory.getByText('CYBERLENS-DEMO-OSV-2026-0001 · active')).toBeVisible()
  await expect(advisory.getByText(/synthetic · CyberLens Demo fixture schema 1/)).toBeVisible()
  await expect(advisory.getByText(/evidence [0-9a-f-]{36}/i)).toBeVisible()
  await expect(page.getByText(/record an analyst applicability decision/)).toBeVisible()
})
