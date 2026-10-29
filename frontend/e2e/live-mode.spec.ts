import { expect, test } from '@playwright/test'

test('Live sign-in identifies the mode and enforces shared-admin password rotation', async ({ page }) => {
  const username = process.env.CYBERLENS_LIVE_SMOKE_USERNAME ?? 'admin'
  const password = process.env.CYBERLENS_LIVE_SMOKE_PASSWORD ?? 'CyberLens-Demo-Only-2026!'

  await page.goto('/')
  await expect(page.getByRole('heading', { name: 'Sign in to your workspace' })).toBeVisible()
  await expect(page.getByText('Demo workspace')).toHaveCount(0)

  await page.getByLabel('Username').fill(username)
  await page.getByLabel('Password').fill(password)
  await page.getByRole('button', { name: 'Sign in' }).click()

  await expect(page.getByRole('heading', { name: 'Change your temporary password' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Investigation workspace' })).toHaveCount(0)
})
