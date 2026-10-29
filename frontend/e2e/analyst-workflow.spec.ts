import { expect, test, type Page } from '@playwright/test'

const navigation = (page: Page) => page.getByRole('navigation', { name: 'Workspace', exact: true })

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
    await page.getByLabel('New password').fill('CyberLens-Analyst-Workflow-2026!')
    await page.getByRole('button', { name: 'Update password' }).click()
  }
  await expect(page.getByRole('heading', { name: 'Investigation workspace' })).toBeVisible()
}

test('analyst can use keyboard navigation and deep links', async ({ page }) => {
  await signIn(page)
  await navigation(page).getByRole('button', { name: 'Assets', exact: true }).focus()
  await expect(navigation(page).getByRole('button', { name: 'Assets', exact: true })).toBeFocused()
  await page.goto('/#/assets')
  await expect(page.getByRole('heading', { name: 'Assets', exact: true })).toBeVisible()
  await page.goto('/#/investigations')
  await expect(page.getByRole('heading', { name: 'Investigations', exact: true })).toBeVisible()
  await page.goto('/#/remediation')
  await expect(page.getByRole('heading', { name: 'Remediation plans', exact: true })).toBeVisible()
  await page.goto('/#/threat-model')
  await expect(page.getByRole('heading', { name: 'Threat modeling', exact: true })).toBeVisible()
  await page.goto('/#/reports')
  await expect(page.getByRole('heading', { name: 'Reports', exact: true })).toBeVisible()
})

test('analyst records an assumption-labeled STRIDE scenario with an explained score', async ({ page }) => {
  await signIn(page)
  await navigation(page).getByRole('button', { name: 'Assets', exact: true }).click()
  await page.getByLabel('Type').selectOption('application')
  const identifier = `Threat model app ${Date.now()}`
  await page.getByLabel('Identifier').fill(identifier)
  await page.getByRole('button', { name: 'Add asset' }).click()
  await expect(page.getByText(/Asset registered/)).toBeVisible()
  await navigation(page).getByRole('button', { name: 'Threat model', exact: true }).click()
  const assetSelect = page.getByRole('combobox', { name: 'Asset', exact: true })
  const targetAssetId = await assetSelect.locator('option').filter({ hasText: identifier }).getAttribute('value')
  await assetSelect.selectOption(targetAssetId!)
  await page.getByLabel('STRIDE category').selectOption('information_disclosure')
  await page.getByLabel('Scenario title').fill('Payroll records may be disclosed')
  await page.getByLabel('Likelihood (1–5)').fill('3')
  await page.getByLabel('Business impact (1–5)').fill('5')
  await page.getByLabel('Confidence (1–5)').fill('2')
  await page.getByLabel('Analyst assumptions').fill('The application contains payroll records.')
  await page.getByLabel('Unconfirmed information').fill('Encryption at rest has not been verified.')
  await page.getByRole('button', { name: 'Create scenario' }).click()
  const createdScenario = page.getByRole('button', { name: /Payroll records may be disclosed/ }).filter({ hasText: identifier })
  await createdScenario.click()
  await expect(page.getByText('Business-impact scenario score: 15/25')).toBeVisible()
  await expect(createdScenario.getByText(/Unconfirmed: Encryption at rest has not been verified/)).toBeVisible()
})

test('viewer credentials keep protected analyst controls hidden', async ({ page }) => {
  test.skip(!process.env.CYBERLENS_VIEWER_USERNAME || !process.env.CYBERLENS_VIEWER_PASSWORD, 'Set viewer credentials for the role workflow.')
  await page.goto('/')
  await page.getByLabel('Username').fill(process.env.CYBERLENS_VIEWER_USERNAME!)
  await page.getByLabel('Password').fill(process.env.CYBERLENS_VIEWER_PASSWORD!)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { name: 'Investigation workspace' })).toBeVisible()
  await navigation(page).getByRole('button', { name: 'Assets', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Assets', exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Add asset' })).toHaveCount(0)
  await navigation(page).getByRole('button', { name: 'Investigations', exact: true }).click()
  await expect(page.getByRole('button', { name: 'Queue analysis' })).toHaveCount(0)
  await navigation(page).getByRole('button', { name: 'Threat model', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Threat modeling', exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Save asset context' })).toHaveCount(0)
  await expect(page.getByRole('button', { name: 'Create scenario' })).toHaveCount(0)
})
