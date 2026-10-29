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
    await page.getByLabel('New password').fill('CyberLens-XON-Smoke-2026!')
    await page.getByRole('button', { name: 'Update password' }).click()
  }
  await expect(page.getByRole('heading', { name: 'Investigation workspace' })).toBeVisible()
}

test('Demo email investigation explicitly selects the offline XposedOrNot fixture', async ({ page }) => {
  await signIn(page)
  const email = `xposedornot-${Date.now()}@example.test`
  await page.getByRole('navigation', { name: 'Workspace', exact: true }).getByRole('button', { name: 'Assets', exact: true }).click()
  await page.getByLabel('Type').selectOption('email')
  await page.getByLabel('Identifier').fill(email)
  const assetResponse = page.waitForResponse((response) =>
    response.url().endsWith('/api/v1/assets') && response.request().method() === 'POST')
  await page.getByRole('button', { name: 'Add asset' }).click()
  const asset = await (await assetResponse).json() as { id: string }
  await expect(page.getByText(/Asset registered/)).toBeVisible()

  await page.getByRole('navigation', { name: 'Workspace', exact: true }).getByRole('button', { name: 'Investigations', exact: true }).click()
  await page.getByRole('combobox', { name: 'Asset', exact: true }).selectOption(asset.id)
  await page.getByLabel('Email breach provider').selectOption('xposedornot')
  await expect(page.locator('.xon-consent')).toContainText('synthetic offline XposedOrNot fixture')
  await expect(page.locator('.xon-consent')).toContainText('No address is sent externally')
  await page.getByRole('combobox', { name: 'Scenario', exact: true }).selectOption('exposed_email')

  const queued = page.waitForResponse((response) =>
    response.url().endsWith('/api/v1/investigations') && response.request().method() === 'POST')
  await page.getByRole('button', { name: 'Queue analysis' }).click()
  const response = await queued
  expect(response.ok()).toBeTruthy()
  const payload = await response.json() as { id: string }
  expect(response.request().postDataJSON()).toMatchObject({ email_breach_provider: 'xposedornot', scenario: 'exposed_email' })
  expect(response.request().postDataJSON()).not.toHaveProperty('xposedornot_authorization_confirmed')
  const resultPanel = page.getByRole('region', { name: 'XposedOrNot community result' })
  await expect(resultPanel).toBeVisible({ timeout: 30_000 })
  await expect(page.getByText('ExampleBreach (synthetic)', { exact: true })).toBeVisible()
  await expect(resultPanel.getByText(/coverage differs from HIBP/i)).toBeVisible()
  expect(payload.id).toBeTruthy()
})

test('Live XposedOrNot selection discloses the email and requires per-investigation confirmation', async ({ page }) => {
  const email = 'authorized-subject@example.test'
  const user = { id: 'xon-analyst', username: 'analyst', email: null, role: 'analyst',
    must_change_password: false, is_active: true }
  const asset = { id: 'xon-email-asset', kind: 'email', identifier: email, notes: '', created_by: user.id,
    criticality: 'unknown', data_classification: 'unknown', trust_zone: 'unknown', exposure_classification: 'unknown',
    business_owner: null, protection_requirements: null, authorization_id: null,
    authorization_expires_at: null, email_breach_authorization_id: null, email_breach_authorization_expires_at: null,
    created_at: '2026-10-19T00:00:00Z', updated_at: '2026-10-19T00:00:00Z' }
  await page.addInitScript(() => { document.cookie = 'cyberlens_csrf=xon-ui-token; path=/' })
  await page.route('**/api/v1/**', async (route) => {
    const url = new URL(route.request().url())
    const path = url.pathname.replace('/api/v1', '')
    const method = route.request().method()
    const json = (status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
    if (path === '/health/ready') return json(200, { status: 'ready', service: 'cyberlens', mode: 'live', demo_data: false,
      dependencies: { database: true, redis: true, worker: true } })
    if (path === '/auth/me') return json(401, { detail: 'Sign in required' })
    if (path === '/auth/csrf') return json(200, { csrf_token: 'xon-ui-token' })
    if (path === '/auth/login' && method === 'POST') return json(200, { user })
    if (path === '/assets' && method === 'GET') return json(200, [asset])
    if (path === '/investigations' && method === 'GET') return json(200, [])
    if (path === '/incidents' && method === 'GET') return json(200, [])
    if (path === '/reports' && method === 'GET') return json(200, [])
    if (path === '/integrations/status') return json(200, { mode: 'live', integrations: [
      { id: 'xposedornot', configured: true, enabled: true, behavior: 'Explicit personal/low-volume use only' },
    ] })
    if (path === '/investigations' && method === 'POST') return json(202, {
      id: 'xon-investigation', status: 'queued', progress: 0, mode: 'live', scenario: null,
      attempt_id: 'xon-attempt', attempt_number: 1,
    })
    if (path === '/investigations/xon-investigation') return json(200, {
      id: 'xon-investigation', status: 'queued', progress: 0, mode: 'live', demo_data: false, scenario: null,
      created_at: '2026-10-19T00:00:00Z', asset, attempts: [], collector_runs: [], findings: [], evidence: [], risk: null,
    })
    return json(200, [])
  })

  await page.goto('/')
  await page.getByLabel('Username').fill(user.username)
  await page.getByLabel('Password').fill('Synthetic-E2E-Password-2026!')
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { name: 'Investigation workspace' })).toBeVisible()
  await page.getByRole('navigation', { name: 'Workspace', exact: true }).getByRole('button', { name: 'Investigations', exact: true }).click()
  await page.getByRole('combobox', { name: 'Asset', exact: true }).selectOption(asset.id)
  await page.getByLabel('Email breach provider').selectOption('xposedornot')
  await expect(page.locator('.xon-consent')).toContainText(email)
  await expect(page.locator('.xon-consent')).toContainText('will be sent to XposedOrNot over HTTPS')
  await expect(page.getByRole('button', { name: 'Queue analysis' })).toBeDisabled()
  await page.getByLabel('I am authorized to submit this address to XposedOrNot for this lookup.').check()

  const queued = page.waitForResponse((response) =>
    response.url().endsWith('/api/v1/investigations') && response.request().method() === 'POST')
  await page.getByRole('button', { name: 'Queue analysis' }).click()
  const response = await queued
  expect(response.request().postDataJSON()).toMatchObject({
    asset_id: asset.id, email_breach_provider: 'xposedornot', xposedornot_authorization_confirmed: true,
  })
})
