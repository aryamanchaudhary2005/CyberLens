import { expect, test } from '@playwright/test'

test('application starts and the initial administrator can sign in', async ({ page }, testInfo) => {
  const username = process.env.CYBERLENS_SMOKE_USERNAME ?? 'admin'
  const password = process.env.CYBERLENS_SMOKE_PASSWORD ?? 'CyberLens-Demo-Only-2026!'
  const consoleErrors: string[] = []
  const failedRequests: string[] = []
  const unexpectedHttpErrors: string[] = []
  let expectedAuthProbes = 0
  const serverErrors: string[] = []
  page.on('pageerror', (error) => consoleErrors.push(error.message))
  page.on('console', (message) => {
    if (message.type() === 'error') consoleErrors.push(message.text())
  })
  page.on('requestfailed', (request) => {
    if (request.failure()?.errorText === 'net::ERR_ABORTED') return
    failedRequests.push(`${request.method()} ${new URL(request.url()).pathname}`)
  })
  page.on('response', (response) => {
    const requestPath = new URL(response.url()).pathname
    const requestSummary = `${response.request().method()} ${requestPath} ${response.status()}`
    if (response.status() === 401 && response.request().method() === 'GET' && requestPath === '/api/v1/auth/me') {
      // The login screen probes the current session; Chrome reports this expected 401 in the console.
      expectedAuthProbes += 1
    } else if (response.status() >= 400) {
      unexpectedHttpErrors.push(requestSummary)
    }
    if (response.status() >= 500) serverErrors.push(requestSummary)
  })

  await page.goto('/')
  await expect(page.getByRole('heading', { name: 'Sign in to your workspace' })).toBeVisible()
  await expect(page.getByText('Demo workspace')).toBeVisible()
  await page.setViewportSize({ width: 1440, height: 1000 })
  await page.screenshot({ path: testInfo.outputPath('login-desktop.png'), fullPage: true, animations: 'disabled' })

  await page.getByLabel('Username').fill(username)
  await page.getByLabel('Password').fill(password)
  const loginResponse = page.waitForResponse((response) => response.url().endsWith('/api/v1/auth/login') && response.request().method() === 'POST')
  await page.getByRole('button', { name: 'Sign in' }).click()
  const login = await loginResponse
  expect(login.ok()).toBeTruthy()
  const session = await login.json() as { user: { must_change_password: boolean } }

  const passwordChange = page.getByRole('heading', { name: 'Change your temporary password' })
  if (session.user.must_change_password) {
    await expect(passwordChange).toBeVisible()
    await page.getByLabel('Current password').fill(password)
    await page.getByLabel('New password').fill('CyberLens-Smoke-Changed-Password-2026!')
    const passwordResponse = page.waitForResponse((response) => response.url().endsWith('/api/v1/auth/change-password') && response.request().method() === 'POST')
    await page.getByRole('button', { name: 'Update password' }).click()
    expect((await passwordResponse).ok()).toBeTruthy()
  }

  await expect(page.getByRole('heading', { name: 'Investigation workspace' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'System and integration status' })).toBeVisible()
  await expect(page.locator('.workspace-status-card > .panel-heading .status-badge')).toHaveText('ready')
  await expect(page.locator('.service-status-item').filter({ hasText: 'Analysis API' }).getByText('available', { exact: true })).toBeVisible()
  await expect(page.getByText(/^Loading workspace records/)).toBeHidden()
  await expect(page.getByText(/^Loading provider observations/)).toBeHidden()
  await expect(page.getByText('Overall risk', { exact: true })).toBeVisible()

  await page.screenshot({ path: testInfo.outputPath('overview-desktop-1440.png'), fullPage: true, animations: 'disabled' })
  for (const width of [390, 768]) {
    await page.setViewportSize({ width, height: width === 390 ? 844 : 1024 })
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
    await page.screenshot({ path: testInfo.outputPath(`overview-${width}.png`), fullPage: true, animations: 'disabled' })
  }

  console.log(`MODULE31_BROWSER_DIAGNOSTICS ${JSON.stringify({ console_errors: consoleErrors, expected_auth_401s: expectedAuthProbes, unexpected_http_errors: unexpectedHttpErrors, failed_requests: failedRequests, server_errors: serverErrors })}`)
  const expectedAuthConsoleErrors = consoleErrors.filter((message) => message.includes('status of 401'))
  const unexpectedConsoleErrors = consoleErrors.filter((message) => !message.includes('status of 401'))
  expect(expectedAuthProbes).toBeGreaterThan(0)
  expect(expectedAuthConsoleErrors).toHaveLength(expectedAuthProbes)
  expect(unexpectedConsoleErrors).toEqual([])
  expect(unexpectedHttpErrors).toEqual([])
  expect(failedRequests).toEqual([])
  expect(serverErrors).toEqual([])
})
