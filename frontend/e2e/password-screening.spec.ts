import { expect, test, type Page } from '@playwright/test'

const syntheticPassword = 'Synthetic-E2E-Password-2026!'
const user = { id: 'screen-admin', username: 'admin', email: null, role: 'admin', is_active: true, must_change_password: true }

async function startWithTemporaryPassword(page: Page, responseStatus: 422 | 503, detail: string) {
  await page.addInitScript(() => { document.cookie = 'cyberlens_csrf=screening-test-token; path=/' })
  await page.route('**/api/v1/**', async (route) => {
    const url = new URL(route.request().url())
    const path = url.pathname.replace('/api/v1', '')
    const method = route.request().method()
    const json = (status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
    if (path === '/health/ready') return json(200, { status: 'ready', service: 'cyberlens', mode: 'live', demo_data: false, dependencies: { database: true, redis: true, worker: true } })
    if (path === '/auth/me') return json(401, { detail: 'Sign in required' })
    if (path === '/auth/csrf') return json(200, { csrf_token: 'screening-test-token' })
    if (path === '/auth/login' && method === 'POST') return json(200, { user })
    if (path === '/auth/change-password' && method === 'POST') return json(responseStatus, { detail })
    return json(404, { detail: `No screening fixture for ${method} ${path}` })
  })
  await page.goto('/')
  await page.getByLabel('Username').fill('admin')
  await page.getByLabel('Password').fill('Synthetic-Existing-Password-2026!')
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { name: 'Change your temporary password' })).toBeVisible()
  await page.getByLabel('Current password').fill('Synthetic-Existing-Password-2026!')
  await page.getByLabel('New password').fill(syntheticPassword)
  await page.getByRole('button', { name: 'Update password' }).click()
}

test('password change explains a confirmed Pwned Passwords match', async ({ page }) => {
  await startWithTemporaryPassword(page, 422,
    'Choose a different password. This password appears in the Pwned Passwords dataset; this does not mean your CyberLens account was breached.')
  await expect(page.getByRole('alert')).toContainText('Choose a different password')
  await expect(page.getByRole('alert')).toContainText('does not mean your CyberLens account was breached')
  await expect(page.getByLabel('New password')).toHaveValue('')
})

test('password change explains a temporary screening outage and asks for retry', async ({ page }) => {
  await startWithTemporaryPassword(page, 503,
    'Password screening is temporarily unavailable. Please retry; your password was not changed.')
  await expect(page.getByRole('alert')).toContainText('temporarily unavailable')
  await expect(page.getByRole('alert')).toContainText('Please retry')
  await expect(page.getByLabel('New password')).toHaveValue('')
})
