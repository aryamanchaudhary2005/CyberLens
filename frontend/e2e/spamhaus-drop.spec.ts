import { expect, test, type Page } from '@playwright/test'

const status = {
  id: 'spamhaus_drop', name: 'Spamhaus DROP IPv4 and IPv6', enabled: true, mode: 'live', freshness: 'fresh',
  snapshot_id: 'snapshot-demo-ui-v1', content_sha256: 'a'.repeat(64), parser_version: 'spamhaus-drop-jsonl-v1',
  record_count: 2, retrieved_at: '2026-10-20T00:00:00Z', published_at: '2026-10-20T00:00:00Z',
  last_successful_revalidation_at: '2026-10-20T00:00:00Z', snapshot_age_seconds: 3600,
  freshness_limit_seconds: 172800, next_refresh_at: '2026-10-21T00:00:00Z',
  metadata: { feeds: { ipv4: { provider_metadata: { copyright: 'Copyright (c) 2026 Spamhaus Project' } } } },
  attribution: 'Spamhaus Project DROP data. Retain the provider date and copyright with this data.',
  latest_attempt: null, coverage_note: 'A no-match means only that an IP is not listed in this snapshot; it does not establish safety.',
}
const cinsStatus = {
  id: 'cins_army', name: 'CINS Army IP list', enabled: true, mode: 'live', freshness: 'fresh',
  snapshot_id: 'cins-snapshot-demo-ui-v1', content_sha256: 'b'.repeat(64), parser_version: 'cins-army-ip-list-v1',
  record_count: 3, retrieved_at: '2026-10-20T00:00:00Z', published_at: null,
  last_successful_revalidation_at: '2026-10-20T00:00:00Z', snapshot_age_seconds: 3600,
  freshness_limit_seconds: 172800, next_refresh_at: '2026-10-21T00:00:00Z', metadata: null,
  attribution: 'Synthetic CINS Army fixture attribution.', latest_attempt: null,
  coverage_note: 'This feed contains individual IP addresses only.', integrity_valid: true,
}

async function mockWorkspace(page: Page, role: 'admin' | 'viewer') {
  const user = { id: `drop-${role}`, username: role, email: null, role, must_change_password: false, is_active: true }
  await page.setViewportSize({ width: 1440, height: 900 })
  await page.addInitScript(() => { document.cookie = 'cyberlens_csrf=drop-ui-token; path=/' })
  await page.route('**/api/v1/**', async (route) => {
    const url = new URL(route.request().url())
    const path = url.pathname.replace('/api/v1', '')
    const method = route.request().method()
    const json = (body: unknown, statusCode = 200) => route.fulfill({
      status: statusCode, contentType: 'application/json', body: JSON.stringify(body),
    })
    if (path === '/health/ready') return json({ status: 'ready', service: 'cyberlens', mode: 'live', demo_data: false,
      dependencies: { database: true, redis: true, worker: true } })
    if (path === '/auth/me') return json({ detail: 'Sign in required' }, 401)
    if (path === '/auth/csrf') return json({ csrf_token: 'drop-ui-token' })
    if (path === '/auth/login' && method === 'POST') return json({ user })
    if (path === '/assets' || path === '/investigations' || path === '/incidents' || path === '/reports') return json([])
    if (path === '/integrations/status') return json({ mode: 'live', integrations: [] })
    if (path === '/integrations/spamhaus-drop/status') return json(status)
    if (path === '/integrations/cins-army/status') return json(cinsStatus)
    if (path === '/integrations/spamhaus-drop/refresh' && method === 'POST') return json({
      id: 'attempt-ui-v1', status: 'queued', trigger_kind: 'admin', requested_at: '2026-10-20T00:00:00Z',
      next_refresh_at: '2026-10-21T00:00:00Z', message: 'Refresh queued.',
    }, 202)
    if (path === '/integrations/cins-army/refresh' && method === 'POST') return json({
      id: 'cins-attempt-ui-v1', status: 'queued', trigger_kind: 'admin', requested_at: '2026-10-20T00:00:00Z',
      next_refresh_at: '2026-10-21T00:00:00Z', message: 'CINS refresh queued.',
    }, 202)
    return json([])
  })
  const initialAuth = page.waitForResponse((response) => response.url().endsWith('/auth/me'))
  await page.goto('/#/integrations')
  await initialAuth
  await page.getByLabel('Username').fill(role)
  await page.getByLabel('Password').fill('Synthetic-Role-Test-Password-2026!')
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { name: 'Spamhaus DROP snapshot' })).toBeVisible()
}

test('Admin sees attributed snapshot status and can queue a CSRF-protected refresh', async ({ page }) => {
  await mockWorkspace(page, 'admin')
  await expect(page.getByText('snapshot-demo-ui-v1', { exact: true })).toBeVisible()
  await expect(page.getByText('Copyright (c) 2026 Spamhaus Project')).toBeVisible()
  await expect(page.getByText(/does not establish safety/)).toBeVisible()
  const panel = page.locator('section[aria-labelledby="spamhaus-feed-heading"]')
  const refresh = page.waitForRequest((request) => request.url().endsWith('/spamhaus-drop/refresh'))
  await panel.getByRole('button', { name: 'Queue feed refresh' }).click()
  const request = await refresh
  expect(request.method()).toBe('POST')
  expect(request.headers()['x-csrf-token']).toBe('drop-ui-token')
})

test('Admin can inspect the CINS snapshot and queue its independent refresh', async ({ page }, testInfo) => {
  await mockWorkspace(page, 'admin')
  const panel = page.locator('section[aria-labelledby="cins-feed-heading"]')
  await expect(panel.getByText('cins-snapshot-demo-ui-v1')).toBeVisible()
  await expect(panel.getByText('Passed · checksum detects later changes; it does not independently prove source authenticity.')).toBeVisible()
  await expect(panel.getByText('The 24-hour default is CyberLens configuration; it is not a claim about the provider\'s publication frequency.')).toBeVisible()
  await page.screenshot({ path: testInfo.outputPath('ui06-integration-feeds.png'), fullPage: true, animations: 'disabled' })
  const refresh = page.waitForRequest((request) => request.url().endsWith('/cins-army/refresh'))
  await panel.getByRole('button', { name: 'Queue feed refresh' }).click()
  const request = await refresh
  expect(request.method()).toBe('POST')
  expect(request.headers()['x-csrf-token']).toBe('drop-ui-token')
})

test('Viewer can inspect feed status but has no refresh control', async ({ page }) => {
  await mockWorkspace(page, 'viewer')
  await expect(page.getByText('snapshot-demo-ui-v1', { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Queue feed refresh' })).toHaveCount(0)
  const cinsPanel = page.locator('section[aria-labelledby="cins-feed-heading"]')
  await expect(cinsPanel.getByText('cins-snapshot-demo-ui-v1')).toBeVisible()
  await expect(cinsPanel.getByRole('button', { name: 'Queue feed refresh' })).toHaveCount(0)
})
