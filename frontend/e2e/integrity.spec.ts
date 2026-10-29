import { expect, test } from '@playwright/test'

test('analyst can review audit and evidence integrity and export the audit chain', async ({ page }, testInfo) => {
  await page.addInitScript(() => { document.cookie = 'cyberlens_csrf=integrity-test-token; path=/' })
  await page.route('**/api/v1/**', async (route) => {
    const url = new URL(route.request().url())
    const path = url.pathname.replace('/api/v1', '')
    const method = route.request().method()
    const json = (status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
    if (path === '/health/ready') return json(200, { status: 'ready', service: 'cyberlens', mode: 'demo' })
    if (path === '/auth/me') return json(401, { detail: 'Sign in required' })
    if (path === '/auth/csrf') return json(200, { csrf_token: 'integrity-test-token' })
    if (path === '/auth/login' && method === 'POST') return json(200, { user: { id: 'analyst-1', username: 'analyst', role: 'analyst', is_active: true, must_change_password: false } })
    if (path === '/assets' || path === '/investigations' || path === '/incidents' || path === '/reports') return json(200, [])
    if (path === '/integrations/status') return json(200, { integrations: [] })
    if (path === '/integrity') return json(200, {
      state: 'verified', checked_at: '2026-10-17T00:00:00Z',
      audit_chain: { state: 'verified', checked_at: '2026-10-17T00:00:00Z', event_count: 4, verified_count: 4,
        last_sequence: 4, last_hash: 'a'.repeat(64), failed_sequence: null, message: 'Every audit event and the chain head verified.' },
      evidence: { state: 'verified', total: 1, checked: 1, counts: { verified: 1, failed: 0, unavailable: 0, incomplete: 0 } },
    })
    if (path === '/integrity/evidence') return json(200, [{ evidence_id: 'evidence-1', state: 'verified', source: 'RDAP fixture',
      observed_at: '2026-10-17T00:00:00Z', stored_sha256: 'b'.repeat(64), calculated_sha256: 'b'.repeat(64), is_synthetic: true }])
    if (path === '/integrity/audit-export') return route.fulfill({ status: 200, contentType: 'application/x-ndjson',
      headers: { 'X-Audit-Chain-State': 'verified' }, body: '{"event_sequence":4}\n' })
    return json(404, { detail: `No test fixture for ${method} ${path}` })
  })

  await page.goto('/#/integrity')
  await page.getByLabel('Username').fill('analyst')
  await page.getByLabel('Password').fill('test-password')
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { name: 'Workspace integrity' })).toBeVisible()
  await expect(page.getByText('Every audit event and the chain head verified.')).toBeVisible()
  await expect(page.getByText('RDAP fixture')).toBeVisible()
  const download = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Export audit JSONL' }).click()
  await expect(await download).toBeTruthy()
  await page.screenshot({ path: testInfo.outputPath('ui06-integrity-verified.png'), fullPage: true, animations: 'disabled' })
})

test('viewer can inspect integrity but cannot export the audit chain', async ({ page }) => {
  await page.route('**/api/v1/**', async (route) => {
    const path = new URL(route.request().url()).pathname.replace('/api/v1', '')
    const json = (status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
    if (path === '/health/ready') return json(200, { status: 'ready', service: 'cyberlens', mode: 'demo' })
    if (path === '/auth/me') return json(200, { id: 'viewer-1', username: 'viewer', role: 'viewer', is_active: true, must_change_password: false })
    if (['/assets', '/investigations', '/incidents', '/reports'].includes(path)) return json(200, [])
    if (path === '/integrations/status') return json(200, { integrations: [] })
    if (path === '/integrity') return json(200, {
      state: 'incomplete', checked_at: '2026-10-17T00:00:00Z',
      audit_chain: { state: 'verified', checked_at: '2026-10-17T00:00:00Z', event_count: 0, verified_count: 0,
        last_sequence: 0, last_hash: '0'.repeat(64), failed_sequence: null, message: 'The chain has no events yet.' },
      evidence: { state: 'incomplete', total: 0, checked: 0, counts: { verified: 0, failed: 0, unavailable: 0, incomplete: 0 } },
    })
    if (path === '/integrity/evidence') return json(200, [])
    return json(404, { detail: `No test fixture for ${route.request().method()} ${path}` })
  })
  await page.goto('/#/integrity')
  await expect(page.getByRole('heading', { name: 'Workspace integrity' })).toBeVisible()
  await expect(page.locator('.integrity-overview').getByText('incomplete', { exact: true }).first()).toBeVisible()
  await expect(page.getByRole('button', { name: 'Export audit JSONL' })).toHaveCount(0)
})
