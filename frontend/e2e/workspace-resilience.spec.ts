import { expect, test, type Page, type Route } from '@playwright/test'

const analyst = { id: 'resilience-analyst', username: 'analyst', email: null, role: 'analyst', must_change_password: false, is_active: true }
const asset = { id: 'asset-one', kind: 'domain', identifier: 'synthetic.example.test', url_retention_complete: true, notes: '', criticality: 'unknown', data_classification: 'unknown', trust_zone: 'unknown', exposure_classification: 'unknown', business_owner: null, protection_requirements: [], authorized_at: null, authorization_note: null, authorization_id: null, authorization_expires_at: null, components: [] }
const incident = (id: string, title: string) => ({ id, title, summary: 'Synthetic case evidence.', classification: 'security_issue', status: 'new', priority: 'medium', owner_id: null, owner: null, asset_id: asset.id, asset_identifier: asset.identifier, investigation_id: null, created_at: '2026-10-20T08:00:00Z', updated_at: '2026-10-20T08:00:00Z', closed_at: null, resolution_summary: null, findings: [], evidence: [], events: [], tasks: [] })

async function mockWorkspace(page: Page, custom?: (path: string, route: Route) => Promise<boolean>) {
  await page.route('**/api/v1/**', async (route) => {
    const path = new URL(route.request().url()).pathname.replace('/api/v1', '')
    if (await custom?.(path, route)) return
    const json = (body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
    if (path === '/auth/me') return json(analyst)
    if (path === '/health/ready') return json({ status: 'ready', service: 'cyberlens', mode: 'demo', demo_data: true, dependencies: { database: true, redis: true, worker: true } })
    if (path === '/assets') return json([asset])
    if (path === '/investigations' || path === '/reports' || path === '/monitoring') return json([])
    if (path === '/incidents') return json([incident('case-one', 'First synthetic case'), incident('case-two', 'Second synthetic case')])
    if (path === '/integrations/status') return json({ integrations: [] })
    if (path.startsWith('/integrations/')) return json({ detail: 'Synthetic feed status outage' }, 503)
    if (path === '/attack/catalog') return json({ techniques: [] })
    if (path === '/attack/catalog/versions') return json({ active_catalog_version: null, active: null, versions: [], attribution: '', checksum_notice: '' })
    return json({ detail: 'No synthetic route' }, 404)
  })
}

test('base collection deep links load despite an optional integration outage', async ({ page }) => {
  await mockWorkspace(page, async (path, route) => {
    if (path !== '/integrations/openphish/status') return false
    await route.fulfill({ status: 200, contentType: 'application/json', body: '[]' })
    return true
  })
  const errors: Error[] = []
  page.on('pageerror', (error) => errors.push(error))
  await page.goto('/#/assets')
  await expect(page.getByRole('heading', { name: 'Assets', exact: true })).toBeVisible()
  await expect(page.getByText(asset.identifier, { exact: true })).toBeVisible()
  await expect(page.getByRole('alert')).toContainText('Other available workspace records are shown.')
  await page.evaluate(() => { window.location.hash = '#/integrations' })
  await expect(page.getByRole('heading', { name: 'OpenPhish Community Feed' })).toBeVisible()
  await expect(page.locator('section[aria-labelledby="openphish-feed-heading"]')).toContainText('status is unavailable.')
  await page.evaluate(() => { window.location.hash = '#/investigations' })
  await expect(page.getByRole('heading', { name: 'Investigations', exact: true })).toBeVisible()
  await page.evaluate(() => { window.location.hash = '#/incidents' })
  await expect(page.getByRole('heading', { name: 'Cases', exact: true })).toBeVisible()
  await page.evaluate(() => { window.location.hash = '#/assets/%E0%A4%A' })
  await expect(page.getByRole('alert').filter({ hasText: 'invalid encoded address' })).toBeVisible()
  expect(errors).toEqual([])
})

test('a slow old incident cannot replace the newly selected incident', async ({ page }) => {
  let releaseFirst!: () => void
  let markFirstRequested!: () => void
  let markFirstDelivered!: () => void
  const firstRequested = new Promise<void>((resolve) => { markFirstRequested = resolve })
  const firstDelivered = new Promise<void>((resolve) => { markFirstDelivered = resolve })
  const holdFirst = new Promise<void>((resolve) => { releaseFirst = resolve })
  await mockWorkspace(page, async (path, route) => {
    if (path === '/incidents/case-one') {
      markFirstRequested()
      await holdFirst
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(incident('case-one', 'First synthetic case')) }).catch(() => undefined)
      markFirstDelivered()
      return true
    }
    if (path === '/incidents/case-two') {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(incident('case-two', 'Second synthetic case')) })
      return true
    }
    return false
  })
  await page.goto('/#/incidents/case-one')
  await firstRequested
  await page.getByRole('button', { name: /Second synthetic case/ }).click()
  await expect(page.getByRole('heading', { name: 'Second synthetic case' })).toBeVisible()
  releaseFirst()
  await firstDelivered
  await expect(page.getByRole('heading', { name: 'First synthetic case' })).toHaveCount(0)
  await expect(page).toHaveURL(/#\/incidents\/case-two$/)
})

test('permanent investigation errors stop polling and finding-link errors are visible', async ({ page }) => {
  let detailCalls = 0
  await mockWorkspace(page, async (path, route) => {
    if (path === '/investigations/missing-investigation') {
      detailCalls += 1
      await route.fulfill({ status: 404, contentType: 'application/json', body: JSON.stringify({ detail: 'The requested investigation is unavailable.' }) })
      return true
    }
    if (path === '/findings/missing-finding') {
      await route.fulfill({ status: 404, contentType: 'application/json', body: JSON.stringify({ detail: 'The requested finding is unavailable.' }) })
      return true
    }
    return false
  })
  await page.goto('/#/investigations/missing-investigation')
  await expect(page.getByRole('alert')).toContainText('requested investigation is unavailable')
  // A permanent 404 must not schedule the next one-second polling attempt.
  await page.waitForTimeout(1300)
  expect(detailCalls).toBe(1)
  await page.evaluate(() => { window.location.hash = '#/findings/missing-finding' })
  await expect(page.getByRole('alert')).toContainText('requested finding is unavailable')
})

test('Demo provider evidence uses its saved synthetic collector identity', async ({ page }) => {
  const id = 'synthetic-provider-results'
  const summary = { id, asset_id: asset.id, asset_kind: 'domain', asset_identifier: asset.identifier,
    mode: 'demo', demo_data: true, scenario: 'routine_website', status: 'completed', progress: 100,
    started_at: '2026-10-20T08:00:00Z', finished_at: '2026-10-20T08:01:00Z', created_at: '2026-10-20T08:00:00Z',
    error_summary: null, attempt_number: 1, risk: null }
  const sources = [
    ['xposedornot', 'Synthetic XposedOrNot fixture'],
    ['openphish', 'Synthetic OpenPhish fixture'],
    ['spamhaus_drop', 'Synthetic Spamhaus DROP fixture'],
    ['cins_army', 'Synthetic CINS Army fixture'],
  ] as const
  const detail = { ...summary, asset, attempts: [], findings: [], risk: null, ip_intelligence: null,
    collector_runs: sources.map(([collector, source]) => ({ collector, source, status: 'success', record_count: 0 })),
    evidence: sources.map(([collector, source]) => ({ id: `evidence-${collector}`, source,
      observed_at: '2026-10-20T08:00:00Z', sha256: 'a'.repeat(64),
      evidence_json: { provider_status: 'no_match', result: 'not_listed_in_snapshot', records: [], matched_networks: [], freshness: 'synthetic', snapshot_age_seconds: 0, snapshot_id: `synthetic-${collector}-v1`, content_sha256: null } })) }
  await mockWorkspace(page, async (path, route) => {
    if (path === '/investigations') {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([summary]) })
      return true
    }
    if (path === `/investigations/${id}`) {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(detail) })
      return true
    }
    if (path === `/investigations/${id}/risk/simulation-options`) {
      await route.fulfill({ status: 200, contentType: 'application/json', body: '[]' })
      return true
    }
    if (path === `/investigations/${id}/graph`) {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ investigation_id: id, nodes: [], edges: [] }) })
      return true
    }
    return false
  })
  await page.goto(`/#/investigations/${id}`)
  await expect(page.getByRole('heading', { name: 'XposedOrNot community result' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'OpenPhish URL evidence' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Spamhaus DROP snapshot evidence' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'CINS Army exact-IP evidence' })).toBeVisible()
  await expect(page.locator('.evidence-details')).toContainText('Synthetic XposedOrNot fixture')
  await expect(page.locator('.evidence-details')).toContainText('Synthetic OpenPhish fixture')
})
