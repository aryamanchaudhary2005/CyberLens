import { expect, test, type Page } from '@playwright/test'

const url = 'https://phishing.example.test/login?campaign=synthetic'
const syntheticAsset = {
  id: 'openphish-demo-asset', kind: 'url', identifier: url, normalized_identifier: url,
  url_retention_complete: true, notes: '', created_by: 'openphish-demo-admin',
  criticality: 'unknown', data_classification: 'unknown', trust_zone: 'unknown',
  exposure_classification: 'unknown', business_owner: null, protection_requirements: [],
  authorized_at: null, authorization_id: null, authorization_expires_at: null,
  created_at: '2026-10-20T00:00:00Z', updated_at: '2026-10-20T00:00:00Z', components: [],
}
const openphishStatus = {
  id: 'openphish', name: 'OpenPhish Community Feed', enabled: false, mode: 'demo', freshness: 'synthetic',
  snapshot_id: 'synthetic-openphish-demo-v1', content_sha256: null, parser_version: 'openphish-demo-v1',
  record_count: 1, retrieved_at: null, published_at: null, last_successful_revalidation_at: null,
  snapshot_age_seconds: 0, freshness_limit_seconds: 86400, next_refresh_at: null, metadata: null,
  attribution: 'Synthetic OpenPhish fixture.', latest_attempt: null,
  coverage_note: 'Demo uses a synthetic reserved-domain URL and makes no external request.',
  configuration_state: 'synthetic_demo', configuration_reason: 'Demo uses a bundled synthetic fixture.',
  access_scope: 'synthetic_demo', integrity_valid: true,
}
const resultObservationAt = '2026-10-20T10:00:00Z'
const evidence = {
  id: 'openphish-demo-evidence', source: 'OpenPhish Community Feed', sha256: 'c'.repeat(64),
  observed_at: resultObservationAt,
  evidence_json: {
    provider: 'OpenPhish Community Feed', source_id: 'openphish', provider_version: 'openphish-demo-v1',
    provider_status: 'listed', result: 'listed', observed_at: resultObservationAt, match_scope: 'exact_url',
    snapshot_id: 'synthetic-openphish-demo-v1', content_sha256: null, parser_version: 'openphish-demo-v1',
    snapshot_record_count: 1, snapshot_retrieved_at: null, snapshot_age_seconds: 0, freshness: 'synthetic',
    attribution: 'Synthetic OpenPhish fixture.',
    coverage_note: 'The feed contains URL strings without per-indicator confidence, brand, or discovery time.',
    provenance: { schema_version: 1, source: 'OpenPhish Community Feed', provider: 'Synthetic fixture',
      provider_version: 'bundled fixture schema 1', observed_at: resultObservationAt,
      freshness: { state: 'synthetic', source_timestamp: null }, status: 'success' },
  },
}
const investigationSummary = {
  id: 'openphish-demo-investigation', asset_id: syntheticAsset.id, asset_kind: 'url',
  asset_identifier: url, mode: 'demo', scenario: 'openphish_match', status: 'completed', progress: 100,
  created_at: resultObservationAt, finished_at: resultObservationAt,
}
const investigationDetail = {
  ...investigationSummary, demo_data: true, requested_by: 'openphish-admin', error_summary: null,
  asset: syntheticAsset, attempts: [],
  collector_runs: [{ id: 'openphish-demo-run', attempt_id: 'openphish-demo-attempt', attempt_number: 1,
    collector: 'openphish', source: 'OpenPhish Community Feed', status: 'success', record_count: 1,
    error_explanation: null }],
  findings: [], evidence: [evidence], risk: null, ip_intelligence: null,
}

async function openWorkspace(page: Page, role: 'admin' | 'viewer', includeInvestigation = false) {
  const user = { id: `openphish-${role}`, username: role, email: null, role,
    must_change_password: false, is_active: true }
  await page.setViewportSize({ width: 1440, height: 900 })
  await page.addInitScript(() => { document.cookie = 'cyberlens_csrf=openphish-ui-token; path=/' })
  await page.route('**/api/v1/**', async (route) => {
    const url = new URL(route.request().url())
    const path = url.pathname.replace('/api/v1', '')
    const method = route.request().method()
    const json = (body: unknown, status = 200) => route.fulfill({
      status, contentType: 'application/json', body: JSON.stringify(body),
    })
    if (path === '/health/ready') return json({ status: 'ready', service: 'cyberlens', mode: 'demo', demo_data: true,
      dependencies: { database: true, redis: true, worker: true } })
    if (path === '/auth/me') return json({ detail: 'Sign in required' }, 401)
    if (path === '/auth/csrf') return json({ csrf_token: 'openphish-ui-token' })
    if (path === '/auth/login' && method === 'POST') return json({ user })
    if (path === '/assets') return json([syntheticAsset])
    if (path === '/investigations' && method === 'GET') return json(includeInvestigation ? [investigationSummary] : [])
    if (path === '/investigations/openphish-demo-investigation') return json(investigationDetail)
    if (path.endsWith('/risk/simulation-options')) return json([])
    if (path.endsWith('/graph')) return json({ investigation_id: investigationSummary.id,
      nodes: [], edges: [], mode: 'demo', notice: 'Synthetic fixture graph.' })
    if (path === '/integrations/status') return json({ mode: 'demo', integrations: [
      { id: 'openphish', name: 'OpenPhish Community URL feed', configured: true,
        behavior: 'Synthetic reserved-domain fixture; no network requests' },
    ] })
    if (path === '/integrations/openphish/status') return json(openphishStatus)
    if (path === '/integrations/spamhaus-drop/status' || path === '/integrations/cins-army/status') {
      return json({ id: path.includes('cins') ? 'cins_army' : 'spamhaus_drop', name: 'Synthetic feed',
        enabled: false, mode: 'demo', freshness: 'synthetic', snapshot_id: null, content_sha256: null,
        parser_version: 'demo-v1', record_count: 0, retrieved_at: null, published_at: null,
        last_successful_revalidation_at: null, snapshot_age_seconds: 0, freshness_limit_seconds: 1,
        next_refresh_at: null, metadata: null, attribution: 'Synthetic', latest_attempt: null,
        coverage_note: 'Synthetic fixture.' })
    }
    if (path === '/investigations' || path === '/incidents' || path === '/reports' || path === '/monitoring') return json([])
    return json([])
  })
  const initialAuth = page.waitForResponse((response) => response.url().endsWith('/auth/me'))
  await page.goto('/#/integrations')
  await initialAuth
  await page.getByLabel('Username').fill(role)
  await page.getByLabel('Password').fill('Synthetic-Role-Test-Password-2026!')
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { name: 'OpenPhish Community Feed' })).toBeVisible()
}

test('Admin sees offline OpenPhish terms and can select the synthetic exact-match scenario', async ({ page }) => {
  await openWorkspace(page, 'admin')
  const panel = page.locator('section[aria-labelledby="openphish-feed-heading"]')
  await expect(panel).toContainText('settings record operator intent; they do not grant provider rights')
  await expect(panel).toContainText('synthetic demo')
  await expect(panel.getByText(url, { exact: true })).toHaveCount(0)
  await expect(panel.getByRole('button', { name: 'Queue feed refresh' })).toBeDisabled()
  await expect(panel).toContainText('no provider request is made')

  await page.getByRole('button', { name: /Assets/ }).click()
  await page.getByRole('button', { name: new RegExp('phishing\\.example\\.test') }).click()
  await page.getByLabel('Demo scenario').selectOption('openphish_match')
  await expect(page.getByLabel('Demo scenario')).toHaveValue('openphish_match')
  await expect(page.getByText(/Demo performs no provider or destination requests/)).toBeVisible()
})

test('Viewer can inspect OpenPhish restrictions but cannot refresh the snapshot', async ({ page }) => {
  await openWorkspace(page, 'viewer')
  const panel = page.locator('section[aria-labelledby="openphish-feed-heading"]')
  await expect(panel.getByText('synthetic-openphish-demo-v1')).toBeVisible()
  await expect(panel.getByRole('button', { name: 'Queue feed refresh' })).toHaveCount(0)
})

test('investigation results show OpenPhish match type, freshness, provenance, and analyst review rule', async ({ page }) => {
  await openWorkspace(page, 'admin', true)
  await page.getByRole('button', { name: 'Investigations' }).click()
  await page.getByRole('button', { name: /phishing\.example\.test/ }).click()
  const result = page.locator('.openphish-evidence')
  await expect(result.getByRole('heading', { name: 'OpenPhish URL evidence' })).toBeVisible()
  await expect(result).toContainText('URL listed in OpenPhish snapshot')
  await expect(result).toContainText('Exact URL match')
  await expect(result).toContainText('synthetic · 0 h old')
  await expect(result).toContainText('synthetic-openphish-demo-v1 · evidence openphish-demo-evidence')
  await expect(result).toContainText('only an analyst decision of applies affects risk')
  await expect(result).toContainText('does not prove that the page is reachable')
  await expect(result).not.toContainText(url)
})
