import { expect, test } from '@playwright/test'

test('administrator can queue official catalog synchronization and inspect its status', async ({ page }, testInfo) => {
  const timestamp = '2026-10-19T00:00:00Z'
  const incident = {
    id: 'incident-catalog', title: 'Catalog status case', summary: 'Catalog UI fixture', classification: 'security_issue',
    status: 'triaged', priority: 'medium', owner_id: 'admin-1', owner: 'admin', asset_id: 'asset-1',
    asset_identifier: 'catalog.example.test', investigation_id: null, created_at: timestamp, updated_at: timestamp,
    closed_at: null, resolution_summary: null, findings: [], evidence: [], events: [], tasks: [],
    attack_matrix: { incident_id: 'incident-catalog', catalog_version: 'legacy-subset-v1', tactics: [], mappings: [],
      suggestions: [], unmapped: [], notice: 'Mappings are analyst reviewed.' },
  }
  const active = {
    id: 'active-version', catalog_version: 'mitre-attack-enterprise-20.0-a'.repeat(1),
    source: 'MITRE ATT&CK Enterprise STIX 2.1', release_version: '20.0',
    source_reference: 'https://github.com/mitre-attack/attack-stix-data/blob/0123456789abcdef0123456789abcdef01234567/enterprise-attack/enterprise-attack-20.0.json',
    retrieved_at: timestamp, checksum: 'a'.repeat(64), import_status: 'active', active: true,
    technique_count: 620, tactic_count: 14, subtechnique_count: 520, revoked_count: 8, deprecated_count: 3,
    error_summary: null, duplicate_of: null, requested_by: 'admin-1', created_at: timestamp, completed_at: timestamp,
  }
  let syncRequested = false
  const pending = { ...active, id: 'pending-version', catalog_version: 'sync-111', release_version: null,
    source_reference: null, retrieved_at: null, checksum: null, import_status: 'queued', active: false,
    technique_count: 0, tactic_count: 0, subtechnique_count: 0, revoked_count: 0, deprecated_count: 0,
    created_at: timestamp, completed_at: null }
  await page.addInitScript(() => { document.cookie = 'cyberlens_csrf=ui-test-token; path=/' })
  await page.route('**/api/v1/**', async (route) => {
    const url = new URL(route.request().url())
    const path = url.pathname.replace('/api/v1', '')
    const method = route.request().method()
    const json = (status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
    if (path === '/health/ready') return json(200, { status: 'ready', service: 'cyberlens', mode: 'live' })
    if (path === '/auth/me') return json(401, { detail: 'Sign in required' })
    if (path === '/auth/csrf') return json(200, { csrf_token: 'ui-test-token' })
    if (path === '/auth/login' && method === 'POST') return json(200, { user: { id: 'admin-1', username: 'admin', role: 'admin', is_active: true, must_change_password: false } })
    if (path === '/assets') return json(200, [])
    if (path === '/investigations') return json(200, [])
    if (path === '/incidents' && method === 'GET') return json(200, [incident])
    if (path === '/incidents/incident-catalog' && method === 'GET') return json(200, incident)
    if (path === '/reports') return json(200, [])
    if (path === '/integrations/status') return json(200, { integrations: [] })
    if (path === '/attack/catalog') return json(200, { catalog_version: active.catalog_version, framework: 'MITRE ATT&CK Enterprise',
      snapshot_date: '2026-10-19', source_url: 'https://attack.mitre.org/', release_version: '20.0', techniques: [] })
    if (path === '/attack/catalog/versions') return json(200, { active_catalog_version: active.catalog_version, active,
      versions: syncRequested ? [pending, active] : [active], attribution: 'MITRE ATT&CK Terms of Use',
      checksum_notice: 'Checksum detects byte changes; it does not authenticate source independently.' })
    if (path === '/attack/catalog/sync' && method === 'POST') { syncRequested = true; return json(202, pending) }
    return json(404, { detail: `No test fixture for ${method} ${path}` })
  })

  await page.goto('/#/incidents/incident-catalog')
  await page.getByLabel('Username').fill('admin')
  await page.getByLabel('Password').fill('test-password')
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { name: 'ATT&CK catalog versions' })).toBeVisible()
  await expect(page.getByText('Enterprise ATT&CK 20.0')).toBeVisible()
  await page.getByRole('button', { name: 'Synchronize official Enterprise catalog' }).click()
  await expect(page.getByText('Sync queued')).toBeVisible()
  await expect(page.getByText(/checksum detects byte changes/i)).toBeVisible()
  await page.screenshot({ path: testInfo.outputPath('ui06-attack-catalog.png'), fullPage: true, animations: 'disabled' })
})
