import { expect, test } from '@playwright/test'

test('analyst can review and override an evidence-linked ATT&CK mapping', async ({ page }, testInfo) => {
  const timestamp = '2026-10-17T00:00:00Z'
  const mapping = {
    id: 'mapping-1', finding_id: null, incident_id: 'incident-1', technique_id: 'T1190',
    technique_name: 'Exploit Public-Facing Application', tactic: 'Initial Access',
    catalog_version: 'cyberlens-attack-enterprise-subset-1.0',
    rationale: 'Analyst-reviewed contextual candidate tied to saved evidence.', confidence: 0.35,
    source: 'cyberlens-rule:vulnerability_internet_facing_app', evidence_role: 'contextual',
    evidence_id: 'evidence-1', evidence_source: 'NVD fixture', evidence_observed_at: timestamp,
    decision: 'proposed', analyst_confirmed: false, created_by: 'analyst-1', reviewed_by: null as string | null,
    reviewed_at: null as string | null, created_at: timestamp, updated_at: timestamp,
  }
  const incident = {
    id: 'incident-1', title: 'ATT&CK UI case', summary: 'Synthetic UI test case', classification: 'confirmed_incident',
    status: 'triaged', priority: 'high', owner_id: 'analyst-1', owner: 'analyst', asset_id: 'asset-1',
    asset_identifier: 'attack-ui.example.test', investigation_id: 'investigation-1', created_at: timestamp,
    updated_at: timestamp, closed_at: null, resolution_summary: null, findings: [], evidence: [], events: [], tasks: [],
    attack_matrix: {
      incident_id: 'incident-1', catalog_version: 'cyberlens-attack-enterprise-subset-1.0',
      tactics: [{ tactic: 'Initial Access', mappings: [mapping] }], mappings: [mapping], suggestions: [], unmapped: [],
      notice: 'Candidate mappings are not proof of adversary behavior.',
    },
  }
  const catalog = { catalog_version: 'cyberlens-attack-enterprise-subset-1.0', framework: 'MITRE ATT&CK Enterprise',
    snapshot_date: '2026-10-17', source_url: 'https://attack.mitre.org/', techniques: [
      { id: 'T1190', name: 'Exploit Public-Facing Application', tactics: ['Initial Access'], url: 'https://attack.mitre.org/techniques/T1190/' },
      { id: 'T1078', name: 'Valid Accounts', tactics: ['Initial Access', 'Persistence'], url: 'https://attack.mitre.org/techniques/T1078/' },
    ] }
  await page.addInitScript(() => { document.cookie = 'cyberlens_csrf=ui-test-token; path=/' })
  await page.route('**/api/v1/**', async (route) => {
    const url = new URL(route.request().url())
    const path = url.pathname.replace('/api/v1', '')
    const method = route.request().method()
    const json = (status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
    if (path === '/health/ready') return json(200, { status: 'ready', service: 'cyberlens', mode: 'demo' })
    if (path === '/auth/me') return json(401, { detail: 'Sign in required' })
    if (path === '/auth/csrf') return json(200, { csrf_token: 'ui-test-token' })
    if (path === '/auth/login' && method === 'POST') return json(200, { user: { id: 'analyst-1', username: 'analyst', role: 'analyst', is_active: true, must_change_password: false } })
    if (path === '/assets') return json(200, [])
    if (path === '/investigations') return json(200, [])
    if (path === '/incidents' && method === 'GET') return json(200, [incident])
    if (path === '/incidents/incident-1' && method === 'GET') return json(200, incident)
    if (path === '/reports') return json(200, [])
    if (path === '/integrations/status') return json(200, { integrations: [] })
    if (path === '/attack/catalog') return json(200, catalog)
    if (path === '/attack/catalog/versions') return json(200, { active_catalog_version: catalog.catalog_version, active: {
      id: 'legacy', catalog_version: catalog.catalog_version, source: 'Bundled catalog', release_version: 'legacy-subset-1.0',
      source_reference: 'bundled:attack_enterprise_subset.json', retrieved_at: timestamp, checksum: 'a'.repeat(64),
      import_status: 'active', active: true, technique_count: 4, tactic_count: 3, subtechnique_count: 2, revoked_count: 0,
      deprecated_count: 0, error_summary: null, duplicate_of: null, requested_by: null, created_at: timestamp, completed_at: timestamp,
    }, versions: [], attribution: 'MITRE ATT&CK Terms of Use', checksum_notice: 'Checksum detects byte changes; it does not authenticate source independently.' })
    if (path === '/attack/mappings/mapping-1' && method === 'PATCH') {
      const body = route.request().postDataJSON() as { decision: string; technique_id?: string; tactic?: string }
      mapping.decision = body.decision as 'proposed' | 'approved' | 'rejected' | 'overridden'
      mapping.analyst_confirmed = body.decision === 'approved' || body.decision === 'overridden'
      mapping.reviewed_by = 'analyst-1'; mapping.reviewed_at = timestamp
      if (body.technique_id) { mapping.technique_id = body.technique_id; mapping.technique_name = 'Valid Accounts'; mapping.tactic = body.tactic ?? 'Initial Access'; mapping.source = 'analyst-override' }
      incident.attack_matrix.tactics[0].mappings = [mapping]
      incident.attack_matrix.mappings = [mapping]
      return json(200, mapping)
    }
    return json(404, { detail: `No test fixture for ${method} ${path}` })
  })

  await page.goto('/#/incidents/incident-1')
  await page.getByLabel('Username').fill('analyst')
  await page.getByLabel('Password').fill('test-password')
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { name: 'MITRE ATT&CK technique matrix' })).toBeVisible()
  await expect(page.getByText('Demo mode uses the bundled offline catalog. Synchronization requests are disabled.')).toBeVisible()
  await expect(page.getByText(/evidence-1/)).toBeVisible()
  await page.getByRole('button', { name: 'Approve', exact: true }).click()
  await expect(page.getByText(/analyst confirmed/)).toBeVisible()
  const override = page.getByRole('combobox', { name: 'Override technique for T1190' })
  await override.selectOption('T1078')
  await page.getByRole('button', { name: 'Override', exact: true }).click()
  await expect(page.getByRole('link', { name: 'T1078 · Valid Accounts' })).toBeVisible()
  await page.setViewportSize({ width: 1440, height: 1200 })
  await page.evaluate(() => {
    const matrix = document.querySelector('.attack-matrix')
    if (matrix) window.scrollTo(0, window.scrollY + matrix.getBoundingClientRect().top - 90)
  })
  await page.screenshot({ path: testInfo.outputPath('ui06-attack-matrix.png'), animations: 'disabled' })
})
