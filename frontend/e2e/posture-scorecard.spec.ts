import { expect, test, type Page } from '@playwright/test'

function metric<T extends Record<string, unknown>>(state: string, values: T, rangeDays: number): T & Record<string, unknown> {
  return {
    state, range_days: rangeDays,
    window_start: new Date(Date.parse('2026-10-17T12:00:00Z') - rangeDays * 24 * 60 * 60 * 1000).toISOString(),
    window_end: '2026-10-17T12:00:00Z',
    scope: 'Registered workspace assets', note: 'Missing observations are not treated as safe.', ...values,
  }
}

function scorecard(empty = false, rangeDays = 30) {
  const metricForRange = <T extends Record<string, unknown>>(state: string, values: T) => metric(state, values, rangeDays)
  return {
    schema_version: 'cyberlens-posture-1.0', generated_at: '2026-10-17T12:00:00Z', range_days: rangeDays,
    window_start: new Date(Date.parse('2026-10-17T12:00:00Z') - rangeDays * 24 * 60 * 60 * 1000).toISOString(), window_end: '2026-10-17T12:00:00Z',
    data_scope: { source: 'PostgreSQL saved workspace records', asset_count: empty ? 0 : 2, investigation_count: empty ? 0 : 2, data_modes: empty ? [] : ['live'] },
    overall_risk: metricForRange(empty ? 'empty' : 'partial', { average_score: empty ? null : 68.5, band: empty ? null : 'high', assets_in_scope: empty ? 0 : 2, assets_with_score: empty ? 0 : 1, assessments_used: empty ? 0 : 1 }),
    assessment_coverage: metricForRange(empty ? 'empty' : 'partial', { assessed_category_slots: empty ? 0 : 3, expected_category_slots: empty ? 0 : 6, coverage_percent: empty ? null : 50, assets_in_scope: empty ? 0 : 2, assets_with_recent_assessment: empty ? 0 : 1, assets_with_score: empty ? 0 : 1, unassessed_category_slots: empty ? 0 : 3 }),
    unassessed_categories: metricForRange(empty ? 'empty' : 'partial', { counts: empty ? {} : { reputation: 1, tls_web: 1, dns_email: 1 }, assets_without_recent_assessment: empty ? 0 : 1, total_unassessed_category_slots: empty ? 0 : 3 }),
    high_critical_findings: metricForRange(empty ? 'empty' : 'partial', { high: empty ? null : 1, critical: empty ? null : 0, total: empty ? null : 1, open_high: null, open_critical: null, open_total: null, open_counts_available: false, assets_with_recent_observation: empty ? 0 : 1, assets_in_scope: empty ? 0 : 2, lifecycle_status_available: false }),
    repeated_findings: metricForRange(empty ? 'empty' : 'available', { repeated_finding_count: empty ? null : 1, repeated_observation_count: empty ? null : 2, distinct_finding_identities: empty ? null : 1, investigations_in_scope: empty ? 0 : 2 }),
    risk_trend: metricForRange(empty ? 'empty' : 'available', { interval: 'day', points: empty ? [] : [
      { period_start: '2026-10-15', average_score: 68.5, asset_count: 1, policy_versions: ['cyberlens-academic-1.0'] },
      { period_start: '2026-10-16', average_score: 41, asset_count: 1, policy_versions: ['cyberlens-academic-2.0'] },
    ], assessments_in_scope: empty ? 0 : 2 }),
    workflow_trend: metricForRange(empty ? 'empty' : 'available', { interval: 'day', points: empty ? [] : [{ period_start: '2026-10-16', investigations: { completed: 1, total: 1 }, monitoring_runs: { completed: 1, total: 1 } }], investigations_count: empty ? 0 : 1, monitoring_run_count: empty ? 0 : 1 }),
    incident_timings: metricForRange(empty ? 'empty' : 'partial', { incident_count: empty ? 0 : 1, triaged_count: 0, triage_pending_or_unrecorded_count: empty ? 0 : 1, triage_mean_seconds: null, triage_median_seconds: null, resolved_count: 0, unresolved_or_unrecorded_count: empty ? 0 : 1, resolution_mean_seconds: null, resolution_median_seconds: null }),
    provider_health: metricForRange(empty ? 'empty' : 'partial', { providers: empty ? [] : [{ id: 'reputation', name: 'VirusTotal', state: 'unavailable', configured: false, eligible_asset_count: 1, provider_status: 'unavailable', source: null, last_observed_at: null, freshness: 'unavailable', data_mode: null, note: 'No observation' }] }),
    asset_criticality: metricForRange(empty ? 'empty' : 'partial', { counts: empty ? { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 } : { critical: 0, high: 1, medium: 0, low: 0, unknown: 1 }, asset_count: empty ? 0 : 2 }),
    security_control_coverage: metricForRange(empty ? 'empty' : 'partial', { findings_in_scope: empty ? 0 : 1, findings_with_mapping: empty ? null : 1, findings_with_validated_mapping: empty ? null : 0, mapped_finding_percent: empty ? null : 100, validated_finding_percent: empty ? null : 0, catalog_version: 'cyberlens-controls-1.0', catalog_control_count: 8, controls_with_validated_findings: empty ? null : 0 }),
  }
}

function feedStatus(id: 'spamhaus_drop' | 'cins_army' | 'openphish') {
  return {
    id, name: id, enabled: false, mode: 'live', freshness: 'not_assessed', snapshot_id: null,
    content_sha256: null, parser_version: 'test-1.0', record_count: 0, retrieved_at: null,
    published_at: null, last_successful_revalidation_at: null, snapshot_age_seconds: null,
    freshness_limit_seconds: 86400, next_refresh_at: null, metadata: null,
    attribution: 'Mocked browser fixture', latest_attempt: null,
    coverage_note: 'Test fixture; no provider request is made.', configuration_state: 'unconfigured',
    configuration_reason: 'No provider connection in this UI test', access_scope: 'public',
  }
}

async function installWorkspaceMocks(page: Page, role: 'analyst' | 'viewer', empty = false) {
  const savedReports: unknown[] = []
  await page.route('**/api/v1/**', async (route) => {
    const url = new URL(route.request().url())
    const path = url.pathname.replace('/api/v1', '')
    const method = route.request().method()
    const json = (status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
    if (path === '/health/ready') return json(200, { status: 'ready', service: 'cyberlens-api', mode: 'live', demo_data: false, dependencies: { database: true, redis: true, worker: true } })
    if (path === '/auth/me') return json(200, { id: `posture-${role}`, username: role, role, is_active: true, must_change_password: false })
    if (path === '/assets' || path === '/investigations' || path === '/incidents') return json(200, [])
    if (path === '/reports' && method === 'GET') return json(200, savedReports)
    if (path === '/integrations/status') return json(200, { integrations: [] })
    if (path === '/integrations/spamhaus-drop/status') return json(200, feedStatus('spamhaus_drop'))
    if (path === '/integrations/cins-army/status') return json(200, feedStatus('cins_army'))
    if (path === '/integrations/openphish/status') return json(200, feedStatus('openphish'))
    if (path === '/monitoring') return json(200, [])
    if (path === '/posture/scorecard') return json(200, scorecard(empty, Number(url.searchParams.get('range_days') ?? '30')))
    if (path === '/reports/posture' && method === 'POST') {
      const body = route.request().postDataJSON() as { format: 'pdf' | 'json'; range_days: number }
      expect(body.range_days).toBe(90)
      const report = { id: 'posture-report-1', format: body.format, investigation_id: null, incident_id: null,
        report_type: 'posture', created_at: '2026-10-17T12:00:00Z', created_by: `posture-${role}`,
        is_demo: false, sha256: 'a'.repeat(64), download_url: '/api/v1/reports/posture-report-1/download' }
      savedReports.push(report)
      return json(201, report)
    }
    if (path === '/reports/posture-report-1/download') return route.fulfill({ status: 200, contentType: 'application/json', body: '{}' })
    return json(404, { detail: `No scorecard UI fixture for ${method} ${path}` })
  })
}

test('analyst reviews scoped scorecard data and exports a posture snapshot', async ({ page }, testInfo) => {
  await installWorkspaceMocks(page, 'analyst')
  await page.setViewportSize({ width: 1440, height: 1000 })
  await page.goto('/')
  await page.getByText('View detailed posture scorecard, trends, and exports', { exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Security posture scorecard' })).toBeVisible()
  await expect(page.getByRole('region', { name: 'Security posture scorecard', exact: true }).getByText('68.5 / 100')).toBeVisible()
  await expect(page.getByText(/Registered workspace assets/).first()).toBeVisible()
  await expect(page.getByText(/does not assert that findings are unresolved/)).toBeVisible()
  await expect(page.getByRole('button', { name: 'Export PDF' })).toBeVisible()
  await page.getByLabel('Scorecard time range').selectOption('90')
  await expect(page.getByText('Risk trend data as a table')).toBeVisible()
  await expect(page.locator('[data-chart-kind="posture-risk"]')).toBeVisible()
  await expect(page.locator('[data-chart-kind="workflow"]')).toBeVisible()
  const posturePanel = page.locator('.posture-panel')
  await posturePanel.scrollIntoViewIfNeeded()
  const topbar = page.locator('.app-shell .topbar')
  await topbar.evaluate((element) => { (element as HTMLElement).style.visibility = 'hidden' })
  await posturePanel.screenshot({ path: testInfo.outputPath('posture-scorecard-available-1440.png'), animations: 'disabled' })
  await topbar.evaluate((element) => { (element as HTMLElement).style.removeProperty('visibility') })
  await page.getByRole('button', { name: 'Export PDF' }).click()
  await expect(page.getByText('Report download started.')).toBeVisible()
  await page.getByRole('button', { name: 'Reports' }).click()
  await expect(page.getByText('Security posture scorecard')).toBeVisible()
})

test('viewer can read unavailable and empty values without an export control', async ({ page }, testInfo) => {
  await installWorkspaceMocks(page, 'viewer', true)
  await page.setViewportSize({ width: 1440, height: 1000 })
  await page.goto('/')
  await page.getByText('View detailed posture scorecard, trends, and exports', { exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Security posture scorecard' })).toBeVisible()
  await expect(page.getByText('empty', { exact: true }).first()).toBeVisible()
  await expect(page.getByRole('button', { name: 'Export PDF' })).toHaveCount(0)
  await expect(page.getByRole('button', { name: 'Export JSON' })).toHaveCount(0)
  await expect(page.getByText('No risk trend points')).toBeVisible()
  const posturePanel = page.locator('.posture-panel')
  await posturePanel.scrollIntoViewIfNeeded()
  const topbar = page.locator('.app-shell .topbar')
  await topbar.evaluate((element) => { (element as HTMLElement).style.visibility = 'hidden' })
  await posturePanel.screenshot({ path: testInfo.outputPath('posture-scorecard-empty-1440.png'), animations: 'disabled' })
  await topbar.evaluate((element) => { (element as HTMLElement).style.removeProperty('visibility') })
})

test('charts and exact-value tables reveal once without changing saved values', async ({ page }, testInfo) => {
  await page.emulateMedia({ reducedMotion: 'no-preference' })
  await installWorkspaceMocks(page, 'analyst')
  await page.goto('/')
  await page.getByText('View detailed posture scorecard, trends, and exports', { exact: true }).click()
  const chart = page.locator('[data-chart-kind="posture-risk"]')
  await chart.scrollIntoViewIfNeeded()
  await expect(chart).toHaveClass(/collection-revealed/)
  await page.getByText('View risk trend data as a table', { exact: true }).click()
  const table = page.locator('.posture-data-alternative').first().locator('.table-wrap')
  await table.scrollIntoViewIfNeeded()
  await expect(table).toHaveClass(/collection-revealed/)
  const values = await table.innerText()
  await page.waitForTimeout(350)
  await expect(table).toHaveCSS('opacity', '1')
  await expect(table.locator('td').first()).toHaveCSS('transition-duration', '0.15s, 0.15s')
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await expect(table).toHaveCSS('animation-name', 'none')
  expect(await table.innerText()).toBe(values)
  await page.evaluate(() => window.scrollTo(0, 0))
  await page.screenshot({ path: testInfo.outputPath('midnight-iris-charts-tables.png'), fullPage: true, animations: 'disabled' })
})

test('risk chart keeps policy versions separate, uses the analyst palette, and follows reduced motion', async ({ page }, testInfo) => {
  await installWorkspaceMocks(page, 'analyst')
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await page.goto('/')
  await page.getByText('View detailed posture scorecard, trends, and exports', { exact: true }).click()
  const riskChart = page.locator('[data-chart-kind="posture-risk"]')
  await expect(riskChart).toBeVisible()
  await expect(riskChart).toHaveAttribute('data-chart-motion', 'static')
  const workflowChart = page.locator('[data-chart-kind="workflow"]')
  await expect(workflowChart).toBeVisible()
  await expect(workflowChart).toHaveAttribute('data-chart-motion', 'static')
  await expect(riskChart.locator('.recharts-legend-item')).toContainText(['Policy cyberlens-academic-1.0', 'Policy cyberlens-academic-2.0'])
  await expect(riskChart.locator('.recharts-line-curve').first()).toHaveAttribute('stroke', 'var(--chart-1)')
  await expect(riskChart.locator('.recharts-line-curve').first()).toHaveCSS('stroke', 'rgb(167, 148, 255)')
  await expect(riskChart.locator('.recharts-cartesian-axis-tick-value').first()).toHaveCSS('fill', 'rgb(167, 185, 204)')
  await page.locator('.posture-inner-panel').first().screenshot({ path: testInfo.outputPath('ui05-risk-history-chart.png'), animations: 'disabled' })
  await page.getByText('View risk trend data as a table').click()
  await expect(page.getByRole('cell', { name: 'cyberlens-academic-1.0' })).toBeVisible()
  await expect(page.getByRole('cell', { name: 'cyberlens-academic-2.0' })).toBeVisible()
  await expect(page.locator('.score-ring')).toHaveAttribute('data-score-motion', 'static')
})

test('chart entrances play once and do not replay after a scorecard refresh', async ({ page }) => {
  await installWorkspaceMocks(page, 'analyst')
  await page.emulateMedia({ reducedMotion: 'no-preference' })
  await page.goto('/')
  const scoreRing = page.locator('.score-ring').first()
  await expect(scoreRing).toHaveAttribute('data-score-motion', 'initial')
  await expect(scoreRing).toHaveAttribute('data-score-motion', 'static', { timeout: 2_000 })
  await page.getByText('View detailed posture scorecard, trends, and exports', { exact: true }).click()
  const riskChart = page.locator('[data-chart-kind="posture-risk"]')
  const workflowChart = page.locator('[data-chart-kind="workflow"]')
  await expect(riskChart).toHaveAttribute('data-chart-motion', 'initial')
  await expect(workflowChart).toHaveAttribute('data-chart-motion', 'initial')
  await expect(riskChart).toHaveAttribute('data-chart-motion', 'static', { timeout: 2_000 })
  await expect(workflowChart).toHaveAttribute('data-chart-motion', 'static')
  await page.getByLabel('Scorecard time range').selectOption('90')
  await expect(page.getByLabel('Scorecard time range')).toHaveValue('90')
  await expect(riskChart).toHaveAttribute('data-chart-motion', 'static')
  await expect(workflowChart).toHaveAttribute('data-chart-motion', 'static')
  await expect(scoreRing).toHaveAttribute('data-score-motion', 'static')
})

test('application motion preference disables posture chart movement', async ({ page }) => {
  await installWorkspaceMocks(page, 'analyst')
  await page.goto('/')
  await page.locator('.user-menu > summary').click()
  await page.getByRole('checkbox', { name: 'Reduce animations' }).check()
  await expect(page.locator('html')).toHaveAttribute('data-motion', 'reduced')
  await page.getByText('View detailed posture scorecard, trends, and exports', { exact: true }).click()
  await expect(page.locator('[data-chart-kind="posture-risk"]')).toHaveAttribute('data-chart-motion', 'static')
  await expect(page.locator('[data-chart-kind="workflow"]')).toHaveAttribute('data-chart-motion', 'static')
  await expect(page.locator('.score-ring').last()).toHaveAttribute('data-score-motion', 'static')
})
