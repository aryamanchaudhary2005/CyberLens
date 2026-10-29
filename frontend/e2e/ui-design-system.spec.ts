import { expect, test, type Page } from '@playwright/test'
import { createHash } from 'node:crypto'

function preservedGraphicHash(markup: string) {
  // UI-00 captured React's development useId namespace r1; production uses r0.
  // Normalize only that generated ID and its matching URL reference. All art,
  // labels, geometry, styles, and the original baseline hash stay unchanged.
  const id = markup.match(/\bid="(r[0-9a-z]+-line)"/)?.[1]
  const normalized = id ? markup.replaceAll(`id="${id}"`, 'id="r1-line"').replaceAll(`url(#${id})`, 'url(#r1-line)') : markup
  return createHash('sha256').update(normalized).digest('hex')
}

const admin = { id: 'ui-admin', username: 'ui-admin', email: null, role: 'admin', must_change_password: false, is_active: true }
const readiness = { status: 'ready', service: 'cyberlens', mode: 'demo', demo_data: true, dependencies: { database: true, redis: true, worker: true } }

function demoFeedStatus(path: string) {
  const id = ({ '/integrations/spamhaus-drop/status': 'spamhaus_drop', '/integrations/cins-army/status': 'cins_army', '/integrations/openphish/status': 'openphish' } as Record<string, string>)[path]
  return id ? { id, name: id, enabled: false, mode: 'demo', freshness: 'not_assessed', snapshot_id: null, content_sha256: null, parser_version: 'synthetic-1.0', record_count: 0, retrieved_at: null, published_at: null, last_successful_revalidation_at: null, snapshot_age_seconds: null, freshness_limit_seconds: 86400, next_refresh_at: null, metadata: null, attribution: 'Synthetic offline fixture', latest_attempt: null, coverage_note: 'No live requests.', configuration_state: 'demo', configuration_reason: 'Offline fixture', access_scope: 'demo' } : null
}

const posture = {
  schema_version: '1.0', generated_at: '2026-10-20T08:00:00Z', range_days: 30, window_start: '2026-09-20T08:00:00Z', window_end: '2026-10-20T08:00:00Z',
  data_scope: { source: 'PostgreSQL', asset_count: 2, investigation_count: 1, data_modes: ['demo'] },
  overall_risk: { state: 'available', scope: 'workspace', range_days: 30, window_start: '2026-09-20T08:00:00Z', window_end: '2026-10-20T08:00:00Z', note: null, average_score: 38, band: 'moderate', assets_in_scope: 2, assets_with_score: 1, assessments_used: 1 },
  assessment_coverage: { state: 'partial', scope: 'workspace', range_days: 30, window_start: '2026-09-20T08:00:00Z', window_end: '2026-10-20T08:00:00Z', note: null, assessed_category_slots: 4, expected_category_slots: 8, coverage_percent: 50, assets_in_scope: 2, assets_with_recent_assessment: 1, assets_with_score: 1, unassessed_category_slots: 4 },
  high_critical_findings: { state: 'available', scope: 'latest observation', range_days: 30, window_start: '2026-09-20T08:00:00Z', window_end: '2026-10-20T08:00:00Z', note: null, high: 1, critical: 0, total: 1, open_high: null, open_critical: null, open_total: null, open_counts_available: false, assets_with_recent_observation: 1, assets_in_scope: 2, lifecycle_status_available: false },
  unassessed_categories: { state: 'partial', scope: 'workspace', range_days: 30, window_start: '2026-09-20T08:00:00Z', window_end: '2026-10-20T08:00:00Z', note: null, counts: { tls: 1 }, assets_without_recent_assessment: 1, total_unassessed_category_slots: 4 },
  provider_health: { state: 'partial', scope: 'latest saved provider observations', range_days: 30, window_start: '2026-09-20T08:00:00Z', window_end: '2026-10-20T08:00:00Z', note: null, providers: [{ id: 'nvd', name: 'NVD', state: 'available', configured: true, eligible_asset_count: 1, provider_status: 'success', source: 'NVD API', last_observed_at: '2026-10-20T07:00:00Z', freshness: 'fresh', data_mode: 'demo', note: null }] },
}

async function mockWorkspace(page: Page, role: 'admin' | 'analyst' | 'viewer' = 'admin') {
  await page.addInitScript(() => { document.cookie = 'cyberlens_csrf=design-ui-token; path=/' })
  await page.route('**/health/ready', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(readiness) }))
  await page.route('**/api/v1/**', async (route) => {
    const url = new URL(route.request().url())
    const path = url.pathname.replace('/api/v1', '')
    const method = route.request().method()
    const json = (status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
    if (path === '/health/ready') return json(200, readiness)
    if (path === '/auth/me') return json(401, { detail: 'Sign in required' })
    if (path === '/auth/csrf') return json(200, { csrf_token: 'design-ui-token' })
    if (path === '/auth/login' && method === 'POST') return json(200, { user: { ...admin, role } })
    if (path === '/assets') return json(200, [])
    if (path === '/investigations') return json(200, [])
    if (path === '/incidents') return json(200, [])
    if (path === '/reports') return json(200, [])
    if (path === '/integrations/status') return json(200, { mode: 'demo', integrations: [{ id: 'nvd', name: 'NVD', configured: true, behavior: 'Saved fixture status' }] })
    const feed = demoFeedStatus(path)
    if (feed) return json(200, feed)
    if (path === '/posture/scorecard') return json(200, posture)
    if (path === '/monitoring') return json(200, [])
    if (path === '/integrity') return json(200, { state: 'verified', checked_at: '2026-10-20T08:00:00Z', audit_chain: { state: 'verified', checked_at: '2026-10-20T08:00:00Z', event_count: 0, verified_count: 0, last_sequence: 0, last_hash: '0'.repeat(64), failed_sequence: null, message: 'No events recorded.' }, evidence: { state: 'incomplete', total: 0, checked: 0, counts: { verified: 0, failed: 0, unavailable: 0, incomplete: 0 } } })
    if (path === '/integrity/evidence') return json(200, [])
    return json(200, [])
  })
}

async function signIn(page: Page) {
  await page.goto('/')
  await expect(page.getByRole('heading', { name: 'Sign in to your workspace' })).toBeVisible()
  await page.getByLabel('Username').fill(admin.username)
  await page.getByLabel('Password').fill('Synthetic-UI-Password-2026!')
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { name: 'Investigation workspace' })).toBeVisible()
}

test('detail transitions preserve form state and do not replay on ordinary updates', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'no-preference' })
  await page.addInitScript(() => {
    const animate = Element.prototype.animate
    const transitions: Animation[] = []
    Element.prototype.animate = function (...args) {
      const animation = animate.apply(this, args)
      if (this.classList.contains('page-transition')) transitions.push(animation)
      return animation
    }
    Object.defineProperty(window, '__sectionTransitions', { value: () => transitions.map(a => a.playState) })
  })
  await mockWorkspace(page)
  const assets = ['one', 'two'].map(id => ({ id, kind: 'domain', identifier: `${id}.example.test`, notes: '', components: [], authorized_at: null, protection_requirements: [], criticality: 'unknown', data_classification: 'unknown', trust_zone: 'unknown', exposure_classification: 'unknown' }))
  await page.route('**/api/v1/assets', route => route.fulfill({ json: assets }))
  await signIn(page)
  await page.locator('.nav-list .rail-link[aria-label="Assets"]').click()
  await page.getByLabel('Identifier', { exact: true }).fill('draft.example.test')
  const states = () => page.evaluate(() => (window as unknown as { __sectionTransitions: () => string[] }).__sectionTransitions())
  const before = (await states()).length
  await page.getByRole('button', { name: /one.example.test/ }).click()
  await expect.poll(async () => (await states()).length).toBeGreaterThan(before)
  const selected = (await states()).length
  await page.getByLabel('Identifier', { exact: true }).fill('retained.example.test')
  await page.evaluate(() => window.dispatchEvent(new HashChangeEvent('hashchange')))
  await page.waitForTimeout(350)
  expect((await states()).length).toBe(selected)
  await expect(page.getByLabel('Identifier', { exact: true })).toHaveValue('retained.example.test')
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await expect(page.locator('html')).toHaveAttribute('data-motion', 'reduced')
  await page.getByRole('button', { name: /two.example.test/ }).click()
  expect((await states()).length).toBe(selected)
  expect((await states()).every(state => state !== 'running')).toBe(true)
})

test('TextRoll settles, overview uses saved data, and screenshots cover desktop and mobile', async ({ page }, testInfo) => {
  await mockWorkspace(page)
  await page.goto('/')
  await expect(page.getByRole('img', { name: 'CyberLens' })).toBeVisible()
  await page.waitForTimeout(650)
  await expect(page.getByRole('img', { name: 'CyberLens' })).toBeVisible()
  await page.screenshot({ path: testInfo.outputPath('login-desktop.png'), fullPage: true, animations: 'disabled' })

  await signIn(page)
  await expect(page.getByRole('heading', { name: 'Risk and coverage' })).toBeVisible()
  await expect(page.locator('.posture-summary-card .bento-metric > strong').nth(0)).toHaveText('38 / 100')
  await expect(page.locator('.posture-summary-card .bento-metric > strong').nth(1)).toHaveText('50%')
  await expect(page.locator('.coverage-metric')).toHaveAttribute('data-state', 'partial')
  await expect(page.locator('.coverage-meter > span')).toHaveCSS('background-color', 'rgb(232, 197, 110)')
  await expect(page.locator('.posture-summary-card')).toContainText('1 of 2 assets scored')
  await expect(page.locator('.posture-summary-card')).toContainText('4 of 8 category slots assessed')
  await expect(page.getByRole('heading', { name: 'Provider freshness' })).toBeVisible()
  await expect(page.locator('.provider-summary-card')).toContainText('Latest saved provider results; this is not a live connectivity probe.')
  await expect(page.getByText('No open incidents in the loaded list')).toBeVisible()
  await expect(page.getByRole('link', { name: /Inspect source configuration/ })).toHaveAttribute('href', '#/integrations')
  await page.screenshot({ path: testInfo.outputPath('overview-desktop.png'), fullPage: true, animations: 'disabled' })

  await page.setViewportSize({ width: 390, height: 844 })
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  await page.screenshot({ path: testInfo.outputPath('overview-mobile-390.png'), fullPage: true, animations: 'disabled' })
  await page.setViewportSize({ width: 768, height: 1024 })
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  await expect(page.getByRole('button', { name: /Start investigation/ })).toHaveCSS('white-space', 'nowrap')
  await page.screenshot({ path: testInfo.outputPath('overview-tablet-768.png'), fullPage: true, animations: 'disabled' })
  await page.setViewportSize({ width: 1440, height: 1000 })
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  await page.screenshot({ path: testInfo.outputPath('overview-wide-1440.png'), fullPage: true, animations: 'disabled' })
})

test('overview keeps unavailable posture distinct from service readiness', async ({ page }, testInfo) => {
  await mockWorkspace(page)
  await page.setViewportSize({ width: 1440, height: 1000 })
  await page.route('**/api/v1/posture/scorecard**', (route) => route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ detail: 'Synthetic scorecard unavailable' }) }))
  await signIn(page)

  const postureCard = page.locator('.posture-summary-card')
  await expect(postureCard.locator('.panel-heading .status-badge')).toHaveText('unavailable')
  await expect(postureCard.getByRole('alert')).toContainText('Synthetic scorecard unavailable')
  await expect(page.locator('.provider-summary-card')).toContainText('Provider freshness unavailable.')
  await expect(page.locator('.workspace-status-card .panel-heading .status-badge')).toHaveText('ready')
  await expect(page.locator('.service-status-item').filter({ hasText: 'PostgreSQL' })).toContainText('available')
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  await page.screenshot({ path: testInfo.outputPath('overview-posture-unavailable-1440.png'), fullPage: true, animations: 'disabled' })
})

test('navigation history, collapsed labels, mobile focus, and reduced motion work', async ({ page }) => {
  await mockWorkspace(page)
  await signIn(page)

  await page.getByRole('button', { name: 'Collapse sidebar' }).click()
  await expect(page.getByRole('button', { name: 'Expand sidebar' })).toBeVisible()
  const assetsNav = page.locator('.nav-list .rail-link[aria-label="Assets"]')
  await expect(assetsNav).toHaveAttribute('data-tooltip', 'Assets')
  await page.getByRole('button', { name: 'Expand sidebar' }).click()
  await page.evaluate(() => { (window as Window & { __module29NavStart?: number }).__module29NavStart = performance.now(); document.querySelector<HTMLButtonElement>('.nav-list .rail-link[aria-label="Assets"]')?.click() })
  await expect(page.getByRole('heading', { name: 'Assets', exact: true })).toBeVisible()
  const interaction = await page.evaluate(() => ({
    routeReadyMs: Number((performance.now() - ((window as Window & { __module29NavStart?: number }).__module29NavStart ?? performance.now())).toFixed(1)),
    controlFeedback: getComputedStyle(document.querySelector('.nav-list .rail-link[aria-label="Assets"]')!).transitionDuration,
    pageTransition: getComputedStyle(document.querySelector('.page-transition')!).animationDuration,
  }))
  console.log(`MODULE29_INTERACTION_METRICS ${JSON.stringify(interaction)}`)
  await expect.poll(() => page.evaluate(() => window.location.hash)).toContain('/assets')
  await page.goBack()
  await expect(page.getByRole('heading', { name: 'Investigation workspace' })).toBeVisible()
  await page.evaluate(() => window.scrollTo(0, 500))
  await page.waitForTimeout(300)
  await expect(page.locator('.topbar')).toHaveClass(/is-scrolled/)
  await page.evaluate(() => window.scrollTo(0, 0))
  await expect(page.locator('.topbar')).not.toHaveClass(/is-scrolled/)

  await page.setViewportSize({ width: 390, height: 844 })
  await page.getByRole('button', { name: 'Open navigation' }).click()
  const drawer = page.getByRole('dialog', { name: 'Primary navigation' })
  await expect(drawer).toBeVisible()
  await expect(page.locator('.nav-list .rail-link[aria-label="Overview"]')).toBeFocused()
  await page.keyboard.press('Escape')
  await expect(page.getByRole('button', { name: 'Open navigation' })).toBeFocused()

  await page.locator('.user-menu > summary').click()
  const reduceMotion = page.getByRole('checkbox', { name: 'Reduce animations' })
  await reduceMotion.check()
  await expect(page.locator('html')).toHaveAttribute('data-motion', 'reduced')
  await expect(page.locator('.page-transition')).toHaveCSS('transform', 'none')
})

test('refined shell keeps navigation readable and captures desktop, collapsed, and mobile states', async ({ page }, testInfo) => {
  await mockWorkspace(page)
  await signIn(page)
  await page.setViewportSize({ width: 1440, height: 900 })
  await expect(page.getByRole('button', { name: 'Administration', exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Overview', exact: true })).toHaveAttribute('aria-current', 'page')
  await expect(page.locator('.rail-link.active')).toHaveCSS('color', 'rgb(188, 176, 255)')
  await expect(page.locator('.rail-link.active svg')).toHaveCSS('width', '18px')
  await expect(page.getByLabel('User menu for ui-admin, admin')).toBeVisible()
  await page.screenshot({ path: testInfo.outputPath('ui03-shell-desktop.png'), animations: 'disabled' })

  await page.getByRole('button', { name: 'Collapse sidebar' }).click()
  await expect(page.locator('.app-shell')).toHaveClass(/sidebar-collapsed/)
  await expect.poll(() => page.evaluate(() => localStorage.getItem('cyberlens-sidebar-collapsed'))).toBe('true')
  const collapsedAssets = page.locator('.nav-list .rail-link[aria-label="Assets"]')
  await collapsedAssets.hover()
  await expect.poll(() => collapsedAssets.evaluate((element) => getComputedStyle(element, '::after').opacity)).toBe('1')
  await page.mouse.move(0, 0)
  await page.screenshot({ path: testInfo.outputPath('ui03-shell-collapsed.png'), animations: 'disabled' })

  await page.setViewportSize({ width: 390, height: 844 })
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  await expect(page.getByRole('button', { name: 'Open navigation' })).toBeVisible()
  await page.screenshot({ path: testInfo.outputPath('ui03-shell-mobile.png'), animations: 'disabled' })
  await page.getByRole('button', { name: 'Open navigation' }).click()
  const drawer = page.getByRole('dialog', { name: 'Primary navigation' })
  await expect(drawer).toBeVisible()
  await expect(page.locator('.nav-list .rail-link[aria-label="Overview"]')).toBeFocused()
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  await expect(page.locator('.nav-list .rail-link[aria-label="Threat model"] .nav-label')).toHaveCSS('white-space', 'nowrap')
  await page.screenshot({ path: testInfo.outputPath('ui03-shell-mobile-drawer.png'), animations: 'disabled' })
  await page.getByRole('button', { name: 'Administration', exact: true }).focus()
  await page.keyboard.press('Tab')
  await expect(page.getByRole('button', { name: 'CyberLens overview' })).toBeFocused()
  await page.keyboard.press('Escape')
  await expect(page.getByRole('button', { name: 'Open navigation' })).toBeFocused()
})

test('viewer navigation keeps administration restricted', async ({ page }) => {
  await mockWorkspace(page, 'viewer')
  await signIn(page)
  await expect(page.getByRole('button', { name: 'Administration', exact: true })).toHaveCount(0)
  for (const label of ['Overview', 'Assets', 'Investigations', 'Incidents', 'Threat model', 'Remediation', 'Reports', 'Integrity', 'Integrations']) {
    await expect(page.locator(`.nav-list .rail-link[aria-label="${label}"]`)).toBeVisible()
  }
})

test('investigation polling preserves applicability draft and focus', async ({ page }, testInfo) => {
  const asset = { id: 'asset-1', kind: 'application', identifier: 'ui billing application', notes: '', criticality: 'unknown', data_classification: 'unknown', trust_zone: 'unknown', exposure_classification: 'unknown', business_owner: null, protection_requirements: [], authorized_at: null, authorization_id: null, authorization_expires_at: null, components: [] }
  const finding = { id: 'finding-1', asset_id: asset.id, investigation_id: 'run-1', evidence_id: 'evidence-1', category: 'vulnerabilities', severity: 'high', title: 'CVE-2026-1000 candidate', explanation: 'Synthetic finding for UI state persistence.', recommendation: 'Review applicability.', source: 'NVD', observed_at: '2026-10-20T08:00:00Z', applicability: 'needs_review', applicability_reason: null, cvss_version: null, cvss_score: null, cvss_vector: null, kev: null, epss_score: null, epss_percentile: null, epss_observed_at: null, epss_provider_status: 'not_assessed', epss_freshness: 'unknown', is_synthetic: true, details_json: { cve_id: 'CVE-2026-1000' }, osv: null }
  let detailCalls = 0
  const investigation = { id: 'run-1', asset_id: asset.id, asset_kind: asset.kind, asset_identifier: asset.identifier, mode: 'demo', demo_data: true, scenario: 'vulnerable_application', status: 'running', progress: 15, started_at: '2026-10-20T08:00:00Z', finished_at: null, created_at: '2026-10-20T08:00:00Z', error_summary: null, attempt_number: 1, risk: null }
  const detail = () => ({ ...investigation, status: detailCalls >= 3 ? 'partial' : 'running', finished_at: detailCalls >= 3 ? '2026-10-20T08:02:00Z' : null, progress: detailCalls >= 3 ? 100 : Math.min(10 + detailCalls * 5, 90), asset, attempts: [{ id: 'attempt-1', attempt_number: 1, retry_kind: 'initial', status: detailCalls >= 3 ? 'partial' : 'running', progress: detailCalls >= 3 ? 100 : Math.min(10 + detailCalls * 5, 90), started_at: investigation.started_at, finished_at: null, created_at: investigation.created_at, error_summary: null }], collector_runs: [], findings: [finding], evidence: [], risk: null })
  await page.addInitScript(() => { document.cookie = 'cyberlens_csrf=design-ui-token; path=/' })
  await page.route('**/health/ready', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(readiness) }))
  await page.route('**/api/v1/**', async (route) => {
    const path = new URL(route.request().url()).pathname.replace('/api/v1', '')
    const json = (status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
    if (path === '/health/ready') return json(200, readiness)
    if (path === '/auth/me') return json(401, { detail: 'Sign in required' })
    if (path === '/auth/csrf') return json(200, { csrf_token: 'design-ui-token' })
    if (path === '/auth/login') return json(200, { user: { ...admin, role: 'analyst' } })
    if (path === '/assets') return json(200, [asset])
    if (path === '/investigations') return json(200, [investigation])
    if (path === '/incidents' || path === '/reports') return json(200, [])
    if (path === '/integrations/status') return json(200, { mode: 'demo', integrations: [] })
    const feed = demoFeedStatus(path)
    if (feed) return json(200, feed)
    if (path === '/investigations/run-1') { detailCalls += 1; return json(200, detail()) }
    if (path === '/investigations/run-1/risk/simulation-options') return json(200, [])
    if (path === '/investigations/run-1/graph') return json(200, { investigation_id: 'run-1', nodes: detailCalls >= 3 ? [{ id: 'graph-asset', type: 'asset', label: asset.identifier, details: {} }] : [], edges: [] })
    return json(200, [])
  })

  await page.goto('/#/investigations/run-1')
  await page.getByLabel('Username').fill(admin.username)
  await page.getByLabel('Password').fill('Synthetic-UI-Password-2026!')
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { name: asset.identifier })).toBeVisible()
  const detailPanel = page.locator('.history-layout > .panel').nth(1)
  await detailPanel.scrollIntoViewIfNeeded()
  await expect.poll(() => detailPanel.evaluate((element) => element.classList.contains('motion-revealed'))).toBe(true)
  const reason = page.getByPlaceholder('Reason for applicability decision')
  await reason.fill('Keep this analyst draft while the job refreshes.')
  await expect(reason).toHaveCSS('font-size', '13px')
  await expect(detailPanel.getByRole('button', { name: 'Does not apply' })).toHaveCSS('min-height', '38px')
  await reason.focus()
  const initialCalls = detailCalls
  await expect.poll(() => detailCalls, { timeout: 5000, intervals: [100, 200, 500] }).toBeGreaterThan(initialCalls)
  await expect(reason).toHaveValue('Keep this analyst draft while the job refreshes.')
  await expect(reason).toBeFocused()
  const revealStartBeforeRefresh = await detailPanel.evaluate((element) => element.getAnimations().find((animation) => (animation as CSSAnimation).animationName === 'workspace-reveal')?.startTime ?? null)
  await expect(page.getByRole('button', { name: `asset: ${asset.identifier}`, exact: true })).toBeAttached()
  await expect(reason).toHaveValue('Keep this analyst draft while the job refreshes.')
  await expect.poll(() => detailPanel.evaluate((element) => element.getAnimations().find((animation) => (animation as CSSAnimation).animationName === 'workspace-reveal')?.startTime ?? null)).toBe(revealStartBeforeRefresh)
  await page.evaluate(() => window.scrollTo(0, 0))
  await page.screenshot({ path: testInfo.outputPath('investigation-desktop.png'), fullPage: true, animations: 'disabled' })
  for (const width of [390, 768, 1440]) {
    await page.setViewportSize({ width, height: width === 390 ? 844 : 1000 })
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
    await expect(reason).toHaveValue('Keep this analyst draft while the job refreshes.')
    await page.evaluate(() => window.scrollTo(0, 0))
    await page.screenshot({ path: testInfo.outputPath(`investigation-${width}.png`), fullPage: true, animations: 'disabled' })
  }
})

test('Change Radar finds a valid completed pair and does not treat a failed run as evidence removal', async ({ page }) => {
  await mockWorkspace(page)
  const run = (id: string, assetId: string, createdAt: string, status = 'completed') => ({ id, asset_id: assetId, asset_kind: 'domain', asset_identifier: `${assetId}.example.test`, mode: 'demo', demo_data: true, scenario: 'routine_website', status, progress: 100, started_at: createdAt, finished_at: createdAt, created_at: createdAt, error_summary: null, attempt_number: 1, risk: null })
  await page.route(/\/api\/v1\/investigations(?:\?|$)/, (route) => route.fulfill({ contentType: 'application/json', body: JSON.stringify([
    run('unpaired', 'new-asset', '2026-10-20T12:00:00Z'),
    run('failed', 'paired-asset', '2026-10-20T11:00:00Z', 'failed'),
    run('current', 'paired-asset', '2026-10-20T10:00:00Z', 'partial'),
    run('previous', 'paired-asset', '2026-10-19T10:00:00Z'),
  ]) }))
  const comparisons: string[] = []
  await page.route('**/changes/**', (route) => {
    comparisons.push(new URL(route.request().url()).pathname)
    return route.fulfill({ contentType: 'application/json', body: JSON.stringify({ current_investigation_id: 'current', previous_investigation_id: 'previous', counts: { new: 0, changed: 0, no_longer_observed: 0, unknown: 2 }, changes: [] }) })
  })
  await signIn(page)
  await expect.poll(() => comparisons).toEqual(['/api/v1/investigations/current/changes/previous'])
  await expect(page.locator('.change-count.unknown dd')).toHaveText('2')
  await expect(page.locator('.change-count.no_longer_observed dd')).toHaveText('0')
  await expect(page.locator('.change-summary-card')).toContainText('Provider gaps remain unknown coverage')
})

test('empty analyst screens retain hierarchy and fit laptop width', async ({ page }, testInfo) => {
  await mockWorkspace(page)
  await signIn(page)
  await page.setViewportSize({ width: 1440, height: 1000 })
  const screens = [
    ['overview', 'Overview', 'Investigation workspace'],
    ['assets', 'Assets', 'Assets'],
    ['investigations', 'Investigations', 'Investigations'],
    ['incidents', 'Incidents', 'Cases'],
    ['threat-model', 'Threat model', 'Threat modeling'],
    ['remediation', 'Remediation', 'Remediation plans'],
    ['reports', 'Reports', 'Reports'],
    ['integrity', 'Integrity', 'Integrity'],
    ['integrations', 'Integrations', 'Integrations'],
    ['admin', 'Administration', 'Administration'],
  ] as const
  for (const [id, label, heading] of screens) {
    await page.locator(`.nav-list .rail-link[aria-label="${label}"]`).click()
    await expect(page.getByRole('heading', { name: heading, exact: true }).first()).toBeVisible()
    const panel = page.locator('.content .panel').first()
    await expect(panel).toHaveCSS('border-radius', '12px')
    await expect(panel).toHaveCSS('border-color', 'rgb(48, 68, 90)')
    for (const width of [390, 768, 1440]) {
      await page.setViewportSize({ width, height: width === 390 ? 844 : 1000 })
      await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
    }
    await page.setViewportSize({ width: 1440, height: 1000 })
    await page.screenshot({ path: testInfo.outputPath(`screen-${id}-1440.png`), fullPage: true, animations: 'disabled' })
  }
})

test('slow and failed requests keep loading and retry information visible', async ({ page }) => {
  let requestFinished = false
  let assetCalls = 0
  await mockWorkspace(page)
  await page.route('**/api/v1/assets', async (route) => {
    assetCalls += 1
    await new Promise((resolve) => setTimeout(resolve, 650))
    requestFinished = true
    return route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ detail: 'Synthetic service unavailable' }) })
  })
  await signIn(page)
  await expect(page.locator('.content > .loading-state')).toBeVisible()
  await expect.poll(() => requestFinished).toBe(true)
  await expect(page.getByRole('alert')).toContainText('assets')
  const retry = page.getByRole('button', { name: 'Retry' })
  await expect(retry).toBeVisible()
  await retry.click()
  await expect.poll(() => assetCalls).toBeGreaterThan(1)
  await page.locator('.nav-list .rail-link[aria-label="Assets"]').click()
  await expect(page.getByText('No assets registered')).toBeVisible()
  await expect(page.getByRole('alert')).toBeVisible()
})

test('motion observer failure leaves page content visible', async ({ page }) => {
  await page.addInitScript(() => {
    Object.defineProperty(window, 'IntersectionObserver', { configurable: true, value: class {
      observe() { throw new Error('Synthetic observer failure') }
      unobserve() {}
      disconnect() {}
    } })
  })
  await mockWorkspace(page)
  await signIn(page)
  await expect(page.getByRole('heading', { name: 'Investigation workspace' })).toBeVisible()
  const firstPanel = page.locator('.page-transition .panel').first()
  await expect(firstPanel).toBeVisible()
  await expect.poll(() => firstPanel.evaluate((element) => getComputedStyle(element).opacity)).toBe('1')
  await expect.poll(() => page.locator('.page-transition [style*="motion-reveal-delay"]').count()).toBe(0)
})

test('panels opened after route entry reveal once and remain stable through loading, errors, and focus', async ({ page }) => {
  await mockWorkspace(page)
  await signIn(page)
  let release: (() => void) | undefined
  const pending = new Promise<void>((resolve) => { release = resolve })
  await page.route('**/api/v1/posture/scorecard**', async (route) => {
    await pending
    await route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ detail: 'Synthetic delayed scorecard unavailable' }) })
  })
  await page.evaluate(() => {
    let starts = 0
    document.addEventListener('animationstart', (event) => {
      if (event.animationName === 'workspace-reveal' && (event.target as Element).matches('.posture-panel')) starts += 1
    })
    Object.defineProperty(window, '__latePanelReveals', { value: () => starts })
  })
  const disclosure = page.locator('.posture-detail-disclosure > summary')
  await disclosure.click()
  const panel = page.locator('.posture-panel')
  await panel.scrollIntoViewIfNeeded()
  await expect(panel).toHaveClass(/motion-revealed/)
  await expect(panel.getByText('Loading saved scorecard data…')).toBeVisible()
  await expect.poll(() => page.evaluate(() => (window as unknown as { __latePanelReveals: () => number }).__latePanelReveals())).toBe(1)
  release?.()
  await expect(panel.getByRole('alert')).toContainText('Synthetic delayed scorecard unavailable')
  await page.waitForTimeout(350)
  await panel.getByRole('button', { name: 'Retry', exact: true }).focus()
  await expect(panel).toHaveCSS('opacity', '1')
  await disclosure.focus()
  await page.waitForTimeout(300)
  expect(await page.evaluate(() => (window as unknown as { __latePanelReveals: () => number }).__latePanelReveals())).toBe(1)
})

test('UI-07 keeps interface motion on shared tokens and cleans up on route changes and sign-out', async ({ page }) => {
  await page.addInitScript(() => {
    const stats = { scrollAdded: 0, scrollRemoved: 0, observersCreated: 0, observersDisconnected: 0 }
    const scrollListeners = new Set<EventListenerOrEventListenerObject>()
    Object.defineProperty(window, '__motionSnapshot', { value: () => ({ ...stats, activeScrollListeners: scrollListeners.size }) })

    const nativeAdd = window.addEventListener.bind(window)
    const nativeRemove = window.removeEventListener.bind(window)
    Object.defineProperty(window, 'addEventListener', { configurable: true, value: (type: string, listener: EventListenerOrEventListenerObject | null, options?: boolean | AddEventListenerOptions) => {
      if (type === 'scroll' && listener && !scrollListeners.has(listener)) { scrollListeners.add(listener); stats.scrollAdded += 1 }
      if (listener) nativeAdd(type, listener as EventListener, options)
    } })
    Object.defineProperty(window, 'removeEventListener', { configurable: true, value: (type: string, listener: EventListenerOrEventListenerObject | null, options?: boolean | EventListenerOptions) => {
      if (type === 'scroll' && listener && scrollListeners.delete(listener)) stats.scrollRemoved += 1
      if (listener) nativeRemove(type, listener as EventListener, options)
    } })

    const NativeObserver = window.IntersectionObserver
    Object.defineProperty(window, 'IntersectionObserver', { configurable: true, value: class extends NativeObserver {
      private trackedDisconnect = false
      constructor(callback: IntersectionObserverCallback, options?: IntersectionObserverInit) {
        super(callback, options)
        stats.observersCreated += 1
      }
      disconnect() {
        if (!this.trackedDisconnect) { this.trackedDisconnect = true; stats.observersDisconnected += 1 }
        super.disconnect()
      }
    } })
  })

  const pageErrors: string[] = []
  page.on('pageerror', (error) => pageErrors.push(error.message))
  await mockWorkspace(page)
  await signIn(page)
  await expect.poll(() => page.evaluate(() => (window as unknown as { __motionSnapshot: () => { activeScrollListeners: number } }).__motionSnapshot().activeScrollListeners)).toBe(1)

  const motion = await page.evaluate(() => {
    const root = getComputedStyle(document.documentElement)
    const timings = Object.fromEntries(['--motion-fast', '--motion-card', '--motion-drawer', '--motion-backdrop', '--motion-page', '--motion-panel', '--motion-loading'].map((name) => {
      const value = root.getPropertyValue(name).trim()
      return [name, parseFloat(value) * (value.endsWith('ms') ? 1 : 1000)]
    }))
    const shell = document.querySelector('.app-shell')!
    const notice = document.createElement('div')
    notice.className = 'alert success'
    shell.append(notice)
    const noticeAnimation = getComputedStyle(notice).animationDuration
    notice.remove()
    return {
      timings,
      control: getComputedStyle(document.querySelector('.rail-link')!).transitionDuration,
      route: getComputedStyle(document.querySelector('.page-transition')!).animationDuration,
      notice: noticeAnimation,
    }
  })
  expect(motion.timings).toEqual({ '--motion-fast': 150, '--motion-card': 180, '--motion-drawer': 200, '--motion-backdrop': 160, '--motion-page': 220, '--motion-panel': 240, '--motion-loading': 1600 })
  expect(motion.control.split(',').map((duration) => duration.trim())).toEqual(['0.15s', '0.15s', '0.15s', '0.15s'])
  expect(motion.route).toBe('0.22s')
  expect(motion.notice).toBe('0.24s')

  const observersBeforeNavigation = await page.evaluate(() => (window as unknown as { __motionSnapshot: () => { observersDisconnected: number } }).__motionSnapshot().observersDisconnected)
  for (const [label, heading] of [['Assets', 'Assets'], ['Investigations', 'Investigations'], ['Overview', 'Investigation workspace']] as const) {
    await page.locator(`.nav-list .rail-link[aria-label="${label}"]`).click()
    await expect(page.getByRole('heading', { name: heading, exact: true }).first()).toBeVisible()
  }
  await expect.poll(() => page.evaluate(() => (window as unknown as { __motionSnapshot: () => { activeScrollListeners: number; observersDisconnected: number } }).__motionSnapshot())).toMatchObject({ activeScrollListeners: 1 })
  const observersAfterNavigation = await page.evaluate(() => (window as unknown as { __motionSnapshot: () => { observersDisconnected: number } }).__motionSnapshot().observersDisconnected)
  expect(observersAfterNavigation).toBeGreaterThan(observersBeforeNavigation)

  await page.locator('.user-menu > summary').click()
  await page.getByRole('button', { name: 'Sign out' }).click()
  await expect(page.getByRole('heading', { name: 'Sign in to your workspace' })).toBeVisible()
  await expect.poll(() => page.evaluate(() => (window as unknown as { __motionSnapshot: () => { activeScrollListeners: number } }).__motionSnapshot().activeScrollListeners)).toBe(0)
  expect(pageErrors).toEqual([])
})

test('UI-07 system and application reduced motion keep content static and operable', async ({ page }) => {
  await mockWorkspace(page)
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await signIn(page)
  await expect(page.locator('html')).toHaveAttribute('data-motion', 'reduced')
  await expect(page.getByRole('heading', { name: 'Investigation workspace' })).toBeVisible()
  await expect(page.locator('.page-transition')).toHaveCSS('animation-name', 'none')
  await expect(page.locator('.nav-list .rail-link').first()).toHaveCSS('transition-duration', '1e-05s')

  await page.locator('.nav-list .rail-link[aria-label="Assets"]').click()
  await expect(page.getByRole('heading', { name: 'Assets', exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Add asset' })).toBeVisible()
})

test('long asset names and notes stay readable without page overflow', async ({ page }, testInfo) => {
  const identifier = `console-${'longtenantlabel'.repeat(14)}.example.test`
  const asset = { id: 'long-asset', kind: 'domain', identifier, notes: 'Analyst context. '.repeat(100), criticality: 'high', data_classification: 'internal', trust_zone: 'internet', exposure_classification: 'public', business_owner: 'Platform operations', protection_requirements: [], authorized_at: null, authorization_id: null, authorization_expires_at: null, components: [] }
  await mockWorkspace(page)
  await page.route('**/api/v1/assets', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([asset]) }))
  await signIn(page)
  await page.locator('.nav-list .rail-link[aria-label="Assets"]').click()
  await page.locator('.asset-row').click()
  await expect(page.getByRole('heading', { name: identifier })).toBeVisible()
  for (const width of [390, 768, 1440]) {
    await page.setViewportSize({ width, height: width === 390 ? 844 : 1000 })
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
    await expect(page.getByRole('heading', { name: identifier })).toBeVisible()
    if (width === 1440) await page.screenshot({ path: testInfo.outputPath('ui06-long-asset-desktop.png'), fullPage: true, animations: 'disabled' })
  }
})

test('UI-06 account rows wrap long identity details and retain their controls', async ({ page }, testInfo) => {
  const account = {
    id: 'ui06-long-account', username: `ops-${'analyst-label'.repeat(5)}`,
    email: `${'identity-context-'.repeat(7)}@example.test`, role: 'analyst',
    must_change_password: false, is_active: true,
  }
  await mockWorkspace(page)
  await page.route('**/api/v1/users', (route) => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify([account]),
  }))
  await signIn(page)
  await page.locator('.nav-list .rail-link[aria-label="Administration"]').click()
  const row = page.locator('.component-row').filter({ hasText: account.username })
  await expect(row).toContainText(account.email)
  await expect(row.getByRole('combobox', { name: `Role for ${account.username}` })).toHaveValue('analyst')
  await expect(row.getByRole('button', { name: 'Reset password' })).toBeVisible()
  for (const width of [390, 768, 1440]) {
    await page.setViewportSize({ width, height: width === 390 ? 844 : 1000 })
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  }
  await page.setViewportSize({ width: 390, height: 844 })
  await page.evaluate(() => window.scrollTo(0, 0))
  await page.screenshot({ path: testInfo.outputPath('ui06-admin-users-mobile.png'), animations: 'disabled' })
  await page.setViewportSize({ width: 1440, height: 1000 })
  await page.screenshot({ path: testInfo.outputPath('ui06-admin-users-desktop.png'), fullPage: true, animations: 'disabled' })
})

test('unsent asset form values survive route changes', async ({ page }) => {
  await mockWorkspace(page)
  await signIn(page)
  await page.locator('.nav-list .rail-link[aria-label="Assets"]').click()
  const identifier = page.getByLabel('Identifier')
  const notes = page.getByLabel('Notes')
  await identifier.fill('draft.example.test')
  await notes.fill('Keep this unsent analyst note while I review another screen.')
  await page.locator('.nav-list .rail-link[aria-label="Overview"]').click()
  await expect(page.getByRole('heading', { name: 'Investigation workspace' })).toBeVisible()
  await page.locator('.nav-list .rail-link[aria-label="Assets"]').click()
  await expect(page.getByLabel('Identifier')).toHaveValue('draft.example.test')
  await expect(page.getByLabel('Notes')).toHaveValue('Keep this unsent analyst note while I review another screen.')
})

test('UI-01 preserves the measured login illustration and form at desktop, tablet, and mobile widths', async ({ page }, testInfo) => {
  await mockWorkspace(page)
  await page.goto('/')
  await expect(page.getByRole('heading', { name: 'Sign in to your workspace' })).toBeVisible()

  for (const width of [390, 768, 1440]) {
    await page.setViewportSize({ width, height: width === 390 ? 844 : 900 })
    const baseline = await page.evaluate(() => {
      const box = (selector: string) => {
        const element = document.querySelector<HTMLElement>(selector)
        if (!element) return null
        const rect = element.getBoundingClientRect()
        const style = getComputedStyle(element)
        return {
          x: Number(rect.x.toFixed(2)), y: Number(rect.y.toFixed(2)),
          width: Number(rect.width.toFixed(2)), height: Number(rect.height.toFixed(2)),
          display: style.display, background: style.backgroundColor, color: style.color,
          backgroundImage: style.backgroundImage, font: style.font, border: style.borderColor,
          radius: style.borderRadius, padding: style.padding, shadow: style.boxShadow,
        }
      }
      return {
        viewport: { width: innerWidth, height: innerHeight },
        bodyFont: getComputedStyle(document.body).font,
        wrapBackground: getComputedStyle(document.querySelector('.login-wrap')!).backgroundImage,
        layout: box('.login-layout'), story: box('.login-story'),
        storyHeading: box('.login-story h2'),
        illustration: box('.workspace-graphic'), caption: box('.workspace-graphic > span'),
        card: box('.login-card'), heading: box('.login-card h1'),
        field: box('.login-card .stack-form input'), submit: box('.login-card .primary-button'),
        svg: { viewBox: document.querySelector('.workspace-graphic svg')?.getAttribute('viewBox'), textCount: document.querySelectorAll('.workspace-graphic svg text').length, markup: document.querySelector('.workspace-graphic svg')?.outerHTML },
        labels: [...document.querySelectorAll('.workspace-graphic svg text')].map((label) => label.textContent?.trim()),
        graphicStyles: ['.graphic-window', '.graphic-divider', '.graphic-tile', '.graphic-icon', '.graphic-icon.violet', '.graphic-text-line', '.workspace-graphic text', '.graphic-orbit', '.graphic-core'].map((selector) => {
          const element = document.querySelector<SVGElement>(selector)!
          const style = getComputedStyle(element)
          return { selector, fill: style.fill, stroke: style.stroke, fontFamily: style.fontFamily, fontSize: style.fontSize }
        }),
      }
    })
    const geometry = width === 390
      ? { layout: [20, 155.69, 350, 532.63], story: [0, 0, 0, 0], illustration: [0, 0, 0, 0], card: [20, 155.69, 350, 532.63] }
      : width === 768
        ? { layout: [20, 131.13, 728, 637.75], story: [26, 182.86, 376.36, 534.28], illustration: [11, 381.27, 406.36, 252.73], card: [428.36, 155.13, 313.64, 589.75] }
        : { layout: [150, 123.67, 1140, 652.66], story: [170, 159.67, 552.88, 580.66], illustration: [155, 388.23, 582.88, 307.05], card: [810, 174.27, 460, 551.47] }
    for (const selector of ['layout', 'story', 'illustration', 'card'] as const) {
      const element = baseline[selector]
      const [x, y, boxWidth, boxHeight] = geometry[selector]
      expect(element?.x).toBeCloseTo(x, 1)
      expect(element?.y).toBeCloseTo(y, 1)
      expect(element?.width).toBeCloseTo(boxWidth, 1)
      expect(element?.height).toBeCloseTo(boxHeight, 1)
    }
    expect(baseline.bodyFont).toContain('15px / 23.25px')
    expect(baseline.wrapBackground).toContain('radial-gradient')
    expect(baseline.storyHeading).toMatchObject({ color: 'rgb(229, 234, 255)' })
    expect(baseline.storyHeading?.font).toContain(width > 900 ? '44px' : '31px')
    expect(baseline.card).toMatchObject({ backgroundImage: 'linear-gradient(130deg, rgb(25, 31, 45), rgb(21, 27, 39))', border: 'rgb(44, 53, 72)', radius: '14px', shadow: 'rgba(0, 0, 0, 0.12) 0px 5px 20px 0px' })
    expect(baseline.caption).toMatchObject({ color: 'rgb(147, 164, 199)', font: expect.stringContaining('11px / 17.05px') })
    expect(baseline.caption?.height).toBe(width === 390 ? 0 : 17.05)
    expect(baseline.field).toMatchObject({ background: 'rgb(10, 17, 25)', color: 'rgb(220, 231, 239)', border: 'rgb(43, 58, 71)', radius: '5px', height: 46, padding: '9px 10px' })
    expect(baseline.submit).toMatchObject({ backgroundImage: 'linear-gradient(115deg, rgb(82, 105, 214), rgb(104, 90, 201))', color: 'rgb(255, 255, 255)', border: 'rgb(139, 156, 240)', radius: '10px', height: 46 })
    expect(baseline.svg).toMatchObject({ viewBox: '0 0 500 290', textCount: 3 })
    const graphicMarkupHash = preservedGraphicHash(baseline.svg?.markup ?? '')
    expect(graphicMarkupHash).toBe('44e80fa6ef682f2b9e82dc8ff3be593ba5aedfb3020026d4e39683a2e068fd17')
    expect(baseline.labels).toEqual(['ASSETS', 'EVIDENCE', 'ANALYST REVIEW'])
    expect(baseline.graphicStyles).toMatchObject([
      { selector: '.graphic-window', fill: 'rgb(19, 26, 42)', stroke: 'rgb(48, 62, 92)' },
      { selector: '.graphic-divider', stroke: 'rgb(48, 62, 92)' },
      { selector: '.graphic-tile', fill: 'rgb(30, 41, 64)', stroke: 'rgb(74, 91, 129)' },
      { selector: '.graphic-icon', fill: 'rgb(43, 61, 99)' },
      { selector: '.graphic-icon.violet', fill: 'rgb(58, 48, 87)' },
      { selector: '.graphic-text-line', stroke: 'rgb(83, 100, 132)' },
      { selector: '.workspace-graphic text', fill: 'rgb(189, 203, 237)', fontSize: '8px' },
      { selector: '.graphic-orbit', fill: 'rgb(20, 28, 44)', stroke: 'rgb(54, 70, 109)' },
      { selector: '.graphic-core', fill: 'rgb(37, 54, 92)', stroke: 'rgb(106, 131, 203)' },
    ])
    expect(await page.locator('.workspace-graphic svg').count()).toBe(1)
    expect(await page.locator('.workspace-graphic > span').textContent()).toBe('Source evidence → analyst review → explainable decisions')
    expect(baseline.story?.display === 'none').toBe(width === 390)
    await page.screenshot({ path: testInfo.outputPath(`ui01-login-${width}.png`), fullPage: true, animations: 'disabled' })
  }
})

test('UI-REF applies Midnight Iris only to the authenticated workspace and retains accessible state distinctions', async ({ page }, testInfo) => {
  await mockWorkspace(page)
  await signIn(page)

  const palette = await page.locator('.app-shell').evaluate((shell) => {
    const style = getComputedStyle(shell)
    const rgb = (hex: string) => `rgb(${[1, 3, 5].map((offset) => Number.parseInt(hex.slice(offset, offset + 2), 16)).join(', ')})`
    const ratio = (foreground: string, background: string) => {
      const luminance = (color: string) => {
        const channels = color.match(/[\d.]+/g)!.slice(0, 3).map(Number).map((value) => {
          const linear = value / 255
          return linear <= 0.04045 ? linear / 12.92 : ((linear + 0.055) / 1.055) ** 2.4
        })
        return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]
      }
      const a = luminance(foreground)
      const b = luminance(background)
      return Number(((Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05)).toFixed(2))
    }
    return {
      tokens: ['--page', '--page-raised', '--surface', '--surface-raised', '--border', '--accent', '--accent-secondary', '--accent-strong', '--text', '--text-secondary', '--text-muted'].map((token) => style.getPropertyValue(token).trim()),
      ratios: {
        primary: ratio(rgb(style.getPropertyValue('--text').trim()), rgb(style.getPropertyValue('--surface').trim())),
        secondary: ratio(rgb(style.getPropertyValue('--text-secondary').trim()), rgb(style.getPropertyValue('--surface-raised').trim())),
        muted: ratio(rgb(style.getPropertyValue('--text-muted').trim()), rgb(style.getPropertyValue('--surface-raised').trim())),
        accentText: ratio(rgb(style.getPropertyValue('--accent-strong').trim()), rgb(style.getPropertyValue('--surface-raised').trim())),
        primaryButton: ratio('rgb(255, 255, 255)', rgb(style.getPropertyValue('--accent').trim())),
        secondaryAccent: ratio(rgb(style.getPropertyValue('--accent-secondary').trim()), rgb(style.getPropertyValue('--surface-raised').trim())),
      },
    }
  })
  expect(palette.tokens).toEqual(['#0c1420', '#121f2e', '#17283a', '#1d3146', '#30445a', '#7156e8', '#a794ff', '#bcb0ff', '#edf4fc', '#c7d5e5', '#a7b9cc'])
  const { secondaryAccent, ...textRatios } = palette.ratios
  expect(Object.values(textRatios).every((value) => value >= 4.5)).toBe(true)
  expect(secondaryAccent).toBeGreaterThanOrEqual(4.5)
  await expect(page.locator('.panel').first()).toHaveCSS('background-color', 'rgb(23, 40, 58)')

  const primary = page.locator('.app-shell .primary-button').first()
  await expect(primary).toBeVisible()
  await expect(primary).toHaveCSS('background-color', 'rgb(113, 86, 232)')
  await expect(primary).toHaveCSS('color', 'rgb(255, 255, 255)')
  expect((await primary.innerText()).trim()).not.toBe('')

  const states = await page.locator('.app-shell').evaluate((shell) => {
    const probes = document.createElement('div')
    probes.className = 'ui01-state-probes'
    probes.style.position = 'fixed'
    probes.style.left = '-10000px'
    probes.innerHTML = '<span class="status-badge success">Success</span><span class="status-badge unavailable">Unavailable</span><span class="status-badge not_assessed">Not assessed</span><span class="status-badge no_match">No match</span>'
    shell.append(probes)
    return [...probes.querySelectorAll<HTMLElement>('.status-badge')].map((badge) => ({
      name: badge.textContent,
      background: getComputedStyle(badge).backgroundColor,
      color: getComputedStyle(badge).color,
    }))
  })
  expect(new Set(states.map((state) => state.background)).size).toBe(4)
  expect(states.map((state) => state.name)).toEqual(['Success', 'Unavailable', 'Not assessed', 'No match'])

  await page.keyboard.press('Tab')
  const keyboardTarget = page.locator(':focus')
  await expect(keyboardTarget).toBeFocused()
  await expect(keyboardTarget).toHaveCSS('outline-style', 'solid')
  await expect(keyboardTarget).toHaveCSS('outline-color', 'rgb(188, 176, 255)')

  for (const width of [390, 768, 1440]) {
    await page.setViewportSize({ width, height: width === 390 ? 844 : 1000 })
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
    await expect(page.getByRole('heading', { name: 'Investigation workspace' })).toBeVisible()
    await page.screenshot({ path: testInfo.outputPath(`ui01-overview-${width}.png`), fullPage: true, animations: 'disabled' })
  }
})

test('UI-08 responsive breakpoints keep the login preservation baseline and workspace inside the viewport', async ({ page }, testInfo) => {
  await mockWorkspace(page)
  const loginWidths = [390, 679, 680, 681, 768, 899, 900, 901, 1440]
  const loginMeasurements = [] as Array<Record<string, unknown>>
  await page.goto('/')
  await expect(page.getByRole('heading', { name: 'Sign in to your workspace' })).toBeVisible()
  for (const width of loginWidths) {
    await page.setViewportSize({ width, height: width <= 680 ? 844 : 900 })
    const state = await page.evaluate(() => {
      const measure = (selector: string) => {
        const element = document.querySelector<HTMLElement>(selector)
        if (!element) return null
        const rect = element.getBoundingClientRect()
        const style = getComputedStyle(element)
        return { x: Number(rect.x.toFixed(2)), y: Number(rect.y.toFixed(2)), width: Number(rect.width.toFixed(2)), height: Number(rect.height.toFixed(2)), display: style.display, color: style.color, background: style.backgroundColor, backgroundImage: style.backgroundImage, border: style.borderColor, radius: style.borderRadius, padding: style.padding, shadow: style.boxShadow, font: style.font }
      }
      return {
        viewport: innerWidth,
        documentWidth: document.documentElement.scrollWidth,
        layout: measure('.login-layout'),
        story: measure('.login-story'),
        illustration: measure('.workspace-graphic'),
        caption: measure('.workspace-graphic > span'),
        card: measure('.login-card'),
        field: measure('.login-card input'),
        submit: measure('.login-card button[type="submit"]'),
        svgHashSource: document.querySelector('.workspace-graphic svg')?.outerHTML,
      }
    })
    loginMeasurements.push({ width, layout: state.layout, story: state.story, illustration: state.illustration, card: state.card, documentWidth: state.documentWidth })
    expect(state.story?.display === 'none').toBe(width <= 680)
    expect(state.documentWidth).toBeLessThanOrEqual(width)
    expect(preservedGraphicHash(state.svgHashSource ?? '')).toBe('44e80fa6ef682f2b9e82dc8ff3be593ba5aedfb3020026d4e39683a2e068fd17')
    expect(state.card).toMatchObject({ backgroundImage: 'linear-gradient(130deg, rgb(25, 31, 45), rgb(21, 27, 39))', border: 'rgb(44, 53, 72)', radius: '14px', shadow: 'rgba(0, 0, 0, 0.12) 0px 5px 20px 0px', padding: width <= 680 ? '26px 22px' : width <= 900 ? '24px' : '32px' })
    expect(state.field).toMatchObject({ background: 'rgb(10, 17, 25)', color: 'rgb(220, 231, 239)', border: 'rgb(43, 58, 71)', radius: '5px', height: 46, padding: '9px 10px' })
    expect(state.submit).toMatchObject({ backgroundImage: 'linear-gradient(115deg, rgb(82, 105, 214), rgb(104, 90, 201))', color: 'rgb(255, 255, 255)', border: 'rgb(139, 156, 240)', radius: '10px', height: 46 })
    const paddingParts = (state.card?.padding ?? '').split(' ').map((value) => Number.parseFloat(value))
    const horizontalPadding = paddingParts.length > 1 ? paddingParts[1] : paddingParts[0]
    // The card rectangle includes its 1px border; preserve that inset when
    // comparing the protected form's content-box geometry.
    expect(state.field?.x).toBeCloseTo((state.card?.x ?? 0) + horizontalPadding + 1, 1)
    expect(state.field?.width).toBeCloseTo((state.card?.width ?? 0) - horizontalPadding * 2 - 2, 1)
    expect(state.submit?.x).toBeCloseTo(state.field?.x ?? 0, 1)
    expect(state.submit?.width).toBeCloseTo(state.field?.width ?? 0, 1)
    expect(state.submit?.y).toBeGreaterThan((state.field?.y ?? 0) + (state.field?.height ?? 0))
    await expect(page.getByLabel('Username')).toBeVisible()
    await expect(page.getByLabel('Password')).toBeVisible()
    await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible()
    await expect(page.locator('.workspace-graphic svg')).toHaveCount(1)
    await expect(page.locator('.workspace-graphic svg text')).toHaveText(['ASSETS', 'EVIDENCE', 'ANALYST REVIEW'])
    if ([390, 680, 768, 900, 1440].includes(width)) {
      await page.screenshot({ path: testInfo.outputPath(`ui08-login-${width}.png`), fullPage: true, animations: 'disabled' })
    }
  }
  console.log(`UI08_LOGIN_BASELINE ${JSON.stringify(loginMeasurements)}`)

  await page.setViewportSize({ width: 1440, height: 1000 })
  await page.getByLabel('Username').fill(admin.username)
  await page.getByLabel('Password').fill('Synthetic-UI-Password-2026!')
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { name: 'Investigation workspace' })).toBeVisible()
  const workspaceWidths = [390, 679, 680, 681, 768, 899, 900, 901, 1119, 1120, 1121, 1440]
  for (const width of workspaceWidths) {
    await page.setViewportSize({ width, height: width <= 680 ? 844 : 1000 })
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
    await expect(page.getByRole('heading', { name: 'Investigation workspace' })).toBeVisible()
    const mobileMenu = page.getByRole('button', { name: 'Open navigation' })
    if (width <= 900) await expect(mobileMenu).toBeVisible()
    else await expect(mobileMenu).toBeHidden()
    if ([390, 680, 768, 900, 1440].includes(width)) {
      await page.evaluate(() => window.scrollTo(0, 0))
      await page.screenshot({ path: testInfo.outputPath(`ui08-workspace-${width}.png`), fullPage: true, animations: 'disabled' })
    }
  }
  // 1152px and 720px are the effective CSS viewport widths for 125% and 200%
  // browser zoom on a 1440px display. They exercise reflow without changing the
  // browser's own zoom preference or the user's OS scaling.
  for (const width of [1152, 720]) {
    await page.setViewportSize({ width, height: 900 })
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
    await expect(page.getByRole('heading', { name: 'Investigation workspace' })).toBeVisible()
  }
})

test('UI-08 interactive names, touch targets, status contrast, and intentional table scrolling are measurable', async ({ page }, testInfo) => {
  await mockWorkspace(page)
  await signIn(page)
  await page.setViewportSize({ width: 390, height: 844 })

  const audit = await page.evaluate(() => {
    const isVisible = (element: Element) => {
      const style = getComputedStyle(element)
      if (style.display === 'none' || style.visibility === 'hidden' || !(element as HTMLElement).getClientRects().length) return false
      for (let parent = element.parentElement; parent; parent = parent.parentElement) {
        if (parent.getAttribute('aria-hidden') === 'true') return false
        if (parent instanceof HTMLDetailsElement && !parent.open && !parent.querySelector(':scope > summary')?.contains(element)) return false
      }
      return true
    }
    const nameOf = (element: Element) => {
      const html = element as HTMLElement
      const labelledBy = html.getAttribute('aria-labelledby')?.split(/\s+/).map((id) => document.getElementById(id)?.textContent?.trim() ?? '').join(' ').trim()
      const explicit = html.getAttribute('aria-label')?.trim() || labelledBy
      if (explicit) return explicit
      if (element instanceof HTMLInputElement || element instanceof HTMLSelectElement || element instanceof HTMLTextAreaElement) {
        return Array.from(element.labels ?? []).map((label) => label.textContent?.trim() ?? '').join(' ').trim() || html.title.trim()
      }
      if (element instanceof HTMLImageElement) return element.alt.trim()
      return html.innerText?.trim() || html.title.trim()
    }
    const interactive = Array.from(document.querySelectorAll('button, a[href], input:not([type="hidden"]), select, textarea, summary, [role="button"], [tabindex="0"]')).filter(isVisible)
    const unnamed = interactive.filter((element) => !nameOf(element)).map((element) => ({ tag: element.tagName, role: element.getAttribute('role'), className: (element as HTMLElement).className?.toString().slice(0, 100) }))
    const undersized = interactive.map((element) => {
      const rect = element.getBoundingClientRect()
      return { element: element.tagName.toLowerCase(), name: nameOf(element), width: Math.round(rect.width), height: Math.round(rect.height) }
    }).filter((item) => item.width < 24 || item.height < 24)

    const contrastRatio = (foreground: number[], background: number[]) => {
      const luminance = (rgb: number[]) => {
        const [r, g, b] = rgb.map((value) => { const channel = value / 255; return channel <= .04045 ? channel / 12.92 : ((channel + .055) / 1.055) ** 2.4 })
        return .2126 * r + .7152 * g + .0722 * b
      }
      const a = luminance(foreground), b = luminance(background)
      return Number(((Math.max(a, b) + .05) / (Math.min(a, b) + .05)).toFixed(2))
    }
    const parseRgb = (value: string) => value.match(/[\d.]+/g)?.slice(0, 3).map(Number) ?? [0, 0, 0]
    const renderedText = Array.from(document.querySelectorAll<HTMLElement>('body *')).filter((element) => {
      if (!isVisible(element) || element.closest('svg') || !Array.from(element.childNodes).some((node) => node.nodeType === Node.TEXT_NODE && node.textContent?.trim())) return false
      return true
    }).map((element) => {
      const foreground = getComputedStyle(element).color
      let backgroundElement: HTMLElement | null = element
      let background = 'rgb(13, 17, 23)'
      while (backgroundElement) {
        const candidate = getComputedStyle(backgroundElement).backgroundColor
        const alpha = candidate.match(/[\d.]+/g)?.[3]
        if (candidate !== 'rgba(0, 0, 0, 0)' && (alpha === undefined || Number(alpha) > 0)) { background = candidate; break }
        backgroundElement = backgroundElement.parentElement
      }
      const rect = element.getBoundingClientRect()
      return { text: element.childNodes.length ? Array.from(element.childNodes).filter((node) => node.nodeType === Node.TEXT_NODE).map((node) => node.textContent?.trim()).filter(Boolean).join(' ').slice(0, 80) : '', ratio: contrastRatio(parseRgb(foreground), parseRgb(background)), foreground, background, selector: element.tagName.toLowerCase() + (element.className ? '.' + element.className.toString().trim().replace(/\s+/g, '.') : ''), x: Math.round(rect.x), y: Math.round(rect.y) }
    })

    const shell = document.querySelector<HTMLElement>('.app-shell')!
    const probe = document.createElement('div')
    probe.style.cssText = 'position:fixed;left:4px;bottom:4px;z-index:99999;display:flex;gap:4px;align-items:center;padding:4px;background:#1b2430'
    probe.innerHTML = '<span class="status-badge success">Success</span><span class="status-badge critical">Critical</span><span class="status-badge high">High</span><span class="status-badge medium">Medium</span><span class="status-badge low">Low</span><span class="status-badge informational">Informational</span><span class="status-badge unavailable">Unavailable</span><span class="status-badge not_assessed">Not assessed</span><span class="status-badge no_match">No match</span><button class="primary-button" disabled>Disabled action</button>'
    shell.append(probe)
    const rgbChannels = (value: string) => value.match(/[\d.]+/g)?.slice(0, 3).map(Number) ?? [0, 0, 0]
    const luminance = (rgb: number[]) => {
      const [r, g, b] = rgb.map((value) => { const srgb = value / 255; return srgb <= .04045 ? srgb / 12.92 : ((srgb + .055) / 1.055) ** 2.4 })
      return .2126 * r + .7152 * g + .0722 * b
    }
    const ratio = (foreground: number[], background: number[]) => {
      const a = luminance(foreground), b = luminance(background)
      return Number(((Math.max(a, b) + .05) / (Math.min(a, b) + .05)).toFixed(2))
    }
    const blend = (foreground: number[], background: number[], opacity: number) => foreground.map((channel, index) => channel * opacity + background[index] * (1 - opacity))
    const colors = Array.from(probe.querySelectorAll<HTMLElement>('.status-badge')).map((element) => {
      const style = getComputedStyle(element)
      return { label: element.innerText, ratio: ratio(rgbChannels(style.color), rgbChannels(style.backgroundColor)), color: style.color, background: style.backgroundColor }
    })
    const disabled = probe.querySelector<HTMLButtonElement>('button')!
    const disabledStyle = getComputedStyle(disabled)
    const parentBackground = rgbChannels(getComputedStyle(probe).backgroundColor)
    const disabledOpacity = Number(disabledStyle.opacity)
    const disabledRatio = ratio(blend(rgbChannels(disabledStyle.color), parentBackground, disabledOpacity), blend(rgbChannels(disabledStyle.backgroundColor), parentBackground, disabledOpacity))
    const disabledColors = { color: disabledStyle.color, background: disabledStyle.backgroundColor }
    probe.remove()

    const firstNavLink = shell.querySelector<HTMLElement>('.rail-link[data-tooltip]')!
    shell.classList.add('sidebar-collapsed')
    const tooltipStyle = getComputedStyle(firstNavLink, '::after')
    const tooltipContrast = ratio(rgbChannels(tooltipStyle.color), rgbChannels(tooltipStyle.backgroundColor))
    shell.classList.remove('sidebar-collapsed')

    const tableFixture = document.createElement('div')
    tableFixture.className = 'panel ui08-table-fixture'
    tableFixture.style.cssText = 'position:fixed;left:-10000px;top:0;width:calc(100vw - 32px)'
    tableFixture.innerHTML = '<div class="table-wrap"><table style="min-width:960px"><caption>Temporary dense table used for responsive overflow verification</caption><thead><tr>' + Array.from({ length: 12 }, (_, index) => `<th>Column ${index + 1}</th>`).join('') + '</tr></thead><tbody><tr>' + Array.from({ length: 12 }, () => '<td>synthetic-long-record-value</td>').join('') + '</tr></tbody></table></div>'
    shell.append(tableFixture)
    const tableWrap = tableFixture.querySelector<HTMLElement>('.table-wrap')!
    const tableOverflow = { clientWidth: tableWrap.clientWidth, scrollWidth: tableWrap.scrollWidth, documentWidth: document.documentElement.scrollWidth }
    tableFixture.remove()
    return { unnamed, undersized, renderedText, colors, disabled: { opacity: disabledOpacity, ratio: disabledRatio, ...disabledColors }, tooltipContrast, tableOverflow }
  })
  const lowestContrastExamples = audit.renderedText.slice().sort((a, b) => a.ratio - b.ratio).slice(0, 5)
  console.log(`UI08_ACCESSIBILITY_SUMMARY ${JSON.stringify({ unnamed: audit.unnamed, undersized: audit.undersized, renderedTextCount: audit.renderedText.length, minimumRenderedContrast: lowestContrastExamples[0]?.ratio, statusContrast: audit.colors.map(({ label, ratio }) => ({ label, ratio })), disabled: audit.disabled, tooltipContrast: audit.tooltipContrast, tableOverflow: audit.tableOverflow })}`)
  console.log(`UI08_LOWEST_RENDERED_TEXT_CONTRAST ${JSON.stringify(lowestContrastExamples)}`)
  expect(audit.unnamed).toEqual([])
  expect(audit.undersized).toEqual([])
  expect(audit.renderedText.every((item) => item.ratio >= 4.5)).toBe(true)
  expect(audit.colors.every((color) => color.ratio >= 4.5)).toBe(true)
  expect(audit.disabled.ratio).toBeGreaterThanOrEqual(4.5)
  expect(audit.tooltipContrast).toBeGreaterThanOrEqual(4.5)
  expect(audit.tableOverflow.scrollWidth).toBeGreaterThan(audit.tableOverflow.clientWidth)
  expect(audit.tableOverflow.documentWidth).toBeLessThanOrEqual(390)
  await page.getByRole('button', { name: 'Open navigation' }).click()
  const drawer = page.getByRole('dialog', { name: 'Primary navigation' })
  await expect(drawer).toBeVisible()
  await expect(page.locator('.nav-list .rail-link[aria-label="Overview"]')).toBeFocused()
  await page.keyboard.press('Shift+Tab')
  await expect(page.getByRole('button', { name: 'CyberLens overview' })).toBeFocused()
  await page.keyboard.press('Shift+Tab')
  await expect(page.getByRole('button', { name: 'Administration', exact: true })).toBeFocused()
  await page.keyboard.press('Tab')
  await expect(page.getByRole('button', { name: 'CyberLens overview' })).toBeFocused()
  await page.keyboard.press('Escape')
  await expect(page.getByRole('button', { name: 'Open navigation' })).toBeFocused()
  const focusTarget = page.getByRole('button', { name: 'Open navigation' })
  await expect(focusTarget).toHaveCSS('outline-style', 'solid')
  const focusContrast = await focusTarget.evaluate((element) => {
    const foreground = getComputedStyle(element).outlineColor.match(/[\d.]+/g)!.slice(0, 3).map(Number)
    const background = getComputedStyle(document.querySelector('.app-shell')!).backgroundColor.match(/[\d.]+/g)!.slice(0, 3).map(Number)
    const luminance = (rgb: number[]) => rgb.map((value) => { const channel = value / 255; return channel <= .04045 ? channel / 12.92 : ((channel + .055) / 1.055) ** 2.4 }).reduce((sum, value, index) => sum + value * [.2126, .7152, .0722][index], 0)
    const a = luminance(foreground), b = luminance(background)
    return Number(((Math.max(a, b) + .05) / (Math.min(a, b) + .05)).toFixed(2))
  })
  expect(focusContrast).toBeGreaterThanOrEqual(3)
  console.log(`UI08_FOCUS_INDICATOR_CONTRAST ${focusContrast}`)
  await page.screenshot({ path: testInfo.outputPath('ui08-mobile-focus-and-drawer-390.png'), animations: 'disabled' })
})

test('UI-08 long errors and dense data stay readable at narrow and effective zoom widths', async ({ page }, testInfo) => {
  const longError = `Synthetic provider error: ${'detail-context-without-spaces-'.repeat(24)}`
  await mockWorkspace(page)
  await page.route('**/api/v1/assets', (route) => route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ detail: longError }) }))
  await signIn(page)
  await page.locator('.nav-list .rail-link[aria-label="Assets"]').click()
  const alert = page.getByRole('alert')
  await expect(alert).toBeVisible()
  // Exercise the existing accessible alert with test-only long error content;
  // the application's provider-error summary deliberately remains concise.
  await alert.locator('span').evaluate((element, value) => { element.textContent = value }, longError)
  await expect(alert).toContainText('Synthetic provider error')
  for (const width of [390, 720, 1152, 1440]) {
    await page.setViewportSize({ width, height: width < 800 ? 844 : 900 })
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
    await expect.poll(() => alert.evaluate((element) => element.scrollWidth <= element.clientWidth + 1)).toBe(true)
    await expect(alert).toBeVisible()
    if (width === 390 || width === 720 || width === 1440) {
      await page.screenshot({ path: testInfo.outputPath(`ui08-long-error-${width}.png`), fullPage: true, animations: 'disabled' })
    }
  }
})
