import { cpus, platform, totalmem, arch } from 'node:os'
import { expect, test, type Page } from '@playwright/test'

const timestamp = '2026-10-21T10:00:00Z'
const user = { id: 'graph-admin', username: 'graph-admin', email: null, role: 'admin', is_active: true, must_change_password: false }
const nodeTypes = ['asset', 'domain', 'ip', 'certificate', 'software', 'cve', 'finding', 'investigation', 'incident', 'playbook_task'] as const
const relationshipTypes = ['investigated_in', 'identifies_domain', 'identifies_ip', 'resolves_to', 'redirects_to', 'presents_certificate', 'includes_software', 'has_finding', 'concerns_software', 'references_cve', 'potentially_affected_by', 'concerns_asset', 'tracks_finding', 'belongs_to_incident']

type FixtureNode = { id: string; type: typeof nodeTypes[number]; label: string; details: Record<string, unknown> }
type FixtureEdge = { id: string; from_node_id: string; from_node_type: typeof nodeTypes[number]; to_node_id: string; to_node_type: typeof nodeTypes[number]; relationship_type: string; evidence_role: 'direct' | 'contextual'; collector: string; source: string; evidence_id: string; observed_at: string; data_mode: 'demo' | 'live'; details: Record<string, unknown> }
type FixtureGraph = { investigation_id: string; generated_at: string; nodes: FixtureNode[]; edges: FixtureEdge[] }

function makeGraph(investigationId: string, nodeCount: number, edgeCount: number): FixtureGraph {
  const nodes = Array.from({ length: nodeCount }, (_, index) => ({
    id: 'node-' + index,
    type: nodeTypes[index % nodeTypes.length],
    label: index === 6 ? '<img src=x>' : ['inventory.example.test', 'login.example.test', '198.51.100.7', 'TLS certificate', 'OpenSSL 3.0.1', 'CVE-2026-1000', 'Finding label', 'Investigation run', 'Incident case', 'Playbook task'][index] ?? 'Synthetic node ' + index,
    details: { fixture: 'synthetic-only', sequence: index, external_label: index === 6 ? '<script>alert(1)</script>' : null },
  })) as FixtureNode[]
  const edges = Array.from({ length: edgeCount }, (_, index) => {
    const from = nodes[index % nodes.length]
    const to = nodes[(index + 1) % nodes.length]
    return {
      id: 'edge-' + index,
      from_node_id: from.id,
      from_node_type: from.type,
      to_node_id: to.id,
      to_node_type: to.type,
      relationship_type: relationshipTypes[index % relationshipTypes.length],
      evidence_role: index % 3 === 0 ? 'contextual' as const : 'direct' as const,
      collector: 'synthetic-fixture',
      source: 'Synthetic fixture provider',
      evidence_id: 'evidence-' + index,
      observed_at: timestamp,
      data_mode: 'demo' as const,
      details: { applicability: 'applies', fixture: 'synthetic-only', from_label: from.label, to_label: to.label, context: index === 0 ? '<img src=external>' : null },
    }
  })
  return { investigation_id: investigationId, generated_at: timestamp, nodes, edges }
}

function makeInvestigation(id: string, older = false) {
  const created = older ? '2026-10-19T10:00:00Z' : timestamp
  return {
    id, asset_id: 'asset-graph', asset_kind: 'domain', asset_identifier: 'inventory.example.test',
    mode: 'demo', demo_data: true, scenario: 'routine_website', status: 'completed', progress: 100,
    started_at: created, finished_at: created, created_at: created, error_summary: null, attempt_number: 1, risk: null,
    asset: { id: 'asset-graph', kind: 'domain', identifier: 'inventory.example.test', url_retention_complete: true, notes: '', criticality: 'medium', data_classification: 'public', trust_zone: 'external', exposure_classification: 'internet_facing', business_owner: null, protection_requirements: [], authorized_at: null, authorization_note: null, authorization_id: null, authorization_expires_at: null, components: [] },
    attempts: [], collector_runs: [], findings: [],
    evidence: Array.from({ length: 850 }, (_, index) => ({
      id: 'evidence-' + index, source: 'Synthetic fixture provider', observed_at: timestamp,
      evidence_json: { freshness: 'fresh', provenance: { provider: 'Synthetic fixture provider' }, applicability: 'applies' },
      sha256: 'a'.repeat(64), is_synthetic: true,
    })),
    ip_intelligence: null,
  }
}

async function installGraphMocks(page: Page, initialGraph: FixtureGraph, usePartial = false) {
  let activeGraph = initialGraph
  let failNextGraph = false
  const current = makeInvestigation('graph-current')
  const previous = makeInvestigation('graph-previous', true)
  if (usePartial) current.status = 'partial'
  await page.addInitScript(() => { document.cookie = 'cyberlens_csrf=graph-ui-token; path=/' })
  await page.route('**/health/ready', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ status: 'ready', service: 'cyberlens', mode: 'demo', demo_data: true, dependencies: { database: true, redis: true, worker: true } }) }))
  await page.route('**/api/v1/**', async (route) => {
    const url = new URL(route.request().url())
    const path = url.pathname.replace('/api/v1', '')
    const method = route.request().method()
    const json = (status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
    if (path === '/health/ready') return json(200, { status: 'ready', service: 'cyberlens-api', mode: 'demo', demo_data: true, dependencies: { database: true, redis: true, worker: true } })
    if (path === '/auth/me') return json(401, { detail: 'Sign in required' })
    if (path === '/auth/csrf') return json(200, { csrf_token: 'graph-ui-token' })
    if (path === '/auth/login' && method === 'POST') return json(200, { user })
    if (path === '/assets') return json(200, [current.asset])
    if (path === '/investigations') return json(200, [current, previous])
    if (path === '/incidents' || path === '/reports' || path === '/monitoring') return json(200, [])
    if (path === '/integrations/status') return json(200, { mode: 'demo', integrations: [] })
    if (path === '/integrations/spamhaus-drop/status' || path === '/integrations/cins-army/status' || path === '/integrations/openphish/status') {
      const id = path.split('/')[2]
      return json(200, { id, name: id, enabled: false, mode: 'demo', freshness: 'not_assessed', snapshot_id: null, content_sha256: null, parser_version: 'synthetic-1.0', record_count: 0, retrieved_at: null, published_at: null, last_successful_revalidation_at: null, snapshot_age_seconds: null, freshness_limit_seconds: 86400, next_refresh_at: null, metadata: null, attribution: 'Synthetic offline fixture', latest_attempt: null, coverage_note: 'No live requests.', configuration_state: 'demo', configuration_reason: 'Offline fixture', access_scope: 'demo' })
    }
    if (path === '/investigations/graph-current' || path === '/investigations/graph-previous') return json(200, path.endsWith('current') ? current : previous)
    if (path === '/investigations/graph-current/graph') {
      if (failNextGraph) {
        failNextGraph = false
        return json(503, { detail: 'Synthetic graph projection unavailable' })
      }
      return json(200, activeGraph)
    }
    if (path === '/investigations/graph-previous/graph') return json(200, { ...activeGraph, investigation_id: 'graph-previous' })
    if (path === '/investigations/graph-current/changes/graph-previous') {
      const edge = activeGraph.edges[0]
      return json(200, { changes: edge ? [{ status: 'new', edge, previous_edge: null, reason: 'Synthetic comparison fixture' }] : [] })
    }
    if (path === '/posture/scorecard') return json(200, {})
    return json(200, [])
  })
  return { setGraph: (graph: FixtureGraph) => { activeGraph = graph }, failGraphOnce: () => { failNextGraph = true } }
}

async function signInToInvestigation(page: Page) {
  await page.goto('/#/investigations/graph-current')
  await page.getByLabel('Username').fill(user.username)
  await page.getByLabel('Password').fill('Synthetic-Graph-Only-Password-2026!')
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { name: 'Investigations', exact: true })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Evidence graph' })).toBeVisible()
  await expect(page.locator('.graph-explorer')).toBeVisible()
}

test('graph controls, evidence detail, filters, keyboard and list stay coordinated', async ({ page }, testInfo) => {
  test.setTimeout(60_000)
  const graph = makeGraph('graph-current', 20, 28)
  await installGraphMocks(page, graph, true)
  await signInToInvestigation(page)
  const svg = page.locator('.graph-canvas')
  const firstNode = page.locator('.graph-canvas [data-node-id="node-0"]')
  const distantNode = page.locator('.graph-canvas [data-node-id="node-19"]')
  const renderedNodeDistance = await firstNode.evaluate((node, other) => {
    const first = (node as SVGGElement).getScreenCTM()
    const second = (other as SVGGElement).getScreenCTM()
    return first && second ? Math.hypot(first.e - second.e, first.f - second.f) : 0
  }, await distantNode.elementHandle())
  expect(renderedNodeDistance).toBeGreaterThan(300)
  const originalView = await svg.getAttribute('viewBox')

  await page.getByRole('button', { name: 'Zoom in' }).click()
  await expect(svg).not.toHaveAttribute('viewBox', originalView!)
  const zoomedView = await svg.getAttribute('viewBox')
  await page.getByRole('button', { name: 'Pan graph right' }).click()
  await expect(svg).not.toHaveAttribute('viewBox', zoomedView!)
  await page.getByRole('button', { name: 'Fit visible nodes' }).click()
  await expect(svg).toHaveAttribute('viewBox', / /)
  await page.getByRole('button', { name: 'Reset view' }).click()
  await expect(svg).toHaveAttribute('viewBox', originalView!)
  await svg.scrollIntoViewIfNeeded()
  const panHandle = page.locator('.graph-pan-handle')
  await panHandle.scrollIntoViewIfNeeded()
  const bounds = await panHandle.boundingBox()
  expect(bounds).not.toBeNull()
  await page.mouse.move(bounds!.x + 2, bounds!.y + 2)
  await page.mouse.down()
  await expect(svg).toHaveClass(/is-panning/)
  await page.mouse.move(bounds!.x + 50, bounds!.y + 28, { steps: 4 })
  await page.mouse.up()
  await expect(svg).not.toHaveAttribute('viewBox', originalView!)
  await page.getByRole('button', { name: 'Reset view' }).click()
  await svg.focus()
  await page.keyboard.press('ArrowRight')
  await expect(svg).not.toHaveAttribute('viewBox', originalView!)
  await page.getByRole('button', { name: 'Reset view' }).click()

  await page.getByLabel('Filter graph by node type').selectOption('software')
  await expect(page.getByText(/Filtered view: showing/)).toBeVisible()
  await expect(page.locator('.graph-node')).toHaveCount(2)
  await page.getByLabel('Filter graph by node type').selectOption('all')
  await page.getByLabel('Filter graph by relationship type').selectOption('references_cve')
  await page.getByLabel('Filter graph by evidence role').selectOption('contextual')
  await expect(page.locator('.graph-edge')).toHaveCount(1)
  await page.getByLabel('Filter graph by relationship type').selectOption('all')
  await page.getByLabel('Filter graph by evidence role').selectOption('all')

  await page.getByLabel('Search graph nodes').fill('CVE-2026-1000')
  await page.getByRole('option', { name: /CVE-2026-1000/ }).click()
  await expect(page.locator('[data-node-id="node-5"]')).toBeFocused()
  await expect(page.getByRole('heading', { name: 'CVE-2026-1000' })).toBeVisible()
  const assetNode = page.getByRole('button', { name: /asset: inventory.example.test/ })
  await assetNode.focus()
  await page.keyboard.press('Enter')
  await expect(page.getByRole('region', { name: 'Selected graph record details' }).getByRole('heading', { name: 'inventory.example.test' })).toBeVisible()
  const positionBefore = await page.locator('[data-node-id="node-0"]').getAttribute('transform')
  await page.getByRole('button', { name: 'Refresh graph' }).click()
  await expect(page.getByRole('button', { name: 'Refresh graph' })).toBeEnabled()
  await expect(page.locator('[data-node-id="node-0"]')).toHaveAttribute('transform', positionBefore!)

  const edgeButton = page.getByRole('button', { name: /direct relationship: investigated in/i })
  await edgeButton.focus()
  await page.keyboard.press('Enter')
  const details = page.getByRole('region', { name: 'Selected graph record details' })
  await expect(details.getByText('Synthetic fixture provider')).toBeVisible()
  await expect(details.getByText('Evidence reference')).toBeVisible()
  await expect(details.getByText('fresh', { exact: true })).toBeVisible()
  await expect(details.getByText('applies', { exact: true }).first()).toBeVisible()
  await expect(page.getByText(/Partial evidence coverage/)).toBeVisible()

  await expect(page.locator('.graph-node-label').filter({ hasText: '<img src=x>' })).toBeVisible()
  await expect(page.locator('.graph-canvas img, .graph-canvas script')).toHaveCount(0)
  await page.getByRole('button', { name: 'Reset view' }).click()
  await firstNode.click()
  await expect(page.getByRole('region', { name: 'Selected graph record details' }).getByRole('heading', { name: 'inventory.example.test' })).toBeVisible()
  const filtersOverflow = await page.locator('.graph-filter-toolbar').evaluate((element) => element.scrollWidth > element.clientWidth)
  expect(filtersOverflow).toBe(false)
  await page.evaluate(() => { window.scrollTo(0, 0); document.querySelectorAll('.graph-canvas-scroll').forEach((element) => { element.scrollLeft = 0; element.scrollTop = 0 }) })
  await page.addStyleTag({ content: '.topbar { position: static !important; }' })
  await page.locator('.graph-explorer').screenshot({ path: testInfo.outputPath('module30-evidence-graph-interactive-desktop.png'), animations: 'disabled' })
  await page.getByRole('button', { name: 'Evidence list' }).click()
  await expect(page.getByRole('heading', { name: /Evidence relationships/ })).toBeVisible()
  await expect(page.getByRole('list', { name: 'Evidence relationships' })).toBeVisible()
  const selectedGraphListNode = page.locator('.graph-node-list .graph-list-link[aria-pressed="true"]')
  await expect(selectedGraphListNode).toHaveCount(1)
  await expect(selectedGraphListNode).toHaveCSS('background-color', 'rgb(43, 41, 77)')
  await page.locator('.graph-explorer').screenshot({ path: testInfo.outputPath('module30-evidence-graph-accessible-list-desktop.png'), animations: 'disabled' })
  await page.getByRole('button', { name: 'Interactive graph' }).click()

  for (const width of [390, 768, 1440]) {
    await page.setViewportSize({ width, height: 900 })
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
    await page.locator('.graph-explorer').screenshot({ path: testInfo.outputPath('module30-evidence-graph-' + width + '.png'), animations: 'disabled' })
  }
})

test('synthetic graph profiles measure loading and interaction and gate effects by size', async ({ browser, page }, testInfo) => {
  const control = await installGraphMocks(page, makeGraph('graph-current', 20, 28))
  await signInToInvestigation(page)
  const measurements: Array<{ nodes: number; edges: number; render_ms: number; search_ms: number; profile: string }> = []
  for (const [nodeCount, edgeCount] of [[20, 28], [120, 240], [400, 800]]) {
    control.setGraph(makeGraph('graph-current', nodeCount, edgeCount))
    await page.evaluate(() => performance.mark('graph-profile-start'))
    await page.getByRole('button', { name: 'Refresh graph' }).click()
    const explorer = page.locator('.graph-explorer')
    await expect(explorer).toHaveAttribute('data-node-count', String(nodeCount))
    await expect(explorer).toHaveAttribute('data-edge-count', String(edgeCount))
    const renderMs = await page.evaluate(() => {
      performance.mark('graph-profile-ready')
      return Number(performance.measure('graph-profile-render', 'graph-profile-start', 'graph-profile-ready').duration.toFixed(1))
    })
    await page.evaluate(() => performance.mark('graph-search-start'))
    await page.getByLabel('Search graph nodes').fill('Synthetic node ' + (nodeCount - 1))
    await expect(page.getByRole('option', { name: 'Synthetic node ' + (nodeCount - 1) })).toBeVisible()
    const searchMs = await page.evaluate(() => {
      performance.mark('graph-search-ready')
      return Number(performance.measure('graph-search-interaction', 'graph-search-start', 'graph-search-ready').duration.toFixed(1))
    })
    const expectedProfile = nodeCount > 120 || edgeCount > 240 ? 'simplified' : 'full'
    await expect(explorer).toHaveAttribute('data-render-profile', expectedProfile)
    if (expectedProfile === 'simplified') await expect(page.locator('.graph-node-enter')).toHaveCount(0)
    measurements.push({ nodes: nodeCount, edges: edgeCount, render_ms: renderMs, search_ms: searchMs, profile: expectedProfile })
  }
  console.log(JSON.stringify({
    benchmark: 'synthetic evidence graph UI',
    test_date: new Date().toISOString(),
    os: platform(), architecture: arch(), cpu: cpus()[0]?.model ?? 'not reported', logical_cpus: cpus().length,
    reported_memory_bytes: totalmem(), browser: browser.version(), viewport: page.viewportSize(),
    fixture_source: 'deterministic generated test data; no production indicators',
    measurements,
  }))
  testInfo.annotations.push({ type: 'benchmark', description: JSON.stringify(measurements) })
})

test('empty and unavailable graph projections are explicit and retryable', async ({ page }) => {
  const emptyGraph = makeGraph('graph-current', 0, 0)
  const control = await installGraphMocks(page, emptyGraph)
  await signInToInvestigation(page)
  control.failGraphOnce()
  await page.getByRole('button', { name: 'Refresh graph' }).click()
  await expect(page.locator('.graph-load-error')).toContainText('Synthetic graph projection unavailable')
  await page.getByRole('button', { name: 'Retry graph' }).click()
  await expect(page.getByText('No evidence nodes are in this saved projection. An empty projection is not a clean result.')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Evidence list' })).toBeVisible()
})
