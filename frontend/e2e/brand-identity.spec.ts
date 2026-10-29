import { expect, test, type Page } from '@playwright/test'

test.use({ video: { mode: 'on', size: { width: 1440, height: 900 } } })

const admin = { id: 'brand-admin', username: 'brand-admin', email: null, role: 'admin', must_change_password: false, is_active: true }
const forcedAdmin = { ...admin, must_change_password: true }
const readiness = { status: 'ready', service: 'cyberlens', mode: 'demo', demo_data: true, dependencies: { database: true, redis: true, worker: true } }
const timeWindow = { start: '2026-09-21T00:00:00Z', end: '2026-10-21T00:00:00Z' }
const metric = { state: 'empty', scope: 'workspace', range_days: 30, window_start: timeWindow.start, window_end: timeWindow.end, note: null }
const scorecard = {
  schema_version: '1.0', generated_at: timeWindow.end, range_days: 30, window_start: timeWindow.start, window_end: timeWindow.end,
  data_scope: { source: 'PostgreSQL', asset_count: 0, investigation_count: 0, data_modes: [] },
  overall_risk: { ...metric, average_score: null, band: null, assets_in_scope: 0, assets_with_score: 0, assessments_used: 0 },
  assessment_coverage: { ...metric, assessed_category_slots: 0, expected_category_slots: 0, coverage_percent: null, assets_in_scope: 0, assets_with_recent_assessment: 0, assets_with_score: 0, unassessed_category_slots: 0 },
  high_critical_findings: { ...metric, high: 0, critical: 0, total: 0, open_high: null, open_critical: null, open_total: null, open_counts_available: false, assets_with_recent_observation: 0, assets_in_scope: 0, lifecycle_status_available: false },
  unassessed_categories: { ...metric, counts: {}, assets_without_recent_assessment: 0, total_unassessed_category_slots: 0 },
  provider_health: { ...metric, providers: [] },
}

async function mockWorkspace(page: Page, options: { mustChangePassword?: boolean; investigation?: boolean } = {}) {
  await page.addInitScript(() => { document.cookie = 'cyberlens_csrf=brand-ui-token; path=/' })
  await page.route('**/health/ready', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(readiness) }))
  await page.route('**/api/v1/**', async (route) => {
    const url = new URL(route.request().url())
    const path = url.pathname.replace('/api/v1', '')
    const method = route.request().method()
    const json = (status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
    if (path === '/health/ready') return json(200, readiness)
    if (path === '/auth/me') return json(401, { detail: 'Sign in required' })
    if (path === '/auth/csrf') return json(200, { csrf_token: 'brand-ui-token' })
    if (path === '/auth/login' && method === 'POST') return json(200, { user: options.mustChangePassword ? forcedAdmin : admin })
    if (path === '/auth/change-password' && method === 'POST') return json(200, admin)
    if (path === '/assets') return json(200, options.investigation ? [asset] : [])
    if (path === '/investigations' && !/\/investigations\//.test(path)) return json(200, options.investigation ? [investigation] : [])
    if (path === '/incidents' || path === '/reports') return json(200, [])
    if (path === '/integrations/status') return json(200, { mode: 'demo', integrations: [] })
    if (path === '/integrations/spamhaus-drop/status') return json(200, feedStatus('spamhaus_drop'))
    if (path === '/integrations/cins-army/status') return json(200, feedStatus('cins_army'))
    if (path === '/integrations/openphish/status') return json(200, { ...feedStatus('openphish'), configuration_state: 'demo', access_scope: 'demo' })
    if (path === '/posture/scorecard') return json(200, scorecard)
    if (path === '/monitoring') return json(200, [])
    if (path === '/investigations/run-1') return json(200, investigationDetail())
    if (path === '/investigations/run-1/graph') return json(200, { investigation_id: 'run-1', nodes: [], edges: [] })
    return json(200, [])
  })
}

const asset = { id: 'asset-1', kind: 'website', identifier: 'brand.example.test', notes: '', criticality: 'unknown', data_classification: 'unknown', trust_zone: 'unknown', exposure_classification: 'unknown', business_owner: null, protection_requirements: [], authorized_at: null, authorization_id: null, authorization_expires_at: null, components: [] }
const investigation = { id: 'run-1', asset_id: asset.id, asset_kind: asset.kind, asset_identifier: asset.identifier, mode: 'demo', demo_data: true, scenario: 'routine_website', status: 'running', progress: 20, started_at: '2026-10-21T08:00:00Z', finished_at: null, created_at: '2026-10-21T08:00:00Z', error_summary: null, attempt_number: 1, risk: null }
let detailCalls = 0
function investigationDetail() {
  detailCalls += 1
  return { ...investigation, status: 'running', progress: 20, asset, attempts: [{ id: 'attempt-1', attempt_number: 1, retry_kind: 'initial', status: 'running', progress: 20, started_at: investigation.started_at, finished_at: null, created_at: investigation.created_at, error_summary: null }], collector_runs: [], findings: [], evidence: [], risk: null }
}

function feedStatus(id: string) {
  return { id, name: id, enabled: false, mode: 'demo', freshness: 'not_assessed', snapshot_id: null, content_sha256: null, parser_version: 'synthetic-1.0', record_count: 0, retrieved_at: null, published_at: null, last_successful_revalidation_at: null, snapshot_age_seconds: null, freshness_limit_seconds: 86400, next_refresh_at: null, metadata: null, attribution: 'Synthetic offline fixture', latest_attempt: null, coverage_note: 'No live requests.', configuration_state: 'demo', access_scope: 'demo' }
}

async function signIn(page: Page) {
  await page.getByLabel('Username').fill(admin.username)
  await page.getByLabel('Password').fill('Synthetic-Brand-Password-2026!')
  await page.getByRole('button', { name: 'Sign in' }).click()
}

test('brand assets render locally at fallback sizes and the login lockup stays accessible', async ({ page }, testInfo) => {
  await mockWorkspace(page)
  await page.goto('/')
  await expect(page.getByRole('heading', { name: 'Sign in to your workspace' })).toBeVisible()
  const lockup = page.getByRole('img', { name: 'CyberLens', exact: true })
  await expect(lockup).toBeVisible()
  await expect(lockup).toHaveCount(1)
  await expect(page.locator('.login-brand .brand-icon')).toHaveAttribute('src', '/brand/cyberlens-icon.svg')
  await expect(page.locator('.login-brand .text-roll-motion')).toHaveCount(9)
  await expect(page.locator('.login-brand .text-roll-motion').first()).toHaveCSS('animation-duration', '0.32s')
  expect(await page.locator('.login-brand .text-roll-base').evaluateAll((glyphs) => glyphs.map((glyph) => glyph.textContent).join(''))).toBe('CyberLens')
  const beforeRoll = await lockup.boundingBox()
  const loginVisual = page.locator('.login-brand .text-roll-visual')
  await loginVisual.evaluate((element) => { (window as Window & { __brandVisual?: Element }).__brandVisual = element })
  await lockup.hover()
  await expect.poll(() => loginVisual.evaluate((element) => element !== (window as Window & { __brandVisual?: Element }).__brandVisual)).toBe(true)
  await page.waitForTimeout(500)
  const afterRoll = await lockup.boundingBox()
  expect(afterRoll?.width).toBeCloseTo(beforeRoll?.width ?? 0, 2)
  expect(await page.locator('.login-brand .text-roll-base').evaluateAll((glyphs) => glyphs.map((glyph) => glyph.textContent).join(''))).toBe('CyberLens')
  await page.screenshot({ path: testInfo.outputPath('brand-login-desktop.png'), fullPage: true, animations: 'disabled' })

  const sizes = await page.evaluate(async () => Promise.all([16, 24, 32, 180].map(async (size) => {
    const image = new Image()
    image.src = `/brand/cyberlens-${size}.png`
    await image.decode()
    return { size, width: image.naturalWidth, height: image.naturalHeight }
  })))
  expect(sizes).toEqual([16, 24, 32, 180].map((size) => ({ size, width: size, height: size })))
  const favicon = await page.request.get('/favicon.svg')
  expect(favicon.ok()).toBe(true)
})

test('sidebar and mobile wordmarks roll once, intentional focus replays, and polling does not restart', async ({ page }, testInfo) => {
  detailCalls = 0
  await mockWorkspace(page, { investigation: true })
  await page.goto('/#/investigations/run-1')
  await expect(page.getByRole('heading', { name: 'Sign in to your workspace' })).toBeVisible()
  await signIn(page)
  await expect(page.getByRole('heading', { name: asset.identifier })).toBeVisible()
  const brandButton = page.getByRole('button', { name: 'CyberLens overview' })
  const visual = page.locator('.sidebar-brand-button .text-roll-visual')
  await expect(visual).toBeVisible()
  expect(await page.locator('.sidebar-brand-button .text-roll-base').evaluateAll((glyphs) => glyphs.map((glyph) => glyph.textContent).join(''))).toBe('CyberLens')
  await expect(brandButton.getByRole('img')).toHaveCount(0)
  await page.screenshot({ path: testInfo.outputPath('brand-app-desktop.png'), fullPage: true, animations: 'disabled' })
  await visual.evaluate((element) => { (window as Window & { __brandVisual?: Element }).__brandVisual = element })
  await brandButton.focus()
  await expect.poll(() => visual.evaluate((element) => element !== (window as Window & { __brandVisual?: Element }).__brandVisual)).toBe(true)
  await expect(visual.locator('.text-roll-motion')).toHaveCount(9)

  await visual.evaluate((element) => { (window as Window & { __brandVisual?: Element }).__brandVisual = element })
  const assetsNav = page.getByRole('button', { name: 'Assets', exact: true })
  await assetsNav.focus()
  await page.keyboard.press('Enter')
  await expect.poll(() => visual.evaluate((element) => element === (window as Window & { __brandVisual?: Element }).__brandVisual)).toBe(true)

  await page.getByRole('button', { name: 'Investigations', exact: true }).focus()
  await page.keyboard.press('Enter')
  const callsBeforeNavigation = detailCalls
  await expect.poll(() => detailCalls, { timeout: 5000, intervals: [100, 250, 500] }).toBeGreaterThan(callsBeforeNavigation)
  const callsBeforePolling = detailCalls
  await expect.poll(() => detailCalls, { timeout: 5000, intervals: [100, 250, 500] }).toBeGreaterThan(callsBeforePolling)
  await expect.poll(() => visual.evaluate((element) => element === (window as Window & { __brandVisual?: Element }).__brandVisual)).toBe(true)

  await page.getByRole('button', { name: 'Collapse sidebar' }).click()
  await expect(brandButton.locator('img')).toBeVisible()
  await page.screenshot({ path: testInfo.outputPath('brand-sidebar-collapsed.png'), fullPage: true, animations: 'disabled' })
  await page.setViewportSize({ width: 390, height: 844 })
  const mobileBrand = page.getByRole('img', { name: 'CyberLens', exact: true })
  await expect(mobileBrand).toBeVisible()
  await expect(page.locator('.mobile-brand .brand-word-stack')).toBeVisible()
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  await page.screenshot({ path: testInfo.outputPath('brand-app-mobile.png'), fullPage: true, animations: 'disabled' })
  await page.setViewportSize({ width: 320, height: 760 })
  await expect(page.locator('.mobile-brand .brand-word-stack')).toBeHidden()
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
})

test('system reduced motion shows a complete static lockup on login, password change, and authenticated screens', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await mockWorkspace(page, { mustChangePassword: true })
  await page.goto('/')
  await expect(page.getByRole('img', { name: 'CyberLens', exact: true })).toBeVisible()
  await expect(page.locator('.login-brand .text-roll')).toHaveText('CyberLens')
  await expect(page.locator('.login-brand .text-roll-motion')).toHaveCount(0)
  await signIn(page)
  await expect(page.getByRole('heading', { name: 'Change your temporary password' })).toBeVisible()
  await expect(page.locator('.login-brand .text-roll')).toHaveText('CyberLens')
  await expect(page.locator('.login-brand .text-roll-motion')).toHaveCount(0)
  await page.getByLabel('Current password').fill('Synthetic-Brand-Password-2026!')
  await page.getByLabel('New password').fill('Synthetic-Brand-Changed-Password-2026!')
  await page.getByRole('button', { name: 'Update password' }).click()
  await expect(page.getByRole('heading', { name: 'Investigation workspace' })).toBeVisible()
  await expect(page.locator('.sidebar-brand-button .text-roll')).toHaveText('CyberLens')
  await expect(page.locator('.sidebar-brand-button .text-roll-motion')).toHaveCount(0)
  await expect(page.locator('html')).toHaveAttribute('data-motion', 'reduced')
})

test('saved app reduced-motion preference also skips the entrance roll', async ({ page }) => {
  await page.addInitScript(() => window.localStorage.setItem('cyberlens-reduce-animations', 'true'))
  await mockWorkspace(page)
  await page.goto('/')
  await expect(page.getByRole('img', { name: 'CyberLens', exact: true })).toBeVisible()
  await expect(page.locator('.login-cyberlens-hello')).toHaveClass(/is-static/)
  await expect(page.locator('.login-brand .text-roll')).toHaveText('CyberLens')
  await expect(page.locator('.login-brand .text-roll-motion')).toHaveCount(0)
  await signIn(page)
  await expect(page.locator('.dashboard-cyberlens-hello')).toHaveClass(/is-static/)
  await expect(page.locator('.sidebar-brand-button .text-roll')).toHaveText('CyberLens')
  await expect(page.locator('.sidebar-brand-button .text-roll-motion')).toHaveCount(0)
})

test('CyberLens write-on artwork is decorative on login and overview without replacing existing content', async ({ page }, testInfo) => {
  await mockWorkspace(page)
  await page.setViewportSize({ width: 1440, height: 900 })
  await page.goto('/')

  const loginEffect = page.locator('.login-cyberlens-hello')
  await expect(loginEffect).toHaveCount(1)
  await expect(loginEffect).toHaveAttribute('aria-hidden', 'true')
  await expect(loginEffect.locator('title')).toHaveText('CyberLens')
  await expect(loginEffect.locator('.cyberlens-hello-effect__draw')).toHaveCount(9)
  await expect(page.getByRole('img', { name: 'CyberLens', exact: true })).toHaveCount(1)
  await expect(page.getByRole('heading', { name: 'Sign in to your workspace' })).toBeVisible()
  await expect(page.getByLabel('Username')).toBeVisible()
  await expect(page.getByLabel('Password')).toBeVisible()
  await expect(page.locator('.workspace-graphic svg text')).toHaveText(['ASSETS', 'EVIDENCE', 'ANALYST REVIEW'])
  expect(await loginEffect.evaluate((element) => getComputedStyle(element).pointerEvents)).toBe('none')
  expect(await loginEffect.evaluate((element) => getComputedStyle(element).position)).toBe('absolute')
  await expect(loginEffect.locator('.cyberlens-hello-effect__draw').first()).toHaveCSS('animation-name', 'cyberlens-signature-draw')
  await expect(loginEffect.locator('.cyberlens-hello-effect__draw').first()).toHaveAttribute('pathLength', '1')
  await page.screenshot({ path: testInfo.outputPath('cyberlens-signature-login.png'), fullPage: true, animations: 'disabled' })

  await signIn(page)
  await expect(page.getByRole('heading', { name: 'Investigation workspace' })).toBeVisible()
  const dashboardEffect = page.locator('.dashboard-cyberlens-hello')
  await expect(dashboardEffect).toHaveCount(1)
  await expect(dashboardEffect).toBeVisible()
  await expect(dashboardEffect).toHaveAttribute('aria-hidden', 'true')
  await expect(dashboardEffect.locator('title')).toHaveText('CyberLens')
  expect(await dashboardEffect.evaluate((element) => getComputedStyle(element).pointerEvents)).toBe('none')
  await expect(page.getByRole('button', { name: /Start investigation/ })).toBeVisible()
  await page.screenshot({ path: testInfo.outputPath('cyberlens-signature-overview.png'), fullPage: true, animations: 'disabled' })
})

test('system reduced motion renders static CyberLens artwork on login and overview', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await mockWorkspace(page)
  await page.setViewportSize({ width: 1440, height: 900 })
  await page.goto('/')

  const loginEffect = page.locator('.login-cyberlens-hello')
  await expect(loginEffect).toHaveClass(/is-static/)
  await expect(loginEffect.locator('.cyberlens-hello-effect__draw').first()).toHaveCSS('animation-name', 'none')
  await expect(loginEffect.locator('.cyberlens-hello-effect__base')).toHaveCSS('opacity', '0.24')
  await expect(loginEffect.locator('.cyberlens-hello-effect__glint').first()).toHaveCSS('animation-name', 'none')
  await signIn(page)
  const dashboardEffect = page.locator('.dashboard-cyberlens-hello')
  await expect(dashboardEffect).toHaveClass(/is-static/)
  await expect(dashboardEffect.locator('.cyberlens-hello-effect__draw').first()).toHaveCSS('animation-name', 'none')
})

test('overview gradient orb stays decorative, behind dashboard content, and uses a static reduced-motion fallback', async ({ page }, testInfo) => {
  await mockWorkspace(page)
  await page.setViewportSize({ width: 1440, height: 900 })
  await page.goto('/')
  await signIn(page)

  const orb = page.getByTestId('overview-gradient-orb')
  await expect(orb).toBeVisible()
  await expect(orb).toHaveAttribute('aria-hidden', 'true')
  await expect(page.getByRole('heading', { name: 'Investigation workspace' })).toBeVisible()
  await expect(page.getByRole('button', { name: /Start investigation/ })).toBeVisible()
  expect(await orb.evaluate((element) => getComputedStyle(element).pointerEvents)).toBe('none')
  expect(await orb.evaluate((element) => getComputedStyle(element).position)).toBe('absolute')
  await expect.poll(() => orb.getAttribute('data-renderer')).toMatch(/^(webgl|fallback)$/)
  await page.screenshot({ path: testInfo.outputPath('overview-gradient-orb.png'), fullPage: true, animations: 'disabled' })

  await page.emulateMedia({ reducedMotion: 'reduce' })
  await page.reload()
  await signIn(page)
  const reducedOrb = page.getByTestId('overview-gradient-orb')
  await expect(reducedOrb).toHaveAttribute('data-motion', 'reduced')
  await expect(reducedOrb).toHaveAttribute('data-renderer', 'fallback')
  await expect(reducedOrb.locator('canvas')).toBeHidden()
  await expect(page.getByRole('heading', { name: 'Investigation workspace' })).toBeVisible()
})

test('overview gradient orb falls back to the local CSS scene when WebGL is unavailable', async ({ page }) => {
  await page.addInitScript(() => {
    Object.defineProperty(HTMLCanvasElement.prototype, 'getContext', {
      configurable: true,
      value(this: HTMLCanvasElement, type: string) {
        if (type === 'webgl') return null
        return null
      },
    })
  })
  await mockWorkspace(page)
  await page.setViewportSize({ width: 1440, height: 900 })
  await page.goto('/')
  await signIn(page)
  const orb = page.getByTestId('overview-gradient-orb')
  await expect(orb).toHaveAttribute('data-renderer', 'fallback')
  await expect(orb).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Investigation workspace' })).toBeVisible()
})

test.describe('recorded motion preview', () => {

test('CyberLens strokes actually advance, pause, replay, and preserve dashboard values and layout', async ({ page }, testInfo) => {
  await mockWorkspace(page)
  await page.setViewportSize({ width: 1440, height: 900 })
  await page.goto('/')
  await signIn(page)
  const title = page.locator('.dashboard-cyberlens-hello')
  const stroke = title.locator('.cyberlens-hello-effect__draw').first()
  const scope = await page.locator('.overview-scope').innerText()
  await page.locator('.page-transition').evaluate((element) => Promise.all(element.getAnimations().map((animation) => animation.finished.catch(() => undefined))))
  const box = await title.boundingBox()
  await page.getByRole('button', { name: 'Replay CyberLens title', exact: true }).click()
  const start = await stroke.evaluate((element) => parseFloat(getComputedStyle(element).strokeDashoffset))
  expect(start).toBeGreaterThan(.1)
  await page.waitForTimeout(220)
  const advancing = await stroke.evaluate((element) => parseFloat(getComputedStyle(element).strokeDashoffset))
  expect(advancing).toBeLessThan(start)
  await page.screenshot({ path: testInfo.outputPath('cyberlens-writing-in-progress.png') })
  await page.getByRole('button', { name: 'Pause background', exact: true }).click()
  await expect(title).toHaveAttribute('data-playback', 'paused')
  const frozen = await stroke.evaluate((element) => getComputedStyle(element).strokeDashoffset)
  await page.waitForTimeout(250)
  expect(await stroke.evaluate((element) => getComputedStyle(element).strokeDashoffset)).toBe(frozen)
  await expect(page.getByRole('button', { name: 'Replay CyberLens title', exact: true })).toBeDisabled()
  await page.getByRole('button', { name: 'Resume background', exact: true }).click()
  await expect(stroke).toHaveCSS('stroke-dashoffset', '0px')
  const glint = title.locator('.cyberlens-hello-effect__glint').first()
  await expect(glint).toHaveCSS('animation-name', 'cyberlens-signature-glint')
  await glint.evaluate((element) => { element.getAnimations()[0].currentTime = 4500 })
  const glintOffset = await glint.evaluate((element) => getComputedStyle(element).strokeDashoffset)
  await expect.poll(() => glint.evaluate((element) => getComputedStyle(element).strokeDashoffset)).not.toBe(glintOffset)
  await page.getByRole('button', { name: 'Pause background', exact: true }).click()
  const pausedGlint = await glint.evaluate((element) => getComputedStyle(element).strokeDashoffset)
  await page.waitForTimeout(180)
  expect(await glint.evaluate((element) => getComputedStyle(element).strokeDashoffset)).toBe(pausedGlint)
  await page.getByRole('button', { name: 'Resume background', exact: true }).click()
  expect(await page.locator('.overview-scope').innerText()).toBe(scope)
  const settledBox = await title.boundingBox()
  expect(box).not.toBeNull()
  expect(settledBox).not.toBeNull()
  for (const key of ['x', 'y', 'width', 'height'] as const) expect(settledBox![key]).toBeCloseTo(box![key], 1)
  await title.locator('.cyberlens-hello-effect__ink').evaluate((element) => { (window as unknown as { __savedInk: Element }).__savedInk = element })
  await page.getByRole('button', { name: 'Collapse sidebar' }).click()
  expect(await title.locator('.cyberlens-hello-effect__ink').evaluate((element) => element === (window as unknown as { __savedInk: Element }).__savedInk)).toBe(true)
  await page.getByRole('button', { name: 'Expand sidebar' }).click()
  for (const width of [1440, 768, 390]) {
    await page.setViewportSize({ width, height: width === 390 ? 844 : 900 })
    await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'instant' as ScrollBehavior }))
    await expect.poll(() => page.evaluate(() => scrollY)).toBe(0)
    await expect(page.locator('.topbar')).not.toHaveClass(/is-scrolled/)
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
    await expect(page.getByRole('button', { name: /Pause background/ })).toBeVisible()
    // Resizing into the mobile header mounts its own one-time brand entrance.
    // Let that finish so the still capture is readable; the video records it.
    await page.waitForTimeout(500)
    await page.screenshot({ path: testInfo.outputPath(`motion-overview-${width}.png`) })
  }
})
})

test('dashboard renderer advances real time, releases frame work, and survives simulated context loss', async ({ page }) => {
  await page.addInitScript(() => {
    const pending = new Set<number>()
    const nativeFrame = requestAnimationFrame.bind(window)
    const nativeCancel = cancelAnimationFrame.bind(window)
    window.requestAnimationFrame = (callback) => {
      const handle = nativeFrame((time) => { pending.delete(handle); callback(time) })
      pending.add(handle)
      return handle
    }
    window.cancelAnimationFrame = (handle) => { pending.delete(handle); nativeCancel(handle) }
    const uniforms = new WeakMap<WebGLUniformLocation, string>()
    const prototype = WebGLRenderingContext.prototype
    const nativeLocation = prototype.getUniformLocation
    const nativeUniform = prototype.uniform1f
    let draws = 0
    let elapsed = 0
    prototype.getUniformLocation = function (program, name) {
      const location = nativeLocation.call(this, program, name)
      if (location) uniforms.set(location, name)
      return location
    }
    prototype.uniform1f = function (location, value) {
      if (location && uniforms.get(location) === 'iTime') { draws += 1; elapsed = value }
      nativeUniform.call(this, location, value)
    }
    Object.defineProperty(window, '__effectStats', { value: () => ({ pending: pending.size, draws, elapsed }) })
  })
  const errors: string[] = []
  page.on('pageerror', (error) => errors.push(error.message))
  await mockWorkspace(page)
  await page.setViewportSize({ width: 1440, height: 900 })
  await page.goto('/')
  await signIn(page)
  const orb = page.getByTestId('overview-gradient-orb')
  const stats = () => page.evaluate(() => (window as unknown as { __effectStats: () => { pending: number; draws: number; elapsed: number } }).__effectStats())
  await expect(orb).toHaveAttribute('data-playback', 'running')
  const renderer = await orb.getAttribute('data-renderer')
  if (renderer === 'webgl') {
    await expect.poll(async () => (await stats()).draws).toBeGreaterThan(2)
    const before = await stats()
    await page.waitForTimeout(600)
    const after = await stats()
    expect(after.elapsed - before.elapsed).toBeGreaterThan(.15)
    expect(after.draws).toBeGreaterThan(before.draws)
    const canvas = await orb.locator('canvas').evaluate((element) => ({ width: (element as HTMLCanvasElement).width, height: (element as HTMLCanvasElement).height }))
    expect(canvas.width * canvas.height).toBeLessThanOrEqual(770_000)
    console.log(`CYBERLENS_ORB_SAMPLE ${JSON.stringify({ renderer, observationSeconds: after.elapsed - before.elapsed, drawCalls: after.draws - before.draws, canvas })}`)
    await page.getByRole('button', { name: 'Pause background', exact: true }).click()
    await expect(orb).toHaveAttribute('data-playback', 'paused')
    await expect.poll(async () => (await stats()).pending).toBe(0)
    const paused = await stats()
    await page.waitForTimeout(200)
    expect((await stats()).elapsed).toBe(paused.elapsed)
    await page.getByRole('button', { name: 'Resume background', exact: true }).click()
    await expect.poll(async () => (await stats()).elapsed).toBeGreaterThan(paused.elapsed)
    await page.evaluate(() => {
      Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' })
      document.dispatchEvent(new Event('visibilitychange'))
    })
    await expect(orb).toHaveAttribute('data-playback', 'paused')
    await expect.poll(async () => (await stats()).pending).toBe(0)
    await page.evaluate(() => {
      Reflect.deleteProperty(document, 'visibilityState')
      document.dispatchEvent(new Event('visibilitychange'))
    })
    await expect(orb).toHaveAttribute('data-playback', 'running')
    await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight))
    await expect(orb).toHaveAttribute('data-playback', 'paused')
    await expect.poll(async () => (await stats()).pending).toBe(0)
    await page.evaluate(() => window.scrollTo(0, 0))
    await expect(orb).toHaveAttribute('data-playback', 'running')
    await orb.locator('canvas').evaluate((element) => element.dispatchEvent(new Event('webglcontextlost', { cancelable: true })))
    await expect(orb).toHaveAttribute('data-renderer', 'fallback')
    // The independent Bento canvas still owns its loop until its own context is lost.
    await page.locator('.dashboard-bento-scene canvas').evaluate((element) => element.dispatchEvent(new Event('contextlost', { cancelable: true })))
    await expect(page.locator('.dashboard-bento-scene')).toHaveAttribute('data-renderer', 'static')
    await expect.poll(async () => (await stats()).pending).toBe(0)
    expect(await orb.evaluate((element) => getComputedStyle(element, '::before').animationName)).toBe('overview-orb-drift')
  } else {
    // WebGL availability is device-dependent; normal motion still has a working CSS renderer.
    expect(await orb.evaluate((element) => getComputedStyle(element, '::before').animationName)).toBe('overview-orb-drift')
  }
  for (let index = 0; index < 3; index += 1) {
    await page.locator('.nav-list .rail-link[aria-label="Assets"]').click()
    await expect(page.getByTestId('overview-gradient-orb')).toHaveCount(0)
    await expect.poll(async () => (await stats()).pending).toBe(0)
    await page.locator('.nav-list .rail-link[aria-label="Overview"]').click()
    await expect(page.getByTestId('overview-gradient-orb')).toHaveCount(1)
  }
  await page.locator('.user-menu > summary').click()
  await page.getByRole('button', { name: 'Sign out', exact: true }).click()
  await expect(page.getByTestId('overview-gradient-orb')).toHaveCount(0)
  // The login now owns one real Earth render loop. Verify the old orb stopped,
  // then pause the new owner before asserting that no frame work remains.
  await expect(page.locator('.login-globe-art')).toHaveAttribute('data-renderer', 'canvas')
  await expect.poll(async () => (await stats()).pending).toBe(1)
  const afterLogout = (await stats()).draws
  await page.getByRole('button', { name: 'Pause decorative globe motion' }).click()
  await expect.poll(async () => (await stats()).pending).toBe(0)
  expect((await stats()).draws).toBe(afterLogout)
  expect(errors).toEqual([])
})

test('reference Bento scene moves pixels, shares pause, and fits narrow layouts', async ({ page }, testInfo) => {
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  await page.emulateMedia({ reducedMotion: 'no-preference' })
  await mockWorkspace(page)
  await page.setViewportSize({ width: 1440, height: 1000 })
  await page.goto('/')
  await signIn(page)
  const scene = page.locator('.dashboard-bento-scene')
  const canvas = scene.locator('canvas')
  await expect(scene).toHaveAttribute('data-renderer', 'canvas')
  await expect(scene).toHaveAttribute('aria-hidden', 'true')
  const snapshot = () => canvas.evaluate(el => (el as HTMLCanvasElement).toDataURL())
  const before = await snapshot()
  await expect.poll(snapshot).not.toBe(before)
  await page.getByRole('button', { name: 'Pause background', exact: true }).click()
  await expect(scene).toHaveAttribute('data-playback', 'paused')
  const stopped = await snapshot()
  await page.waitForTimeout(250)
  expect(await snapshot()).toBe(stopped)
  await page.getByRole('button', { name: 'Resume background', exact: true }).click()
  await expect.poll(snapshot).not.toBe(stopped)
  await page.screenshot({ path: testInfo.outputPath('reference-bento-desktop.png'), fullPage: true })
  for (const width of [390, 680, 768, 900]) {
    await page.setViewportSize({ width, height: 1000 })
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
    await expect(page.getByRole('button', { name: 'Start investigation', exact: false })).toBeVisible()
    await page.screenshot({ path: testInfo.outputPath(`reference-bento-${width}.png`), fullPage: true })
  }
  expect(errors).toEqual([])
})

test('reference Bento scene stays static for reduced motion and survives renderer failure', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await mockWorkspace(page)
  const rendererRequests: string[] = []
  page.on('request', request => { if (request.url().includes('dashboard-bento-renderer')) rendererRequests.push(request.url()) })
  await page.goto('/')
  await signIn(page)
  const scene = page.locator('.dashboard-bento-scene')
  await expect(scene).toHaveAttribute('data-renderer', 'static')
  expect(rendererRequests).toEqual([])
  await page.route('**/*dashboard-bento-renderer*', route => route.abort('failed'))
  await page.getByRole('button', { name: 'Enable decorative motion', exact: true }).click()
  await expect.poll(() => rendererRequests.length).toBeGreaterThan(0)
  await expect(scene).toHaveAttribute('data-renderer', 'static')
  await expect(page.getByRole('heading', { name: 'Investigation workspace' })).toBeVisible()
  await page.getByRole('button', { name: 'Start investigation', exact: false }).click()
  await expect(scene).toHaveCount(0)
})

test('CSS orb fallback really moves and both motion preferences stop decorative movement', async ({ page }) => {
  await page.addInitScript(() => {
    const native = HTMLCanvasElement.prototype.getContext
    Object.defineProperty(HTMLCanvasElement.prototype, 'getContext', { value(this: HTMLCanvasElement, ...args: Parameters<typeof native>) {
      if (String(args[0]).startsWith('webgl')) return null
      return Reflect.apply(native, this, args)
    } })
  })
  await mockWorkspace(page)
  await page.goto('/')
  await signIn(page)
  const orb = page.getByTestId('overview-gradient-orb')
  await expect(orb).toHaveAttribute('data-renderer', 'fallback')
  const transform = () => orb.evaluate((element) => getComputedStyle(element, '::before').transform)
  const before = await transform()
  await expect.poll(transform).not.toBe(before)
  await page.getByRole('button', { name: 'Pause background', exact: true }).click()
  const paused = await transform()
  await page.waitForTimeout(200)
  expect(await transform()).toBe(paused)
  await page.getByRole('button', { name: 'Resume background', exact: true }).click()
  await expect.poll(transform).not.toBe(paused)
  await page.locator('.user-menu > summary').click()
  await page.getByRole('checkbox', { name: 'Reduce animations' }).check()
  await expect(orb).toHaveAttribute('data-playback', 'static')
  await expect(page.getByRole('button', { name: 'Motion reduced', exact: true })).toBeDisabled()
  expect(await orb.evaluate((element) => getComputedStyle(element, '::before').animationName)).toBe('none')
  await expect(page.locator('.dashboard-cyberlens-hello .cyberlens-hello-effect__draw').first()).toHaveCSS('stroke-dashoffset', '0px')
  await page.getByRole('checkbox', { name: 'Reduce animations' }).uncheck()
  await expect(orb).toHaveAttribute('data-playback', 'running')
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await expect(orb).toHaveAttribute('data-playback', 'static')
  await expect(orb.locator('canvas')).toBeHidden()
  expect(await orb.evaluate((element) => getComputedStyle(element, '::before').animationName)).toBe('none')
})

test('data saving starts static without requesting WebGL and explains disabled effects controls', async ({ page }) => {
  await page.addInitScript(() => {
    const connection = Object.assign(new EventTarget(), { saveData: true })
    Object.defineProperty(navigator, 'connection', { configurable: true, value: connection })
    const native = HTMLCanvasElement.prototype.getContext
    let attempts = 0
    Object.defineProperty(HTMLCanvasElement.prototype, 'getContext', { value(this: HTMLCanvasElement, ...args: Parameters<typeof native>) {
      if (String(args[0]).startsWith('webgl')) attempts += 1
      return Reflect.apply(native, this, args)
    } })
    Object.defineProperty(window, '__webglAttempts', { value: () => attempts })
  })
  await mockWorkspace(page)
  await page.goto('/')
  await signIn(page)
  const orb = page.getByTestId('overview-gradient-orb')
  await expect(orb).toHaveAttribute('data-playback', 'static')
  await expect(orb.locator('canvas')).toBeHidden()
  await expect(page.getByRole('button', { name: 'Motion reduced', exact: true })).toBeDisabled()
  await expect(page.getByRole('button', { name: 'Motion reduced', exact: true })).toHaveAttribute('title', /data-saving/)
  expect(await page.evaluate(() => (window as unknown as { __webglAttempts: () => number }).__webglAttempts())).toBe(0)
  await page.evaluate(() => {
    const connection = (navigator as Navigator & { connection: EventTarget & { saveData: boolean } }).connection
    connection.saveData = false
    connection.dispatchEvent(new Event('change'))
  })
  await expect(orb).toHaveAttribute('data-playback', 'running')
  await expect(page.getByRole('button', { name: 'Pause background', exact: true })).toBeEnabled()
})


test('decorative opt-in carries from login to the dashboard while operational motion stays reduced', async ({ page }, testInfo) => {
  const errors: string[] = []
  page.on('pageerror', (error) => errors.push(error.message))
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await mockWorkspace(page)
  await page.goto('/')
  await expect(page.locator('.login-globe-art')).toHaveAttribute('data-state', 'static')
  await page.getByRole('button', { name: 'Enable decorative motion' }).click()
  await expect(page.locator('.login-globe-art')).toHaveAttribute('data-renderer', 'canvas')
  await signIn(page)
  const orb = page.getByTestId('overview-gradient-orb')
  await expect(orb).toHaveAttribute('data-playback', 'running')
  await expect(page.locator('html')).toHaveAttribute('data-motion', 'reduced')
  await expect(page.locator('.dashboard-cyberlens-hello')).toHaveAttribute('data-playback', 'running')
  await expect(page.locator('.dashboard-cyberlens-hello .cyberlens-hello-effect__glint').first()).toHaveCSS('animation-duration', '7s')
  await page.getByRole('button', { name: 'Pause background', exact: true }).click()
  await expect(orb).toHaveAttribute('data-playback', 'paused')
  await page.getByRole('button', { name: 'Resume background', exact: true }).click()
  await expect(orb).toHaveAttribute('data-playback', 'running')
  await page.screenshot({ path: testInfo.outputPath('dashboard-explicit-motion.png'), fullPage: true })
  await page.waitForTimeout(2500)
  expect(errors).toEqual([])
})
