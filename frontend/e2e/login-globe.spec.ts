import { expect, test, type Page } from '@playwright/test'

type GlobeTestWindow = Window & { __setLoginGlobeIntersecting?: (isIntersecting: boolean) => void }

const demoReadiness = { status: 'ready', service: 'cyberlens', mode: 'demo', demo_data: true, dependencies: { database: true, redis: true, worker: true } }
const demoUser = { id: 'globe-admin', username: 'globe-admin', email: null, role: 'admin', must_change_password: false, is_active: true }

async function mockLogin(page: Page, loginPayloads: unknown[] = [], reducedMotion = false) {
  await page.addInitScript((reduceAnimations) => {
    document.cookie = 'cyberlens_csrf=ui02-test-token; path=/'
    window.localStorage.setItem('cyberlens-reduce-animations', String(reduceAnimations))
  }, reducedMotion)
  await page.route('**/health/ready', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(demoReadiness) }))
  await page.route('**/api/v1/**', async (route) => {
    const path = new URL(route.request().url()).pathname.replace('/api/v1', '')
    const method = route.request().method()
    const json = (status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
    if (path === '/health/ready') return json(200, demoReadiness)
    if (path === '/auth/me') return json(401, { detail: 'Sign in required' })
    if (path === '/auth/csrf') return json(200, { csrf_token: 'ui02-test-token' })
    if (path === '/integrations/status') return json(200, { mode: 'demo', integrations: [] })
    if (path === '/auth/login' && method === 'POST') {
      loginPayloads.push(JSON.parse(route.request().postData() ?? '{}'))
      return json(200, { user: demoUser })
    }
    if (path === '/auth/logout' && method === 'POST') return route.fulfill({ status: 204 })
    return json(200, [])
  })
}

test('login globe stays behind the preserved login content at 390, 768, and 1440 pixels', async ({ page }, testInfo) => {
  const externalRequests: string[] = []
  page.on('request', (request) => {
    const hostname = new URL(request.url()).hostname
    if (hostname !== '127.0.0.1' && hostname !== 'localhost') externalRequests.push(request.url())
  })
  await mockLogin(page)
  await page.goto('/')
  await expect(page.getByRole('heading', { name: 'Sign in to your workspace' })).toBeVisible()
  await expect.poll(() => page.locator('.login-globe-object').evaluate((image) => (image as HTMLImageElement).naturalWidth)).toBeGreaterThan(0)
  await expect(page.getByRole('button', { name: 'Pause decorative globe motion' })).toBeVisible()
  await expect(page.locator('.login-globe-art')).toHaveCount(1)
  await expect(page.locator('.login-globe-toggle')).toHaveCount(1)
  await expect(page.locator('.login-globe-canvas')).toHaveCount(1)

  for (const width of [390, 768, 1440]) {
    await page.setViewportSize({ width, height: width === 390 ? 844 : 900 })
    const geometry = await page.evaluate(() => {
      const measure = (selector: string) => {
        const rect = document.querySelector(selector)!.getBoundingClientRect()
        return [rect.x, rect.y, rect.width, rect.height].map((value) => Number(value.toFixed(2)))
      }
      const art = document.querySelector<HTMLElement>('.login-globe-art')!
      const image = document.querySelector<HTMLImageElement>('.login-globe-object')!
      const toggle = document.querySelector<HTMLButtonElement>('.login-globe-toggle')!
      const rect = toggle.getBoundingClientRect()
      const imageRect = image.getBoundingClientRect()
      return {
        layout: measure('.login-layout'), story: measure('.login-story'), graphic: measure('.workspace-graphic'), card: measure('.login-card'),
        storyDisplay: getComputedStyle(document.querySelector('.login-story')!).display,
        artHidden: art.getAttribute('aria-hidden'), artPointerEvents: getComputedStyle(art).pointerEvents,
        imagePointerEvents: getComputedStyle(image).pointerEvents, imageOpacity: getComputedStyle(image).opacity,
        globeIntersectsViewport: imageRect.bottom > 0 && imageRect.top < window.innerHeight && imageRect.right > 0 && imageRect.left < window.innerWidth,
        togglePosition: getComputedStyle(toggle).position, toggleBottom: rect.bottom,
        formTop: document.querySelector('.login-layout')!.getBoundingClientRect().top,
        diagramHash: [...document.querySelectorAll('.workspace-graphic svg text')].map((item) => item.textContent?.trim()).join('|'),
        formOrder: [...document.querySelectorAll('.login-card form input, .login-card form button')].map((item) => (item as HTMLInputElement).name || (item as HTMLButtonElement).textContent?.trim()),
        scrollWidth: document.documentElement.scrollWidth,
      }
    })

    const baseline = width === 390
      ? { layout: [20, 155.69, 350, 532.63], story: [0, 0, 0, 0], graphic: [0, 0, 0, 0], card: [20, 155.69, 350, 532.63] }
      : width === 768
        ? { layout: [20, 131.13, 728, 637.75], story: [26, 182.86, 376.36, 534.28], graphic: [11, 381.27, 406.36, 252.73], card: [428.36, 155.13, 313.64, 589.75] }
        : { layout: [150, 123.67, 1140, 652.66], story: [170, 159.67, 552.88, 580.66], graphic: [155, 388.23, 582.88, 307.05], card: [810, 174.27, 460, 551.47] }

    for (const key of ['layout', 'story', 'graphic', 'card'] as const) {
      expect(geometry[key], `${key} geometry at ${width}px`).toHaveLength(baseline[key].length)
      geometry[key].forEach((value, index) => expect(value, `${key}[${index}] at ${width}px`).toBeCloseTo(baseline[key][index], 1))
    }
    expect(geometry.storyDisplay).toBe(width <= 680 ? 'none' : 'block')
    expect(geometry.artHidden).toBe('true')
    expect(geometry.artPointerEvents).toBe('none')
    expect(geometry.imagePointerEvents).toBe('none')
    expect(Number(geometry.imageOpacity)).toBeLessThanOrEqual(.2)
    if (width === 390) expect(geometry.globeIntersectsViewport).toBe(true)
    expect(geometry.togglePosition).toBe('absolute')
    expect(geometry.toggleBottom).toBeLessThan(geometry.formTop)
    expect(geometry.diagramHash).toBe('ASSETS|EVIDENCE|ANALYST REVIEW')
    expect(geometry.formOrder).toEqual(['username', 'password', 'Sign in'])
    expect(geometry.scrollWidth).toBeLessThanOrEqual(width)

    await expect(page.getByRole('button', { name: 'Pause decorative globe motion' })).toBeVisible()
    await page.screenshot({ path: testInfo.outputPath(`login-globe-${width}.png`), fullPage: true, animations: 'disabled' })
    if (width === 1440) {
      await page.getByLabel('Username').focus()
      await page.keyboard.press('Tab')
      await expect(page.getByLabel('Password')).toBeFocused()
      await page.keyboard.press('Tab')
      await expect(page.getByRole('button', { name: 'Sign in' })).toBeFocused()
      await page.keyboard.press('Tab')
      await expect(page.getByRole('button', { name: 'Pause decorative globe motion' })).toBeFocused()
    }
  }
  expect(externalRequests).toEqual([])
})

test('globe motion pauses and resumes accessibly, and reduced motion is static', async ({ page }) => {
  await mockLogin(page)
  await page.goto('/')
  const toggle = page.getByRole('button', { name: 'Pause decorative globe motion' })
  await expect(toggle).toBeVisible()
  await expect(page.locator('.login-globe-art')).toHaveAttribute('data-state', 'running')
  const canvas = page.locator('.login-globe-canvas')
  await expect(page.locator('.login-globe-art')).toHaveAttribute('data-renderer', 'canvas')
  const before = await canvas.getAttribute('data-rotation')
  const pixels = await canvas.evaluate((element) => (element as HTMLCanvasElement).toDataURL())
  await expect.poll(() => canvas.getAttribute('data-rotation')).not.toBe(before)
  await expect.poll(() => canvas.evaluate((element) => (element as HTMLCanvasElement).toDataURL())).not.toBe(pixels)

  await toggle.focus()
  await expect(toggle).toBeFocused()
  await page.keyboard.press('Enter')
  await expect(page.getByRole('button', { name: 'Resume decorative globe motion' })).toBeVisible()
  await expect(page.locator('.login-globe-art')).toHaveAttribute('data-state', 'paused')
  await expect(page.locator('.login-cyberlens-hello')).toHaveAttribute('data-playback', 'paused')
  await expect(page.locator('.login-cyberlens-hello .cyberlens-hello-effect__glint').first()).toHaveCSS('animation-play-state', 'paused')
  const frozen = await canvas.getAttribute('data-rotation')
  await page.waitForTimeout(250)
  expect(await canvas.getAttribute('data-rotation')).toBe(frozen)
  await page.keyboard.press('Enter')
  await expect(page.getByRole('button', { name: 'Pause decorative globe motion' })).toBeVisible()
  await expect(page.locator('.login-cyberlens-hello')).toHaveAttribute('data-playback', 'running')

  await page.emulateMedia({ reducedMotion: 'reduce' })
  await expect(page.locator('.login-globe-art')).toHaveAttribute('data-state', 'static')
  await expect(page.getByRole('button', { name: 'Enable decorative motion' })).toBeEnabled()
  await expect(page.locator('.login-globe-object')).toHaveCSS('animation-name', 'none')
  await expect(page.locator('.login-cyberlens-hello .cyberlens-hello-effect__glint').first()).toHaveCSS('animation-name', 'none')
})

test('saved application motion preference also renders the globe statically', async ({ page }) => {
  await mockLogin(page, [], true)
  await page.goto('/')
  await expect(page.locator('html')).toHaveAttribute('data-motion', 'reduced')
  await expect(page.locator('.login-globe-art')).toHaveAttribute('data-state', 'static')
  await expect(page.getByRole('button', { name: 'Enable decorative motion' })).toBeEnabled()
  await expect(page.locator('.login-globe-object')).toHaveCSS('animation-name', 'none')
})

test('offscreen and hidden-document states stop the globe render loop and restore it when visible', async ({ page }) => {
  await mockLogin(page)
  await page.addInitScript(() => {
    const observers: ControlledObserver[] = []
    class ControlledObserver {
      private target: Element | null = null
      readonly root: Element | Document | null = null
      readonly rootMargin = '0px'
      readonly thresholds = [0.01]

      constructor(private readonly callback: IntersectionObserverCallback) { observers.push(this) }

      observe(target: Element) { this.target = target; this.dispatch(true) }
      unobserve(target: Element) { if (this.target === target) this.target = null }
      disconnect() { this.target = null }
      takeRecords(): IntersectionObserverEntry[] { return [] }

      dispatch(isIntersecting: boolean) {
        if (!this.target) return
        const entry = { target: this.target, isIntersecting, intersectionRatio: isIntersecting ? 1 : 0 } as IntersectionObserverEntry
        this.callback([entry], this as unknown as IntersectionObserver)
      }
    }

    Object.defineProperty(window, 'IntersectionObserver', { configurable: true, value: ControlledObserver })
    ;(window as GlobeTestWindow).__setLoginGlobeIntersecting = (isIntersecting) => {
      observers.forEach((observer) => observer.dispatch(isIntersecting))
    }
  })
  await page.goto('/')

  const art = page.locator('.login-globe-art')
  const globe = page.locator('.login-globe-canvas')
  await expect(art).toHaveAttribute('data-renderer', 'canvas')
  await expect(art).toHaveAttribute('data-state', 'running')

  await page.evaluate(() => (window as GlobeTestWindow).__setLoginGlobeIntersecting?.(false))
  await expect(art).toHaveAttribute('data-state', 'paused')
  const frozen = await globe.getAttribute('data-frames')
  await page.waitForTimeout(250)
  expect(await globe.getAttribute('data-frames')).toBe(frozen)

  await page.evaluate(() => {
    Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' })
    document.dispatchEvent(new Event('visibilitychange'))
  })
  await page.evaluate(() => (window as GlobeTestWindow).__setLoginGlobeIntersecting?.(true))
  await expect(art).toHaveAttribute('data-state', 'paused')

  await page.evaluate(() => {
    Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' })
    document.dispatchEvent(new Event('visibilitychange'))
  })
  await expect(art).toHaveAttribute('data-state', 'running')
  await expect.poll(() => globe.getAttribute('data-frames')).not.toBe(frozen)
})

test('a failed lazy globe import falls back locally while login renders immediately', async ({ page }) => {
  await mockLogin(page)
  await page.route(/\/(?:src\/components\/LoginGlobeBackground\.tsx|assets\/LoginGlobeBackground-[^/]+\.js)(?:\?.*)?$/, (route) => route.abort())
  await page.goto('/')

  await expect(page.getByRole('heading', { name: 'Sign in to your workspace' })).toBeVisible()
  await expect(page.getByLabel('Username')).toBeVisible()
  await expect(page.locator('.login-globe-art[data-state="static"] .login-globe-static')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Pause decorative globe motion' })).toHaveCount(0)
})

test('an unavailable globe asset uses a static fallback without blocking login', async ({ page }) => {
  const loginPayloads: unknown[] = []
  await mockLogin(page, loginPayloads)
  await page.route('**/login-globe.svg', (route) => route.abort())
  await page.goto('/')
  await expect(page.locator('.login-globe-fallback')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Globe motion disabled' })).toBeDisabled()
  await expect(page.getByLabel('Username')).toBeVisible()
  await expect(page.getByLabel('Password')).toBeVisible()
  await expect(page.locator('canvas')).toHaveCount(0)

  for (let cycle = 0; cycle < 2; cycle++) {
    await page.getByLabel('Username').fill('globe-admin')
    await page.getByLabel('Password').fill('Synthetic-UI-Password-2026!')
    await page.getByRole('button', { name: 'Sign in' }).click()
    await expect(page.getByRole('heading', { name: 'Investigation workspace' })).toBeVisible()
    await expect(page.locator('.login-globe-art')).toHaveCount(0)
    // The authenticated overview has its own decorative canvas; only assert
    // that the login background renderer was removed after sign-in.
    await expect(page.locator('.login-globe-art canvas')).toHaveCount(0)

    await page.locator('summary.user-chip').click()
    await page.getByRole('button', { name: 'Sign out' }).click()
    await expect(page.getByRole('heading', { name: 'Sign in to your workspace' })).toBeVisible()
    await expect(page.locator('.login-globe-fallback')).toHaveCount(1)
    await expect(page.locator('canvas')).toHaveCount(0)
  }
  expect(loginPayloads).toEqual([
    { username: 'globe-admin', password: 'Synthetic-UI-Password-2026!' },
    { username: 'globe-admin', password: 'Synthetic-UI-Password-2026!' },
  ])
})


for (const preference of ['system', 'saved'] as const) {
  test(`explicit decorative opt-in works with ${preference} reduced motion without altering protected content`, async ({ page }) => {
    const rendererRequests: string[] = []
    page.on('request', (request) => { if (/digital-earth/.test(request.url())) rendererRequests.push(request.url()) })
    await mockLogin(page, [], preference === 'saved')
    if (preference === 'system') await page.emulateMedia({ reducedMotion: 'reduce' })
    await page.goto('/')
    await expect(page.locator('.login-globe-art')).toHaveAttribute('data-state', 'static')
    await expect(page.locator('.login-globe-canvas')).toHaveCount(0)
    expect(rendererRequests).toEqual([])
    const protectedContent = async () => page.locator('.login-layout').evaluate((layout) => ({
      markup: layout.innerHTML,
      boxes: [...layout.querySelectorAll('.login-card, .workspace-graphic, input, button')].map((element) => {
        const r = element.getBoundingClientRect(), s = getComputedStyle(element)
        return [r.x, r.y, r.width, r.height, s.color, s.font, s.backgroundColor]
      }),
    }))
    const before = await protectedContent()
    await page.getByRole('button', { name: 'Enable decorative motion' }).click()
    await expect(page.locator('.login-globe-art')).toHaveAttribute('data-renderer', 'canvas')
    const canvas = page.locator('.login-globe-canvas')
    const angle = await canvas.getAttribute('data-rotation')
    await expect.poll(() => canvas.getAttribute('data-rotation')).not.toBe(angle)
    expect(await protectedContent()).toEqual(before)
    // The user's reduced-motion setting remains intact for original content.
    await expect(page.locator('html')).toHaveAttribute('data-motion', 'reduced')
    const highlight = page.locator('.login-cyberlens-hello .cyberlens-hello-effect__glint').first()
    await expect(highlight).toHaveCSS('animation-duration', '7s')
    await expect(highlight).toHaveCSS('animation-iteration-count', 'infinite')
    await page.getByRole('button', { name: 'Pause decorative globe motion' }).click()
    await expect(highlight).toHaveCSS('animation-play-state', 'paused')
    const stopped = await canvas.getAttribute('data-frames')
    await page.waitForTimeout(250)
    expect(await canvas.getAttribute('data-frames')).toBe(stopped)
  })
}

test('renderer import failure and context loss retain a usable static login', async ({ page }) => {
  await mockLogin(page)
  await page.route(/digital-earth/, (route) => route.abort())
  await page.goto('/')
  await expect(page.getByRole('button', { name: 'Globe motion disabled', exact: true })).toBeDisabled()
  await expect(page.getByLabel('Username')).toBeVisible()
  await expect(page.locator('.login-globe-object')).toHaveCSS('opacity', '0.19')
  await page.unroute(/digital-earth/)
  await page.reload()
  await expect(page.locator('.login-globe-art')).toHaveAttribute('data-renderer', 'canvas')
  await page.locator('.login-globe-canvas').evaluate((canvas) => canvas.dispatchEvent(new Event('contextlost')))
  await expect(page.locator('.login-globe-canvas')).toHaveCount(0)
  await expect(page.locator('.login-globe-art')).toHaveAttribute('data-state', 'static')
  await expect(page.getByLabel('Username')).toBeVisible()
})

test('real sphere rotates without WebGL, pauses on demand, and disposes across login cycles', async ({ page }, testInfo) => {
  await mockLogin(page)
  await page.addInitScript(() => {
    const native = HTMLCanvasElement.prototype.getContext
    Object.defineProperty(HTMLCanvasElement.prototype, 'getContext', { value(this: HTMLCanvasElement, ...args: Parameters<typeof native>) {
      if (String(args[0]).startsWith('webgl')) return null
      return native.apply(this, args)
    } })
  })
  await page.setViewportSize({ width: 1440, height: 900 })
  await page.goto('/')
  for (let cycle = 0; cycle < 3; cycle++) {
    const canvas = page.locator('.login-globe-canvas')
    await expect(canvas).toHaveCount(1)
    await expect(page.locator('.login-globe-art')).toHaveAttribute('data-renderer', 'canvas')
    const oldCanvas = await canvas.elementHandle()
    const before = await canvas.getAttribute('data-rotation')
    await expect.poll(() => canvas.getAttribute('data-rotation')).not.toBe(before)
    if (cycle === 0) {
      await page.waitForTimeout(1200)
      await page.screenshot({ path: testInfo.outputPath('digital-earth-login.png'), fullPage: true })
      const sample = await canvas.evaluate((element) => ({ width: (element as HTMLCanvasElement).width, height: (element as HTMLCanvasElement).height, frames: element.getAttribute('data-frames') }))
      expect(sample.width).toBeLessThanOrEqual(960)
      console.log(`DIGITAL_EARTH_SAMPLE ${JSON.stringify(sample)}`)
    }
    await page.getByLabel('Username').fill('globe-admin')
    await page.getByLabel('Password').fill('Synthetic-UI-Password-2026!')
    await page.getByRole('button', { name: 'Sign in' }).click()
    await expect(page.getByRole('heading', { name: 'Investigation workspace' })).toBeVisible()
    await expect(canvas).toHaveCount(0)
    const frames = await oldCanvas!.getAttribute('data-frames')
    await page.waitForTimeout(150)
    expect(await oldCanvas!.getAttribute('data-frames')).toBe(frames)
    await page.locator('summary.user-chip').click()
    await page.getByRole('button', { name: 'Sign out' }).click()
    await expect(page.getByRole('heading', { name: 'Sign in to your workspace' })).toBeVisible()
    await oldCanvas!.dispose()
  }
})
