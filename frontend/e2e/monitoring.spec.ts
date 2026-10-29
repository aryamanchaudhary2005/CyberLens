import { expect, test } from '@playwright/test'

const asset = {
  id: 'asset-monitor-1', kind: 'domain', identifier: 'monitor.example.test', notes: '',
  criticality: 'unknown', data_classification: 'unknown', trust_zone: 'unknown', exposure_classification: 'unknown',
  business_owner: null, protection_requirements: [], authorized_at: '2026-10-17T10:00:00Z',
  authorization_note: 'Written permission', authorization_id: 'authorization-1',
  authorization_expires_at: '2026-11-16T10:00:00Z', components: [],
}

const run = {
  id: 'monitor-run-1', schedule_id: 'schedule-1', investigation_id: 'investigation-1',
  previous_investigation_id: 'investigation-0', scheduled_for: '2026-10-18T10:00:00Z',
  status: 'partial', started_at: '2026-10-18T10:01:00Z', finished_at: '2026-10-18T10:02:00Z',
  failure_detail: null, mode: 'live', created_at: '2026-10-18T10:00:00Z',
}

function schedule(status: 'active' | 'paused' | 'failed' | 'completed' = 'active') {
  return {
    id: 'schedule-1', asset_id: asset.id, authorization_id: asset.authorization_id, owner_id: 'analyst-1',
    cadence: 'daily', status, next_run_at: status === 'completed' ? null : '2026-10-19T10:00:00Z',
    last_run_at: null, failure_code: null, failure_detail: null,
    created_at: '2026-10-17T10:00:00Z', updated_at: '2026-10-17T10:00:00Z', completed_at: null,
  }
}

test('analyst can schedule, pause, resume, cancel, and compare monitoring runs', async ({ page }, testInfo) => {
  await page.addInitScript(() => { document.cookie = 'cyberlens_csrf=monitoring-token; path=/' })
  let schedules: ReturnType<typeof schedule>[] = []
  await page.route('**/api/v1/**', async (route) => {
    const url = new URL(route.request().url())
    const path = url.pathname.replace('/api/v1', '')
    const method = route.request().method()
    const json = (status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
    if (path === '/health/ready') return json(200, { status: 'ready', service: 'cyberlens-api', mode: 'live', demo_data: false, dependencies: { database: true, redis: true, worker: true } })
    if (path === '/auth/me') return json(200, { id: 'analyst-1', username: 'analyst', role: 'analyst', is_active: true, must_change_password: false })
    if (path === '/assets') return json(200, [asset])
    if (path === '/investigations' || path === '/incidents' || path === '/reports') return json(200, [])
    if (path === '/integrations/status') return json(200, { integrations: [] })
    if (path === '/monitoring' && method === 'GET') return json(200, schedules)
    if (path === '/monitoring' && method === 'POST') {
      const request = route.request().postDataJSON() as { asset_id: string; authorization_id: string; cadence: string }
      expect(request.asset_id).toBe(asset.id)
      expect(request.authorization_id).toBe(asset.authorization_id)
      schedules = [schedule()]
      return json(201, schedules[0])
    }
    if (path === '/monitoring/schedule-1/pause') { schedules = [schedule('paused')]; return json(200, schedules[0]) }
    if (path === '/monitoring/schedule-1/resume') { schedules = [schedule('active')]; return json(200, schedules[0]) }
    if (path === '/monitoring/schedule-1/cancel') { schedules = [schedule('completed')]; return json(200, schedules[0]) }
    if (path === '/monitoring/schedule-1/history') return json(200, [run])
    if (path === '/monitoring/schedule-1/runs/monitor-run-1/changes') return json(200, {
      current_investigation_id: 'investigation-1', previous_investigation_id: 'investigation-0',
      changes: [{ status: 'unknown', edge: { id: 'edge-1', from_node_id: 'a', from_node_type: 'asset',
        to_node_id: 'domain', to_node_type: 'domain', relationship_type: 'resolves_to', evidence_role: 'direct',
        collector: 'dns_rdap', source: 'DNS provider', evidence_id: 'evidence-1', observed_at: '2026-10-18T10:02:00Z',
        data_mode: 'live', details: {} }, previous_edge: null, reason: 'Provider coverage unavailable; absence is not evidence of removal.' }],
      counts: { new: 0, changed: 0, no_longer_observed: 0, unknown: 1 },
    })
    return json(404, { detail: `No test fixture for ${method} ${path}` })
  })

  await page.goto('/#/assets/asset-monitor-1')
  await expect(page.getByRole('heading', { name: 'monitor.example.test' })).toBeVisible()
  await page.getByRole('button', { name: 'Schedule daily' }).click()
  await expect(page.getByText('Daily schedule')).toBeVisible()
  await page.getByText('Run history').click()
  await expect(page.getByRole('link', { name: 'Open investigation' })).toBeVisible()
  await page.getByRole('button', { name: 'View Change Radar' }).click()
  await expect(page.getByText(/1 unknown/)).toBeVisible()
  await expect(page.getByText('Provider coverage unavailable; absence is not evidence of removal.')).toBeVisible()
  await expect(page.locator('.monitoring-summary strong')).toHaveCSS('font-size', '15px')
  await expect(page.locator('.monitoring-times > div').first()).toHaveCSS('background-color', 'rgb(16, 28, 43)')
  await page.addStyleTag({ content: '.topbar { position: static !important; }' })
  await page.locator('.monitoring-section').screenshot({ path: testInfo.outputPath('ui05-monitoring-change-radar.png'), animations: 'disabled' })
  await page.getByRole('button', { name: 'Pause' }).click()
  await expect(page.getByText('paused', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Resume' }).click()
  await expect(page.getByText('active', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Cancel schedule' }).click()
  await expect(page.getByText('completed', { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Cancel schedule' })).toHaveCount(0)
})

test('viewer can inspect a schedule but cannot create or control it', async ({ page }) => {
  await page.route('**/api/v1/**', async (route) => {
    const path = new URL(route.request().url()).pathname.replace('/api/v1', '')
    const json = (status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
    if (path === '/health/ready') return json(200, { status: 'ready', service: 'cyberlens-api', mode: 'live', demo_data: false, dependencies: { database: true, redis: true, worker: true } })
    if (path === '/auth/me') return json(200, { id: 'viewer-1', username: 'viewer', role: 'viewer', is_active: true, must_change_password: false })
    if (path === '/assets') return json(200, [asset])
    if (path === '/investigations' || path === '/incidents' || path === '/reports') return json(200, [])
    if (path === '/integrations/status') return json(200, { integrations: [] })
    if (path === '/monitoring') return json(200, [schedule()])
    return json(404, { detail: `No viewer fixture for ${route.request().method()} ${path}` })
  })
  await page.goto('/#/assets/asset-monitor-1')
  await expect(page.getByText('Daily schedule')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Schedule daily' })).toHaveCount(0)
  await expect(page.getByRole('button', { name: 'Pause' })).toHaveCount(0)
  await expect(page.getByRole('button', { name: 'Cancel schedule' })).toHaveCount(0)
})
