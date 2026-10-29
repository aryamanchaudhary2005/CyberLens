import { expect, test, type Page } from '@playwright/test'

const apiOrigin = process.env.CYBERLENS_API_ORIGIN ?? 'http://localhost:8000'
const adminPassword = process.env.CYBERLENS_E2E_ADMIN_PASSWORD ?? 'CyberLens-Smoke-Changed-Password-2026!'
const analystTemporaryPassword = 'CyberLens-Analyst-Temp-2026!'
const analystPassword = 'CyberLens-Analyst-Workflow-2026!'
const viewerTemporaryPassword = 'CyberLens-Viewer-Temp-2026!'
const viewerPassword = 'CyberLens-Viewer-Readonly-2026!'
const bootstrapPassword = process.env.CYBERLENS_SMOKE_PASSWORD ?? 'CyberLens-Demo-Only-2026!'

const navigation = (page: Page) => page.getByRole('navigation', { name: 'Workspace', exact: true })

async function submitLogin(page: Page) {
  const pending = page.waitForResponse((response) => response.url().endsWith('/api/v1/auth/login') && response.request().method() === 'POST')
  await page.getByRole('button', { name: 'Sign in' }).click()
  return pending
}

async function signIn(page: Page, username: string, password: string, changedPassword: string) {
  await page.goto('/')
  await expect(page.getByRole('heading', { name: 'Sign in to your workspace' })).toBeVisible()
  await page.getByLabel('Username').fill(username)
  await page.getByLabel('Password').fill(password)
  const response = await submitLogin(page)
  expect(response.ok()).toBeTruthy()
  const payload = await response.json() as { user: { must_change_password: boolean } }
  if (payload.user.must_change_password) {
    await expect(page.getByRole('heading', { name: 'Change your temporary password' })).toBeVisible()
    await page.getByLabel('Current password').fill(password)
    await page.getByLabel('New password').fill(changedPassword)
    await page.getByRole('button', { name: 'Update password' }).click()
  }
  await expect(page.getByRole('heading', { name: 'Investigation workspace' })).toBeVisible()
}

async function signOut(page: Page) {
  await page.locator('.user-chip').click()
  await page.getByRole('button', { name: 'Sign out' }).click()
  await expect(page.getByRole('heading', { name: 'Sign in to your workspace' })).toBeVisible()
}

async function signInAdmin(page: Page) {
  await page.goto('/')
  await expect(page.getByRole('heading', { name: 'Sign in to your workspace' })).toBeVisible()
  await page.getByLabel('Username').fill(process.env.CYBERLENS_SMOKE_USERNAME ?? 'admin')
  await page.getByLabel('Password').fill(adminPassword)
  let response = await submitLogin(page)
  let submittedPassword = adminPassword
  if (!response.ok()) {
    submittedPassword = bootstrapPassword
    await page.getByLabel('Password').fill(bootstrapPassword)
    response = await submitLogin(page)
  }
  expect(response.ok()).toBeTruthy()
  const payload = await response.json() as { user: { must_change_password: boolean } }
  if (payload.user.must_change_password) {
    await expect(page.getByRole('heading', { name: 'Change your temporary password' })).toBeVisible()
    await page.getByLabel('Current password').fill(submittedPassword)
    await page.getByLabel('New password').fill(adminPassword)
    await page.getByRole('button', { name: 'Update password' }).click()
  }
  await expect(page.getByRole('heading', { name: 'Investigation workspace' })).toBeVisible()
}

async function createWorkspaceUser(page: Page, username: string, password: string, role: 'analyst' | 'viewer') {
  await page.getByRole('button', { name: 'Administration' }).click()
  await expect(page.getByRole('heading', { name: 'Administration', exact: true })).toBeVisible()
  await page.getByLabel('Username').fill(username)
  await page.getByLabel('Temporary password').fill(password)
  await page.getByLabel('Email').fill(`${username}@example.test`)
  await page.locator('.two-column > .panel').nth(1).getByLabel('Role').selectOption(role)
  await page.getByRole('button', { name: 'Create account' }).click()
  await expect(page.getByText(`${username}@example.test`)).toBeVisible()
}

async function queueInvestigation(page: Page) {
  const queuedResponse = page.waitForResponse((response) =>
    response.url().endsWith('/api/v1/investigations') && response.request().method() === 'POST')
  await page.getByRole('button', { name: /Run investigation/ }).click()
  const response = await queuedResponse
  expect(response.ok()).toBeTruthy()
  const payload = await response.json() as { id: string }
  await expect.poll(async () => {
    const detail = await page.request.get(`${apiOrigin}/api/v1/investigations/${payload.id}`)
    if (!detail.ok()) return 'not-ready'
    return (await detail.json()).status as string
  }, { timeout: 120_000, intervals: [500, 1000, 2000] }).toMatch(/^(completed|partial)$/)
  await expect(page.locator('.result-panel > .panel-heading .status-badge')).toHaveText(/^(completed|partial)$/)
  return payload.id
}

test('Admin provisions roles, Analyst completes a case workflow, Viewer stays read-only', async ({ page }) => {
  test.setTimeout(360_000)
  const suffix = Date.now().toString(36)
  const analyst = `e2e-analyst-${suffix}`
  const viewer = `e2e-viewer-${suffix}`

  await signInAdmin(page)
  await createWorkspaceUser(page, analyst, analystTemporaryPassword, 'analyst')
  await createWorkspaceUser(page, viewer, viewerTemporaryPassword, 'viewer')
  await signOut(page)

  await signIn(page, analyst, analystTemporaryPassword, analystPassword)
  await expect(page.getByRole('button', { name: 'Administration' })).toHaveCount(0)
  await navigation(page).getByRole('button', { name: 'Assets', exact: true }).click()
  const assetIdentifier = `workflow-${suffix}.example.test`
  await page.getByLabel('Identifier').fill(assetIdentifier)
  const assetResponsePromise = page.waitForResponse((response) =>
    response.url().endsWith('/api/v1/assets') && response.request().method() === 'POST')
  await page.getByRole('button', { name: 'Add asset' }).click()
  const createdAsset = await (await assetResponsePromise).json() as { id: string }
  await expect(page.getByRole('heading', { name: assetIdentifier })).toBeVisible()

  const firstInvestigationId = await queueInvestigation(page)
  const firstDetailResponse = await page.request.get(`${apiOrigin}/api/v1/investigations/${firstInvestigationId}`)
  expect(firstDetailResponse.ok()).toBeTruthy()
  const firstDetail = await firstDetailResponse.json() as { findings: Array<{ id: string }> }
  expect(firstDetail.findings.length).toBeGreaterThan(0)
  const findingId = firstDetail.findings[0].id

  const incidentResponsePromise = page.waitForResponse((response) =>
    response.url().endsWith('/api/v1/incidents') && response.request().method() === 'POST')
  await page.getByRole('button', { name: 'Create case' }).first().click()
  const createdIncident = await (await incidentResponsePromise).json() as { id: string; title: string }
  await expect(page.getByRole('heading', { name: 'Cases', exact: true })).toBeVisible()
  await expect(page.getByRole('heading', { name: createdIncident.title })).toBeVisible()
  await page.getByPlaceholder('Add an analyst timeline note').fill('Workflow verification: analyst reviewed the synthetic evidence.')
  await page.getByRole('button', { name: 'Add event' }).click()
  await expect(page.getByText('Workflow verification: analyst reviewed the synthetic evidence.')).toBeVisible()

  const firstTask = page.locator('.task-row').first()
  await firstTask.getByRole('combobox').selectOption('completed')
  await firstTask.getByPlaceholder('Action notes').fill('Verified using the saved Demo fixture.')
  await firstTask.getByRole('button', { name: 'Save' }).click()
  await expect(firstTask.getByRole('combobox')).toHaveValue('completed')

  await navigation(page).getByRole('button', { name: 'Remediation', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Remediation plans', exact: true })).toBeVisible()
  await page.getByLabel('Plan title').fill(`Patch plan ${suffix}`)
  await expect(page.getByLabel('Finding').locator(`option[value="${findingId}"]`)).toBeAttached()
  await page.getByLabel('Finding').selectOption(findingId)
  await page.getByRole('main').getByLabel('Incident').selectOption(createdIncident.id)
  await expect(page.getByLabel('Playbook task')).toBeVisible()
  const incidentDetailResponse = await page.request.get(`${apiOrigin}/api/v1/incidents/${createdIncident.id}`)
  expect(incidentDetailResponse.ok()).toBeTruthy()
  const incidentDetail = await incidentDetailResponse.json() as { tasks: Array<{ id: string }> }
  await page.getByLabel('Playbook task').selectOption(incidentDetail.tasks[0].id)
  const planResponsePromise = page.waitForResponse((response) =>
    response.url().endsWith('/api/v1/remediation/plans') && response.request().method() === 'POST')
  await page.getByRole('button', { name: 'Create plan' }).click()
  const createdPlan = await (await planResponsePromise).json() as { id: string; title: string }
  await expect(page.getByRole('heading', { name: createdPlan.title })).toBeVisible()

  await page.getByLabel('Action title').fill('Deploy and verify vendor patch')
  await page.getByLabel('Action type').last().fill('patch')
  await page.getByLabel('Verification instructions').fill('Repeat the inventory check and confirm the fixed version is present.')
  const actionResponsePromise = page.waitForResponse((response) =>
    response.url().endsWith(`/api/v1/remediation/plans/${createdPlan.id}/actions`) && response.request().method() === 'POST')
  await page.getByRole('button', { name: 'Add action' }).click()
  expect((await actionResponsePromise).ok()).toBeTruthy()
  await page.getByLabel('Catalog control').selectOption('SI-2')
  await page.getByLabel('Rationale').fill('The candidate requires a tested vendor fix and a follow-up inventory check.')
  const mappingResponsePromise = page.waitForResponse((response) =>
    response.url().includes(`/api/v1/remediation/findings/${findingId}/controls`) && response.request().method() === 'POST')
  await page.getByRole('button', { name: 'Add control mapping' }).click()
  expect((await mappingResponsePromise).ok()).toBeTruthy()

  await navigation(page).getByRole('button', { name: 'Incidents', exact: true }).click()
  await expect(page.getByRole('heading', { name: createdIncident.title })).toBeVisible()
  const remediationReportPromise = page.waitForResponse((response) =>
    response.url().endsWith('/api/v1/reports') && response.request().method() === 'POST')
  await page.getByRole('button', { name: 'JSON' }).click()
  const remediationReport = await (await remediationReportPromise).json() as { id: string }
  const remediationSnapshotResponse = await page.request.get(`${apiOrigin}/api/v1/reports/${remediationReport.id}`)
  expect(remediationSnapshotResponse.ok()).toBeTruthy()
  const remediationSnapshot = await remediationSnapshotResponse.json() as { snapshot: { remediation_plans: Array<{ id: string }> } }
  expect(remediationSnapshot.snapshot.remediation_plans.some((item) => item.id === createdPlan.id)).toBeTruthy()

  await navigation(page).getByRole('button', { name: 'Assets', exact: true }).click()
  await page.getByRole('button', { name: new RegExp(assetIdentifier) }).click()
  const secondInvestigationId = await queueInvestigation(page)
  await navigation(page).getByRole('button', { name: 'Investigations', exact: true }).click()
  await page.locator('.compare-box select').selectOption(firstInvestigationId)
  await page.getByRole('button', { name: 'Compare', exact: true }).click()
  await expect(page.locator('.compare-box pre')).toBeVisible()

  await page.goto(`/#/assets/${encodeURIComponent(createdAsset.id)}`)
  await expect(page.getByRole('heading', { name: assetIdentifier })).toBeVisible()
  await page.goto(`/#/investigations/${firstInvestigationId}`)
  await expect(page.getByRole('heading', { name: 'Investigations', exact: true })).toBeVisible()
  await expect(page.getByRole('heading', { name: assetIdentifier })).toBeVisible()
  await page.goto(`/#/findings/${findingId}`)
  await expect(page.getByRole('heading', { name: 'Investigations', exact: true })).toBeVisible()
  await expect(page.getByRole('heading', { name: assetIdentifier })).toBeVisible()
  await page.goto(`/#/investigations/${secondInvestigationId}/compare/${firstInvestigationId}`)
  await expect(page.getByRole('heading', { name: 'Investigations', exact: true })).toBeVisible()
  await expect(page.getByRole('heading', { name: assetIdentifier })).toBeVisible()
  await page.goto(`/#/incidents/${createdIncident.id}`)
  await expect(page.getByRole('heading', { name: 'Cases', exact: true })).toBeVisible()
  await expect(page.getByRole('heading', { name: createdIncident.title })).toBeVisible()
  await page.goto(`/#/remediation/${createdPlan.id}`)
  await expect(page.getByRole('heading', { name: 'Remediation plans', exact: true })).toBeVisible()
  await expect(page.getByRole('heading', { name: createdPlan.title })).toBeVisible()
  await page.goto(`/#/reports/${remediationReport.id}`)
  await expect(page.getByRole('heading', { name: 'Reports', exact: true })).toBeVisible()

  await signOut(page)
  await signIn(page, viewer, viewerTemporaryPassword, viewerPassword)
  await expect(page.getByRole('button', { name: 'Administration' })).toHaveCount(0)
  await navigation(page).getByRole('button', { name: 'Assets', exact: true }).click()
  await expect(page.getByRole('status').filter({ hasText: 'Read-only access' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Add asset' })).toHaveCount(0)
  await navigation(page).getByRole('button', { name: 'Investigations', exact: true }).click()
  await expect(page.getByRole('button', { name: 'Queue analysis' })).toHaveCount(0)
  await expect(page.getByRole('status').filter({ hasText: 'Read-only access' })).toBeVisible()
  await navigation(page).getByRole('button', { name: 'Incidents', exact: true }).click()
  await expect(page.getByRole('status').filter({ hasText: 'Read-only access' })).toBeVisible()
  await expect(page.getByPlaceholder('Add an analyst timeline note')).toHaveCount(0)
  await navigation(page).getByRole('button', { name: 'Remediation', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Remediation plans', exact: true })).toBeVisible()
  await expect(page.getByRole('status').filter({ hasText: 'only Analysts and Admins' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Create plan' })).toHaveCount(0)
})
