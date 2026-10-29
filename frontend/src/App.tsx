import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { ApiError, downloadReport, getReadiness, login as loginRequest, request, type Asset, type CinsArmyStatus, type Finding, type Incident, type Investigation, type OpenPhishStatus, type Readiness, type Report, type SpamhausDropStatus, type User } from './api'
import { AdminScreen } from './features/admin'
import { AssetsScreen } from './features/assets'
import { LoadingState } from './components/ui'
import { Icon } from './components/icons'
import { BrandLockup } from './components/Brand'
import { WorkspaceGraphic } from './components/WorkspaceGraphic'
import { LoginGlobeGate } from './components/LoginGlobeGate'
import { CyberLensHelloEffect } from './components/CyberLensHelloEffect'
import { settleSubmittedFormDrafts, useRouteFormDrafts } from './components/form-drafts'
import { useSectionMotion, useStickyHeader, useViewportReveals } from './components/motion'
import { IntegrationsScreen } from './features/integrations'
import { IntegrityScreen } from './features/integrity'
import { IncidentsScreen } from './features/incidents'
import { InvestigationsScreen } from './features/investigations'
import { Overview } from './features/overview'
import { ReportsScreen } from './features/reports'
import { RemediationScreen } from './features/remediation'
import { ThreatModelScreen } from './features/threat-model'
import { message, severityPriority } from './features/helpers'
import type { CpeResult, InvestigationDetail, View } from './features/types'
import { listAssets, listIncidents, listInvestigations, listReports } from './generated/client'
import './graph.css'
import './attack-catalog.css'

const nav: Array<{ id: View; title: string; icon: 'overview' | 'assets' | 'investigations' | 'incidents' | 'threat-model' | 'remediation' | 'reports' | 'integrity' | 'integrations' }> = [
  { id: 'overview', title: 'Overview', icon: 'overview' }, { id: 'assets', title: 'Assets', icon: 'assets' },
  { id: 'investigations', title: 'Investigations', icon: 'investigations' }, { id: 'incidents', title: 'Incidents', icon: 'incidents' },
  { id: 'threat-model', title: 'Threat model', icon: 'threat-model' },
  { id: 'remediation', title: 'Remediation', icon: 'remediation' }, { id: 'reports', title: 'Reports', icon: 'reports' },
  { id: 'integrity', title: 'Integrity', icon: 'integrity' }, { id: 'integrations', title: 'Integrations', icon: 'integrations' },
]

function storedPreference(key: string): boolean {
  try { return typeof window !== 'undefined' && window.localStorage.getItem(key) === 'true' }
  catch { return false }
}

function feedStatusValue<T extends SpamhausDropStatus>(result: PromiseSettledResult<T>, providerId: string): T | null {
  if (result.status !== 'fulfilled' || !result.value || result.value.id !== providerId) return null
  if (typeof result.value.freshness !== 'string' || typeof result.value.record_count !== 'number') return null
  return result.value
}

function App() {
  const [user, setUser] = useState<User | null>(null)
  const [authenticating, setAuthenticating] = useState(true)
  const [readiness, setReadiness] = useState<Readiness | null>(null)
  const [view, setView] = useState<View>('overview')
  const [assets, setAssets] = useState<Asset[]>([])
  const [investigations, setInvestigations] = useState<Investigation[]>([])
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [reports, setReports] = useState<Report[]>([])
  const [selectedReportId, setSelectedReportId] = useState('')
  const [comparisonRoute, setComparisonRoute] = useState<{ current: string; other: string } | null>(null)
  const [integrations, setIntegrations] = useState<Array<Record<string, unknown>>>([])
  const [spamhausDrop, setSpamhausDrop] = useState<SpamhausDropStatus | null>(null)
  const [cinsArmy, setCinsArmy] = useState<CinsArmyStatus | null>(null)
  const [openPhish, setOpenPhish] = useState<OpenPhishStatus | null>(null)
  const [selectedAssetId, setSelectedAssetId] = useState('')
  const [selectedInvestigationId, setSelectedInvestigationId] = useState('')
  const [pollKey, setPollKey] = useState(0)
  const [investigation, setInvestigation] = useState<InvestigationDetail | null>(null)
  const [selectedIncidentId, setSelectedIncidentId] = useState('')
  const [selectedRemediationPlanId, setSelectedRemediationPlanId] = useState('')
  const [selectedThreatScenarioId, setSelectedThreatScenarioId] = useState('')
  const [incident, setIncident] = useState<Incident | null>(null)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(false)
  const [loading, setLoading] = useState(false)
  const [routeInitialized, setRouteInitialized] = useState(false)
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => storedPreference('cyberlens-sidebar-collapsed'))
  const [mobileNavOpen, setMobileNavOpen] = useState(false)
  const [brandReplayToken, setBrandReplayToken] = useState(0)
  const [isNarrow, setIsNarrow] = useState(() => typeof window !== 'undefined' && window.matchMedia('(max-width: 900px)').matches)
  const [systemReducedMotion, setSystemReducedMotion] = useState(() => typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches)
  const [manualReducedMotion, setManualReducedMotion] = useState(() => storedPreference('cyberlens-reduce-animations'))
  const [decorativeMotionEnabled, setDecorativeMotionEnabled] = useState(false)
  const enableDecorativeMotion = () => setDecorativeMotionEnabled(true)
  useEffect(() => {
    document.documentElement.dataset.decorativeMotion = decorativeMotionEnabled ? 'full' : 'auto'
    return () => { delete document.documentElement.dataset.decorativeMotion }
  }, [decorativeMotionEnabled])
  const [overviewIntroPlayed, setOverviewIntroPlayed] = useState(false)
  const mobileMenuButton = useRef<HTMLButtonElement>(null)
  const mobileNav = useRef<HTMLElement>(null)
  const pageTransition = useRef<HTMLDivElement>(null)
  const topbar = useRef<HTMLElement>(null)
  const refreshSequence = useRef(0)
  const sessionIdentity = useRef<string | undefined>(user?.id)
  const selectedInvestigation = useRef(selectedInvestigationId)
  const selectedIncident = useRef(selectedIncidentId)
  const resolvingFindingRoute = useRef(false)
  sessionIdentity.current = user?.id
  selectedInvestigation.current = selectedInvestigationId
  selectedIncident.current = selectedIncidentId
  const reducedMotion = systemReducedMotion || manualReducedMotion

  const workspaceMotionEnabled = Boolean(user && !user.must_change_password)
  useViewportReveals(pageTransition, view, reducedMotion, workspaceMotionEnabled)
  useSectionMotion(pageTransition, view, [selectedAssetId, selectedInvestigationId, selectedIncidentId, selectedReportId, selectedRemediationPlanId, selectedThreatScenarioId, comparisonRoute?.other ?? ''].join(':'), reducedMotion, workspaceMotionEnabled)
  useStickyHeader(topbar, workspaceMotionEnabled)
  useRouteFormDrafts(workspaceMotionEnabled, `${view}:${selectedAssetId}:${selectedInvestigationId}:${selectedIncidentId}`)

  useEffect(() => {
    const narrow = window.matchMedia('(max-width: 900px)')
    const motion = window.matchMedia('(prefers-reduced-motion: reduce)')
    const onNarrow = () => { setIsNarrow(narrow.matches); if (!narrow.matches) setMobileNavOpen(false) }
    const onMotion = () => { setSystemReducedMotion(motion.matches); setDecorativeMotionEnabled(false) }
    narrow.addEventListener?.('change', onNarrow)
    motion.addEventListener?.('change', onMotion)
    return () => { narrow.removeEventListener?.('change', onNarrow); motion.removeEventListener?.('change', onMotion) }
  }, [])

  useEffect(() => {
    document.documentElement.dataset.motion = reducedMotion ? 'reduced' : 'full'
    try { window.localStorage.setItem('cyberlens-reduce-animations', String(manualReducedMotion)) } catch { /* local preference storage is optional */ }
  }, [reducedMotion, manualReducedMotion])

  useEffect(() => {
    try { window.localStorage.setItem('cyberlens-sidebar-collapsed', String(sidebarCollapsed)) } catch { /* local preference storage is optional */ }
  }, [sidebarCollapsed])

  useEffect(() => {
    if (!mobileNavOpen) return
    const focusable = () => Array.from(mobileNav.current?.querySelectorAll<HTMLElement>('button:not(:disabled), a[href], input:not(:disabled), [tabindex="0"]') ?? []).filter((element) => element.getClientRects().length > 0)
    const firstNavItem = mobileNav.current?.querySelector<HTMLElement>('.nav-list .rail-link')
    if (firstNavItem) firstNavItem.focus()
    else focusable()[0]?.focus()
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault(); setMobileNavOpen(false); mobileMenuButton.current?.focus(); return
      }
      if (event.key !== 'Tab') return
      const items = focusable()
      if (!items.length) return
      const first = items[0]; const last = items[items.length - 1]
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus() }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus() }
    }
    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [mobileNavOpen])

  useEffect(() => {
    let routeRequest: AbortController | undefined
    const applyRoute = () => {
      routeRequest?.abort()
      resolvingFindingRoute.current = false
      let parts: string[]
      try { parts = window.location.hash.replace(/^#\/?/, '').split('/').filter(Boolean).map(decodeURIComponent) }
      catch { setError('This link contains an invalid encoded address.'); setView('overview'); setRouteInitialized(true); return }
      const [resource, id] = parts
      setRouteInitialized(true)
      if (!resource || resource === 'overview') { setView('overview'); return }
      if (resource === 'assets') { setView('assets'); setSelectedAssetId(id ?? ''); return }
      if (resource === 'investigations') { setView('investigations'); setSelectedInvestigationId(id ?? ''); setComparisonRoute(id && parts[2] === 'compare' && parts[3] ? { current: id, other: parts[3] } : null); return }
      if (resource === 'incidents') { setView('incidents'); setSelectedIncidentId(id ?? ''); return }
      if (resource === 'threat-model') { setView('threat-model'); setSelectedThreatScenarioId(id ?? ''); return }
      if (resource === 'remediation') { setView('remediation'); setSelectedRemediationPlanId(id ?? ''); return }
      if (resource === 'reports') { setView('reports'); setSelectedReportId(id ?? ''); return }
      if (resource === 'integrity') { setView('integrity'); return }
      if (resource === 'integrations') { setView('integrations'); return }
      if (resource === 'admin') { setView('admin'); return }
      if (resource === 'findings' && id) {
        setView('investigations')
        resolvingFindingRoute.current = true
        if (user) {
          const controller = new AbortController()
          routeRequest = controller
          void request<Finding>(`/findings/${encodeURIComponent(id)}`, { signal: controller.signal }).then((finding) => {
            if (controller.signal.aborted) return
            resolvingFindingRoute.current = false
            setComparisonRoute(null)
            setSelectedInvestigationId(finding.investigation_id)
          }).catch((reason: unknown) => {
            if (controller.signal.aborted) return
            resolvingFindingRoute.current = false
            setSelectedInvestigationId('')
            setError(message(reason))
          })
        }
        return
      }
      setView('overview')
    }
    applyRoute()
    window.addEventListener('hashchange', applyRoute)
    return () => { routeRequest?.abort(); window.removeEventListener('hashchange', applyRoute) }
  }, [user])

  useEffect(() => {
    if (!routeInitialized || resolvingFindingRoute.current) return
    let target = `#/${view}`
    if (view === 'assets' && selectedAssetId) target += `/${encodeURIComponent(selectedAssetId)}`
    if (view === 'investigations' && selectedInvestigationId) target += `/${encodeURIComponent(selectedInvestigationId)}`
    if (view === 'investigations' && comparisonRoute && comparisonRoute.current === selectedInvestigationId) target += `/compare/${encodeURIComponent(comparisonRoute.other)}`
    if (view === 'incidents' && selectedIncidentId) target += `/${encodeURIComponent(selectedIncidentId)}`
    if (view === 'threat-model' && selectedThreatScenarioId) target += `/${encodeURIComponent(selectedThreatScenarioId)}`
    if (view === 'remediation' && selectedRemediationPlanId) target += `/${encodeURIComponent(selectedRemediationPlanId)}`
    if (view === 'reports' && selectedReportId) target += `/${encodeURIComponent(selectedReportId)}`
    if (window.location.hash !== target) window.location.hash = target.slice(1)
  }, [routeInitialized, view, selectedAssetId, selectedInvestigationId, selectedIncidentId, selectedThreatScenarioId, selectedRemediationPlanId, selectedReportId, comparisonRoute])

  const refresh = useCallback(async () => {
    if (!user || user.must_change_password) return
    const sequence = ++refreshSequence.current
    const userId = user.id
    setLoading(true)
    const [nextAssets, nextInvestigations, nextIncidents, nextReports, integrationData, feedStatus, cinsStatus, openPhishStatus] = await Promise.allSettled([
      listAssets(), listInvestigations(), listIncidents(), listReports(), request<{ integrations: Array<Record<string, unknown>> }>('/integrations/status'),
      request<SpamhausDropStatus>('/integrations/spamhaus-drop/status'),
      request<CinsArmyStatus>('/integrations/cins-army/status'),
      request<OpenPhishStatus>('/integrations/openphish/status'),
    ])
    if (sequence !== refreshSequence.current || sessionIdentity.current !== userId) return
    if (nextAssets.status === 'fulfilled') setAssets(nextAssets.value)
    if (nextInvestigations.status === 'fulfilled') setInvestigations(nextInvestigations.value)
    if (nextIncidents.status === 'fulfilled') setIncidents(nextIncidents.value)
    if (nextReports.status === 'fulfilled') setReports(nextReports.value)
    if (integrationData.status === 'fulfilled') setIntegrations(integrationData.value.integrations)
    const nextSpamhausStatus = feedStatusValue(feedStatus, 'spamhaus_drop')
    const nextCinsStatus = feedStatusValue(cinsStatus, 'cins_army')
    const nextOpenPhishStatus = feedStatusValue(openPhishStatus, 'openphish')
    const validOpenPhishStatus = nextOpenPhishStatus && typeof nextOpenPhishStatus.configuration_state === 'string' && typeof nextOpenPhishStatus.access_scope === 'string' ? nextOpenPhishStatus : null
    setSpamhausDrop(nextSpamhausStatus)
    setCinsArmy(nextCinsStatus)
    setOpenPhish(validOpenPhishStatus)
    const failures = [
      ['assets', nextAssets], ['investigations', nextInvestigations], ['incidents', nextIncidents], ['reports', nextReports],
      ['integration status', integrationData], ['Spamhaus status', feedStatus], ['CINS Army status', cinsStatus], ['OpenPhish status', openPhishStatus],
    ] as const
    const unavailable = failures.filter(([, result]) => result.status === 'rejected').map(([label]) => label)
    if (feedStatus.status === 'fulfilled' && !nextSpamhausStatus) unavailable.push('Spamhaus status')
    if (cinsStatus.status === 'fulfilled' && !nextCinsStatus) unavailable.push('CINS Army status')
    if (openPhishStatus.status === 'fulfilled' && !validOpenPhishStatus) unavailable.push('OpenPhish status')
    if (unavailable.length) setError((current) => current || `Could not refresh ${unavailable.join(', ')}. Other available workspace records are shown.`)
    setLoading(false)
  }, [user])

  useEffect(() => {
    const controller = new AbortController()
    getReadiness(controller.signal).then((result) => { if (!controller.signal.aborted) setReadiness(result) }).catch((reason: unknown) => { if (!controller.signal.aborted) setError(message(reason)) })
    request<User>('/auth/me', { signal: controller.signal }).then((result) => { if (!controller.signal.aborted) setUser(result) }).catch(() => { if (!controller.signal.aborted) setUser(null) }).finally(() => { if (!controller.signal.aborted) setAuthenticating(false) })
    return () => controller.abort()
  }, [])

  useEffect(() => { if (user) void refresh() }, [user, refresh])

  useEffect(() => {
    if (!selectedInvestigationId || !user || user.must_change_password || view !== 'investigations') return
    let active = true
    let timer = 0
    let delay = 1000
    const controller = new AbortController()
    const load = async () => {
      try {
        const result = await request<InvestigationDetail>(`/investigations/${encodeURIComponent(selectedInvestigationId)}`, { signal: controller.signal })
        if (!active) return
        setInvestigation(result)
        delay = 1000
        if (['queued', 'running'].includes(result.status)) {
          timer = window.setTimeout(load, delay)
          delay = Math.min(delay * 2, 5000)
        } else void refresh()
      } catch (reason) {
        if (!active || (reason instanceof DOMException && reason.name === 'AbortError')) return
        setError(message(reason))
        if (reason instanceof ApiError && reason.status !== 408 && reason.status !== 429 && reason.status < 500) return
        timer = window.setTimeout(load, delay)
        delay = Math.min(delay * 2, 5000)
      }
    }
    void load()
    return () => { active = false; controller.abort(); window.clearTimeout(timer) }
  }, [selectedInvestigationId, user, view, refresh, pollKey])

  useEffect(() => {
    if (!selectedIncidentId || !user || user.must_change_password || view !== 'incidents') return
    const controller = new AbortController()
    request<Incident>(`/incidents/${encodeURIComponent(selectedIncidentId)}`, { signal: controller.signal }).then((result) => {
      if (!controller.signal.aborted) setIncident(result)
    }).catch((reason: unknown) => { if (!controller.signal.aborted) setError(message(reason)) })
    return () => controller.abort()
  }, [selectedIncidentId, user, view])

  async function signIn(username: string, password: string) {
    setBusy(true); setError('')
    try { setUser(await loginRequest(username, password)); setNotice('Signed in to the shared workspace.') }
    catch (reason) { setError(message(reason)) }
    finally { setBusy(false) }
  }

  async function signOut() {
    try { await request('/auth/logout', { method: 'POST' }) } catch { /* clear the local view if the server session already expired */ }
    ++refreshSequence.current
    setUser(null); setAssets([]); setInvestigations([]); setIncidents([]); setReports([]); setIntegrations([])
    setSpamhausDrop(null); setCinsArmy(null); setOpenPhish(null); setInvestigation(null); setIncident(null)
    setSelectedAssetId(''); setSelectedInvestigationId(''); setSelectedIncidentId(''); setSelectedReportId('')
    setSelectedRemediationPlanId(''); setSelectedThreatScenarioId(''); setComparisonRoute(null)
    setError(''); setNotice(''); setLoading(false); setView('overview')
  }

  async function runAction<T>(action: () => Promise<T>, success?: string): Promise<T | undefined> {
    setBusy(true); setError(''); setNotice('')
    try { const value = await action(); if (success) { setNotice(success); settleSubmittedFormDrafts(true) } return value }
    catch (reason) { settleSubmittedFormDrafts(false); setError(message(reason)); return undefined }
    finally { setBusy(false) }
  }

  const demo = readiness?.mode === 'demo'
  const selectedAsset = useMemo(() => assets.find((item) => item.id === selectedAssetId) ?? null, [assets, selectedAssetId])
  const markOverviewIntroPlayed = useCallback(() => setOverviewIntroPlayed(true), [])

  function navigate(nextView: View) {
    resolvingFindingRoute.current = false
    setView(nextView)
    if (mobileNavOpen) { setMobileNavOpen(false); window.requestAnimationFrame(() => mobileMenuButton.current?.focus()) }
  }

  if (authenticating) return <main className="login-wrap"><LoadingState label="Restoring your workspace session…" /></main>
  if (!user) return <LoginScreen onLogin={signIn} busy={busy} error={error} readiness={readiness} reducedMotion={reducedMotion} decorativeMotionEnabled={decorativeMotionEnabled} onEnableMotion={enableDecorativeMotion} />
  if (user.must_change_password) return <PasswordChangeScreen user={user} onChanged={setUser} onSignOut={signOut} reducedMotion={reducedMotion} />

  return <div className={`app-shell${sidebarCollapsed ? ' sidebar-collapsed' : ''}${mobileNavOpen ? ' mobile-nav-open' : ''}`}>
    {mobileNavOpen && <button className="nav-backdrop" aria-label="Close navigation" onClick={() => { setMobileNavOpen(false); mobileMenuButton.current?.focus() }} />}
    <aside className="rail" id="primary-navigation" aria-label="Primary navigation" ref={mobileNav} role={mobileNavOpen && isNarrow ? 'dialog' : undefined} aria-modal={mobileNavOpen && isNarrow ? true : undefined} aria-hidden={isNarrow && !mobileNavOpen}>
      <div className="sidebar-brand-row">
        <button className="sidebar-brand-button" aria-label="CyberLens overview" onClick={() => navigate('overview')} onMouseEnter={() => setBrandReplayToken((value) => value + 1)} onFocus={() => setBrandReplayToken((value) => value + 1)}><BrandLockup className="sidebar-wordmark" size={39} subtitle="ANALYST WORKSPACE" decorative animate={!reducedMotion} replayToken={brandReplayToken} /></button>
        <button className="sidebar-collapse" type="button" aria-controls="primary-navigation" aria-expanded={!sidebarCollapsed} aria-label={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'} title={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'} onClick={() => setSidebarCollapsed((value) => !value)}><Icon name="collapse" size={18} /></button>
      </div>
      <nav className="nav-list" aria-label="Workspace">
        <p className="nav-section-label">Workspace</p>
        {nav.map((item) => <button key={item.id} type="button" className={`rail-link ${view === item.id ? 'active' : ''}`} onClick={() => navigate(item.id)} title={item.title} data-tooltip={item.title} aria-label={item.title} aria-current={view === item.id ? 'page' : undefined}><Icon name={item.icon} /><span className="nav-label">{item.title}</span></button>)}
        {user.role === 'admin' && <><p className="nav-section-label admin-nav-label">Manage</p><button type="button" className={`rail-link ${view === 'admin' ? 'active' : ''}`} onClick={() => navigate('admin')} title="Administration" data-tooltip="Administration" aria-label="Administration" aria-current={view === 'admin' ? 'page' : undefined}><Icon name="admin" /><span className="nav-label">Administration</span></button></>}
      </nav>
      <div className="rail-bottom"><span className="sidebar-role-mark" aria-hidden="true">{user.role.slice(0, 1).toUpperCase()}</span><span className="sidebar-role-copy">Signed in as <strong>{user.role}</strong></span></div>
    </aside>
    <section className="workspace">
      <header className="topbar" ref={topbar}>
        <button ref={mobileMenuButton} className="mobile-menu-button" type="button" aria-label={mobileNavOpen ? 'Close navigation' : 'Open navigation'} aria-controls="primary-navigation" aria-expanded={mobileNavOpen} onClick={() => setMobileNavOpen((value) => !value)}><Icon name="menu" /><span>Menu</span></button>
        <BrandLockup className="mobile-brand" size={27} animate={!reducedMotion} replayOnHover />
        <div className="crumb"><span>Workspace</span><span className="crumb-slash">/</span><strong>{nav.find((item) => item.id === view)?.title ?? 'Administration'}</strong></div>
        <div className="topbar-right"><span className={`mode-pill ${demo ? 'demo' : 'live'}`} aria-label={readiness ? `${demo ? 'Demo' : 'Live'} mode` : 'Application status connecting'}><span className="status-dot" />{readiness ? `${demo ? 'Demo' : 'Live'} mode` : 'Connecting'}</span>
          <details className="user-menu"><summary className="user-chip" aria-label={`User menu for ${user.username}, ${user.role}`}><span className="avatar small">{user.username.slice(0, 2).toUpperCase()}</span><span className="header-user-copy"><strong>{user.username}</strong><small>{user.role}</small></span><span className="chevron">⌄</span></summary>
            <div className="user-menu-popover"><p>Signed in as <strong>{user.username}</strong><small>{user.role}</small></p><label className="motion-preference"><input type="checkbox" checked={reducedMotion} disabled={systemReducedMotion} onChange={(event) => { setManualReducedMotion(event.target.checked); setDecorativeMotionEnabled(false) }} />Reduce animations</label>{systemReducedMotion && <small className="system-motion-note">Required by your system preference</small>}<button className="text-button sign-out-button" onClick={() => void signOut()}>Sign out</button></div>
          </details></div>
      </header>
      <main className="content">
        {loading && <LoadingState label="Loading workspace records…" />}
        {demo && <div className="demo-banner"><span className="banner-icon">i</span><span><strong>Demo data</strong> · Synthetic fixtures only. No external security checks run in this mode.</span></div>}
        {error && <div className="alert error" role="alert"><span>{error}</span>{user && <button className="small-button" disabled={loading} onClick={() => { setError(''); void refresh() }}>Retry</button>}<button onClick={() => setError('')} aria-label="Dismiss error">×</button></div>}
        {notice && <div className="alert success" role="status"><span>{notice}</span><button onClick={() => setNotice('')} aria-label="Dismiss notice">×</button></div>}
        <div className="page-transition" key={view} data-page-view={view} ref={pageTransition}>
        {view === 'overview' && <Overview readiness={readiness} assets={assets} investigations={investigations} incidents={incidents} integrations={integrations} onNavigate={navigate} onOpenInvestigation={(id) => { setSelectedInvestigationId(id); navigate('investigations') }} canExportPosture={user.role !== 'viewer'} onExportPosture={createPostureReport} animateIntro={!overviewIntroPlayed} onIntroComplete={markOverviewIntroPlayed} reducedMotion={reducedMotion} decorativeMotionEnabled={decorativeMotionEnabled} onEnableMotion={enableDecorativeMotion} />}
        {view === 'assets' && <AssetsScreen assets={assets} selectedAsset={selectedAsset} selectedAssetId={selectedAssetId} canEdit={user.role !== 'viewer'} live={!demo} busy={busy}
          onSelect={setSelectedAssetId} onCreate={(data) => runAction(async () => { const created = await request<Asset>('/assets', { method: 'POST', body: JSON.stringify(data) }); await refresh(); setSelectedAssetId(created.id); return created }, 'Asset registered.')}
          onUpdateNotes={(id, notes) => runAction(async () => { await request(`/assets/${id}`, { method: 'PATCH', body: JSON.stringify({ notes }) }); await refresh() }, 'Asset notes saved.')}
          onConfirmUrlRetention={(id, identifier) => runAction(async () => { await request(`/assets/${id}/url-retention-confirmation`, { method: 'POST', body: JSON.stringify({ identifier }) }); await refresh() }, 'Complete URL retention confirmed.')}
          onAuthorize={(id, note, expiresInDays) => runAction(async () => { await request(`/assets/${id}/authorization`, { method: 'POST', body: JSON.stringify({ authorized: true, note, expires_in_days: expiresInDays }) }); await refresh() }, 'Authorization record saved.')}
          onRevokeAuthorization={(id) => runAction(async () => { await request(`/assets/${id}/authorization`, { method: 'DELETE' }); await refresh() }, 'Authorization revoked.')}
          onRevokeEmailBreachAuthorization={(id) => runAction(async () => { await request(`/assets/${id}/email-breach-authorization`, { method: 'DELETE' }); await refresh() }, 'XposedOrNot authorization revoked.')}
          onAddComponent={(id, data) => runAction(async () => { await request(`/assets/${id}/components`, { method: 'POST', body: JSON.stringify(data) }); await refresh() }, 'Software component added.')}
          onDeleteComponent={(assetId, componentId) => runAction(async () => { await request(`/assets/${assetId}/components/${componentId}`, { method: 'DELETE' }); await refresh() }, 'Component removed.')}
          onRun={(assetId, scenario) => startRun(assetId, scenario)} runBusy={busy} onCpeSearch={async (component) => {
            const params = new URLSearchParams({ keyword_search: `${component.vendor} ${component.product}`, limit: '20',
              software_vendor: component.vendor, software_product: component.product, software_version: component.version })
            const result = await runAction(() => request<{ results: CpeResult[] }>(`/integrations/nvd/cpes?${params.toString()}`))
            return result?.results ?? []
          }} onSelectCpe={(assetId, componentId, cpe) => runAction(async () => { await request(`/integrations/assets/${assetId}/components/${componentId}/cpe?cpe_name=${encodeURIComponent(cpe)}`, { method: 'PUT' }); await refresh() }, 'CPE selected for review.')}/>
        }
        {view === 'investigations' && <InvestigationsScreen items={investigations} selected={investigation?.id === selectedInvestigationId ? investigation : null} assets={assets} canRun={user.role !== 'viewer'} isDemo={Boolean(demo)} busy={busy}
          xposedornotEnabled={Boolean(demo) || Boolean(integrations.find((item) => item.id === 'xposedornot')?.configured)}
          onSelect={(id) => { setSelectedInvestigationId(id); setComparisonRoute(null); setSelectedIncidentId('') }} onRun={(asset, scenario, provider, authorized) => startRun(asset, scenario, provider, authorized)}
          onRetry={(id) => runAction(async () => { await request(`/investigations/${id}/retry`, { method: 'POST' }); setPollKey((value) => value + 1); await refresh() }, 'Investigation retry queued.')}
          onApplicability={(findingId, applicability, reason) => runAction(async () => { await request(`/findings/${findingId}/applicability`, { method: 'PATCH', body: JSON.stringify({ applicability, reason }) }); await loadInvestigation(selectedInvestigationId); await refresh() }, 'Applicability decision saved and risk recalculated.')}
          onCreateIncident={(finding) => runAction(async () => { const created = await request<Incident>('/incidents', { method: 'POST', body: JSON.stringify({ title: finding.title, summary: finding.explanation, asset_id: finding.asset_id, investigation_id: finding.investigation_id, finding_ids: [finding.id], priority: severityPriority(finding.severity), classification: 'security_issue' }) }); await refresh(); setSelectedIncidentId(created.id); setView('incidents') }, 'Incident case created.')}
          onReport={(format) => createReport({ format, investigation_id: selectedInvestigationId })}
          onCompare={(otherId) => { setComparisonRoute({ current: selectedInvestigationId, other: otherId }); return runAction(() => request<Record<string, unknown>>(`/investigations/${selectedInvestigationId}/compare/${otherId}`)) }}/>
        }
        {view === 'incidents' && <IncidentsScreen items={incidents} selected={incident?.id === selectedIncidentId ? incident : null} canEdit={user.role !== 'viewer'} canSyncAttackCatalog={user.role === 'admin'} isDemo={Boolean(demo)} busy={busy} onSelect={setSelectedIncidentId}
          onUpdate={(id, body) => runAction(async () => { const userId = user.id; const result = await request<Incident>(`/incidents/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify(body) }); if (sessionIdentity.current === userId && selectedIncident.current === id) setIncident(result); await refresh() }, 'Incident updated.')}
          onEvent={(id, messageText) => runAction(async () => { await request(`/incidents/${id}/events`, { method: 'POST', body: JSON.stringify({ message: messageText }) }); await reloadIncident(id) }, 'Timeline event recorded.')}
          onTask={(id, taskId, status, notes) => runAction(async () => { await request(`/incidents/${id}/tasks/${taskId}`, { method: 'PATCH', body: JSON.stringify({ status, notes }) }); await reloadIncident(id) }, 'Playbook task saved.')}
          onReport={(id, format) => createReport({ format, incident_id: id })}
          onAttackCreate={(id, suggestion) => runAction(async () => { await request('/attack/mappings', { method: 'POST', body: JSON.stringify({ incident_id: id, catalog_version: suggestion.catalog_version, technique_id: suggestion.technique_id, tactic: suggestion.tactic, evidence_id: suggestion.evidence_id, rationale: suggestion.rationale, confidence: suggestion.confidence, evidence_role: suggestion.evidence_role }) }); await reloadIncident(id) }, 'ATT&CK mapping proposed for analyst review.')}
          onAttackDecision={(id, mappingId, decision, techniqueId, tactic) => runAction(async () => { const body: Record<string, unknown> = { decision }; if (decision === 'overridden' && techniqueId) { body.technique_id = techniqueId; body.tactic = tactic; body.rationale = 'Analyst override selected after review of the linked evidence.'; body.confidence = 0.6; body.evidence_role = 'contextual' } await request(`/attack/mappings/${mappingId}`, { method: 'PATCH', body: JSON.stringify(body) }); await reloadIncident(id) }, 'ATT&CK mapping review saved.')}/>
        }
        {view === 'remediation' && <RemediationScreen user={user} incidents={incidents} selectedPlanId={selectedRemediationPlanId} onSelect={setSelectedRemediationPlanId} />}
        {view === 'threat-model' && <ThreatModelScreen assets={assets} initialAssetId={selectedAssetId} investigations={investigations} incidents={incidents} user={user} selectedScenarioId={selectedThreatScenarioId} onSelectScenario={setSelectedThreatScenarioId} onAssetsChanged={refresh} />}
        {view === 'reports' && <ReportsScreen reports={reports} selectedReportId={selectedReportId} onDownload={(id) => runAction(() => downloadReport(id), 'Report download started.')} />}
        {view === 'integrity' && <IntegrityScreen canExport={user.role !== 'viewer'} />}
        {view === 'integrations' && <IntegrationsScreen integrations={integrations} isDemo={Boolean(demo)} spamhausDrop={spamhausDrop} cinsArmy={cinsArmy} openPhish={openPhish} canRefreshSpamhaus={user.role === 'admin'} canRefreshCinsArmy={user.role === 'admin'} canRefreshOpenPhish={user.role === 'admin'} onRefreshSpamhaus={() => runAction(async () => { await request('/integrations/spamhaus-drop/refresh', { method: 'POST' }); await refresh() }, 'Spamhaus DROP refresh queued.')} onRefreshCinsArmy={() => runAction(async () => { await request('/integrations/cins-army/refresh', { method: 'POST' }); await refresh() }, 'CINS Army refresh queued.')} onRefreshOpenPhish={() => runAction(async () => { await request('/integrations/openphish/refresh', { method: 'POST' }); await refresh() }, 'OpenPhish refresh queued.')} />}
        {view === 'admin' && user.role === 'admin' && <AdminScreen user={user} onUserChanged={(updated) => { setUser(updated); if (updated.role !== 'admin') setView('overview') }} runAction={runAction} />}
        <footer className="page-footer"><span>CYBERLENS <b>·</b> SECURITY ANALYSIS WORKSPACE</span><span>ACADEMIC PRIORITIZATION · {readiness?.mode?.toUpperCase() ?? 'CONNECTING'}</span></footer>
        </div>
      </main>
    </section>
  </div>

  async function startRun(assetId: string, scenario?: string, emailBreachProvider?: 'hibp' | 'xposedornot', xposedAuthorizationConfirmed = false) {
    const payload: { asset_id: string; scenario?: string; email_breach_provider?: 'hibp' | 'xposedornot'; xposedornot_authorization_confirmed?: boolean } = { asset_id: assetId }
    if (demo && scenario) payload.scenario = scenario
    if (emailBreachProvider) payload.email_breach_provider = emailBreachProvider
    if (emailBreachProvider === 'xposedornot' && !demo) payload.xposedornot_authorization_confirmed = xposedAuthorizationConfirmed
    const created = await runAction(() => request<{ id: string }>('/investigations', { method: 'POST', body: JSON.stringify(payload) }), 'Investigation queued.')
    if (created) { setSelectedInvestigationId(created.id); setView('investigations'); await refresh() }
  }

  async function loadInvestigation(id: string) {
    const userId = user?.id
    const result = await request<InvestigationDetail>(`/investigations/${encodeURIComponent(id)}`)
    if (sessionIdentity.current === userId && selectedInvestigation.current === id) setInvestigation(result)
  }

  async function reloadIncident(id: string) {
    const userId = user?.id
    const result = await request<Incident>(`/incidents/${encodeURIComponent(id)}`)
    if (sessionIdentity.current === userId && selectedIncident.current === id) setIncident(result)
    await refresh()
  }

  async function createReport(payload: { format: 'pdf' | 'json'; investigation_id?: string; incident_id?: string }) {
    const created = await runAction(() => request<Report>('/reports', { method: 'POST', body: JSON.stringify(payload) }), 'Snapshot report generated.')
    if (created) { await refresh(); await runAction(() => downloadReport(created.id), 'Report download started.') }
  }

  async function createPostureReport(rangeDays: number, format: 'pdf' | 'json') {
    const created = await runAction(() => request<Report>('/reports/posture', {
      method: 'POST', body: JSON.stringify({ range_days: rangeDays, format }),
    }), 'Posture scorecard report generated.')
    if (created) { setSelectedReportId(created.id); await refresh(); await runAction(() => downloadReport(created.id), 'Report download started.') }
  }
}

function LoginScreen({ onLogin, busy, error, readiness, reducedMotion, decorativeMotionEnabled, onEnableMotion }: { onLogin: (username: string, password: string) => Promise<void>; busy: boolean; error: string; readiness: Readiness | null; reducedMotion: boolean; decorativeMotionEnabled: boolean; onEnableMotion: () => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [decorativePaused, setDecorativePaused] = useState(false)
  return <main className="login-wrap"><div className="login-layout"><section className="login-story" aria-labelledby="login-story-heading"><p className="login-story-kicker">EVIDENCE. CONTEXT. CONFIDENCE.</p><h2 id="login-story-heading">A clearer view of<br/>your security posture.</h2><p>Connect assets, review source evidence, and move from investigation to an informed decision.</p><WorkspaceGraphic /><div className="login-principles"><span>Evidence-led analysis</span><span>Analyst-controlled decisions</span><span>One focused workspace</span></div></section><section className="login-card panel"><div className="login-brand"><BrandLockup size={42} animate={!reducedMotion} replayOnHover /></div><p className="eyebrow">SECURITY ANALYST WORKSPACE</p><h1>Sign in to your workspace</h1><p className="subtitle">Use your workspace account to view assets and investigation records.</p>
    {readiness?.mode === 'demo' && <div className="demo-banner"><span className="banner-icon">i</span><span><strong>Demo workspace</strong> · Initial account: admin</span></div>}
    {error && <div className="alert error" role="alert">{error}</div>}
    <form onSubmit={(event) => { event.preventDefault(); void onLogin(username, password) }} className="stack-form">
      <label>Username<input autoComplete="username" name="username" value={username} onChange={(event) => setUsername(event.target.value)} /></label>
      <label>Password<input type="password" autoComplete="current-password" name="password" value={password} onChange={(event) => setPassword(event.target.value)} /></label>
      <button className="primary-button wide" type="submit" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
    </form>
  </section></div><LoginGlobeGate reducedMotion={reducedMotion && !decorativeMotionEnabled} paused={decorativePaused} onPausedChange={setDecorativePaused} onEnableMotion={onEnableMotion} /><CyberLensHelloEffect className="login-cyberlens-hello" speed={1.1} reducedMotion={reducedMotion && !decorativeMotionEnabled} paused={decorativePaused} /></main>
}

function PasswordChangeScreen({ user, onChanged, onSignOut, reducedMotion }: { user: User; onChanged: (user: User) => void; onSignOut: () => Promise<void>; reducedMotion: boolean }) {
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  return <main className="login-wrap"><section className="login-card panel"><div className="login-brand"><BrandLockup size={42} animate={!reducedMotion} replayOnHover /></div><p className="eyebrow">ACCOUNT SECURITY</p><h1>Change your temporary password</h1><p className="subtitle">Set a password with at least 12 characters before using this workspace.</p>
    {error && <div className="alert error" role="alert">{error}</div>}
    <p className="card-note">The new password is checked once after submission. Live mode uses a padded five-character HIBP range lookup; Demo mode uses an offline fixture. A provider outage leaves your password and sessions unchanged.</p>
    <form className="stack-form" onSubmit={async (event) => { event.preventDefault(); setError(''); setBusy(true); try { const updated = await request<User>('/auth/change-password', { method: 'POST', body: JSON.stringify({ current_password: current, new_password: next }) }); onChanged(updated) } catch (reason) { setError(message(reason)); setNext('') } finally { setBusy(false) } }}>
      <label>Current password<input type="password" value={current} onChange={(e) => setCurrent(e.target.value)} /></label>
      <label>New password<input type="password" minLength={12} value={next} onChange={(e) => setNext(e.target.value)} /></label>
      <button className="primary-button wide" type="submit" disabled={busy || next.length < 12}>{busy ? 'Checking password…' : 'Update password'}</button>
    </form><button className="text-button" onClick={() => void onSignOut()}>Sign out</button><p className="card-note">Signed in as {user.username}</p>
  </section></main>
}

export default App
