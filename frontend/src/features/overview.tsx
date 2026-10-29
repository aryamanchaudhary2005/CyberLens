import { lazy, Suspense, useEffect, useMemo, useState } from 'react'
import type { Asset, EvidenceGraphChanges, Incident, Investigation, MonitoringSchedule, Readiness } from '../api'
import { request } from '../api'
import { Empty, StatusBadge } from '../components/ui'
import { CyberLensHelloEffect } from '../components/CyberLensHelloEffect'
import { GradientOrbBackground } from '../components/GradientOrbBackground'
import { DashboardBentoScene } from '../components/DashboardBentoScene'
import { useMotionConstraints } from '../components/motion'
import { date } from './helpers'
import type { View } from './types'
import { PostureScorecard, PostureSummaryCards } from './posture'

const RiskHistoryChart = lazy(() => import('../components/charts').then((module) => ({ default: module.RiskHistoryChart })))

type OverviewProps = {
  readiness: Readiness | null
  assets: Asset[]
  investigations: Investigation[]
  incidents: Incident[]
  integrations: Array<Record<string, unknown>>
  onNavigate: (view: View) => void
  onOpenInvestigation: (id: string) => void
  canExportPosture: boolean
  onExportPosture: (days: number, format: 'pdf' | 'json') => Promise<void>
  animateIntro: boolean
  onIntroComplete: () => void
  reducedMotion: boolean
  decorativeMotionEnabled: boolean
  onEnableMotion: () => void
}

const comparable = new Set(['completed', 'partial'])

export function Overview({ readiness, assets, investigations, incidents, integrations, onNavigate, onOpenInvestigation, canExportPosture, onExportPosture, animateIntro, onIntroComplete, reducedMotion, decorativeMotionEnabled, onEnableMotion }: OverviewProps) {
  const [schedules, setSchedules] = useState<MonitoringSchedule[] | null>(null)
  const [scheduleError, setScheduleError] = useState('')
  const [changes, setChanges] = useState<EvidenceGraphChanges | null>(null)
  const [changeError, setChangeError] = useState('')
  const [postureDetailsOpen, setPostureDetailsOpen] = useState(false)
  const [effectsPaused, setEffectsPaused] = useState(false)
  const [titleReplay, setTitleReplay] = useState(0)
  const decorativeReduced = reducedMotion && !decorativeMotionEnabled
  const motionConstrained = useMotionConstraints(decorativeReduced)
  const dataSaving = useMotionConstraints(false)

  const comparisonPair = useMemo(() => {
    const completed = investigations.filter((item) => comparable.has(item.status)).slice().sort((a, b) => b.created_at.localeCompare(a.created_at) || b.id.localeCompare(a.id))
    for (const [index, current] of completed.entries()) {
      const previous = completed.slice(index + 1).find((item) => item.asset_id === current.asset_id)
      if (previous) return { current, previous }
    }
    return null
  }, [investigations])

  useEffect(() => {
    const controller = new AbortController()
    setSchedules(null); setScheduleError('')
    void request<MonitoringSchedule[]>('/monitoring?page=1&page_size=100', { signal: controller.signal })
      .then((result) => setSchedules(result))
      .catch((reason: unknown) => {
        if (reason instanceof DOMException && reason.name === 'AbortError') return
        setScheduleError(reason instanceof Error ? reason.message : 'Monitoring status is unavailable.')
      })
    return () => controller.abort()
  }, [])

  useEffect(() => {
    if (!animateIntro) return
    const timer = window.setTimeout(onIntroComplete, 390)
    return () => window.clearTimeout(timer)
  }, [animateIntro, onIntroComplete])

  useEffect(() => {
    const controller = new AbortController()
    setChanges(null); setChangeError('')
    if (!comparisonPair) return () => controller.abort()
    void request<EvidenceGraphChanges>(`/investigations/${encodeURIComponent(comparisonPair.current.id)}/changes/${encodeURIComponent(comparisonPair.previous.id)}`, { signal: controller.signal })
      .then((result) => setChanges(result))
      .catch((reason: unknown) => {
        if (reason instanceof DOMException && reason.name === 'AbortError') return
        setChangeError(reason instanceof Error ? reason.message : 'Evidence comparison is unavailable.')
      })
    return () => controller.abort()
  }, [comparisonPair?.current.id, comparisonPair?.previous.id])

  const recent = investigations.slice().sort((a, b) => b.created_at.localeCompare(a.created_at) || b.id.localeCompare(a.id)).slice(0, 4)
  const openIncidents = incidents.filter((item) => item.status !== 'closed')
  const configuredIntegrationCount = integrations.filter((item) => item.configured === true).length
  const riskHistory = investigations.filter((item) => comparable.has(item.status)).slice().sort((a, b) => a.created_at.localeCompare(b.created_at) || a.id.localeCompare(b.id))
  const scoredInvestigations = riskHistory.filter((item) => item.risk?.score != null)
  const missingRiskCount = riskHistory.length - scoredInvestigations.length
  const riskSummary = scoredInvestigations.length
    ? `${scoredInvestigations.length} of ${riskHistory.length} completed or partial investigations have numeric scores from ${date(riskHistory[0].created_at)} to ${date(riskHistory[riskHistory.length - 1].created_at)}.${missingRiskCount ? ` ${missingRiskCount} saved observations have no numeric score.` : ''}`
    : 'No numeric scores are available in the loaded completed or partial investigation history.'

  return <div className="overview-page">
    <GradientOrbBackground reducedMotion={decorativeReduced} paused={effectsPaused} />
    <div className="overview-content">
    <div className="page-heading overview-heading"><CyberLensHelloEffect className="dashboard-cyberlens-hello" speed={1.1} reducedMotion={decorativeReduced} paused={effectsPaused} replayToken={titleReplay} /><div><p className="eyebrow">SECURITY OPERATIONS</p><h1>Investigation workspace</h1><p className="subtitle">A current view of saved assessments, evidence changes, response work, and provider coverage.</p></div><button className="primary-button" onClick={() => onNavigate('investigations')}><span aria-hidden="true">＋</span> Start investigation</button></div>
    <div className="overview-meta-row"><p className="overview-scope">{assets.length} assets and {investigations.length} investigation records in the workspace lists currently loaded.</p><div className="overview-motion-controls" role="group" aria-label="Decorative motion">{decorativeReduced && !dataSaving && <button className="text-button" type="button" onClick={onEnableMotion} title="Animate decorative backgrounds and lettering for this tab; operational motion stays reduced.">Enable decorative motion</button>}<button className="text-button" type="button" disabled={motionConstrained} title={motionConstrained ? 'Reduced-motion or data-saving preferences keep decorative effects static.' : undefined} aria-pressed={effectsPaused} onClick={() => setEffectsPaused((value) => !value)}>{motionConstrained ? 'Motion reduced' : effectsPaused ? 'Resume background' : 'Pause background'}</button><button className="text-button" type="button" disabled={motionConstrained || effectsPaused} onClick={() => setTitleReplay((value) => value + 1)}>Replay CyberLens title</button></div></div>

    <DashboardBentoScene reducedMotion={decorativeReduced} paused={effectsPaused} />
    <div className={`bento-grid${animateIntro ? ' bento-intro' : ''}`} role="region" aria-label="Security workspace overview">
      <PostureSummaryCards />

      <section className="panel bento-card bento-span-5 incident-summary-card" aria-labelledby="overview-incidents-heading">
        <div className="panel-heading"><div><p className="eyebrow">RESPONSE WORK</p><h2 id="overview-incidents-heading">Open incidents</h2></div><span className="count-pill">{openIncidents.length}</span></div>
        {openIncidents.length ? <ul className="bento-record-list">{openIncidents.slice(0, 3).map((item) => <li key={item.id}><button className="bento-record-button" onClick={() => { window.location.hash = `/incidents/${encodeURIComponent(item.id)}` }}><span className={`severity ${item.priority}`}>{item.priority}</span><span><strong>{item.title}</strong><small>{item.asset_identifier} · {item.status.replaceAll('_', ' ')} · updated {date(item.updated_at)}</small></span><span className="chevron" aria-hidden="true">›</span></button></li>)}</ul> : <Empty title="No open incidents in the loaded list" text="Closed incidents are not included in this summary." />}
        <button className="text-button bento-card-action" onClick={() => onNavigate('incidents')}>Open incident register <span aria-hidden="true">→</span></button>
      </section>

      <section className="panel bento-card bento-span-7 recent-investigations-card" aria-labelledby="overview-investigations-heading">
        <div className="panel-heading"><div><p className="eyebrow">LATEST SAVED RUNS</p><h2 id="overview-investigations-heading">Recent investigations</h2></div><button className="text-button" onClick={() => onNavigate('investigations')}>View all <span aria-hidden="true">→</span></button></div>
        {recent.length ? <div className="table-wrap bento-table-wrap"><table><thead><tr><th>Asset</th><th>Status</th><th>Risk</th><th>Observed</th><th><span className="sr-only">Open</span></th></tr></thead><tbody>{recent.map((item) => <tr key={item.id}><td><strong className="technical-value">{item.asset_identifier ?? 'Asset unavailable'}</strong><small>{item.asset_kind ?? 'Type unavailable'}</small></td><td><StatusBadge value={item.status} /></td><td>{item.risk?.score == null ? <StatusBadge value="insufficient data" /> : <span className="risk-value">{item.risk.score}<small> / 100 · {item.risk.band}</small></span>}</td><td>{date(item.created_at)}</td><td><button className="small-button" onClick={() => onOpenInvestigation(item.id)}>Open</button></td></tr>)}</tbody></table></div> : <Empty title="No investigations yet" text="Register an asset and start an investigation to create a saved record." action="Open investigations" onAction={() => onNavigate('investigations')} />}
      </section>

      <section className="panel bento-card bento-span-6 change-summary-card" aria-labelledby="overview-changes-heading">
        <div className="panel-heading"><div><p className="eyebrow">EVIDENCE GRAPH</p><h2 id="overview-changes-heading">Change Radar</h2></div><button className="text-button" onClick={() => onNavigate('investigations')}>Review <span aria-hidden="true">→</span></button></div>
        {changeError && <div className="overview-card-error" role="alert">{changeError}</div>}
        {!changeError && !comparisonPair && <Empty title="No comparison pair" text="Two completed or partial investigations for the same asset are needed to compare saved evidence." />}
        {!changeError && comparisonPair && !changes && <p className="loading-inline" role="status">Comparing the latest available pair…</p>}
        {changes && comparisonPair && <>
          <p className="comparison-context">{comparisonPair.current.asset_identifier ?? 'Asset'} · {date(comparisonPair.current.created_at)} compared with {date(comparisonPair.previous.created_at)}</p>
          <dl className="change-count-grid">{(['new', 'changed', 'no_longer_observed', 'unknown'] as const).map((status) => <div key={status} className={`change-count ${status}`}><dt>{status.replaceAll('_', ' ')}</dt><dd>{changes.counts[status]}</dd></div>)}</dl>
          <p className="bento-scope">Provider gaps remain unknown coverage; they are not reported as removals.</p>
        </>}
      </section>

      <section className="panel bento-card bento-span-6 monitoring-summary-card" aria-labelledby="overview-monitoring-heading">
        <div className="panel-heading"><div><p className="eyebrow">SCHEDULED REVIEWS</p><h2 id="overview-monitoring-heading">Monitoring</h2></div><button className="text-button" onClick={() => onNavigate('assets')}>Assets <span aria-hidden="true">→</span></button></div>
        {scheduleError && <div className="overview-card-error" role="alert">{scheduleError}</div>}
        {!scheduleError && schedules === null && <p className="loading-inline" role="status">Loading saved schedules…</p>}
        {!scheduleError && schedules && (schedules.length ? <>
          <dl className="monitoring-count-grid"><div><dt>Active</dt><dd>{schedules.filter((item) => item.status === 'active').length}</dd></div><div><dt>Paused</dt><dd>{schedules.filter((item) => item.status === 'paused').length}</dd></div><div><dt>Failed</dt><dd>{schedules.filter((item) => item.status === 'failed').length}</dd></div></dl>
          <ul className="monitoring-summary-list">{schedules.slice(0, 3).map((item) => <li key={item.id}><span><strong>{item.cadence} · {assets.find((asset) => asset.id === item.asset_id)?.identifier ?? 'Asset'}</strong><small>{item.next_run_at ? `Next run ${date(item.next_run_at)}` : item.failure_detail ?? 'No next run scheduled'}</small></span><StatusBadge value={item.status} /></li>)}</ul>
          <p className="bento-scope">Newest {schedules.length} schedule records returned by the monitoring API.</p>
        </> : <Empty title="No monitoring schedules" text="Schedules are created from an explicitly authorized website asset." />)}
      </section>

      <section className="panel bento-card bento-span-12 risk-trend-card" aria-labelledby="overview-risk-trend-heading">
        <div className="panel-heading"><div><p className="eyebrow">SAVED ASSESSMENTS</p><h2 id="overview-risk-trend-heading">Risk history</h2></div><button className="text-button" onClick={() => onNavigate('investigations')}>Investigations <span aria-hidden="true">→</span></button></div>
        <p className="chart-summary" id="overview-risk-summary">{riskSummary} Scores are saved assessment values, not probabilities of compromise.</p>
        {scoredInvestigations.length > 0 ? <>
          <p className="chart-summary">Separate lines represent the saved risk-policy version. Missing scores remain gaps and are not treated as zero.</p>
          <p className="chart-exact-summary">Latest saved values: {riskHistory.slice(-5).map((item) => date(item.created_at) + ' ' + (item.risk?.score == null ? 'no numeric score' : item.risk.score + '/100') + ' · ' + (item.risk?.explanation.rule_version ?? item.risk?.version ?? 'policy unknown')).join(' ; ')}. The table below contains every point.</p>
          <div className="chart-wrap bento-chart" role="img" aria-label={`Risk score trend. ${riskSummary} Lines do not cross risk-policy versions.`}><Suspense fallback={<div className="chart-skeleton" role="status">Loading saved score chart…</div>}><RiskHistoryChart points={riskHistory.map((item) => ({ name: date(item.created_at), score: item.risk?.score ?? null, policyVersion: item.risk?.explanation.rule_version ?? item.risk?.version ?? null }))} /></Suspense></div>
          <details className="chart-data-alternative"><summary>View exact chart values</summary><div className="table-wrap"><table><caption>Saved investigation risk values and policy versions in the loaded history order.</caption><thead><tr><th>Observed</th><th>Asset</th><th>Risk score</th><th>Band</th><th>Policy version</th></tr></thead><tbody>{riskHistory.map((item) => <tr key={item.id}><td>{date(item.created_at)}</td><td className="technical-value">{item.asset_identifier ?? 'Unavailable'}</td><td>{item.risk?.score ?? 'No numeric score'}</td><td>{item.risk?.band ?? 'Unavailable'}</td><td>{item.risk?.explanation.rule_version ?? item.risk?.version ?? 'Unknown'}</td></tr>)}</tbody></table></div></details>
        </> : <Empty title="No scored investigations" text="Risk history appears when saved assessments have usable coverage." />}
      </section>

      <section className="panel bento-card bento-span-12 workspace-status-card" aria-labelledby="overview-system-heading">
        <div className="panel-heading"><div><p className="eyebrow">WORKSPACE SERVICES</p><h2 id="overview-system-heading">System and integration status</h2></div><StatusBadge value={readiness ? 'ready' : 'connecting'} /></div>
        <div className="service-status-grid">
          <ServiceStatus name="Analysis API" detail="FastAPI workspace service" available={Boolean(readiness)} />
          <ServiceStatus name="PostgreSQL" detail="Saved workspace records" available={Boolean(readiness?.dependencies.database)} />
          <ServiceStatus name="Redis" detail="Shared jobs and limits" available={Boolean(readiness?.dependencies.redis)} />
          <ServiceStatus name="RQ worker" detail="Investigation execution heartbeat" available={Boolean(readiness?.dependencies.worker)} />
        </div>
        <p className="bento-scope">Integration configuration: {configuredIntegrationCount} of {integrations.length} configured. Configuration is not a live provider connectivity probe.</p>
        <p className="bento-caveat">Service readiness comes from the API, PostgreSQL, Redis, and worker readiness responses. Provider freshness is shown above from saved observations.</p>
      </section>
    </div>

    <details className="posture-detail-disclosure" open={postureDetailsOpen} onToggle={(event) => setPostureDetailsOpen(event.currentTarget.open)}>
      <summary>View detailed posture scorecard, trends, and exports</summary>
      {postureDetailsOpen && <PostureScorecard canExport={canExportPosture} onExport={onExportPosture} />}
    </details>
    </div>
  </div>
}

function ServiceStatus({ name, detail, available, stateLabel }: { name: string; detail: string; available: boolean; stateLabel?: string }) {
  return <div className="service-status-item"><span className={`service-status-mark ${available ? 'available' : 'unavailable'}`} aria-hidden="true">{available ? '✓' : '—'}</span><span><strong>{name}</strong><small>{detail}</small></span><StatusBadge value={stateLabel ?? (available ? 'available' : 'unavailable')} /></div>
}
