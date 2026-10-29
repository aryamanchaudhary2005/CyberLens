import { lazy, Suspense, useEffect, useState } from 'react'
import { request, type PostureMetric, type PostureMetricState, type PostureScorecard } from '../api'
import { Empty, StatusBadge } from '../components/ui'
import { ScoreRing } from '../components/WorkspaceGraphic'

const PostureRiskChart = lazy(() => import('../components/charts').then((module) => ({ default: module.PostureRiskChart })))
const PostureWorkflowChart = lazy(() => import('../components/charts').then((module) => ({ default: module.PostureWorkflowChart })))

const ranges = [7, 30, 90, 365] as const

function validateScorecard(value: PostureScorecard, detailed = false) {
  const isRecord = (item: unknown): item is Record<string, unknown> => typeof item === 'object' && item !== null && !Array.isArray(item)
  const summaryKeys = ['overall_risk', 'assessment_coverage', 'high_critical_findings', 'unassessed_categories', 'provider_health'] as const
  const detailKeys = ['repeated_findings', 'risk_trend', 'workflow_trend', 'asset_criticality', 'incident_timings', 'security_control_coverage'] as const
  const keys = detailed ? [...summaryKeys, ...detailKeys] : summaryKeys
  if (!isRecord(value) || keys.some((key) => !isRecord(value[key]) || typeof value[key].state !== 'string') ||
    !isRecord(value.data_scope) || !Array.isArray(value.data_scope.data_modes) || !Array.isArray(value.provider_health.providers) ||
    value.provider_health.providers.some((provider) => !isRecord(provider) || typeof provider.id !== 'string' || typeof provider.name !== 'string' || typeof provider.freshness !== 'string' || typeof provider.state !== 'string') ||
    (detailed && (!Array.isArray(value.risk_trend.points) || !Array.isArray(value.workflow_trend.points) || !isRecord(value.unassessed_categories.counts) || !isRecord(value.asset_criticality.counts)))) {
    throw new Error('The saved posture response is incomplete or unavailable. Retry to load the current scorecard.')
  }
  return value
}

function metricStateLabel(state: PostureMetricState): string {
  return state.replaceAll('_', ' ')
}

function ScopeNote({ metric }: { metric: PostureMetric }) {
  return <p className="posture-scope">{metric.range_days}-day range · {metric.scope} {metric.note}</p>
}

function MetricCard({ title, value, metric, detail }: { title: string; value: string; metric: PostureMetric; detail: string }) {
  return <article className="posture-metric-card">
    <div className="posture-metric-heading"><h3>{title}</h3><StatusBadge value={metricStateLabel(metric.state)} /></div>
    <strong className="posture-metric-value">{value}</strong>
    <p>{detail}</p>
    <ScopeNote metric={metric} />
  </article>
}

export function PostureSummaryCards() {
  const [scorecard, setScorecard] = useState<PostureScorecard | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [reload, setReload] = useState(0)

  useEffect(() => {
    const controller = new AbortController()
    setLoading(true); setError('')
    void request<PostureScorecard>('/posture/scorecard?range_days=30', { signal: controller.signal })
      .then((result) => { setScorecard(validateScorecard(result)); setLoading(false) })
      .catch((reason: unknown) => {
        if (reason instanceof DOMException && reason.name === 'AbortError') return
        setError(reason instanceof Error ? reason.message : 'Posture summary is unavailable.')
        setLoading(false)
      })
    return () => controller.abort()
  }, [reload])

  const metricValue = (value: number | null, suffix = '') => value == null ? 'Unavailable' : `${value}${suffix}`
  const providerStatus = (provider: PostureScorecard['provider_health']['providers'][number]) =>
    provider.provider_status == null ? metricStateLabel(provider.state) : Array.isArray(provider.provider_status) ? provider.provider_status.join(', ') : provider.provider_status

  return <>
    <section className="panel bento-card bento-span-7 posture-summary-card" aria-labelledby="overview-posture-heading">
      <div className="panel-heading"><div><p className="eyebrow">WORKSPACE POSTURE · 30 DAYS</p><h2 id="overview-posture-heading">Risk and coverage</h2></div><StatusBadge value={loading ? 'loading' : error ? 'unavailable' : scorecard?.overall_risk.state ?? 'unavailable'} /></div>
      {loading && <div className="bento-metric-grid" role="status" aria-label="Loading risk and coverage"><div className="bento-metric-skeleton" /><div className="bento-metric-skeleton" /></div>}
      {error && <div className="overview-card-error" role="alert"><span>{error}</span><button className="small-button" onClick={() => setReload((value) => value + 1)}>Retry</button></div>}
      {!loading && !error && scorecard && <>
        <div className="bento-metric-grid">
          <article className="bento-metric risk-metric"><div><h3>Overall risk</h3><StatusBadge value={metricStateLabel(scorecard.overall_risk.state)} /></div><ScoreRing value={scorecard.overall_risk.average_score} band={scorecard.overall_risk.band} /><strong>{scorecard.overall_risk.average_score == null ? metricStateLabel(scorecard.overall_risk.state) : <>{scorecard.overall_risk.average_score}<small> / 100</small></>}</strong><p>{scorecard.overall_risk.band ?? 'No scored assessments'} · {scorecard.overall_risk.assets_with_score} of {scorecard.overall_risk.assets_in_scope} assets scored</p></article>
          <article className="bento-metric coverage-metric" data-state={scorecard.assessment_coverage.state}><div><h3>Assessment coverage</h3><StatusBadge value={metricStateLabel(scorecard.assessment_coverage.state)} /></div><strong>{metricValue(scorecard.assessment_coverage.coverage_percent, '%')}</strong><div className="coverage-meter" aria-hidden="true"><span style={{ width: `${Math.max(0, Math.min(100, scorecard.assessment_coverage.coverage_percent ?? 0))}%` }} /></div><p>{scorecard.assessment_coverage.assessed_category_slots} of {scorecard.assessment_coverage.expected_category_slots} category slots assessed</p></article>
          <article className="bento-metric"><div><h3>High / critical observations</h3><StatusBadge value={metricStateLabel(scorecard.high_critical_findings.state)} /></div><strong>{metricValue(scorecard.high_critical_findings.total)}</strong><p>Latest saved observations · High {scorecard.high_critical_findings.high ?? 'Unavailable'} · Critical {scorecard.high_critical_findings.critical ?? 'Unavailable'}</p></article>
          <article className="bento-metric"><div><h3>Unassessed categories</h3><StatusBadge value={metricStateLabel(scorecard.unassessed_categories.state)} /></div><strong>{scorecard.unassessed_categories.total_unassessed_category_slots}</strong><p>{scorecard.unassessed_categories.assets_without_recent_assessment} assets without recent assessment</p></article>
        </div>
        <p className="bento-scope">Saved PostgreSQL observations · {scorecard.data_scope.asset_count} assets in scope · data modes: {scorecard.data_scope.data_modes.join(', ') || 'none recorded'} · through {new Date(scorecard.window_end).toLocaleDateString()}</p>
        <p className="bento-caveat">Risk is an academic prioritization score, not a probability of compromise. Missing or unassessed data is not safe.</p>
      </>}
    </section>
    <section className="panel bento-card bento-span-5 provider-summary-card" aria-labelledby="overview-provider-heading">
      <div className="panel-heading"><div><p className="eyebrow">SAVED COLLECTOR STATUS</p><h2 id="overview-provider-heading">Provider freshness</h2></div><span className="tiny-note">30-day view</span></div>
      {loading && <p className="empty-line" role="status">Loading provider observations…</p>}
      {error && <p className="provider-unavailable" role="status">Provider freshness unavailable.</p>}
      {!loading && !error && scorecard && (scorecard.provider_health.providers.length ? <>
        <div className="provider-observation-summary"><span className="provider-summary-symbol" aria-hidden="true"><svg viewBox="0 0 32 32" fill="none"><path d="M6 24V14m10 10V7m10 17V11" stroke="currentColor" strokeWidth="3" strokeLinecap="round" /></svg></span><div><strong>{scorecard.provider_health.providers.filter((provider) => provider.freshness === 'fresh').length}<small> / {scorecard.provider_health.providers.length}</small></strong><span>providers with fresh saved data</span></div></div>
        <ul className="provider-summary-list">{scorecard.provider_health.providers.slice(0, 5).map((provider) => <li key={provider.id}><span><strong>{provider.name}</strong><small>{provider.last_observed_at ? `Observed ${new Date(provider.last_observed_at).toLocaleString()}` : provider.note ?? 'No saved observation'}</small></span><span className="provider-summary-state"><StatusBadge value={providerStatus(provider)} /><StatusBadge value={provider.freshness.replaceAll('_', ' ')} /></span></li>)}</ul>
        {scorecard.provider_health.providers.length > 5 && <p className="bento-scope">Showing 5 of {scorecard.provider_health.providers.length} providers.</p>}
      </> : <Empty title="No provider observations" text="Saved collector results will appear here after an investigation. Unavailable data is not a clean verdict." />)}
      <p className="bento-scope">Latest saved provider results; this is not a live connectivity probe.</p>
      <a className="source-status-link" href="#/integrations">Inspect source configuration <span aria-hidden="true">↗</span></a>
    </section>
  </>
}

function seconds(value: number | null): string {
  if (value == null) return 'Unavailable'
  const hours = value / 3600
  if (hours >= 48) return `${(hours / 24).toFixed(1)} days`
  if (hours >= 1) return `${hours.toFixed(1)} hours`
  return `${Math.round(value / 60)} minutes`
}

export function PostureScorecard({ canExport, onExport }: { canExport: boolean; onExport: (days: number, format: 'pdf' | 'json') => Promise<void> }) {
  const [rangeDays, setRangeDays] = useState<number>(30)
  const [scorecard, setScorecard] = useState<PostureScorecard | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [exporting, setExporting] = useState(false)
  const [exportError, setExportError] = useState('')
  const [reloadKey, setReloadKey] = useState(0)

  useEffect(() => {
    const controller = new AbortController()
    setLoading(true)
    setError('')
    void request<PostureScorecard>(`/posture/scorecard?range_days=${rangeDays}`, { signal: controller.signal })
      .then((result) => { setScorecard(validateScorecard(result, true)); setLoading(false) })
      .catch((reason: unknown) => {
        if (reason instanceof DOMException && reason.name === 'AbortError') return
        setError(reason instanceof Error ? reason.message : 'Posture scorecard could not be loaded.')
        setLoading(false)
      })
    return () => controller.abort()
  }, [rangeDays, reloadKey])

  async function exportReport(format: 'pdf' | 'json') {
    setExporting(true)
    setExportError('')
    try { await onExport(rangeDays, format) }
    catch (reason) { setExportError(reason instanceof Error ? reason.message : 'Scorecard export failed.') }
    finally { setExporting(false) }
  }

  return <section className="panel chart-panel posture-panel" aria-labelledby="posture-heading">
    <div className="panel-heading posture-title-row">
      <div><p className="eyebrow">WORKSPACE HEALTH</p><h2 id="posture-heading">Security posture scorecard</h2>
        <p className="subtitle">Saved assessments, observations, workflow history, and control mappings with explicit data coverage.</p></div>
      <label className="posture-range">Time range
        <select aria-label="Scorecard time range" value={rangeDays} onChange={(event) => setRangeDays(Number(event.target.value))}>
          {ranges.map((days) => <option key={days} value={days}>{days} days</option>)}
        </select>
      </label>
    </div>
    {canExport && <div className="button-row posture-export">
      <button className="small-button" disabled={exporting || loading || !scorecard} onClick={() => void exportReport('pdf')}>{exporting ? 'Preparing export…' : 'Export PDF'}</button>
      <button className="small-button" disabled={exporting || loading || !scorecard} onClick={() => void exportReport('json')}>Export JSON</button>
      {exportError && <span className="error-text" role="alert">{exportError}</span>}
    </div>}
    {loading && <p role="status" className="note-box">Loading saved scorecard data…</p>}
    {error && <div className="alert error" role="alert"><span>{error}</span><button className="small-button" onClick={() => setReloadKey((value) => value + 1)}>Retry</button></div>}
    {!loading && !error && scorecard && <>
      <p className="posture-window">Data window: <time dateTime={scorecard.window_start}>{new Date(scorecard.window_start).toLocaleString()}</time> through <time dateTime={scorecard.window_end}>{new Date(scorecard.window_end).toLocaleString()}</time>. Source: {scorecard.data_scope.source}. Assets in scope: {scorecard.data_scope.asset_count}. Data modes: {scorecard.data_scope.data_modes.join(', ') || 'none recorded'}.</p>
      <div className="posture-summary-grid">
        <MetricCard title="Overall risk" value={scorecard.overall_risk.average_score == null ? metricStateLabel(scorecard.overall_risk.state) : `${scorecard.overall_risk.average_score} / 100`} metric={scorecard.overall_risk} detail={`${scorecard.overall_risk.band ?? 'No score'} · ${scorecard.overall_risk.assets_with_score} of ${scorecard.overall_risk.assets_in_scope} assets scored`} />
        <MetricCard title="Assessment coverage" value={scorecard.assessment_coverage.coverage_percent == null ? metricStateLabel(scorecard.assessment_coverage.state) : `${scorecard.assessment_coverage.coverage_percent}%`} metric={scorecard.assessment_coverage} detail={`${scorecard.assessment_coverage.assessed_category_slots} of ${scorecard.assessment_coverage.expected_category_slots} applicable category slots assessed`} />
        <MetricCard title="Latest high/critical observations" value={scorecard.high_critical_findings.total == null ? metricStateLabel(scorecard.high_critical_findings.state) : String(scorecard.high_critical_findings.total)} metric={scorecard.high_critical_findings} detail={`High ${scorecard.high_critical_findings.high ?? 'Unavailable'} · Critical ${scorecard.high_critical_findings.critical ?? 'Unavailable'} · latest observed`} />
        <MetricCard title="Repeated findings" value={scorecard.repeated_findings.repeated_finding_count == null ? metricStateLabel(scorecard.repeated_findings.state) : String(scorecard.repeated_findings.repeated_finding_count)} metric={scorecard.repeated_findings} detail={`${scorecard.repeated_findings.repeated_observation_count ?? 'Unavailable'} repeated observations across saved investigations`} />
      </div>
      <p className="note-box">Risk is an academic prioritization aid, not a probability of compromise. Finding records have no open/closed lifecycle, so the high/critical metric describes latest observations and does not assert that findings are unresolved.</p>

      <div className="posture-grid-two">
        <section className="panel posture-inner-panel" aria-labelledby="posture-risk-trend-heading">
          <div className="panel-heading"><div><p className="eyebrow">ASSESSMENTS</p><h3 id="posture-risk-trend-heading">Risk trend</h3></div><StatusBadge value={metricStateLabel(scorecard.risk_trend.state)} /></div>
          {scorecard.risk_trend.points.length ? <>
            <p className="chart-summary">Average saved assessment score, 0–100. Different or mixed policy versions are shown as separate series or isolated points; they are not connected.</p>
            <p className="chart-exact-summary">Latest values: {scorecard.risk_trend.points.slice(-5).map((point) => new Date(point.period_start).toLocaleDateString() + ' ' + point.average_score + '/100 · ' + (point.policy_versions?.join(', ') || 'policy unknown')).join(' ; ')}. The table below contains every period.</p>
            <div className="chart-wrap posture-chart" role="img" aria-label={`Risk trend across ${scorecard.risk_trend.points.length} saved periods. Policy changes are shown without connecting incompatible versions.`}><Suspense fallback={<div className="chart-skeleton" role="status">Loading saved risk chart…</div>}><PostureRiskChart points={scorecard.risk_trend.points} /></Suspense></div>
            <details className="posture-data-alternative"><summary>View risk trend data as a table</summary><div className="table-wrap"><table><caption>Saved average risk by {scorecard.risk_trend.interval}. Empty periods are omitted.</caption><thead><tr><th>Period starts</th><th>Average score / 100</th><th>Assets</th><th>Risk policy versions</th></tr></thead><tbody>{scorecard.risk_trend.points.map((point) => <tr key={point.period_start}><td>{point.period_start}</td><td>{point.average_score}</td><td>{point.asset_count}</td><td>{point.policy_versions?.length ? point.policy_versions.join(', ') : 'Unknown'}</td></tr>)}</tbody></table></div></details>
          </> : <Empty title="No risk trend points" text={`No numeric assessment revisions are available in this ${rangeDays}-day window.`} />}
          <ScopeNote metric={scorecard.risk_trend} />
        </section>
        <section className="panel posture-inner-panel" aria-labelledby="posture-workflow-heading">
          <div className="panel-heading"><div><p className="eyebrow">ACTIVITY</p><h3 id="posture-workflow-heading">Investigations and monitoring</h3></div><StatusBadge value={metricStateLabel(scorecard.workflow_trend.state)} /></div>
          {scorecard.workflow_trend.points.length ? <>
            <p className="chart-summary">Saved run counts by {scorecard.workflow_trend.interval}; unavailable values remain gaps. The adjacent table provides exact counts.</p>
            <p className="chart-exact-summary">Latest counts: {scorecard.workflow_trend.points.slice(-5).map((point) => new Date(point.period_start).toLocaleDateString() + ' investigations ' + (point.investigations.total ?? 'unavailable') + ', monitoring ' + (point.monitoring_runs.total ?? 'unavailable')).join(' ; ')}. The table below contains every period.</p>
            <div className="chart-wrap posture-chart" role="img" aria-label={`Investigation and scheduled monitoring counts over ${scorecard.workflow_trend.points.length} saved periods.`}><Suspense fallback={<div className="chart-skeleton" role="status">Loading saved workflow chart…</div>}><PostureWorkflowChart points={scorecard.workflow_trend.points.map((point) => ({ period_start: point.period_start, investigations: point.investigations.total, monitoring: point.monitoring_runs.total }))} /></Suspense></div>
            <details className="posture-data-alternative"><summary>View workflow trend data as a table</summary><div className="table-wrap"><table><caption>Saved investigation and scheduled monitoring counts by {scorecard.workflow_trend.interval}.</caption><thead><tr><th>Period starts</th><th>Investigations</th><th>Monitoring runs</th></tr></thead><tbody>{scorecard.workflow_trend.points.map((point) => <tr key={point.period_start}><td>{point.period_start}</td><td>{point.investigations.total ?? 'Unavailable'}</td><td>{point.monitoring_runs.total ?? 'Unavailable'}</td></tr>)}</tbody></table></div></details>
          </> : <Empty title="No workflow activity" text={`No investigations or monitoring runs are recorded in this ${rangeDays}-day window.`} />}
          <ScopeNote metric={scorecard.workflow_trend} />
        </section>
      </div>

      <div className="posture-grid-two">
        <section className="panel posture-inner-panel"><div className="panel-heading"><div><p className="eyebrow">ASSESSMENT GAPS</p><h3>Unassessed categories</h3></div><StatusBadge value={metricStateLabel(scorecard.unassessed_categories.state)} /></div>
          {Object.keys(scorecard.unassessed_categories.counts).length ? <ul className="posture-count-list">{Object.entries(scorecard.unassessed_categories.counts).map(([category, count]) => <li key={category}><span>{category.replaceAll('_', ' ')}</span><strong>{count} assets</strong></li>)}</ul> : <p role="status">{scorecard.unassessed_categories.state === 'empty' ? 'No applicable asset categories are in scope.' : 'Category coverage is unavailable.'}</p>}
          <ScopeNote metric={scorecard.unassessed_categories} />
        </section>
        <section className="panel posture-inner-panel"><div className="panel-heading"><div><p className="eyebrow">ASSET CONTEXT</p><h3>Criticality distribution</h3></div><StatusBadge value={metricStateLabel(scorecard.asset_criticality.state)} /></div>
          <ul className="posture-count-list">{Object.entries(scorecard.asset_criticality.counts).map(([criticality, count]) => <li key={criticality}><span>{criticality}</span><strong>{count} assets</strong></li>)}</ul>
          <ScopeNote metric={scorecard.asset_criticality} />
        </section>
      </div>

      <div className="posture-grid-two">
        <section className="panel posture-inner-panel"><div className="panel-heading"><div><p className="eyebrow">INCIDENT OPERATIONS</p><h3>Triage and resolution timing</h3></div><StatusBadge value={metricStateLabel(scorecard.incident_timings.state)} /></div>
          <dl className="posture-timing-list"><div><dt>Incidents in cohort</dt><dd>{scorecard.incident_timings.incident_count}</dd></div><div><dt>Median triage</dt><dd>{seconds(scorecard.incident_timings.triage_median_seconds)}</dd></div><div><dt>Median resolution</dt><dd>{seconds(scorecard.incident_timings.resolution_median_seconds)}</dd></div><div><dt>Unresolved or unrecorded</dt><dd>{scorecard.incident_timings.unresolved_or_unrecorded_count}</dd></div></dl>
          <ScopeNote metric={scorecard.incident_timings} />
        </section>
        <section className="panel posture-inner-panel"><div className="panel-heading"><div><p className="eyebrow">CONTROL MAPPING</p><h3>Security-control coverage</h3></div><StatusBadge value={metricStateLabel(scorecard.security_control_coverage.state)} /></div>
          <p className="posture-large-value">{scorecard.security_control_coverage.validated_finding_percent == null ? metricStateLabel(scorecard.security_control_coverage.state) : `${scorecard.security_control_coverage.validated_finding_percent}%`}</p>
          <p>{scorecard.security_control_coverage.findings_with_validated_mapping ?? 'Unavailable'} of {scorecard.security_control_coverage.findings_in_scope} current findings have a validated control mapping.</p>
          <p className="tiny-note">Catalog {scorecard.security_control_coverage.catalog_version} · {scorecard.security_control_coverage.controls_with_validated_findings ?? 'Unavailable'} of {scorecard.security_control_coverage.catalog_control_count} controls represented by validated mappings.</p>
          <ScopeNote metric={scorecard.security_control_coverage} />
        </section>
      </div>

      <section className="panel posture-inner-panel"><div className="panel-heading"><div><p className="eyebrow">PROVIDER OBSERVATIONS</p><h3>Provider health and data freshness</h3></div><StatusBadge value={metricStateLabel(scorecard.provider_health.state)} /></div>
        <div className="table-wrap"><table><thead><tr><th>Provider</th><th>Saved status</th><th>Freshness</th><th>Last observation</th><th>Scope</th></tr></thead><tbody>{scorecard.provider_health.providers.map((provider) => <tr key={provider.id}><td><strong>{provider.name}</strong><small>{provider.data_mode === 'demo' ? 'Synthetic Demo observation' : provider.source ?? 'No saved source'}</small></td><td><StatusBadge value={provider.provider_status == null ? metricStateLabel(provider.state) : Array.isArray(provider.provider_status) ? provider.provider_status.join(', ') : provider.provider_status} /></td><td><StatusBadge value={provider.freshness.replaceAll('_', ' ')} /></td><td>{provider.last_observed_at ? new Date(provider.last_observed_at).toLocaleString() : 'Unavailable'}</td><td>{provider.eligible_asset_count} eligible assets · {provider.configured ? 'configured' : 'not configured'}</td></tr>)}</tbody></table></div>
        <ScopeNote metric={scorecard.provider_health} />
      </section>
    </>}
  </section>
}
