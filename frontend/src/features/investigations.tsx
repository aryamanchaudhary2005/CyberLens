import { useEffect, useRef, useState } from 'react'
import { request, type Asset, type EvidenceGraph, type EvidenceGraphChange, type Finding, type Investigation, type RiskSimulation, type RiskSimulationOption, type RiskSensitivity } from '../api'
import { EvidenceGraphExplorer } from '../components/EvidenceGraphExplorer'
import { Empty, PageTitle, StatusBadge } from '../components/ui'
import { date, defaultScenario, message, scenariosForKind } from './helpers'
import type { InvestigationDetail } from './types'

export function InvestigationsScreen(props: { items: Investigation[]; selected: InvestigationDetail | null; assets: Asset[]; canRun: boolean; isDemo: boolean; busy: boolean; xposedornotEnabled: boolean; onSelect: (id: string) => void; onRun: (assetId: string, scenario?: string, provider?: 'hibp' | 'xposedornot', authorized?: boolean) => unknown; onRetry: (id: string) => unknown; onApplicability: (id: string, applicability: string, reason: string) => unknown; onCreateIncident: (finding: Finding) => unknown; onReport: (format: 'pdf' | 'json') => unknown; onCompare: (id: string) => Promise<Record<string, unknown> | undefined> }) {
  const [assetId, setAssetId] = useState(''); const [scenario, setScenario] = useState('routine_website'); const [emailBreachProvider, setEmailBreachProvider] = useState<'hibp' | 'xposedornot'>('hibp'); const [xposedAuthorizationConfirmed, setXposedAuthorizationConfirmed] = useState(false); const [compareId, setCompareId] = useState(''); const [decisionReason, setDecisionReason] = useState<Record<string, string>>({}); const [comparison, setComparison] = useState<Record<string, unknown> | null>(null); const [sensitivity, setSensitivity] = useState<RiskSensitivity | null>(null); const [sensitivityLoading, setSensitivityLoading] = useState(false); const [simulationOptions, setSimulationOptions] = useState<RiskSimulationOption[] | null>(null); const [simulation, setSimulation] = useState<RiskSimulation | null>(null); const [simulationBusy, setSimulationBusy] = useState(false); const [simulationError, setSimulationError] = useState('')
  const simulationRequestId = useRef(0)
  const selectedAsset = props.assets.find((item) => item.id === assetId)
  const selectedBreachProvider = props.selected?.email_breach_provider === 'xposedornot'
    ? 'XposedOrNot community dataset'
    : props.selected?.email_breach_provider === 'hibp' ? 'Have I Been Pwned' : null
  const comparable = props.items.filter((item) => item.asset_id === props.selected?.asset_id && item.id !== props.selected.id)
  const simulationStateKey = props.selected ? `${props.selected.id}:${props.selected.status}:${props.selected.findings.map((item) => `${item.id}:${item.applicability}:${item.evidence_id ?? ''}`).join('|')}` : ''
  useEffect(() => {
    simulationRequestId.current += 1
    setSimulationBusy(false)
    let active = true
    setSimulationOptions(null); setSimulation(null); setSimulationError('')
    if (!props.selected || !['completed', 'partial', 'failed'].includes(props.selected.status)) {
      setSimulationOptions([])
      return () => { active = false }
    }
    request<RiskSimulationOption[]>(`/investigations/${props.selected.id}/risk/simulation-options`).then((result) => {
      if (active) setSimulationOptions(result)
    }).catch((reason: unknown) => {
      if (active) { setSimulationOptions([]); setSimulationError(message(reason)) }
    })
    return () => { active = false }
  }, [props.selected?.id, props.selected?.status, simulationStateKey])
  async function runSimulation(option: RiskSimulationOption) {
    if (!props.selected) return
    const requestId = ++simulationRequestId.current
    setSimulationBusy(true); setSimulationError(''); setSimulation(null)
    try {
      const result = await request<RiskSimulation>(`/investigations/${props.selected.id}/risk/simulate`, {
        method: 'POST', body: JSON.stringify({ action: option.action, finding_id: option.finding_id }),
      })
      if (requestId === simulationRequestId.current) setSimulation(result)
    } catch (reason) { if (requestId === simulationRequestId.current) setSimulationError(message(reason)) }
    finally { if (requestId === simulationRequestId.current) setSimulationBusy(false) }
  }
  return <>
    <PageTitle eyebrow="ANALYSIS PIPELINE" title="Investigations" subtitle="Monitor background collectors, review captured evidence, and record applicability decisions." />
    {!props.canRun && <div className="note-box" role="status">Read-only access: investigation runs, retries, applicability decisions, and incident creation require Analyst or Admin permission.</div>}
    {props.canRun && <section className="panel compact-panel"><div className="panel-heading"><div><p className="eyebrow">NEW ANALYSIS</p><h2>Start an investigation</h2></div></div><div className="form-grid"><label>Asset<select value={assetId} onChange={(e) => { const next = e.target.value; setAssetId(next); setXposedAuthorizationConfirmed(false); const found = props.assets.find((item) => item.id === next); if (found) setScenario(defaultScenario(found.kind)); setEmailBreachProvider('hibp') }}><option value="">Choose an asset</option>{props.assets.map((asset) => <option key={asset.id} value={asset.id}>{asset.identifier} · {asset.kind}</option>)}</select></label>{props.isDemo && <label>Scenario<select value={scenario} onChange={(e) => setScenario(e.target.value)}>{scenariosForKind(selectedAsset?.kind ?? 'domain').map(([id, title]) => <option key={id} value={id}>{title}</option>)}</select></label>}{selectedAsset?.kind === 'email' && <label>Email breach provider<select value={emailBreachProvider} onChange={(e) => { setEmailBreachProvider(e.target.value as 'hibp' | 'xposedornot'); setXposedAuthorizationConfirmed(false) }}><option value="hibp">Have I Been Pwned (existing provider)</option><option value="xposedornot" disabled={!props.isDemo && !props.xposedornotEnabled}>XposedOrNot community dataset</option></select></label>}{selectedAsset?.kind === 'email' && emailBreachProvider === 'xposedornot' && <div className="note-box xon-consent" role="note">{props.isDemo ? 'Demo uses a synthetic offline XposedOrNot fixture. No address is sent externally.' : <><strong>Privacy and use notice</strong><p>The selected email address, {selectedAsset.identifier}, will be sent to XposedOrNot over HTTPS for a breach lookup. XposedOrNot's community endpoint is for personal, low-volume use; it has its own dataset and does not have identical coverage to HIBP. No provider switch or fallback occurs.</p><label className="consent-check"><input type="checkbox" checked={xposedAuthorizationConfirmed} onChange={(event) => setXposedAuthorizationConfirmed(event.target.checked)} />I am authorized to submit this address to XposedOrNot for this lookup.</label></>}</div>}<button className="primary-button align-end" disabled={!assetId || props.busy || (props.isDemo && !scenariosForKind(selectedAsset?.kind ?? '').some(([id]) => id === scenario)) || (!props.isDemo && emailBreachProvider === 'xposedornot' && !xposedAuthorizationConfirmed)} onClick={() => props.onRun(assetId, props.isDemo ? scenario : undefined, selectedAsset?.kind === 'email' ? emailBreachProvider : undefined, xposedAuthorizationConfirmed)}>Queue analysis</button></div></section>}
    <div className="two-column history-layout"><section className="panel"><div className="panel-heading"><div><p className="eyebrow">HISTORY</p><h2>Saved investigations</h2></div><span className="count-pill">{props.items.length}</span></div>
      {props.items.length ? <div className="asset-list">{props.items.map((item) => <button key={item.id} className={`asset-row ${props.selected?.id === item.id ? 'selected' : ''}`} onClick={() => { props.onSelect(item.id); setComparison(null) }}><span className="asset-type">{item.asset_kind?.slice(0, 3).toUpperCase() ?? 'JOB'}</span><span className="asset-main"><strong>{item.asset_identifier ?? item.id}</strong><small>{date(item.created_at)} · {item.mode}{item.scenario ? ` · ${item.scenario.replaceAll('_', ' ')}` : ''}</small></span><StatusBadge value={item.status} /></button>)}</div> : <Empty title="No investigation history" text="Start one from Assets or use the form above." />}
    </section><section className="panel result-panel">
      {!props.selected ? <Empty title="Choose an investigation" text="Saved results, collection status, risk coverage, and evidence appear here." /> : <>
        <div className="panel-heading"><div><p className="eyebrow">{props.selected.demo_data ? 'DEMO DATA · ' : ''}{props.selected.asset.kind.toUpperCase()} · RESULT</p><h2>{props.selected.asset.identifier}</h2><p className="tiny-note">{date(props.selected.created_at)} · {props.selected.scenario?.replaceAll('_', ' ') ?? 'live collection'}{selectedBreachProvider ? ` · ${selectedBreachProvider}` : ''}</p></div><span className="button-row"><StatusBadge value={props.selected.status} />{['partial', 'failed'].includes(props.selected.status) && props.canRun && <button className="small-button" onClick={() => props.onRetry(props.selected!.id)}>Retry</button>}</span></div>
        {['queued', 'running'].includes(props.selected.status) ? <div className="progress-wrap"><div className="progress-label"><span>Collectors running</span><span>{props.selected.progress}%</span></div><div className="progress-track"><span style={{ width: `${props.selected.progress}%` }} /></div></div> : props.selected.error_summary && <div className="note-box">{props.selected.error_summary}</div>}
        <div className="section-heading"><h3>Attempt history</h3><span>{props.selected.attempts.length} attempts</span></div><div className="collector-list">{props.selected.attempts.map((attempt) => <div className="collector-row" key={attempt.id}><span><strong>Attempt {attempt.attempt_number} · {attempt.retry_kind}</strong><small>{attempt.error_summary ?? `Started ${date(attempt.started_at ?? attempt.created_at)}`}</small></span><StatusBadge value={attempt.status} /></div>)}</div>
        <div className="risk-card"><div><p className="eyebrow">EXPLAINABLE RISK · {props.selected.risk?.explanation.rule_version ?? props.selected.risk?.version ?? 'pending'}</p><strong>{props.selected.risk?.score == null ? 'Insufficient data' : `${props.selected.risk.score} / 100`}</strong><span className={`risk-band ${props.selected.risk?.band ?? ''}`}>{props.selected.risk?.band?.replaceAll('_', ' ') ?? 'pending'}</span></div><p>{props.selected.risk?.explanation.metric_notice ?? 'Risk is calculated after collectors finish.'}</p><small>{props.selected.risk?.explanation.calibration_notice ?? 'No calibration claim is made without labeled outcome evidence.'}</small></div>
        {props.selected.risk && <div className="coverage-row"><div><strong>Assessed</strong><span>{props.selected.risk.assessed_categories.join(', ') || 'None'}</span></div><div><strong>Not assessed</strong><span>{props.selected.risk.excluded_categories.join(', ') || 'None'}</span></div></div>}
        {props.selected.risk && <section className="risk-detail" aria-label="Risk score details"><div className="section-heading"><h3>Score contributors</h3><span>{props.selected.risk.explanation.contributors?.length ?? 0}</span></div>{props.selected.risk.explanation.contributors?.length ? <ul className="plain-list">{props.selected.risk.explanation.contributors.map((item) => <li key={item.finding_id}><strong>{item.category}</strong> · {item.severity} · {item.category_score} points · {item.weight_percent}% weight{item.kev_floor ? ' · CISA KEV floor 90' : ''}{item.cvss_unavailable ? ' · CVSS unavailable' : ''}<small>{item.source || 'source unavailable'} · {item.observed_at ? date(item.observed_at) : 'observation time unavailable'}</small></li>)}</ul> : <p className="empty-line">No applicable finding contributes to the current score.</p>}<div className="coverage-row"><div><strong>Source coverage</strong><span>{Object.entries(props.selected.risk.explanation.source_coverage ?? {}).map(([source, item]) => `${source}: ${item.status}`).join(' · ') || 'No source provenance recorded'}</span></div><div><strong>Freshness</strong><span>{Object.values(props.selected.risk.explanation.freshness ?? {}).map((item) => item.state).filter(Boolean).join(', ') || 'Unknown'}</span></div></div>{props.selected.risk.explanation.epss_notice && <p className="tiny-note">{props.selected.risk.explanation.epss_notice}</p>}</section>}
        {props.selected.risk && <section className="sensitivity-box"><div className="section-heading"><h3>Weight sensitivity</h3><button className="small-button" disabled={sensitivityLoading} onClick={async () => { setSensitivityLoading(true); try { setSensitivity(await request<RiskSensitivity>(`/investigations/${props.selected!.id}/risk/sensitivity`)) } finally { setSensitivityLoading(false) } }}>{sensitivityLoading ? 'Calculating…' : 'Analyze weights'}</button></div>{sensitivity && <ul className="plain-list">{sensitivity.variants.map((item) => <li key={item.category}><strong>{item.category}</strong>: {item.lower_score ?? '—'} ({item.lower_delta == null ? '—' : `${item.lower_delta >= 0 ? '+' : ''}${item.lower_delta}`}) to {item.upper_score ?? '—'} ({item.upper_delta == null ? '—' : `${item.upper_delta >= 0 ? '+' : ''}${item.upper_delta}`})</li>)}</ul>}</section>}
        <section className="simulation-box" aria-labelledby="simulation-heading"><div className="section-heading"><div><h3 id="simulation-heading">What-if remediation</h3><span>Side-effect-free risk projection · {props.selected.risk?.version ?? 'policy unavailable'}</span></div></div><p>Explore the score if one evidence-backed finding were remediated. This does not change saved findings, evidence, reports, investigations, or risk assessments.</p>
          {simulationError && <p className="error-text" role="alert">{simulationError}</p>}
          {simulationOptions === null ? <p className="empty-line" role="status">Loading evidence-backed actions…</p> : simulationOptions.length === 0 ? <p className="empty-line">No supported remediation simulations are available for this investigation. Actions require an applicable finding and matching saved evidence.</p> : <ul className="simulation-actions">{simulationOptions.map((option) => <li key={`${option.action}-${option.finding_id}`}><span><strong>{option.label}</strong><small>{option.finding_title} · {option.category} · {option.evidence_source} · Evidence {option.evidence_id}</small></span><button className="small-button" aria-label={`Simulate ${option.label} for ${option.finding_title}`} disabled={simulationBusy} onClick={() => void runSimulation(option)}>{simulationBusy ? 'Projecting…' : 'Simulate'}</button></li>)}</ul>}
          {simulation && <div className="simulation-result" aria-live="polite"><h4>{simulation.action_label}: {simulation.affected.title}</h4><p><strong>Baseline:</strong> {simulation.baseline.score == null ? 'Insufficient data' : `${simulation.baseline.score} / 100 · ${simulation.baseline.band}`} <span aria-hidden="true">→</span> <strong>Projected:</strong> {simulation.projected.score == null ? 'Insufficient data' : `${simulation.projected.score} / 100 · ${simulation.projected.band}`}</p><p>Risk policy {simulation.risk_policy_version}. Only the selected finding is excluded in this scenario.</p><div className="simulation-evidence"><strong>Affected evidence</strong><span>{simulation.affected.evidence_source} · {date(simulation.affected.evidence_observed_at)} · SHA-256 {simulation.affected.evidence_sha256}{simulation.affected.evidence_synthetic ? ' · Demo evidence' : ''}</span></div><h4>Category scores</h4><ul className="simulation-changes">{simulation.category_changes.map((change) => <li key={change.category}><span>{change.category.replaceAll('_', ' ')}</span><strong>{change.baseline_score ?? 'Unknown'} <span aria-hidden="true">→</span> {change.projected_score ?? 'Unknown'} · Δ {change.change == null ? 'unknown' : `${change.change > 0 ? '+' : ''}${change.change}`}</strong></li>)}</ul><h4>Assumptions</h4><ul className="plain-list">{simulation.assumptions.map((assumption) => <li key={assumption}>{assumption}</li>)}</ul></div>}
        </section>
        <div className="section-heading"><h3>Collector status</h3><span>{props.selected.collector_runs.length} checks</span></div><div className="collector-list">{props.selected.collector_runs.map((run, index) => <div className="collector-row" key={`${String(run.attempt_id)}-${String(run.collector)}-${index}`}><span><strong>{String(run.source)}</strong><small>Attempt {String(run.attempt_number ?? '—')} · {String(run.collector)}</small>{Boolean(run.error_explanation) && <small>{String(run.error_explanation)}</small>}</span><StatusBadge value={String(run.status)} /></div>)}</div>
        <div className="section-heading"><h3>Findings</h3><span>{props.selected.findings.length} captured</span>{props.canRun && <div className="button-row"><button className="small-button" onClick={() => props.onReport('pdf')}>PDF report</button><button className="small-button" onClick={() => props.onReport('json')}>JSON</button></div>}</div>
        {providerEvidence(props.selected, 'xposedornot', 'xposedornot').map((evidence) => <XposedOrNotEvidence key={String(evidence.id)} evidence={evidence} />)}
        {providerEvidence(props.selected, 'openphish', 'openphish').map((evidence) => <OpenPhishEvidence key={String(evidence.id)} evidence={evidence} />)}
        {providerEvidence(props.selected, 'spamhaus_drop', 'spamhaus_drop').map((evidence) => <SpamhausDropEvidence key={String(evidence.id)} evidence={evidence} />)}
        {providerEvidence(props.selected, 'cins_army', 'cins_army').map((evidence) => <CinsArmyEvidence key={String(evidence.id)} evidence={evidence} />)}
        {props.selected.ip_intelligence && <IpIntelligenceSummary value={props.selected.ip_intelligence} />}
        {props.selected.findings.length ? props.selected.findings.map((finding) => <FindingCard key={finding.id} finding={finding} reason={decisionReason[finding.id] ?? ''} onReason={(value) => setDecisionReason((current) => ({ ...current, [finding.id]: value }))} onDecision={(value) => props.onApplicability(finding.id, value, decisionReason[finding.id] || 'Reviewed against the recorded inventory and source evidence.')} onCase={() => props.onCreateIncident(finding)} canReview={props.canRun} />) : <p className="empty-line">No findings were recorded. Missing coverage is shown above and should not be read as a safe result.</p>}
        {props.selected.evidence.length > 0 && <details className="evidence-details"><summary>Captured evidence and SHA-256 checksums ({props.selected.evidence.length})</summary>{props.selected.evidence.map((item) => <div key={String(item.id)} className="evidence-card"><div className="progress-label"><strong>{String(item.source)}</strong><code>{String(item.sha256)}</code></div><pre>{JSON.stringify(item.evidence_json, null, 2)}</pre></div>)}</details>}
        <EvidenceGraphPanel selected={props.selected} investigations={props.items} />
        {comparable.length > 0 && <div className="compare-box"><div className="section-heading"><h3>Compare history</h3></div><select value={compareId} onChange={(e) => setCompareId(e.target.value)}><option value="">Choose earlier run</option>{comparable.map((item) => <option key={item.id} value={item.id}>{date(item.created_at)} · {item.status}</option>)}</select><button className="small-button" disabled={!compareId} onClick={async () => { setComparison(null); const result = await props.onCompare(compareId); if (result) setComparison(result) }}>Compare</button>{comparison && <pre>{JSON.stringify(comparison, null, 2)}</pre>}</div>}
      </>}
    </section></div>
  </>
}

/** Join provider evidence to its saved collector identity, including synthetic Demo source labels. */
function providerEvidence(investigation: InvestigationDetail, collector: string, sourceId: string) {
  const runs = investigation.collector_runs.filter((run) => run.collector === collector)
  const runSources = new Set(runs.map((run) => String(run.source ?? '')).filter(Boolean))
  return investigation.evidence.filter((item) => {
    const payload = item.evidence_json && typeof item.evidence_json === 'object'
      ? item.evidence_json as Record<string, unknown> : {}
    const provenance = payload.provenance && typeof payload.provenance === 'object'
      ? payload.provenance as Record<string, unknown> : {}
    const savedSourceId = payload.source_id ?? provenance.source_id
    if (savedSourceId === sourceId) return true
    return runSources.has(String(item.source ?? ''))
  }).slice(0, 1)
}

function XposedOrNotEvidence({ evidence }: { evidence: Record<string, unknown> }) {
  const payload = evidence.evidence_json && typeof evidence.evidence_json === 'object'
    ? evidence.evidence_json as Record<string, unknown> : {}
  const records = Array.isArray(payload.records) ? payload.records as Array<Record<string, unknown>> : []
  const status = String(payload.result ?? payload.provider_status ?? 'unknown')
  return <section className="xon-evidence" aria-labelledby="xon-evidence-heading">
    <div className="section-heading"><h3 id="xon-evidence-heading">XposedOrNot community result</h3><span>{status.replaceAll('_', ' ')}</span></div>
    <p>{String(payload.coverage_note ?? 'XposedOrNot has a separate community dataset and does not have identical coverage to HIBP.')}</p>
    {status === 'no_match' && <p role="status">{String(payload.no_match_message ?? "No record found in this provider's dataset.")}</p>}
    {records.length > 0 && <ul className="plain-list">{records.map((record, index) => <li key={`${String(record.record_id ?? record.name ?? 'record')}-${index}`}><strong>{String(record.name ?? 'Unnamed provider record')}</strong>{record.record_id ? ` · ${String(record.record_id)}` : ''}<small>Date: {String(record.breach_date ?? 'not supplied')} · Verification: {record.verified === true ? 'verified by provider' : record.verified === false ? 'provider marked unverified' : 'not supplied'} · Exposed data: {Array.isArray(record.exposed_data) && record.exposed_data.length ? record.exposed_data.join(', ') : 'not supplied'}</small></li>)}</ul>}
    <small>Observed {String(payload.observed_at ?? evidence.observed_at ?? 'time unavailable')} · Evidence ID {String(evidence.id ?? 'unavailable')}. Provider records describe historical exposure and do not establish current compromise.</small>
  </section>
}

function OpenPhishEvidence({ evidence }: { evidence: Record<string, unknown> }) {
  const payload = evidence.evidence_json && typeof evidence.evidence_json === 'object'
    ? evidence.evidence_json as Record<string, unknown> : {}
  const provenance = payload.provenance && typeof payload.provenance === 'object'
    ? payload.provenance as Record<string, unknown> : {}
  const result = String(payload.result ?? payload.provider_status ?? 'unknown')
  const matchScope = String(payload.match_scope ?? 'unknown')
  const freshness = String(payload.freshness ?? 'unknown')
  const resultLabel = result === 'listed' ? 'URL listed in OpenPhish snapshot'
    : result === 'contextual_hostname_match' ? 'Hostname context only'
      : result === 'not_listed_in_snapshot' ? 'No exact URL match in this snapshot'
        : 'Listing status unknown'
  const reviewNotice = result === 'listed'
    ? 'A feed listing does not prove that the page is reachable, that a user encountered it, or that the asset is compromised. Review the evidence; only an analyst decision of applies affects risk.'
    : result === 'contextual_hostname_match'
      ? 'The hostname association is contextual only. It is not a verdict against this URL and does not affect risk.'
      : result === 'not_listed_in_snapshot'
        ? 'No exact URL match in this snapshot. This does not establish that the URL is safe.'
        : 'Coverage is unknown. Missing, stale, or invalid snapshot data is not a clean result.'
  return <section className="vulnerability-intelligence openphish-evidence" aria-labelledby="openphish-evidence-heading">
    <h3 id="openphish-evidence-heading">OpenPhish URL evidence</h3>
    <dl className="feed-metadata-grid">
      <div><dt>Snapshot result</dt><dd>{resultLabel}</dd></div>
      <div><dt>Match type</dt><dd>{matchScope === 'exact_url' ? 'Exact URL match' : matchScope === 'contextual_hostname' ? 'Hostname context only' : 'Not established'}</dd></div>
      <div><dt>Snapshot freshness</dt><dd>{freshness}{payload.snapshot_age_seconds != null ? ` · ${Math.floor(Number(payload.snapshot_age_seconds) / 3600)} h old` : ''}</dd></div>
      <div><dt>Snapshot and evidence</dt><dd>{String(payload.snapshot_id ?? 'Snapshot unavailable')} · evidence {String(evidence.id ?? 'unavailable')}</dd></div>
      <div><dt>Snapshot SHA-256</dt><dd>{String(payload.content_sha256 ?? 'Unavailable')}</dd></div>
      <div><dt>Snapshot retrieved</dt><dd>{payload.snapshot_retrieved_at ? date(String(payload.snapshot_retrieved_at)) : 'Unavailable'}</dd></div>
      <div><dt>Provider observation</dt><dd>{payload.observed_at ? date(String(payload.observed_at)) : evidence.observed_at ? date(String(evidence.observed_at)) : 'Unavailable'}</dd></div>
      <div><dt>Evidence source and version</dt><dd>{String(provenance.source ?? payload.provider ?? 'OpenPhish Community Feed')} · {String(provenance.provider_version ?? payload.provider_version ?? 'version unavailable')}</dd></div>
    </dl>
    {typeof payload.url_retention_limitation === 'string' && <p role="note">{payload.url_retention_limitation}</p>}
    <p>{String(payload.coverage_note ?? 'The community feed contains URL strings only; it does not supply per-URL confidence, brand, discovery date, or observation time.')}</p>
    <p role="note">{reviewNotice}</p>
    <small>{String(payload.attribution ?? 'OpenPhish Community Feed')} · indicators remain in the protected local snapshot and are not copied into this result view.</small>
  </section>
}

function SpamhausDropEvidence({ evidence }: { evidence: Record<string, unknown> }) {
  const payload = evidence.evidence_json && typeof evidence.evidence_json === 'object'
    ? evidence.evidence_json as Record<string, unknown> : {}
  const matches = Array.isArray(payload.matched_networks) ? payload.matched_networks as Array<Record<string, unknown>> : []
  const listed = payload.result === 'listed' || payload.result === 'stale_match'
  const status = String(payload.freshness ?? payload.provider_status ?? 'unknown')
  return <section className="xon-evidence spamhaus-evidence" aria-labelledby="spamhaus-evidence-heading">
    <h3 id="spamhaus-evidence-heading">Spamhaus DROP snapshot evidence</h3>
    <dl className="feed-metadata-grid">
      <div><dt>Snapshot result</dt><dd>{listed ? 'Listed in this snapshot' : payload.result === 'not_listed_in_snapshot' ? 'Not listed in this snapshot' : payload.result === 'stale_no_match' ? 'Not listed in this stale snapshot' : String(payload.result ?? 'No result')}</dd></div>
      <div><dt>Freshness</dt><dd>{status}{payload.snapshot_age_seconds != null ? ` · ${Math.floor(Number(payload.snapshot_age_seconds) / 3600)} h old` : ''}</dd></div>
      <div><dt>Provider publication date</dt><dd>{payload.provider_published_at ? date(String(payload.provider_published_at)) : 'Unavailable'}</dd></div>
      <div><dt>Snapshot ID</dt><dd>{String(payload.snapshot_id ?? 'Unavailable')} · evidence {String(evidence.id ?? 'unavailable')}</dd></div>
      <div><dt>Matched network and SBL ID</dt><dd>{matches.length ? matches.map((item) => `${String(item.network)} (${String(item.sbl_id)})`).join(', ') : 'No matching network in this saved snapshot'}</dd></div>
      <div><dt>Snapshot checksum</dt><dd>{String(payload.content_sha256 ?? 'Unavailable')}</dd></div>
    </dl>
    <p>{String(payload.attribution ?? 'Spamhaus Project DROP data')}</p>
    <small>{String(payload.coverage_note ?? 'A no-match result does not establish safety or complete reputation coverage.')}</small>
  </section>
}

function CinsArmyEvidence({ evidence }: { evidence: Record<string, unknown> }) {
  const payload = evidence.evidence_json && typeof evidence.evidence_json === 'object'
    ? evidence.evidence_json as Record<string, unknown> : {}
  const listed = payload.result === 'listed' || payload.result === 'stale_match'
  return <section className="xon-evidence spamhaus-evidence" aria-labelledby="cins-evidence-heading">
    <h3 id="cins-evidence-heading">CINS Army exact-IP evidence</h3>
    <dl className="feed-metadata-grid">
      <div><dt>Snapshot result</dt><dd>{listed ? 'Exact IP listed' : payload.result === 'not_listed_in_snapshot' ? 'Exact IP not listed in this snapshot' : payload.result === 'stale_no_match' ? 'Not listed in a stale snapshot' : String(payload.result ?? 'Unknown')}</dd></div>
      <div><dt>Freshness</dt><dd>{String(payload.freshness ?? 'unknown')}{payload.snapshot_age_seconds != null ? ` · ${Math.floor(Number(payload.snapshot_age_seconds) / 3600)} h old` : ''}</dd></div>
      <div><dt>Matched exact IP</dt><dd>{String(payload.matched_ip ?? 'No exact match')}</dd></div>
      <div><dt>Snapshot ID</dt><dd>{String(payload.snapshot_id ?? 'Unavailable')} · evidence {String(evidence.id ?? 'unavailable')}</dd></div>
      <div><dt>Snapshot checksum</dt><dd>{String(payload.content_sha256 ?? 'Unavailable')}</dd></div>
      <div><dt>Snapshot retrieved</dt><dd>{payload.snapshot_retrieved_at ? date(String(payload.snapshot_retrieved_at)) : 'Unavailable'}</dd></div>
      <div><dt>Last successful revalidation</dt><dd>{payload.last_successful_revalidation_at ? date(String(payload.last_successful_revalidation_at)) : 'Unavailable'}</dd></div>
      <div><dt>Provider publication date</dt><dd>Not supplied by this feed</dd></div>
    </dl>
    <p>{String(payload.attribution ?? 'CINS Army IP list')}</p>
    <small>{String(payload.coverage_note ?? 'This feed provides IP addresses only. It does not include per-indicator scores, attack categories, report counts, or first-seen times.')}</small>
  </section>
}

function IpIntelligenceSummary({ value }: { value: NonNullable<InvestigationDetail['ip_intelligence']> }) {
  const classificationLabel: Record<string, string> = {
    baseline_listed: 'Baseline listing', baseline_not_listed: 'Baseline absence',
    newly_observed_listing: 'Newly observed listing', continuing_listing: 'Continuing listing',
    no_longer_listed: 'No longer listed', continuing_absence: 'Continuing absence', unknown: 'Unknown',
  }
  return <section className="panel ip-intelligence-panel" aria-labelledby="ip-intelligence-heading">
    <div className="panel-heading"><div><p className="eyebrow">SOURCE COMPARISON</p><h3 id="ip-intelligence-heading">IP intelligence history · {value.asset_ip}</h3></div><StatusBadge value={value.corroboration_label === 'Listed by two sources' ? 'corroborated' : value.corroboration_label.toLowerCase().replaceAll(' ', '_')} /></div>
    <p><strong>{value.corroboration_label}</strong></p>
    <p>{value.corroboration_note}</p>
    <div className="ip-source-grid">{value.sources.map((source) => <article key={source.collector} className="integration-card">
      <div className="card-top"><span className="card-label">{source.source}</span><StatusBadge value={source.state} /></div>
      <p>Result: {source.result.replaceAll('_', ' ')} · freshness {source.freshness}</p>
      <small>Observed {source.observed_at ? date(source.observed_at) : 'not observed'} · snapshot {source.snapshot_id ?? 'not available'} · evidence {source.evidence_id ?? 'not available'}</small>
      {source.collector === 'reputation' && <small>VirusTotal remains an independent provider result; it is not counted as a second address-list source.</small>}
    </article>)}</div>
    <h4>Listing changes</h4>
    {value.history.length ? <ol className="ip-listing-history">{value.history.map((event, index) => <li key={`${event.investigation_id}-${event.collector}-${index}`}>
      <StatusBadge value={classificationLabel[event.classification ?? 'unknown'] ?? event.classification ?? 'unknown'} />
      <strong>{event.source}</strong><span>{event.result.replaceAll('_', ' ')} · {event.investigation_created_at ? date(event.investigation_created_at) : 'time unavailable'}</span>
      <small>Snapshot {event.snapshot_id ?? 'unavailable'} · observed {event.observed_at ? date(event.observed_at) : 'time unavailable'} · evidence {event.evidence_id ?? 'unavailable'}</small>
      {event.reason && <small>{event.reason}</small>}
    </li>)}</ol> : <p className="empty-line">No saved IP list observations are available.</p>}
    <small>Failed, stale, or unavailable runs remain unknown and do not create removal events. Absence from a later valid snapshot is not proof of remediation.</small>
  </section>
}

export function EvidenceGraphPanel({ selected, investigations }: { selected: InvestigationDetail | null; investigations: Investigation[] }) {
  const [graph, setGraph] = useState<EvidenceGraph | null>(null)
  const [graphLoading, setGraphLoading] = useState(false)
  const [graphError, setGraphError] = useState('')
  const [graphRefresh, setGraphRefresh] = useState(0)
  const [comparisonId, setComparisonId] = useState('')
  const [changes, setChanges] = useState<EvidenceGraphChange[] | null>(null)
  const [comparisonError, setComparisonError] = useState('')
  const [comparisonVersion, setComparisonVersion] = useState(0)
  const comparisonRequest = useRef<AbortController | null>(null)
  const comparable = investigations.filter((item) => item.asset_id === selected?.asset_id && item.id !== selected?.id &&
    ['completed', 'partial'].includes(item.status) && item.created_at < (selected?.created_at ?? '')).sort((a, b) => b.created_at.localeCompare(a.created_at))

  useEffect(() => {
    setGraph(null)
    setGraphError('')
    setChanges(null)
    setComparisonError('')
  }, [selected?.id])

  useEffect(() => {
    const controller = new AbortController()
    if (!selected) {
      setGraphLoading(false)
      return () => controller.abort()
    }
    setGraphLoading(true)
    setGraphError('')
    request<EvidenceGraph>('/investigations/' + selected.id + '/graph', { signal: controller.signal }).then((result) => {
      if (!controller.signal.aborted) setGraph(result)
    }).catch((reason: unknown) => {
      if (!controller.signal.aborted) setGraphError(message(reason))
    }).finally(() => {
      if (!controller.signal.aborted) setGraphLoading(false)
    })
    return () => controller.abort()
  }, [selected?.id, selected?.status, selected?.finished_at, selected?.evidence.length, graphRefresh])

  useEffect(() => () => { comparisonRequest.current?.abort() }, [selected?.id])
  useEffect(() => {
    setComparisonId(comparable[0]?.id ?? '')
    setChanges(null)
  }, [selected?.id])

  async function compareGraph() {
    if (!selected || !comparisonId) return
    comparisonRequest.current?.abort()
    const controller = new AbortController()
    comparisonRequest.current = controller
    setComparisonError('')
    setChanges(null)
    try {
      const result = await request<{ changes: EvidenceGraphChange[] }>(
        '/investigations/' + selected.id + '/changes/' + comparisonId, { signal: controller.signal })
      if (!controller.signal.aborted) {
        setChanges(result.changes)
        setComparisonVersion((value) => value + 1)
      }
    } catch (reason) {
      if (!controller.signal.aborted) setComparisonError(message(reason))
    }
  }

  const currentGraph = graph?.investigation_id === selected?.id ? graph : null
  const collectorOutage = selected?.collector_runs.some((run) =>
    ['failed', 'unavailable', 'quota_limited', 'timed_out'].includes(String(run.status ?? ''))) ?? false
  const partialEvidence = selected?.status === 'partial' || collectorOutage
  const canAnimateChanges = currentGraph !== null && currentGraph.nodes.length <= 120 && currentGraph.edges.length <= 240

  return <section className="evidence-graph" aria-labelledby="evidence-graph-heading">
    <div className="section-heading">
      <div><h3 id="evidence-graph-heading">Evidence graph</h3><p>Saved relationships link back to their source evidence.</p></div>
      <div className="graph-heading-actions">
        <span>{currentGraph ? currentGraph.nodes.length + ' nodes · ' + currentGraph.edges.length + ' evidence relationships' : graphLoading ? 'Loading projection' : 'Projection unavailable'}</span>
        {selected && <button type="button" className="small-button" onClick={() => setGraphRefresh((value) => value + 1)} disabled={graphLoading}>{graphLoading ? 'Refreshing…' : 'Refresh graph'}</button>}
      </div>
    </div>
    {!selected ? <p className="empty-line">Choose an investigation to inspect its saved evidence relationships.</p> : <>
      {partialEvidence && <p className="graph-filter-state" role="status">Partial evidence coverage: the graph contains relationships supported by saved evidence. Failed or unavailable collectors remain unknown and do not imply a missing relationship.</p>}
      {graphLoading && currentGraph && <p className="graph-filter-state" role="status">Refreshing the projection. Current node positions and selection remain available.</p>}
      {graphError && <div className="graph-load-error" role="alert"><p>{graphError}</p><button type="button" className="small-button" onClick={() => setGraphRefresh((value) => value + 1)}>Retry graph</button></div>}
      {graphLoading && !currentGraph && <p className="empty-line" role="status">Loading saved evidence relationships…</p>}
      {!graphLoading && !currentGraph && !graphError && <Empty title="Graph unavailable" text="No projection is available for this investigation yet." />}
      {currentGraph && <>
        <div className="graph-toolbar" role="group" aria-label="Evidence comparison">
          <label>Compare with<select aria-label="Earlier investigation for change radar" value={comparisonId} onChange={(event) => { setComparisonId(event.target.value); setChanges(null); setComparisonError('') }}>
            <option value="">Choose earlier investigation</option>{comparable.map((item) => <option key={item.id} value={item.id}>{date(item.created_at)} · {item.status}</option>)}
          </select></label>
          <button className="small-button" disabled={!comparisonId} onClick={() => void compareGraph()}>Show changes</button>
        </div>
        {comparisonError && <p className="error-text" role="alert">{comparisonError}</p>}
        <EvidenceGraphExplorer key={currentGraph.investigation_id} graph={currentGraph} evidence={selected.evidence} />
        {changes && <div className="graph-changes" aria-live="polite"><div className="section-heading"><h3>Change radar</h3><span>{changes.length} classifications</span></div>
          <p className="graph-change-help">Absence is reported only when a later investigation completed the relevant collection. Provider outages remain unknown coverage.</p>
          {changes.length ? <ul>{changes.map((change) => <li key={comparisonVersion + '-' + change.status + '-' + change.edge.id} className={canAnimateChanges && ['new', 'changed'].includes(change.status) ? 'graph-change-enter' : ''}>
            <span className={'graph-change-status ' + change.status}>{change.status.replaceAll('_', ' ')}</span>
            <strong>{change.edge.relationship_type.replaceAll('_', ' ')}</strong>
            <span>{String(change.edge.details.from_label ?? change.edge.from_node_id)} → {String(change.edge.details.to_label ?? change.edge.to_node_id)}</span>
            <small>{change.reason}</small>
          </li>)}</ul> : <p className="empty-line">No relationship changes were observed between these investigations.</p>}
        </div>}
      </>}
    </>}
  </section>
}
export function FindingCard({ finding, reason, onReason, onDecision, onCase, canReview }: { finding: Finding; reason: string; onReason: (value: string) => void; onDecision: (value: string) => void; onCase: () => void; canReview: boolean }) {
  const needsReview = finding.category === 'vulnerabilities'
  const spamhaus = finding.source === 'Spamhaus Project DROP'
  const supportsApplicability = needsReview || spamhaus
  const cvssScore = finding.cvss_score
  const cvssVersion = finding.cvss_version
  const kev = finding.kev
  const percent = (value: number | null) => value == null ? 'Unavailable' : `${(value * 100).toFixed(1)}%`
  const epssStatus: Record<string, string> = { success: 'Provider result', no_match: 'No score available', unavailable: 'Provider unavailable', quota_limited: 'Provider quota limit', failed: 'Invalid provider response', not_assessed: 'Not assessed' }
  return <article className="finding-card"><div className="finding-heading"><span className={`severity ${finding.severity}`}>{finding.severity}</span><div><strong>{finding.title}</strong><small>{finding.category.replaceAll('_', ' ')} · {finding.source}{finding.is_synthetic ? ' · Demo data' : ''}</small></div>{canReview && <button className="small-button" onClick={onCase}>Create case</button>}</div><p>{finding.explanation}</p><div className="recommendation"><strong>Recommended action</strong><span>{finding.recommendation}</span></div>
    {supportsApplicability && <div className="applicability-box"><span>Applicability: <strong>{finding.applicability.replaceAll('_', ' ')}</strong>{finding.details_json.cve_id ? ` · ${String(finding.details_json.cve_id)}` : ''}</span>{finding.applicability_reason && <small>{finding.applicability_reason}</small>}{canReview && <div className="decision-controls"><input aria-label="Reason for applicability decision" value={reason} onChange={(e) => onReason(e.target.value)} placeholder="Reason for applicability decision" /><button className="small-button" onClick={() => onDecision('applies')}>Applies</button><button className="small-button" onClick={() => onDecision('does_not_apply')}>Does not apply</button><button className="small-button" onClick={() => onDecision('needs_review')}>Needs review</button></div>}{spamhaus && <small>Only a current, direct IP match that an analyst marks applies contributes to reputation risk. The prioritization severity is a CyberLens review rule.</small>}</div>}
    {needsReview && <section className="vulnerability-intelligence" aria-label="Vulnerability intelligence"><h4>Vulnerability intelligence</h4><dl><div><dt>CVSS</dt><dd>{typeof cvssScore === 'number' ? `${cvssScore} · ${String(cvssVersion ?? 'version unavailable')}` : 'Unavailable'} · {finding.severity}</dd></div><div><dt>CISA KEV</dt><dd>{kev === true ? 'Listed' : kev === false ? 'Not listed' : 'Unknown'}</dd></div><div><dt>EPSS</dt><dd>{percent(finding.epss_score)} probability in the next 30 days · {percent(finding.epss_percentile)} percentile</dd></div><div><dt>EPSS provider</dt><dd>{epssStatus[finding.epss_provider_status ?? 'not_assessed'] ?? finding.epss_provider_status ?? 'Not assessed'} · {finding.epss_freshness ?? 'Freshness unknown'}</dd></div><div><dt>EPSS observed</dt><dd>{finding.epss_observed_at ? date(finding.epss_observed_at) : 'Not observed'}</dd></div></dl><small>EPSS is a predictive estimate. It is not proof of exploitation or compromise and does not change the risk score.</small></section>}
    {spamhaus && <section className="vulnerability-intelligence" aria-label="Spamhaus DROP match details"><h4>Spamhaus DROP match details</h4><dl><div><dt>Matched networks</dt><dd>{Array.isArray(finding.details_json.matched_networks) ? (finding.details_json.matched_networks as Array<Record<string, unknown>>).map((item) => `${String(item.network)} (${String(item.sbl_id)})`).join(', ') : 'Unavailable'}</dd></div><div><dt>Snapshot ID</dt><dd>{String(finding.details_json.snapshot_id ?? 'Unavailable')}</dd></div><div><dt>Freshness</dt><dd>{String(finding.details_json.freshness ?? 'Unknown')} · provider date {finding.details_json.provider_published_at ? date(String(finding.details_json.provider_published_at)) : 'unavailable'}</dd></div><div><dt>Attribution</dt><dd>{String(finding.details_json.attribution ?? 'Spamhaus Project')}</dd></div></dl><small>DROP is an advisory list, not complete reputation coverage or evidence of compromise.</small></section>}
    {finding.osv && <section className="vulnerability-intelligence osv-intelligence" aria-label="OSV package advisory"><h4>OSV package advisory</h4><dl><div><dt>Advisory</dt><dd>{finding.osv.advisory_id} · {finding.osv.advisory_status}</dd></div><div><dt>Package</dt><dd>{finding.osv.ecosystem} {finding.osv.package_name}@{finding.osv.package_version}</dd></div><div><dt>Aliases</dt><dd>{finding.osv.aliases.length ? finding.osv.aliases.join(', ') : 'None supplied'}</dd></div><div><dt>Provider status / freshness</dt><dd>{finding.osv.provider_status} · {finding.osv.freshness} · {finding.osv.provider_version}</dd></div><div><dt>Observed</dt><dd>{date(finding.osv.observed_at)} · evidence {finding.osv.evidence_id ?? 'unavailable'}</dd></div><div><dt>Fixed versions</dt><dd>{finding.osv.fixed_versions.join(', ') || 'None documented'}</dd></div><div><dt>Severity metadata</dt><dd>{finding.osv.severity_metadata.length ? finding.osv.severity_metadata.map((item) => `${item.type}: ${item.score}`).join(' · ') : 'Unknown; no supported severity was supplied'}</dd></div></dl>{finding.osv.withdrawn && <p role="status">This advisory is withdrawn and is retained in evidence history.</p>}{finding.osv.references.length > 0 && <div><strong>References</strong><ul>{finding.osv.references.map((reference) => <li key={reference.url}><a href={reference.url} target="_blank" rel="noreferrer">{reference.type || 'Reference'} · {reference.url}</a></li>)}</ul></div>}<small>OSV version matching creates a candidate only. Review the saved ranges and confirm applicability before it affects risk.</small></section>}
    <details className="finding-details"><summary>Source details</summary><pre>{JSON.stringify(finding.details_json, null, 2)}</pre></details>
  </article>
}


