import { useCallback, useEffect, useState } from 'react'
import { downloadAuditExport, request, type EvidenceIntegrity, type IntegritySummary } from '../api'
import { Empty, LoadingState, PageTitle, StatusBadge } from '../components/ui'
import { date } from './helpers'

export function IntegrityScreen({ canExport }: { canExport: boolean }) {
  const [summary, setSummary] = useState<IntegritySummary | null>(null)
  const [evidence, setEvidence] = useState<EvidenceIntegrity[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const [integrity, records] = await Promise.all([
        request<IntegritySummary>('/integrity'),
        request<EvidenceIntegrity[]>('/integrity/evidence?page=1&page_size=50'),
      ])
      setSummary(integrity)
      setEvidence(records)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Integrity information is unavailable.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { void load() }, [load])

  return <>
    <PageTitle eyebrow="RECORD VERIFICATION" title="Integrity" subtitle="Verify the audit chain and recompute checksums for saved evidence." />
    <section className="panel integrity-panel" aria-labelledby="integrity-summary-heading">
      <div className="panel-heading"><div><p className="eyebrow">CURRENT CHECK</p><h2 id="integrity-summary-heading">Workspace integrity</h2></div>
        <div className="button-row"><button className="small-button" onClick={() => void load()} disabled={loading}>Verify again</button>
          {canExport && <button className="small-button" onClick={() => void downloadAuditExport().catch((reason: unknown) => setError(reason instanceof Error ? reason.message : 'Audit export failed.'))}>Export audit JSONL</button>}</div>
      </div>
      {loading && <LoadingState label="Verifying saved records…" />}
      {error && <div className="alert error" role="alert">{error}</div>}
      {!loading && summary && <>
        <div className="integrity-overview">
          <div><span>Overall state</span><StatusBadge value={summary.state} /></div>
          <div><span>Audit chain</span><StatusBadge value={summary.audit_chain.state} /><small>{summary.audit_chain.message}</small></div>
          <div><span>Evidence checksums</span><StatusBadge value={summary.evidence.state} /><small>{summary.evidence.checked} checked of {summary.evidence.total}</small></div>
        </div>
        <p className="integrity-note">Checksums can detect later changes to stored records. They do not prove forensic authenticity, collection context, or chain of custody.</p>
        <p className="integrity-meta">Checked {date(summary.checked_at)} · Audit events {summary.audit_chain.event_count} · Last sequence {summary.audit_chain.last_sequence ?? 'none'}</p>
      </>}
    </section>
    <section className="panel integrity-panel" aria-labelledby="evidence-integrity-heading">
      <div className="panel-heading"><div><p className="eyebrow">SAVED SNAPSHOTS</p><h2 id="evidence-integrity-heading">Evidence checksums</h2></div><span className="count-pill">{summary?.evidence.total ?? evidence.length}</span></div>
      {!loading && summary && summary.evidence.total > evidence.length && <p className="integrity-meta">Showing the newest {evidence.length} of {summary.evidence.total} snapshots (maximum 50 per view).</p>}
      {loading ? <LoadingState label="Loading evidence checksums…" /> : evidence.length ? <div className="table-wrap"><table><thead><tr><th>Evidence</th><th>Observed</th><th>State</th><th>Stored SHA-256</th><th>Calculated SHA-256</th></tr></thead>
        <tbody>{evidence.map((item) => <tr key={item.evidence_id}><td><strong>{item.source ?? 'Evidence unavailable'}</strong><small>{item.evidence_id}{item.is_synthetic ? ' · Demo' : ''}</small></td>
          <td>{item.observed_at ? date(item.observed_at) : 'Unavailable'}</td><td><StatusBadge value={item.state} />{item.message && <small>{item.message}</small>}</td>
          <td><code className="hash">{item.stored_sha256 ?? 'Unavailable'}</code></td><td><code className="hash">{item.calculated_sha256 ?? 'Unavailable'}</code></td></tr>)}</tbody></table></div>
        : <Empty title="No evidence snapshots" text="There are no saved evidence checksums to verify yet. This state is incomplete, not a clean verification." />}
    </section>
  </>
}
