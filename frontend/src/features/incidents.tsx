import { useEffect, useState } from 'react'
import { request, type AttackCatalogVersions, type AttackSuggestion, type AttackTechnique, type Incident } from '../api'
import { Empty, PageTitle, StatusBadge } from '../components/ui'
import { date, nextStatuses } from './helpers'
import '../attack-catalog.css'

export function IncidentsScreen(props: { items: Incident[]; selected: Incident | null; canEdit: boolean; canSyncAttackCatalog: boolean; isDemo: boolean; busy: boolean; onSelect: (id: string) => void; onUpdate: (id: string, body: Record<string, unknown>) => unknown; onEvent: (id: string, message: string) => unknown; onTask: (id: string, taskId: string, status: string, notes: string) => unknown; onReport: (id: string, format: 'pdf' | 'json') => unknown; onAttackCreate: (id: string, suggestion: AttackSuggestion) => unknown; onAttackDecision: (id: string, mappingId: string, decision: 'approved' | 'rejected' | 'overridden', techniqueId?: string, tactic?: string) => unknown }) {
  const [eventText, setEventText] = useState(''); const [taskDrafts, setTaskDrafts] = useState<Record<string, { status: string; notes: string }>>({}); const [resolution, setResolution] = useState(''); const [reopenReason, setReopenReason] = useState('')
  const [attackTechniques, setAttackTechniques] = useState<AttackTechnique[]>([]); const [overrideSelections, setOverrideSelections] = useState<Record<string, string>>({})
  const [catalogVersions, setCatalogVersions] = useState<AttackCatalogVersions | null>(null); const [catalogStatusError, setCatalogStatusError] = useState(''); const [syncBusy, setSyncBusy] = useState(false)
  const item = props.selected
  const refreshCatalogVersions = async () => {
    try { setCatalogVersions(await request<AttackCatalogVersions>('/attack/catalog/versions')); setCatalogStatusError('') }
    catch (error) { setCatalogStatusError(error instanceof Error ? error.message : 'Catalog status is unavailable.') }
  }
  useEffect(() => {
    let active = true
    if (!item) { setAttackTechniques([]); setCatalogVersions(null); return () => { active = false } }
    request<{ techniques: AttackTechnique[] }>('/attack/catalog').then((catalog) => { if (active) setAttackTechniques(catalog.techniques.filter((technique) => technique.selectable !== false)) }).catch(() => { if (active) setAttackTechniques([]) })
    request<AttackCatalogVersions>('/attack/catalog/versions').then((versions) => { if (active) setCatalogVersions(versions) }).catch((error) => { if (active) setCatalogStatusError(error instanceof Error ? error.message : 'Catalog status is unavailable.') })
    return () => { active = false }
  }, [item?.id])
  useEffect(() => {
    if (!item || !catalogVersions?.versions.some((row) => ['queued', 'dispatched', 'downloading', 'validating'].includes(row.import_status))) return
    const timer = window.setInterval(() => { void refreshCatalogVersions() }, 2500)
    return () => window.clearInterval(timer)
  }, [item?.id, catalogVersions?.versions])
  useEffect(() => {
    if (!item) return
    setResolution(item.resolution_summary ?? '')
    setReopenReason('')
    setEventText('')
    setTaskDrafts(Object.fromEntries((item.tasks ?? []).map((task) => [String(task.id), { status: String(task.status), notes: String(task.notes ?? '') }])))
  }, [item?.id])
  return <><PageTitle eyebrow="INCIDENT RESPONSE" title="Cases" subtitle="Track triage, response tasks, evidence references, and recovery decisions." />
    {!props.canEdit && <div className="note-box" role="status">Read-only access: incident transitions, timeline entries, remediation tasks, and reports require Analyst or Admin permission.</div>}
    <div className="two-column history-layout"><section className="panel"><div className="panel-heading"><div><p className="eyebrow">CASE REGISTER</p><h2>Incident cases</h2></div><span className="count-pill">{props.items.length}</span></div>{props.items.length ? <div className="asset-list">{props.items.map((row) => <button key={row.id} className={`asset-row ${item?.id === row.id ? 'selected' : ''}`} onClick={() => props.onSelect(row.id)}><span className="asset-type">{row.priority.slice(0, 1).toUpperCase()}</span><span className="asset-main"><strong>{row.title}</strong><small>{row.asset_identifier} · {row.classification.replaceAll('_', ' ')} · {date(row.updated_at)}</small></span><StatusBadge value={row.status} /></button>)}</div> : <Empty title="No cases yet" text="Create a case from an investigation finding." />}</section>
      <section className="panel incident-detail">{!item ? <Empty title="Choose a case" text="Review its timeline and complete the versioned response playbook." /> : <>
        <div className="panel-heading"><div><p className="eyebrow">CASE · {item.priority.toUpperCase()} PRIORITY</p><h2>{item.title}</h2><p className="tiny-note">{item.asset_identifier} · owner {item.owner ?? 'unassigned'} · opened {date(item.created_at)}</p></div><StatusBadge value={item.status} /></div>
        <p className="panel-copy">{item.summary || 'No case summary recorded.'}</p>
        {props.canEdit && <div className="form-grid"><label>Classification<select value={item.classification} onChange={(e) => props.onUpdate(item.id, { classification: e.target.value })}>{[['suspected_incident', 'Suspected incident'], ['confirmed_incident', 'Confirmed incident'], ['security_issue', 'Security issue'], ['false_positive', 'False positive']].map(([id, label]) => <option key={id} value={id}>{label}</option>)}</select></label><label>Priority<select value={item.priority} onChange={(e) => props.onUpdate(item.id, { priority: e.target.value })}>{['low', 'medium', 'high', 'critical'].map((value) => <option key={value}>{value}</option>)}</select></label></div>}
        {props.canEdit && item.status !== 'closed' && <div className="workflow-controls"><strong>Move case</strong><div className="button-row">{nextStatuses(item.status).map((status) => <button className="small-button" key={status} onClick={() => status === 'closed' ? props.onUpdate(item.id, { status, resolution_summary: resolution.trim() || item.resolution_summary || '' }) : props.onUpdate(item.id, { status })}>{status.replaceAll('_', ' ')}</button>)}</div>{item.status === 'resolved' && <label>Resolution summary<input value={resolution || item.resolution_summary || ''} onChange={(e) => setResolution(e.target.value)} placeholder="Document recovery verification and outcome" /></label>}</div>}
        {props.canEdit && item.status === 'closed' && <div className="workflow-controls"><strong>Reopen case</strong><div className="inline-form"><input value={reopenReason} onChange={(e) => setReopenReason(e.target.value)} placeholder="Reason, at least 8 characters" /><button className="small-button" onClick={() => props.onUpdate(item.id, { status: 'triaged', reason: reopenReason })}>Reopen</button></div></div>}
        <div className="section-heading"><h3>Evidence references</h3><span>{item.evidence?.length ?? 0} snapshots</span>{props.canEdit && <div className="button-row"><button className="small-button" onClick={() => props.onReport(item.id, 'pdf')}>PDF report</button><button className="small-button" onClick={() => props.onReport(item.id, 'json')}>JSON</button></div>}</div>
        {item.findings?.map((finding) => <div className="linked-evidence" key={String(finding.id)}><span className={`severity ${String(finding.severity)}`}>{String(finding.severity)}</span><strong>{String(finding.title)}</strong><small>{String(finding.source)}</small></div>)}
        {item.attack_matrix && <section className="attack-matrix" aria-labelledby="attack-matrix-heading">
          <div className="section-heading"><h3 id="attack-matrix-heading">MITRE ATT&CK technique matrix</h3><span>{item.attack_matrix.catalog_version}</span></div>
          <p className="card-note">{item.attack_matrix.notice} Candidate rules never establish that adversary behavior occurred. Unmapped items remain unknown.</p>
          {item.attack_matrix.tactics.length ? <div className="attack-tactic-list" role="list" aria-label="Mapped ATT&CK tactics">
            {item.attack_matrix.tactics.map((group) => <section className="attack-tactic" role="listitem" key={group.tactic}><h4>{group.tactic}</h4>
              {group.mappings.map((mapping) => <article className="attack-mapping" key={mapping.id}>
                <div><strong><a href={`https://attack.mitre.org/techniques/${mapping.technique_id.replace('.', '/')}/`} target="_blank" rel="noreferrer">{mapping.technique_id} · {mapping.technique_name}</a></strong>
                  <small>{mapping.decision.replaceAll('_', ' ')} · {mapping.evidence_role} evidence · confidence {(mapping.confidence * 100).toFixed(0)}%{mapping.analyst_confirmed ? ' · analyst confirmed' : ''}</small>
                  <p>{mapping.rationale}</p><small>Source: {mapping.source} · Evidence: <code>{mapping.evidence_id}</code> ({mapping.evidence_source}) · reviewed {date(mapping.reviewed_at ?? '') || 'not reviewed'}</small>
                  <small>Catalog: {mapping.catalog_release_version ?? mapping.catalog_version} · {mapping.catalog_source ?? 'MITRE ATT&CK Enterprise'}{mapping.catalog_source_reference ? ` · ${mapping.catalog_source_reference}` : ''}</small>
                  {mapping.finding_id && <small>Finding: <a href={`#/findings/${encodeURIComponent(mapping.finding_id)}`}>{mapping.finding_id}</a></small>}
                </div>
                {props.canEdit && <div className="attack-review-controls"><div className="button-row"><button className="small-button" disabled={props.busy} onClick={() => props.onAttackDecision(item.id, mapping.id, 'approved')}>Approve</button><button className="small-button danger-button" disabled={props.busy} onClick={() => props.onAttackDecision(item.id, mapping.id, 'rejected')}>Reject</button></div>
                  <div className="inline-form"><label className="sr-only" htmlFor={`attack-override-${mapping.id}`}>Override technique for {mapping.technique_id}</label><select id={`attack-override-${mapping.id}`} value={overrideSelections[mapping.id] ?? ''} onChange={(event) => setOverrideSelections((old) => ({ ...old, [mapping.id]: event.target.value }))}><option value="">Choose override technique</option>{attackTechniques.map((candidate) => <option key={candidate.id} value={candidate.id}>{candidate.id} · {candidate.name}</option>)}</select><button className="small-button" disabled={props.busy || !overrideSelections[mapping.id]} onClick={() => { const selected = attackTechniques.find((candidate) => candidate.id === overrideSelections[mapping.id]); if (selected) props.onAttackDecision(item.id, mapping.id, 'overridden', selected.id, selected.tactics[0]) }}>Override</button></div>
                </div>}
              </article>)}
            </section>)}
          </div> : <p className="empty-line">No reviewed or proposed techniques are mapped to this incident.</p>}
          {item.attack_matrix.suggestions.length > 0 && <div className="attack-suggestions"><h4>Contextual candidates for review</h4>{item.attack_matrix.suggestions.map((suggestion) => <article className="attack-suggestion" key={`${suggestion.finding_id}-${suggestion.technique_id}`}><div><strong>{suggestion.technique_id} · {suggestion.technique_name}</strong><small>{suggestion.tactic} · {suggestion.source} · contextual · {(suggestion.confidence * 100).toFixed(0)}% confidence · evidence <code>{suggestion.evidence_id}</code></small><p>{suggestion.rationale}</p></div>{props.canEdit && <button className="small-button" disabled={props.busy} onClick={() => props.onAttackCreate(item.id, suggestion)}>Propose mapping</button>}</article>)}</div>}
          {item.attack_matrix.unmapped.length > 0 && <div className="attack-unmapped"><h4>Unmapped records</h4><ul>{item.attack_matrix.unmapped.map((record) => <li key={record.finding_id}><strong>{record.title}</strong><small>{record.category.replaceAll('_', ' ')} · {record.reason}</small></li>)}</ul></div>}
          <section className="attack-catalog-manager" aria-labelledby="attack-catalog-heading">
            <div className="section-heading"><h4 id="attack-catalog-heading">ATT&CK catalog versions</h4><button className="small-button" onClick={() => void refreshCatalogVersions()}>Refresh status</button></div>
            <p className="card-note">{catalogVersions?.checksum_notice ?? 'Catalog checksums help detect changes to retrieved bytes; they do not authenticate the source independently.'}</p>
            {props.isDemo && <p className="note-box" role="status">Demo mode uses the bundled offline catalog. Synchronization requests are disabled.</p>}
            {props.canSyncAttackCatalog && !props.isDemo && <button className="small-button" disabled={syncBusy || props.busy} onClick={async () => {
              setSyncBusy(true); setCatalogStatusError('')
              try { await request('/attack/catalog/sync', { method: 'POST', body: '{}' }); await refreshCatalogVersions() }
              catch (error) { setCatalogStatusError(error instanceof Error ? error.message : 'Catalog synchronization could not be queued.') }
              finally { setSyncBusy(false) }
            }}>{syncBusy ? 'Queueing synchronization…' : 'Synchronize official Enterprise catalog'}</button>}
            {catalogStatusError && <p className="error-note" role="alert">{catalogStatusError}</p>}
            {catalogVersions?.active && <p className="tiny-note">Active: <strong>{catalogVersions.active.release_version ?? catalogVersions.active.catalog_version}</strong> · retrieved {date(catalogVersions.active.retrieved_at ?? '') || 'date unavailable'} · {catalogVersions.active.technique_count} techniques</p>}
            {catalogVersions?.versions.length ? <ul className="attack-catalog-version-list" aria-label="Available catalog versions">{catalogVersions.versions.map((version) => <li key={version.id}>
              <strong>{version.release_version ? `Enterprise ATT&CK ${version.release_version}` : `Sync ${version.import_status}`}</strong>
              <span>{version.active ? 'Active' : version.import_status.replaceAll('_', ' ')} · {version.tactic_count} tactics · {version.technique_count} techniques</span>
              {version.retrieved_at && <span>Retrieved {date(version.retrieved_at)}</span>}
              {version.checksum && <code>SHA-256 {version.checksum.slice(0, 16)}…</code>}
              {version.source_reference && <code>{version.source_reference}</code>}
              {version.duplicate_of && <span>Same content as {version.duplicate_of}</span>}
              {version.error_summary && <span className="error-note" role="alert">{version.error_summary}</span>}
            </li>)}</ul> : !catalogStatusError && <p className="empty-line">No catalog version status is available.</p>}
            {catalogVersions?.attribution && <small>{catalogVersions.attribution} <a href="https://attack.mitre.org/resources/attack-data-and-tools/" target="_blank" rel="noreferrer">Terms of Use</a>.</small>}
          </section>
        </section>}
        <div className="section-heading"><h3>Response playbook</h3><span>Analyst actions only</span></div><div className="task-list">{item.tasks?.map((task) => { const draft = taskDrafts[String(task.id)] ?? { status: String(task.status), notes: String(task.notes ?? '') }; return <div className="task-row" key={String(task.id)}><div className="task-main"><strong>{String(task.title)}</strong><small>{String(task.stage).replaceAll('_', ' ')} · {String(task.description)}</small>{Boolean(task.completed_by) && <small>Completed by {String(task.completed_by)} · {date(String(task.completed_at))}</small>}</div>{props.canEdit && <div className="task-controls"><select aria-label={`Status for ${String(task.title)}`} value={draft.status} onChange={(e) => setTaskDrafts((old) => ({ ...old, [String(task.id)]: { ...draft, status: e.target.value } }))}>{['pending', 'in_progress', 'completed', 'skipped'].map((status) => <option key={status}>{status}</option>)}</select><input aria-label={`Notes for ${String(task.title)}`} value={draft.notes} onChange={(e) => setTaskDrafts((old) => ({ ...old, [String(task.id)]: { ...draft, notes: e.target.value } }))} placeholder="Action notes"/><button className="small-button" disabled={props.busy} onClick={() => props.onTask(item.id, String(task.id), draft.status, draft.notes)}>Save</button></div>}</div> })}</div>
        {props.canEdit && <form className="inline-form event-form" onSubmit={(e) => { e.preventDefault(); props.onEvent(item.id, eventText); setEventText('') }}><input value={eventText} onChange={(e) => setEventText(e.target.value)} placeholder="Add an analyst timeline note" required/><button className="small-button">Add event</button></form>}
        <div className="section-heading"><h3>Chronological timeline</h3><span>{item.events?.length ?? 0} entries</span></div><div className="timeline">{item.events?.map((event) => <div className="timeline-item" key={String(event.id)}><i /><div><strong>{String(event.event_type).replaceAll('_', ' ')}</strong><small>{String(event.actor)} · {date(String(event.created_at))}</small><p>{String(event.message)}</p></div></div>)}</div>
      </>}</section></div></>
}


