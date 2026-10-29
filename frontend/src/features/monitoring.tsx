import { useEffect, useState } from 'react'
import { request, type Asset, type EvidenceGraphChanges, type MonitoringCadence, type MonitoringRun, type MonitoringSchedule } from '../api'
import { StatusBadge } from '../components/ui'

function timestamp(value: string | null): string {
  return value ? new Date(value).toLocaleString() : 'Not run yet'
}

export function MonitoringSection({ asset, canManage, demo }: { asset: Asset; canManage: boolean; demo: boolean }) {
  const [schedules, setSchedules] = useState<MonitoringSchedule[]>([])
  const [runs, setRuns] = useState<MonitoringRun[]>([])
  const [expanded, setExpanded] = useState('')
  const [changes, setChanges] = useState<EvidenceGraphChanges | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function loadSchedules(signal?: AbortSignal) {
    const result = await request<MonitoringSchedule[]>(`/monitoring?asset_id=${encodeURIComponent(asset.id)}`, { signal })
    setSchedules(result)
    if (expanded && !result.some((item) => item.id === expanded)) setExpanded('')
  }

  useEffect(() => {
    const controller = new AbortController()
    setSchedules([]); setRuns([]); setExpanded(''); setChanges(null); setError('')
    void loadSchedules(controller.signal).catch((reason: unknown) => {
      if (!(reason instanceof DOMException && reason.name === 'AbortError')) setError(reason instanceof Error ? reason.message : 'Monitoring schedules could not be loaded.')
    })
    return () => controller.abort()
  }, [asset.id])

  useEffect(() => {
    if (!expanded) { setRuns([]); setChanges(null); return }
    const controller = new AbortController()
    void request<MonitoringRun[]>(`/monitoring/${expanded}/history`, { signal: controller.signal })
      .then(setRuns)
      .catch((reason: unknown) => {
        if (!(reason instanceof DOMException && reason.name === 'AbortError')) setError(reason instanceof Error ? reason.message : 'Monitoring history could not be loaded.')
      })
    return () => controller.abort()
  }, [expanded])

  async function act(action: () => Promise<unknown>) {
    setBusy(true); setError(''); setChanges(null)
    try { await action(); await loadSchedules() }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'Monitoring action failed.') }
    finally { setBusy(false) }
  }

  async function create(cadence: MonitoringCadence) {
    if (!asset.authorization_id) return
    await act(() => request<MonitoringSchedule>('/monitoring', {
      method: 'POST', body: JSON.stringify({ asset_id: asset.id, authorization_id: asset.authorization_id, cadence }),
    }))
  }

  async function compare(run: MonitoringRun) {
    setError(''); setChanges(null)
    try {
      const result = await request<EvidenceGraphChanges>(`/monitoring/${run.schedule_id}/runs/${run.id}/changes`)
      setChanges(result)
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Change comparison could not be loaded.') }
  }

  return <section className="subsection monitoring-section" aria-labelledby={`monitoring-heading-${asset.id}`}>
    <h3 id={`monitoring-heading-${asset.id}`}>Continuous monitoring</h3>
    <p className="card-note">Scheduled runs create separate saved investigations and use the existing evidence comparison. No containment or external notifications are triggered.</p>
    {demo && <p className="tiny-note">Demo schedules use offline synthetic investigation scenarios.</p>}
    {!asset.authorization_id && <p className="note-box" role="status">An active, explicit website authorization is required before a schedule can be created or resumed.</p>}
    {error && <p className="error-text" role="alert">{error}</p>}
    {canManage && asset.authorization_id && <div className="button-row monitoring-create" aria-label="Create monitoring schedule">
      <button className="small-button" disabled={busy} onClick={() => void create('daily')}>Schedule daily</button>
      <button className="small-button" disabled={busy} onClick={() => void create('weekly')}>Schedule weekly</button>
    </div>}
    {schedules.length === 0 ? <p className="tiny-note">No monitoring schedules for this asset.</p> : <ul className="monitoring-list">
      {schedules.map((schedule) => <li key={schedule.id} className="monitoring-card">
        <div className="monitoring-summary">
          <div><strong>{schedule.cadence === 'daily' ? 'Daily' : 'Weekly'} schedule</strong><small>Owner record {schedule.owner_id.slice(0, 8)} · authorization {schedule.authorization_id.slice(0, 8)}</small></div>
          <StatusBadge value={schedule.status} />
        </div>
        <dl className="monitoring-times"><div><dt>Next run</dt><dd>{timestamp(schedule.next_run_at)}</dd></div><div><dt>Last run</dt><dd>{timestamp(schedule.last_run_at)}</dd></div></dl>
        {schedule.failure_detail && <p className="error-text">{schedule.failure_detail}</p>}
        {canManage && <div className="button-row monitoring-actions">
          {schedule.status === 'active' && <button className="small-button" disabled={busy} onClick={() => void act(() => request(`/monitoring/${schedule.id}/pause`, { method: 'POST' }))}>Pause</button>}
          {(schedule.status === 'paused' || schedule.status === 'failed') && <button className="small-button" disabled={busy || !asset.authorization_id} onClick={() => void act(() => request(`/monitoring/${schedule.id}/resume`, { method: 'POST', body: JSON.stringify({ authorization_id: asset.authorization_id }) }))}>Resume</button>}
          {schedule.status !== 'completed' && <button className="small-button" disabled={busy} onClick={() => void act(() => request(`/monitoring/${schedule.id}/cancel`, { method: 'POST' }))}>Cancel schedule</button>}
        </div>}
        <details onToggle={(event) => { if (event.currentTarget.open) { setExpanded(schedule.id); setChanges(null) } else if (expanded === schedule.id) setExpanded('') }}>
          <summary>Run history</summary>
          {expanded === schedule.id && <div className="monitoring-history">
            {runs.length ? <ol>{runs.map((run) => <li key={run.id}>
              <strong>{timestamp(run.scheduled_for)}</strong> <StatusBadge value={run.status} />
              <a href={`#/investigations/${encodeURIComponent(run.investigation_id)}`}>Open investigation</a>
              {run.previous_investigation_id && ['completed', 'partial', 'failed'].includes(run.status) && <button className="small-button" onClick={() => void compare(run)}>View Change Radar</button>}
              {run.failure_detail && <p className="error-text">{run.failure_detail}</p>}
            </li>)}</ol> : <p className="tiny-note">No scheduled runs yet.</p>}
            {changes && <section className="monitoring-changes" aria-live="polite">
              <h4>Change Radar</h4>
              <p>{changes.counts.new} new · {changes.counts.changed} changed · {changes.counts.no_longer_observed} no longer observed · {changes.counts.unknown} unknown</p>
              {changes.changes.length ? <ul>{changes.changes.slice(0, 20).map((change, index) => <li key={`${change.edge.id}-${index}`}><StatusBadge value={change.status} /> {change.edge.relationship_type.replaceAll('_', ' ')} · {change.edge.source}<small>{change.reason}</small></li>)}</ul> : <p className="tiny-note">No graph relationship changes were reported.</p>}
              <p className="tiny-note">Unavailable provider coverage appears as unknown and is not reported as removal.</p>
            </section>}
          </div>}
        </details>
      </li>)}
    </ul>}
  </section>
}
