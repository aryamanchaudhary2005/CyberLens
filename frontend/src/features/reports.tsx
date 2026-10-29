import type { Report } from '../api'
import { Empty, PageTitle } from '../components/ui'
import { date } from './helpers'

export function ReportsScreen({ reports, selectedReportId, onDownload }: { reports: Report[]; selectedReportId?: string; onDownload: (id: string) => unknown }) {
  return <><PageTitle eyebrow="EVIDENCE EXPORTS" title="Reports" subtitle="Exports are immutable snapshots of the saved records at generation time." />
    <section className="panel"><div className="panel-heading"><div><p className="eyebrow">GENERATED REPORTS</p><h2>Workspace archive</h2></div><span className="count-pill">{reports.length}</span></div>{reports.length ? <div className="table-wrap"><table><thead><tr><th>Report</th><th>Format</th><th>Generated</th><th>SHA-256</th><th /></tr></thead><tbody>{reports.map((item) => <tr key={item.id} className={selectedReportId === item.id ? 'selected-row' : undefined}><td><strong>{item.report_type === 'posture' ? 'Security posture scorecard' : item.report_type === 'incident' || (!item.report_type && item.incident_id) ? 'Incident report' : 'Investigation report'}</strong><small>{item.is_demo ? 'Contains synthetic Demo observations' : item.incident_id ?? item.investigation_id ?? 'Workspace scorecard snapshot'}</small></td><td>{item.format.toUpperCase()}</td><td>{date(item.created_at)}</td><td><code className="hash">{item.sha256}</code></td><td><button className="small-button" onClick={() => onDownload(item.id)}>Download</button></td></tr>)}</tbody></table></div> : <Empty title="No reports yet" text="Generate an export from an investigation, incident, or the posture scorecard." />}</section>
  </>
}


