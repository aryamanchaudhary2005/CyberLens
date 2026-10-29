import { useEffect, useMemo, useState } from 'react'
import { request, type Finding, type FindingControlMapping, type Incident, type RemediationPlan, type RemediationStatus, type SecurityControl, type VerificationEvidence, type User } from '../api'
import { Empty, PageTitle, StatusBadge } from '../components/ui'

const statuses: RemediationStatus[] = ['proposed', 'planned', 'implemented', 'validated', 'rejected', 'not_applicable']
type IncidentDetail = Incident & { tasks?: Array<Record<string, unknown>> }
type PlanEditorDraft = { title: string; description: string; action_type: string; owner_id: string; priority: string; due_at: string; status: RemediationStatus; assumptions: string; notes: string }

export function RemediationScreen(props: { user: User; incidents: Incident[]; selectedPlanId: string; onSelect: (id: string) => void }) {
  const canEdit = props.user.role === 'admin' || props.user.role === 'analyst'
  const [plans, setPlans] = useState<RemediationPlan[]>([])
  const [controls, setControls] = useState<SecurityControl[]>([])
  const [findings, setFindings] = useState<Finding[]>([])
  const [plan, setPlan] = useState<RemediationPlan | null>(null)
  const [planEdit, setPlanEdit] = useState<PlanEditorDraft>({ title: '', description: '', action_type: '', owner_id: '', priority: 'medium', due_at: '', status: 'proposed', assumptions: '', notes: '' })
  const [incidentDetail, setIncidentDetail] = useState<IncidentDetail | null>(null)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [planDraft, setPlanDraft] = useState({ title: '', description: '', action_type: 'security_hardening', finding_id: '', incident_id: '', playbook_task_id: '', priority: 'medium', due_at: '', assumptions: '', notes: '' })
  const [actionDraft, setActionDraft] = useState({ title: '', description: '', action_type: 'configuration_change', priority: 'medium', due_at: '', assumptions: '', verification_instructions: '', notes: '' })
  const [mappingDraft, setMappingDraft] = useState({ control_id: '', rationale: '', confidence: '0.8' })

  async function load(selectedId = props.selectedPlanId) {
    setLoading(true); setError('')
    try {
      const [nextPlans, nextControls, nextFindings] = await Promise.all([
        request<RemediationPlan[]>('/remediation/plans?page=1&page_size=100'),
        request<SecurityControl[]>('/remediation/controls'),
        request<Finding[]>('/findings?limit=500'),
      ])
      setPlans(nextPlans); setControls(nextControls); setFindings(nextFindings)
      const wanted = selectedId || nextPlans[0]?.id || ''
      props.onSelect(wanted)
      setPlan(wanted ? await request<RemediationPlan>(`/remediation/plans/${wanted}`) : null)
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Could not load remediation records.') }
    finally { setLoading(false) }
  }

  useEffect(() => { void load() }, [])
  useEffect(() => {
    if (!props.selectedPlanId) { setPlan(null); return }
    request<RemediationPlan>(`/remediation/plans/${props.selectedPlanId}`).then(setPlan).catch((reason: unknown) => setError(reason instanceof Error ? reason.message : 'Could not load this plan.'))
  }, [props.selectedPlanId])
  useEffect(() => {
    if (!plan) return
    setPlanEdit({ title: plan.title, description: plan.description, action_type: plan.action_type, owner_id: plan.owner_id ?? '',
      priority: plan.priority, due_at: localDateTime(plan.due_at), status: plan.status, assumptions: plan.assumptions.join('\n'), notes: plan.notes ?? '' })
  }, [plan?.id])
  useEffect(() => {
    if (!planDraft.incident_id) { setIncidentDetail(null); setPlanDraft((draft) => ({ ...draft, playbook_task_id: '' })); return }
    request<IncidentDetail>(`/incidents/${planDraft.incident_id}`).then((value) => setIncidentDetail(value)).catch(() => setIncidentDetail(null))
  }, [planDraft.incident_id])

  const selectedFinding = useMemo(() => findings.find((item) => item.id === plan?.finding_id) ?? null, [findings, plan?.finding_id])
  async function mutate(action: () => Promise<unknown>, message: string, selectResult?: (result: unknown) => string) {
    setBusy(true); setError(''); setNotice('')
    try { const result = await action(); setNotice(message); const selectedId = selectResult?.(result); if (selectedId) props.onSelect(selectedId); await load(selectedId ?? props.selectedPlanId) }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'The remediation update failed.') }
    finally { setBusy(false) }
  }

  async function createPlan(event: React.FormEvent) {
    event.preventDefault()
    await mutate(async () => {
      const created = await request<RemediationPlan>('/remediation/plans', { method: 'POST', body: JSON.stringify({
        ...planDraft, finding_id: planDraft.finding_id || null, incident_id: planDraft.incident_id || null,
        playbook_task_id: planDraft.playbook_task_id || null, owner_id: props.user.id,
        due_at: planDraft.due_at || null, assumptions: planDraft.assumptions.split('\n').map((value) => value.trim()).filter(Boolean), status: 'proposed',
      }) })
      setPlanDraft({ title: '', description: '', action_type: 'security_hardening', finding_id: '', incident_id: '', playbook_task_id: '', priority: 'medium', due_at: '', assumptions: '', notes: '' })
      return created
    }, 'Remediation plan created.', (result) => (result as RemediationPlan).id)
  }

  async function createAction(event: React.FormEvent) {
    event.preventDefault()
    if (!plan) return
    await mutate(() => request(`/remediation/plans/${plan.id}/actions`, { method: 'POST', body: JSON.stringify({
      ...actionDraft, due_at: actionDraft.due_at || null,
      assumptions: actionDraft.assumptions.split('\n').map((value) => value.trim()).filter(Boolean), status: 'proposed',
      owner_id: props.user.id,
    }) }), 'Remediation action added.')
    setActionDraft({ title: '', description: '', action_type: 'configuration_change', priority: 'medium', due_at: '', assumptions: '', verification_instructions: '', notes: '' })
  }

  async function createMapping(event: React.FormEvent) {
    event.preventDefault()
    if (!plan?.finding_id) return
    await mutate(() => request(`/remediation/findings/${plan.finding_id}/controls`, { method: 'POST', body: JSON.stringify({
      ...mappingDraft, confidence: Number(mappingDraft.confidence), status: 'proposed',
    }) }), 'Finding mapped to a catalog control.')
    setMappingDraft({ control_id: '', rationale: '', confidence: '0.8' })
  }

  async function savePlan(event: React.FormEvent) {
    event.preventDefault()
    if (!plan) return
    await mutate(() => request(`/remediation/plans/${plan.id}`, { method: 'PATCH', body: JSON.stringify({
      ...planEdit, owner_id: planEdit.owner_id || null,
      due_at: planEdit.due_at ? new Date(planEdit.due_at).toISOString() : null,
      assumptions: planEdit.assumptions.split('\n').map((value) => value.trim()).filter(Boolean),
      notes: planEdit.notes || null,
    }) }), 'Plan details saved.')
  }

  return <>
    <PageTitle eyebrow="REMEDIATION TRACKING" title="Remediation plans" subtitle="Track proposed work, owners, control mappings, and evidence-backed verification. Original findings and risk assessments remain unchanged." />
    {!canEdit && <div className="note-box" role="status">Read-only access: only Analysts and Admins can create plans, update actions, map controls, or validate work.</div>}
    {error && <div className="alert error" role="alert">{error}</div>}{notice && <div className="alert success" role="status">{notice}</div>}
    {canEdit && <section className="panel remediation-create"><div className="panel-heading"><div><p className="eyebrow">NEW TRACKING RECORD</p><h2>Create remediation plan</h2></div></div>
      <form className="form-grid remediation-form" onSubmit={(event) => void createPlan(event)}>
        <label>Plan title<input required minLength={3} maxLength={300} value={planDraft.title} onChange={(event) => setPlanDraft({ ...planDraft, title: event.target.value })} /></label>
        <label>Action type<input required value={planDraft.action_type} onChange={(event) => setPlanDraft({ ...planDraft, action_type: event.target.value })} /></label>
        <label>Finding<select value={planDraft.finding_id} onChange={(event) => setPlanDraft({ ...planDraft, finding_id: event.target.value })}><option value="">No finding linked</option>{findings.map((item) => <option key={item.id} value={item.id}>{item.severity.toUpperCase()} · {item.title}</option>)}</select></label>
        <label>Incident<select value={planDraft.incident_id} onChange={(event) => setPlanDraft({ ...planDraft, incident_id: event.target.value, playbook_task_id: '' })}><option value="">No incident linked</option>{props.incidents.map((item) => <option key={item.id} value={item.id}>{item.title}</option>)}</select></label>
        {incidentDetail?.tasks?.length ? <label>Playbook task<select value={planDraft.playbook_task_id} onChange={(event) => setPlanDraft({ ...planDraft, playbook_task_id: event.target.value })}><option value="">No task linked</option>{incidentDetail.tasks.map((task) => <option key={String(task.id)} value={String(task.id)}>{String(task.title)}</option>)}</select></label> : null}
        <label>Priority<select value={planDraft.priority} onChange={(event) => setPlanDraft({ ...planDraft, priority: event.target.value })}>{['low', 'medium', 'high', 'critical'].map((item) => <option key={item}>{item}</option>)}</select></label>
        <label>Due date<input type="datetime-local" value={planDraft.due_at} onChange={(event) => setPlanDraft({ ...planDraft, due_at: event.target.value })} /></label>
        <label className="wide-field">Description<textarea rows={2} value={planDraft.description} onChange={(event) => setPlanDraft({ ...planDraft, description: event.target.value })} /></label>
        <label>Assumptions, one per line<textarea rows={2} value={planDraft.assumptions} onChange={(event) => setPlanDraft({ ...planDraft, assumptions: event.target.value })} /></label>
        <label>Notes<textarea rows={2} value={planDraft.notes} onChange={(event) => setPlanDraft({ ...planDraft, notes: event.target.value })} /></label>
        <button className="primary-button" disabled={busy || loading}>Create plan</button>
      </form>
    </section>}
    <div className="two-column remediation-layout"><section className="panel"><div className="panel-heading"><div><p className="eyebrow">WORK QUEUE</p><h2>Plans</h2></div><span className="count-pill">{plans.length}</span></div>
      {loading ? <p className="empty-line" role="status">Loading remediation plans…</p> : plans.length ? <div className="asset-list">{plans.map((item) => <button key={item.id} className={`asset-row ${plan?.id === item.id ? 'selected' : ''}`} onClick={() => props.onSelect(item.id)}><span className="asset-type">{item.priority.slice(0, 1).toUpperCase()}</span><span className="asset-main"><strong>{item.title}</strong><small>{item.action_type} · {item.actions.length} actions · updated {new Date(item.updated_at).toLocaleDateString()}</small></span><StatusBadge value={item.status} /></button>)}</div> : <Empty title="No remediation plans" text="Create a plan to track work connected to a finding, incident, or playbook task." />}
    </section>
    <section className="panel remediation-detail">{!plan ? <Empty title="Choose a plan" text="Select a plan to review its actions, controls, and verification evidence." /> : <>
      <div className="panel-heading"><div><p className="eyebrow">{plan.priority.toUpperCase()} PRIORITY · {plan.action_type}</p><h2>{plan.title}</h2><p className="tiny-note">Created {new Date(plan.created_at).toLocaleString()} · updated {new Date(plan.updated_at).toLocaleString()}</p></div><StatusBadge value={plan.status} /></div>
      <p className="panel-copy">{plan.description || 'No description recorded.'}</p>
      <div className="remediation-links"><span>Finding: {plan.finding_id ? <a href={`#/findings/${encodeURIComponent(plan.finding_id)}`}>{selectedFinding?.title ?? plan.finding_id}</a> : 'not linked'}</span><span>Incident: {plan.incident_id ? <a href={`#/incidents/${encodeURIComponent(plan.incident_id)}`}>{plan.incident_id}</a> : 'not linked'}</span><span>Playbook task: {plan.playbook_task_id ?? 'not linked'}</span><span>Owner: {plan.owner_id === props.user.id ? props.user.username : plan.owner_id ?? 'unassigned'}</span><span>Due: {plan.due_at ? new Date(plan.due_at).toLocaleString() : 'not set'}</span></div>
      {plan.assumptions.length > 0 && <div className="note-box"><strong>Assumptions</strong><ul>{plan.assumptions.map((item, index) => <li key={index}>{item}</li>)}</ul></div>}
      {canEdit && <details className="workflow-controls remediation-editor"><summary>Edit plan details</summary><form className="form-grid remediation-form" onSubmit={(event) => void savePlan(event)}>
        <label>Title<input required minLength={3} value={planEdit.title} onChange={(event) => setPlanEdit({ ...planEdit, title: event.target.value })} /></label>
        <label>Action type<input required value={planEdit.action_type} onChange={(event) => setPlanEdit({ ...planEdit, action_type: event.target.value })} /></label>
        <label>Status<select value={planEdit.status} onChange={(event) => setPlanEdit({ ...planEdit, status: event.target.value as RemediationStatus })}>{statuses.map((value) => <option key={value}>{value}</option>)}</select></label>
        <label>Priority<select value={planEdit.priority} onChange={(event) => setPlanEdit({ ...planEdit, priority: event.target.value })}>{['low', 'medium', 'high', 'critical'].map((value) => <option key={value}>{value}</option>)}</select></label>
        <label>Owner<select value={planEdit.owner_id} onChange={(event) => setPlanEdit({ ...planEdit, owner_id: event.target.value })}><option value="">Unassigned</option><option value={props.user.id}>{props.user.username} (you)</option>{plan.owner_id && plan.owner_id !== props.user.id && <option value={plan.owner_id}>{plan.owner_id}</option>}</select></label>
        <label>Due date<input type="datetime-local" value={planEdit.due_at} onChange={(event) => setPlanEdit({ ...planEdit, due_at: event.target.value })} /></label>
        <label className="wide-field">Description<textarea rows={2} value={planEdit.description} onChange={(event) => setPlanEdit({ ...planEdit, description: event.target.value })} /></label>
        <label>Assumptions, one per line<textarea rows={2} value={planEdit.assumptions} onChange={(event) => setPlanEdit({ ...planEdit, assumptions: event.target.value })} /></label>
        <label>Notes<textarea rows={2} value={planEdit.notes} onChange={(event) => setPlanEdit({ ...planEdit, notes: event.target.value })} /></label>
        <button className="small-button" disabled={busy}>Save plan</button>
      </form></details>}
      <div className="section-heading"><h3>Remediation actions</h3><span>{plan.actions.length} recorded</span></div>
      {plan.actions.length ? <div className="task-list">{plan.actions.map((action) => <ActionRow key={action.id} action={action} evidence={plan.verification_evidence} ownerName={action.owner_id === props.user.id ? props.user.username : action.owner_id ?? 'unassigned'} currentUserId={props.user.id} currentUsername={props.user.username} canEdit={canEdit} busy={busy} onSave={(body) => mutate(() => request(`/remediation/plans/${plan.id}/actions/${action.id}`, { method: 'PATCH', body: JSON.stringify(body) }), 'Action updated.')} />)}</div> : <p className="empty-line">No actions are recorded yet.</p>}
      {canEdit && <form className="form-grid remediation-form subsection" onSubmit={(event) => void createAction(event)}><h3 className="wide-field">Add action</h3>
        <label>Action title<input required value={actionDraft.title} onChange={(event) => setActionDraft({ ...actionDraft, title: event.target.value })} /></label>
        <label>Action type<input required value={actionDraft.action_type} onChange={(event) => setActionDraft({ ...actionDraft, action_type: event.target.value })} /></label>
        <label>Priority<select value={actionDraft.priority} onChange={(event) => setActionDraft({ ...actionDraft, priority: event.target.value })}>{['low', 'medium', 'high', 'critical'].map((item) => <option key={item}>{item}</option>)}</select></label>
        <label>Due date<input type="datetime-local" value={actionDraft.due_at} onChange={(event) => setActionDraft({ ...actionDraft, due_at: event.target.value })} /></label>
        <label className="wide-field">Description<textarea rows={2} value={actionDraft.description} onChange={(event) => setActionDraft({ ...actionDraft, description: event.target.value })} /></label>
        <label className="wide-field">Verification instructions<textarea rows={2} value={actionDraft.verification_instructions} onChange={(event) => setActionDraft({ ...actionDraft, verification_instructions: event.target.value })} /></label>
        <label>Assumptions, one per line<textarea rows={2} value={actionDraft.assumptions} onChange={(event) => setActionDraft({ ...actionDraft, assumptions: event.target.value })} /></label>
        <label>Notes<textarea rows={2} value={actionDraft.notes} onChange={(event) => setActionDraft({ ...actionDraft, notes: event.target.value })} /></label>
        <button className="primary-button" disabled={busy}>Add action</button>
      </form>}
      {plan.finding_id && <><div className="section-heading"><h3>Security-control mapping</h3><span>{plan.control_mappings.length} mappings · {controls[0]?.catalog_version ?? 'local catalog'}</span></div>
        {plan.control_mappings.map((mapping) => <MappingRow key={mapping.id} mapping={mapping} evidence={plan.verification_evidence} canEdit={canEdit} busy={busy} onSave={(body) => mutate(() => request(`/remediation/findings/${plan.finding_id}/controls/${mapping.id}`, { method: 'PATCH', body: JSON.stringify(body) }), 'Control mapping updated.')} />)}
        {canEdit && <form className="form-grid remediation-form subsection" onSubmit={(event) => void createMapping(event)}><h3 className="wide-field">Map finding to a control</h3>
          <label>Catalog control<select required value={mappingDraft.control_id} onChange={(event) => setMappingDraft({ ...mappingDraft, control_id: event.target.value })}><option value="">Choose a control</option>{controls.map((control) => <option key={control.id} value={control.id}>{control.id} · {control.title}</option>)}</select></label>
          <label>Confidence (0–1)<input type="number" min="0" max="1" step="0.05" value={mappingDraft.confidence} onChange={(event) => setMappingDraft({ ...mappingDraft, confidence: event.target.value })} /></label>
          <label className="wide-field">Rationale<textarea required minLength={8} rows={2} value={mappingDraft.rationale} onChange={(event) => setMappingDraft({ ...mappingDraft, rationale: event.target.value })} /></label>
          <button className="primary-button" disabled={busy || !mappingDraft.control_id}>Add control mapping</button>
        </form>}
      </>}
    </>}</section></div>
  </>
}

function EvidenceSelect({ evidence, value, onChange, label }: { evidence: VerificationEvidence[]; value: string; onChange: (value: string) => void; label: string }) {
  return <label className="verification-select">{label}<select value={value} onChange={(event) => onChange(event.target.value)}><option value="">Select saved evidence</option>{evidence.map((item) => <option key={item.id} value={item.id}>{item.source} · {new Date(item.observed_at).toLocaleString()} · {item.is_synthetic ? 'synthetic Demo' : 'Live evidence'} · {item.id.slice(0, 8)}</option>)}</select></label>
}

function ActionRow({ action, evidence, ownerName, currentUserId, currentUsername, canEdit, busy, onSave }: { action: RemediationPlan['actions'][number]; evidence: VerificationEvidence[]; ownerName: string; currentUserId: string; currentUsername: string; canEdit: boolean; busy: boolean; onSave: (body: Record<string, unknown>) => unknown }) {
  const [status, setStatus] = useState(action.status)
  const [evidenceId, setEvidenceId] = useState(action.verification_evidence_id ?? '')
  const [notes, setNotes] = useState(action.notes ?? '')
  const [draft, setDraft] = useState(() => ({ title: action.title, description: action.description, action_type: action.action_type,
    owner_id: action.owner_id ?? '', priority: action.priority, due_at: localDateTime(action.due_at),
    assumptions: action.assumptions.join('\n'), verification_instructions: action.verification_instructions }))
  return <article className="remediation-record"><div className="task-main"><strong>{draft.title}</strong><small>{draft.action_type} · {draft.priority} priority · owner {draft.owner_id === currentUserId ? currentUsername : ownerName} · {draft.due_at ? new Date(draft.due_at).toLocaleDateString() : 'no due date'}</small><p>{draft.description}</p>{draft.verification_instructions && <small>Verify: {draft.verification_instructions}</small>}{draft.assumptions && <small>Assumptions: {draft.assumptions.split('\n').filter(Boolean).join(' · ')}</small>}</div>
    {canEdit ? <details className="remediation-editor"><summary>Edit action</summary><div className="remediation-controls">
      <label>Title<input required minLength={3} value={draft.title} onChange={(event) => setDraft({ ...draft, title: event.target.value })} /></label>
      <label>Action type<input required value={draft.action_type} onChange={(event) => setDraft({ ...draft, action_type: event.target.value })} /></label>
      <label>Owner<select value={draft.owner_id} onChange={(event) => setDraft({ ...draft, owner_id: event.target.value })}><option value="">Unassigned</option><option value={currentUserId}>{currentUsername} (you)</option>{action.owner_id && action.owner_id !== currentUserId && <option value={action.owner_id}>{action.owner_id}</option>}</select></label>
      <label>Priority<select value={draft.priority} onChange={(event) => setDraft({ ...draft, priority: event.target.value })}>{['low', 'medium', 'high', 'critical'].map((value) => <option key={value}>{value}</option>)}</select></label>
      <label>Due date<input type="datetime-local" value={draft.due_at} onChange={(event) => setDraft({ ...draft, due_at: event.target.value })} /></label>
      <label>Status<select value={status} disabled={busy} onChange={(event) => setStatus(event.target.value as RemediationStatus)}>{statuses.map((value) => <option key={value}>{value}</option>)}</select></label>
      <label className="wide-field">Description<textarea rows={2} value={draft.description} onChange={(event) => setDraft({ ...draft, description: event.target.value })} /></label>
      <label className="wide-field">Verification instructions<textarea rows={2} value={draft.verification_instructions} onChange={(event) => setDraft({ ...draft, verification_instructions: event.target.value })} /></label>
      <label>Assumptions, one per line<textarea rows={2} value={draft.assumptions} onChange={(event) => setDraft({ ...draft, assumptions: event.target.value })} /></label>
      <label>Notes<input value={notes} onChange={(event) => setNotes(event.target.value)} /></label>
      <EvidenceSelect evidence={evidence} value={evidenceId} onChange={setEvidenceId} label="Verification evidence"/>
      <button className="small-button" disabled={busy || (status === 'validated' && !evidenceId)} onClick={() => onSave({ ...draft, due_at: draft.due_at ? new Date(draft.due_at).toISOString() : null,
        owner_id: draft.owner_id || null, status, assumptions: draft.assumptions.split('\n').map((value) => value.trim()).filter(Boolean),
        notes: notes || null, verification_evidence_id: evidenceId || null })}>Save action</button>
    </div></details> : <div><StatusBadge value={action.status} /><p className="tiny-note">{action.verification_evidence_id ? `Verification evidence: ${action.verification_evidence_id}` : 'No verification evidence recorded.'}</p></div>}
  </article>
}

function MappingRow({ mapping, evidence, canEdit, busy, onSave }: { mapping: FindingControlMapping; evidence: VerificationEvidence[]; canEdit: boolean; busy: boolean; onSave: (body: Record<string, unknown>) => unknown }) {
  const [status, setStatus] = useState(mapping.status)
  const [evidenceId, setEvidenceId] = useState(mapping.verification_evidence_id ?? '')
  const [rationale, setRationale] = useState(mapping.rationale)
  const [confidence, setConfidence] = useState(String(mapping.confidence))
  return <article className="remediation-record"><div className="task-main"><strong>{mapping.control.id} · {mapping.control.title}</strong><small>Catalog {mapping.catalog_version} · confidence {Math.round(Number(confidence) * 100)}%</small><p>{mapping.control.objective}</p><small>{mapping.control.guidance}</small></div>
    {canEdit ? <div className="remediation-controls"><label>Rationale<textarea rows={2} minLength={8} value={rationale} onChange={(event) => setRationale(event.target.value)} /></label><label>Confidence<input type="number" min="0" max="1" step="0.05" value={confidence} onChange={(event) => setConfidence(event.target.value)} /></label><label>Status<select value={status} disabled={busy} onChange={(event) => setStatus(event.target.value as RemediationStatus)}>{statuses.map((value) => <option key={value}>{value}</option>)}</select></label><EvidenceSelect evidence={evidence} value={evidenceId} onChange={setEvidenceId} label="Verification evidence"/><button className="small-button" disabled={busy || (status === 'validated' && !evidenceId)} onClick={() => onSave({ rationale, confidence: Number(confidence), status, verification_evidence_id: evidenceId || null })}>Save mapping</button></div> : <div><p>{mapping.rationale}</p><StatusBadge value={mapping.status} /><p className="tiny-note">{mapping.verification_evidence_id ? `Evidence: ${mapping.verification_evidence_id}` : 'Not validated'}</p></div>}
  </article>
}

function localDateTime(value: string | null): string {
  if (!value) return ''
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return ''
  const pad = (number: number) => String(number).padStart(2, '0')
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`
}
