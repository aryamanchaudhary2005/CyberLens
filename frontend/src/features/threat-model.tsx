import { useEffect, useMemo, useState } from 'react'
import { request, type Asset, type Finding, type Incident, type Investigation, type ThreatModelOwner, type ThreatReviewStatus, type ThreatScenario, type ThreatStride, type User } from '../api'
import { Empty, PageTitle, StatusBadge } from '../components/ui'

const stride: Array<[ThreatStride, string]> = [
  ['spoofing', 'Spoofing'], ['tampering', 'Tampering'], ['repudiation', 'Repudiation'],
  ['information_disclosure', 'Information disclosure'], ['denial_of_service', 'Denial of service'], ['elevation_of_privilege', 'Elevation of privilege'],
]
const reviewStates: ThreatReviewStatus[] = ['draft', 'needs_review', 'confirmed', 'rejected']
const lines = (value: string) => value.split('\n').map((line) => line.trim()).filter(Boolean)
type Draft = { asset_id: string; finding_id: string; investigation_id: string; incident_id: string; stride_category: ThreatStride; title: string; description: string; likelihood: number; business_impact: number; confidence: number; assumptions: string; unconfirmed_information: string; owner_id: string; review_status: ThreatReviewStatus }
const emptyDraft = (assetId = ''): Draft => ({ asset_id: assetId, finding_id: '', investigation_id: '', incident_id: '', stride_category: 'spoofing', title: '', description: '', likelihood: 3, business_impact: 3, confidence: 2, assumptions: '', unconfirmed_information: '', owner_id: '', review_status: 'draft' })

export function ThreatModelScreen(props: { assets: Asset[]; investigations: Investigation[]; incidents: Incident[]; user: User; initialAssetId: string; selectedScenarioId: string; onSelectScenario: (id: string) => void; onAssetsChanged: () => Promise<void> }) {
  const canEdit = props.user.role === 'admin' || props.user.role === 'analyst'
  const [scenarios, setScenarios] = useState<ThreatScenario[]>([])
  const [owners, setOwners] = useState<ThreatModelOwner[]>([])
  const [assetId, setAssetId] = useState(props.initialAssetId)
  const [findings, setFindings] = useState<Finding[]>([])
  const [draft, setDraft] = useState<Draft>(emptyDraft())
  const [profile, setProfile] = useState({ criticality: 'unknown', data_classification: 'unknown', trust_zone: 'unknown', exposure_classification: 'unknown', business_owner: '', protection_requirements: '' })
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const selectedScenario = scenarios.find((item) => item.id === props.selectedScenarioId) ?? null
  const selectedAsset = props.assets.find((asset) => asset.id === assetId) ?? null
  const score = draft.likelihood * draft.business_impact
  const relevantInvestigations = useMemo(() => props.investigations.filter((item) => item.asset_id === assetId), [props.investigations, assetId])
  const relevantIncidents = useMemo(() => props.incidents.filter((item) => item.asset_id === assetId), [props.incidents, assetId])

  async function loadScenarios() {
    setLoading(true); setError('')
    try {
      const [nextScenarios, nextOwners] = await Promise.all([
        request<ThreatScenario[]>('/threat-model/scenarios?page=1&page_size=200'), request<ThreatModelOwner[]>('/threat-model/owners'),
      ])
      setScenarios(nextScenarios); setOwners(nextOwners)
    }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'Threat scenarios could not be loaded.') }
    finally { setLoading(false) }
  }
  useEffect(() => { void loadScenarios() }, [])
  useEffect(() => { if (!assetId && props.initialAssetId) setAssetId(props.initialAssetId) }, [assetId, props.initialAssetId])
  useEffect(() => {
    if (!assetId) { setFindings([]); return }
    let cancelled = false
    request<Finding[]>(`/findings?asset_id=${encodeURIComponent(assetId)}&limit=200`).then((items) => { if (!cancelled) setFindings(items) }).catch(() => { if (!cancelled) setFindings([]) })
    return () => { cancelled = true }
  }, [assetId])
  useEffect(() => {
    if (!selectedAsset) return
    setProfile({ criticality: selectedAsset.criticality, data_classification: selectedAsset.data_classification,
      trust_zone: selectedAsset.trust_zone, exposure_classification: selectedAsset.exposure_classification,
      business_owner: selectedAsset.business_owner ?? '', protection_requirements: selectedAsset.protection_requirements.join('\n') })
  }, [selectedAsset])
  useEffect(() => {
    if (!selectedScenario) { setDraft(emptyDraft(assetId)); return }
    setAssetId(selectedScenario.asset_id)
    setDraft({ asset_id: selectedScenario.asset_id, finding_id: selectedScenario.finding_id ?? '', investigation_id: selectedScenario.investigation_id ?? '', incident_id: selectedScenario.incident_id ?? '', stride_category: selectedScenario.stride_category,
      title: selectedScenario.title, description: selectedScenario.description, likelihood: selectedScenario.likelihood, business_impact: selectedScenario.business_impact, confidence: selectedScenario.confidence,
      assumptions: selectedScenario.assumptions.join('\n'), unconfirmed_information: selectedScenario.unconfirmed_information.join('\n'), owner_id: selectedScenario.owner_id ?? '', review_status: selectedScenario.review_status })
  }, [props.selectedScenarioId, selectedScenario?.updated_at])

  async function saveProfile(event: React.FormEvent) {
    event.preventDefault(); if (!selectedAsset || !canEdit) return
    setBusy(true); setError(''); setNotice('')
    try {
      await request(`/threat-model/assets/${selectedAsset.id}`, { method: 'PATCH', body: JSON.stringify({ ...profile, business_owner: profile.business_owner || null, protection_requirements: lines(profile.protection_requirements) }) })
      await props.onAssetsChanged(); setNotice('Asset threat context saved.')
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Asset threat context could not be saved.') }
    finally { setBusy(false) }
  }
  async function saveScenario(event: React.FormEvent) {
    event.preventDefault(); if (!canEdit) return
    setBusy(true); setError(''); setNotice('')
    const body = { asset_id: assetId, finding_id: draft.finding_id || null, investigation_id: draft.investigation_id || null, incident_id: draft.incident_id || null,
      stride_category: draft.stride_category, title: draft.title, description: draft.description, likelihood: Number(draft.likelihood), business_impact: Number(draft.business_impact), confidence: Number(draft.confidence),
      assumptions: lines(draft.assumptions), unconfirmed_information: lines(draft.unconfirmed_information), owner_id: draft.owner_id || null, review_status: draft.review_status }
    try {
      if (selectedScenario) await request(`/threat-model/scenarios/${selectedScenario.id}`, { method: 'PATCH', body: JSON.stringify(body) })
      else await request('/threat-model/scenarios', { method: 'POST', body: JSON.stringify(body) })
      await loadScenarios(); setNotice(selectedScenario ? 'Threat scenario updated.' : 'Threat scenario recorded.')
      if (!selectedScenario) setDraft(emptyDraft(assetId))
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Threat scenario could not be saved.') }
    finally { setBusy(false) }
  }

  return <>
    <PageTitle eyebrow="ANALYST WORKSPACE" title="Threat modeling" subtitle="Record STRIDE scenarios with explicit business context, review state, and analyst assumptions." />
    <div className="threat-model-layout">
      <section className="panel">
        <label>Asset<select value={assetId} onChange={(event) => { setAssetId(event.target.value); props.onSelectScenario(''); setDraft(emptyDraft(event.target.value)) }}><option value="">Select an asset</option>{props.assets.map((asset) => <option key={asset.id} value={asset.id}>{asset.identifier}</option>)}</select></label>
        {selectedAsset ? <>
          <form className="stack-form threat-profile" onSubmit={saveProfile}>
            <h2>Business and protection context</h2>
            <p className="card-note">Unknown is an explicit value. These fields describe business context and do not change technical severity or risk scoring.</p>
            <div className="form-grid">
              <label>Asset criticality<select disabled={!canEdit} value={profile.criticality} onChange={(e) => setProfile({ ...profile, criticality: e.target.value })}>{['unknown', 'low', 'medium', 'high', 'critical'].map((x) => <option key={x}>{x}</option>)}</select></label>
              <label>Data classification<select disabled={!canEdit} value={profile.data_classification} onChange={(e) => setProfile({ ...profile, data_classification: e.target.value })}>{['unknown', 'public', 'internal', 'confidential', 'restricted'].map((x) => <option key={x}>{x}</option>)}</select></label>
              <label>Trust zone<select disabled={!canEdit} value={profile.trust_zone} onChange={(e) => setProfile({ ...profile, trust_zone: e.target.value })}>{['unknown', 'untrusted', 'external', 'partner', 'internal', 'restricted'].map((x) => <option key={x}>{x}</option>)}</select></label>
              <label>Exposure classification<select disabled={!canEdit} value={profile.exposure_classification} onChange={(e) => setProfile({ ...profile, exposure_classification: e.target.value })}>{['unknown', 'internet_facing', 'partner_facing', 'internal', 'isolated'].map((x) => <option key={x}>{x}</option>)}</select></label>
            </div>
            <label>Business owner<input disabled={!canEdit} maxLength={200} value={profile.business_owner} onChange={(e) => setProfile({ ...profile, business_owner: e.target.value })} placeholder="Team or accountable owner" /></label>
            <label>Protection requirements<textarea disabled={!canEdit} rows={3} value={profile.protection_requirements} onChange={(e) => setProfile({ ...profile, protection_requirements: e.target.value })} placeholder="One requirement per line" /></label>
            {canEdit && <button className="small-button" disabled={busy}>Save asset context</button>}
          </form>
        </> : <Empty title="Choose an asset" text="Asset threat context and linked scenarios appear here." />}
      </section>
      <section className="panel">
        <div className="panel-heading"><div><p className="eyebrow">STRIDE · ANALYST ASSESSMENT</p><h2>{selectedScenario ? 'Review scenario' : 'New scenario'}</h2></div>{selectedScenario && <StatusBadge value={selectedScenario.review_status} />}</div>
        {canEdit && assetId ? <form className="stack-form" onSubmit={saveScenario}>
          <label>STRIDE category<select value={draft.stride_category} onChange={(e) => setDraft({ ...draft, stride_category: e.target.value as ThreatStride })}>{stride.map(([id, label]) => <option key={id} value={id}>{label}</option>)}</select></label>
          <label>Scenario title<input required minLength={3} maxLength={300} value={draft.title} onChange={(e) => setDraft({ ...draft, title: e.target.value })} /></label>
          <label>Description<textarea rows={3} maxLength={10000} value={draft.description} onChange={(e) => setDraft({ ...draft, description: e.target.value })} /></label>
          <div className="form-grid">
            <label>Finding link<select value={draft.finding_id} onChange={(e) => { const finding = findings.find((row) => row.id === e.target.value); setDraft({ ...draft, finding_id: e.target.value, investigation_id: finding?.investigation_id ?? draft.investigation_id }) }}><option value="">None</option>{findings.map((finding) => <option key={finding.id} value={finding.id}>{finding.title}</option>)}</select></label>
            <label>Investigation link<select value={draft.investigation_id} onChange={(e) => setDraft({ ...draft, investigation_id: e.target.value })}><option value="">None</option>{relevantInvestigations.map((item) => <option key={item.id} value={item.id}>{item.id.slice(0, 8)} · {item.status}</option>)}</select></label>
            <label>Incident link<select value={draft.incident_id} onChange={(e) => setDraft({ ...draft, incident_id: e.target.value })}><option value="">None</option>{relevantIncidents.map((item) => <option key={item.id} value={item.id}>{item.title}</option>)}</select></label>
            <label>Scenario owner<select value={draft.owner_id} onChange={(e) => setDraft({ ...draft, owner_id: e.target.value })}><option value="">Unassigned</option>{owners.map((owner) => <option key={owner.id} value={owner.id}>{owner.username} · {owner.role}</option>)}</select></label>
            <label>Likelihood (1–5)<input type="number" min={1} max={5} value={draft.likelihood} onChange={(e) => setDraft({ ...draft, likelihood: Number(e.target.value) })} /></label>
            <label>Business impact (1–5)<input type="number" min={1} max={5} value={draft.business_impact} onChange={(e) => setDraft({ ...draft, business_impact: Number(e.target.value) })} /></label>
            <label>Confidence (1–5)<input type="number" min={1} max={5} value={draft.confidence} onChange={(e) => setDraft({ ...draft, confidence: Number(e.target.value) })} /></label>
            <label>Review status<select value={draft.review_status} onChange={(e) => setDraft({ ...draft, review_status: e.target.value as ThreatReviewStatus })}>{reviewStates.map((x) => <option key={x}>{x}</option>)}</select></label>
          </div>
          <div className="risk-explanation" aria-live="polite"><strong>Business-impact scenario score: {score}/25</strong><p>Likelihood ({draft.likelihood}/5) × business impact ({draft.business_impact}/5) = {score}/25. Confidence is recorded separately and does not change this score.</p><small>Separate from technical severity and the CyberLens technical risk score.</small></div>
          <label>Analyst assumptions<textarea rows={3} value={draft.assumptions} onChange={(e) => setDraft({ ...draft, assumptions: e.target.value })} placeholder="One assumption per line" /></label>
          <label>Unconfirmed information<textarea rows={3} value={draft.unconfirmed_information} onChange={(e) => setDraft({ ...draft, unconfirmed_information: e.target.value })} placeholder="One unconfirmed item per line; unknown information is not treated as safe" /></label>
          <p className="card-note">Assumptions are analyst supplied. Keep unconfirmed information listed until it is verified; confirmed scenarios cannot contain unresolved items.</p>
          <div className="button-row"><button className="primary-button" disabled={busy || !draft.title.trim()}>{selectedScenario ? 'Save scenario' : 'Create scenario'}</button>{selectedScenario && <button type="button" className="small-button" onClick={() => { props.onSelectScenario(''); setDraft(emptyDraft(assetId)) }}>New scenario</button>}</div>
        </form> : !canEdit ? <p className="card-note">Viewers can review threat scenarios and asset context. Admin or Analyst role is required to make changes.</p> : <Empty title="Select an asset" text="Choose an asset before creating a threat scenario." />}
      </section>
    </div>
    <section className="panel threat-list">
      <div className="panel-heading"><div><p className="eyebrow">THREAT REGISTER</p><h2>Recorded scenarios</h2></div><button className="small-button" onClick={() => void loadScenarios()} disabled={loading}>Refresh</button></div>
      {error && <p className="error-text" role="alert">{error}</p>}{notice && <p className="success-text" role="status">{notice}</p>}
      {loading ? <p className="card-note" role="status">Loading threat scenarios…</p> : scenarios.length ? <ul className="threat-scenario-list">{scenarios.map((item) => <li key={item.id}><button className={`threat-scenario-row ${item.id === props.selectedScenarioId ? 'selected-row' : ''}`} onClick={() => { setAssetId(item.asset_id); props.onSelectScenario(item.id) }}><span><strong>{item.title}</strong><small>{stride.find(([id]) => id === item.stride_category)?.[1]} · {props.assets.find((asset) => asset.id === item.asset_id)?.identifier ?? 'Asset'} · likelihood {item.likelihood}/5 · business impact {item.business_impact}/5</small>{item.unconfirmed_information.length > 0 && <small className="warning-text">Unconfirmed: {item.unconfirmed_information.join('; ')}</small>}{item.assumptions.length > 0 && <small>Analyst assumptions: {item.assumptions.join('; ')}</small>}</span><span className="threat-score">{item.business_impact_score}/25 <StatusBadge value={item.review_status} /></span></button></li>)}</ul> : <Empty title="No scenarios recorded" text="Create a STRIDE scenario for an asset when an analyst assessment is needed." />}
    </section>
  </>
}
