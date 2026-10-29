import type { paths } from './generated/api'

export type FastApiPaths = paths
const readinessRoute: keyof paths = '/api/v1/health/ready'

export type Readiness = {
  status: 'ready'
  service: string
  mode: 'demo' | 'live'
  demo_data: boolean
  dependencies: { database: boolean; redis: boolean; worker: boolean }
}

export type User = { id: string; username: string; email: string | null; role: 'admin' | 'analyst' | 'viewer'; must_change_password: boolean; is_active: boolean }
export type Asset = { id: string; kind: string; identifier: string; url_retention_complete: boolean; notes: string; criticality: 'unknown' | 'low' | 'medium' | 'high' | 'critical'; data_classification: 'unknown' | 'public' | 'internal' | 'confidential' | 'restricted'; trust_zone: 'unknown' | 'untrusted' | 'external' | 'partner' | 'internal' | 'restricted'; exposure_classification: 'unknown' | 'internet_facing' | 'partner_facing' | 'internal' | 'isolated'; business_owner: string | null; protection_requirements: string[]; authorized_at: string | null; authorization_note: string | null; authorization_id: string | null; authorization_expires_at: string | null; email_breach_authorization_id?: string | null; email_breach_authorization_expires_at?: string | null; components: Component[] }
export type ThreatStride = 'spoofing' | 'tampering' | 'repudiation' | 'information_disclosure' | 'denial_of_service' | 'elevation_of_privilege'
export type ThreatReviewStatus = 'draft' | 'needs_review' | 'confirmed' | 'rejected'
export type ThreatModelOwner = { id: string; username: string; role: User['role'] }
export type ThreatScenario = { id: string; asset_id: string; finding_id: string | null; investigation_id: string | null; incident_id: string | null; stride_category: ThreatStride; title: string; description: string; likelihood: number; business_impact: number; confidence: number; assumptions: string[]; unconfirmed_information: string[]; owner_id: string | null; review_status: ThreatReviewStatus; business_impact_score: number; calculation_explanation: string; score_notice: string; created_by: string; created_at: string; updated_at: string }
export type Component = { id: string; asset_id: string; vendor: string; product: string; version: string; cpe_name: string | null; package_ecosystem?: 'npm' | 'PyPI' | null; package_name?: string | null }
export type OsvFinding = { advisory_id: string; aliases: string[]; ecosystem: 'npm' | 'PyPI'; package_name: string; package_version: string; affected: Array<Record<string, unknown>>; fixed_versions: string[]; references: Array<{ type: string; url: string }>; severity_metadata: Array<{ type: string; score: string }>; published: string | null; modified: string | null; withdrawn: string | null; observed_at: string; provider_status: string; freshness: string; provider_version: string; advisory_status: string; evidence_id: string | null }
export type Finding = { id: string; asset_id: string; investigation_id: string; evidence_id: string | null; category: string; severity: string; title: string; explanation: string; recommendation: string; source: string; observed_at: string; applicability: string; applicability_reason: string | null; cvss_version: string | null; cvss_score: number | null; cvss_vector: string | null; kev: boolean | null; epss_score: number | null; epss_percentile: number | null; epss_observed_at: string | null; epss_provider_status: string | null; epss_freshness: string | null; is_synthetic: boolean; details_json: Record<string, unknown>; osv: OsvFinding | null }
export type Investigation = { id: string; asset_id: string; asset_kind: string | null; asset_identifier: string | null; mode: string; demo_data: boolean; scenario: string | null; email_breach_provider?: 'hibp' | 'xposedornot' | null; email_breach_authorization_id?: string | null; status: string; progress: number; started_at: string | null; finished_at: string | null; created_at: string; error_summary: string | null; attempt_number: number | null; risk: Risk | null }
export type InvestigationAttempt = { id: string; attempt_number: number; retry_kind: 'initial' | 'manual' | 'automatic' | 'recovery'; status: string; progress: number; started_at: string | null; finished_at: string | null; created_at: string; error_summary: string | null }
export type MonitoringCadence = 'daily' | 'weekly'
export type MonitoringScheduleStatus = 'active' | 'paused' | 'failed' | 'completed'
export type MonitoringSchedule = { id: string; asset_id: string; authorization_id: string; owner_id: string; mode: 'demo' | 'live'; cadence: MonitoringCadence; status: MonitoringScheduleStatus; next_run_at: string | null; last_run_at: string | null; failure_code: string | null; failure_detail: string | null; created_at: string; updated_at: string; completed_at: string | null }
export type MonitoringRun = { id: string; schedule_id: string; investigation_id: string; previous_investigation_id: string | null; scheduled_for: string; status: 'queued' | 'running' | 'completed' | 'partial' | 'failed'; started_at: string | null; finished_at: string | null; failure_detail: string | null; mode: 'demo' | 'live'; created_at: string }
export type GraphNodeType = 'asset' | 'domain' | 'ip' | 'certificate' | 'software' | 'cve' | 'finding' | 'investigation' | 'incident' | 'playbook_task'
export type GraphRelationshipType = 'investigated_in' | 'identifies_domain' | 'identifies_ip' | 'resolves_to' | 'redirects_to' | 'presents_certificate' | 'includes_software' | 'has_finding' | 'concerns_software' | 'references_cve' | 'potentially_affected_by' | 'concerns_asset' | 'tracks_finding' | 'belongs_to_incident'
export type EvidenceGraphNode = { id: string; type: GraphNodeType; label: string; details: Record<string, unknown> }
export type EvidenceGraphEdge = { id: string; from_node_id: string; from_node_type: GraphNodeType; to_node_id: string; to_node_type: GraphNodeType; relationship_type: GraphRelationshipType; evidence_role: 'direct' | 'contextual'; collector: string; source: string; evidence_id: string; observed_at: string; data_mode: 'demo' | 'live'; details: Record<string, unknown> }
export type EvidenceGraph = { investigation_id: string; generated_at: string; nodes: EvidenceGraphNode[]; edges: EvidenceGraphEdge[] }
export type EvidenceGraphChange = { status: 'new' | 'changed' | 'no_longer_observed' | 'unknown'; edge: EvidenceGraphEdge; previous_edge: EvidenceGraphEdge | null; reason: string }
export type EvidenceGraphChanges = { current_investigation_id: string; previous_investigation_id: string; changes: EvidenceGraphChange[]; counts: Record<EvidenceGraphChange['status'], number> }
export type RiskContributor = { finding_id: string; category: string; severity: string; severity_value: number | null; source: string; evidence_id: string | null; observed_at: string | null; category_score: number; weight_percent: number; kev_floor: boolean; cvss_unavailable?: boolean }
export type VulnerabilityIntelligenceTrace = { finding_id: string; cve_id: string | null; cvss: { version: string | null; score: number | null; severity: string; vector: string | null }; epss: { score: number | null; percentile: number | null; observed_at: string | null; provider_status: string; freshness: string; source_date: string | null; provider: string; provider_version: string; cache_state: string }; kev: boolean | null; applicability: string; evidence_id: string | null }
export type Risk = { version: string; score: number | null; band: string; assessed_categories: string[]; excluded_categories: string[]; category_scores: Record<string, unknown>; contributing_finding_ids: string[]; explanation: { weights_percent?: Record<string, number>; metric_notice?: string; calibration_notice?: string; rule_version?: string; contributors?: RiskContributor[]; vulnerability_intelligence?: VulnerabilityIntelligenceTrace[]; epss_notice?: string; freshness?: Record<string, { source: string; observed_at: string | null; state: string; source_timestamp: string | null }>; source_coverage?: Record<string, { status: string; provider: string; provider_version: string }>; coverage?: Record<string, { collectors: Record<string, string>; covered: boolean }>; [key: string]: unknown } }
export type RiskSensitivity = { version: string; baseline_score: number | null; variants: Array<{ category: string; weight_percent: number; lower_weight_percent: number; upper_weight_percent: number; lower_score: number | null; upper_score: number | null; lower_delta: number | null; upper_delta: number | null }> }
export type RiskSimulationAction = 'patch_applicable_cve' | 'fix_security_headers' | 'replace_expired_or_mismatched_certificate' | 'fix_spf_or_dmarc' | 'resolve_validated_reputation_finding' | 'resolve_verified_breach_issue'
export type RiskSimulationOption = { action: RiskSimulationAction; label: string; finding_id: string; finding_title: string; category: string; evidence_id: string; evidence_source: string; evidence_observed_at: string }
export type RiskSimulationScore = { policy_version: string; score: number | null; band: string; category_scores: Record<string, number>; assessed_categories: string[]; excluded_categories: string[] }
export type RiskSimulation = { investigation_id: string; action: RiskSimulationAction; action_label: string; risk_policy_version: string; baseline: RiskSimulationScore; projected: RiskSimulationScore; category_changes: Array<{ category: string; baseline_score: number | null; projected_score: number | null; change: number | null }>; affected: { finding_id: string; title: string; category: string; severity: string; source: string; evidence_id: string; evidence_source: string; evidence_observed_at: string; evidence_sha256: string; evidence_synthetic: boolean }; assumptions: string[] }
export type AttackTechnique = { id: string; name: string; tactics: string[]; url: string; external_id?: string | null; stix_id?: string | null; description?: string | null; tactic_ids?: string[]; selectable_tactics?: string[]; references?: Array<Record<string, string>>; created?: string | null; modified?: string | null; revoked?: boolean; deprecated?: boolean; is_subtechnique?: boolean; parent_id?: string | null; selectable?: boolean }
export type AttackCatalogVersion = { id: string; catalog_version: string; source: string; release_version: string | null; source_reference: string | null; retrieved_at: string | null; checksum: string | null; import_status: 'queued' | 'dispatched' | 'downloading' | 'validating' | 'active' | 'available' | 'failed' | 'duplicate'; active: boolean; technique_count: number; tactic_count: number; subtechnique_count: number; revoked_count: number; deprecated_count: number; error_summary: string | null; duplicate_of: string | null; requested_by: string | null; created_at: string; completed_at: string | null }
export type AttackCatalogVersions = { active_catalog_version: string | null; active: AttackCatalogVersion | null; versions: AttackCatalogVersion[]; attribution: string; checksum_notice: string }
export type AttackMapping = { id: string; finding_id: string | null; incident_id: string | null; technique_id: string; technique_name: string; tactic: string; catalog_version: string; catalog_release_version?: string | null; catalog_source?: string | null; catalog_source_reference?: string | null; catalog_checksum?: string | null; catalog_attribution?: string | null; rationale: string; confidence: number; source: string; evidence_role: 'direct' | 'contextual'; evidence_id: string; evidence_source: string; evidence_observed_at: string | null; decision: 'proposed' | 'approved' | 'rejected' | 'overridden'; analyst_confirmed: boolean; created_by: string; reviewed_by: string | null; reviewed_at: string | null; created_at: string; updated_at: string }
export type AttackSuggestion = Omit<AttackMapping, 'id' | 'decision' | 'analyst_confirmed' | 'created_by' | 'reviewed_by' | 'reviewed_at' | 'created_at' | 'updated_at' | 'evidence_source' | 'evidence_observed_at'> & { decision: 'suggested'; notice: string; incident_id: string | null }
export type AttackMatrix = { incident_id: string; catalog_version: string; tactics: Array<{ tactic: string; mappings: AttackMapping[] }>; mappings: AttackMapping[]; suggestions: AttackSuggestion[]; unmapped: Array<{ finding_id: string; title: string; category: string; reason: string }>; notice: string }
export type Incident = { id: string; title: string; summary: string; classification: string; status: string; priority: string; owner_id: string | null; owner: string | null; asset_id: string; asset_identifier: string | null; investigation_id: string | null; created_at: string; updated_at: string; closed_at: string | null; resolution_summary: string | null; findings?: Array<Record<string, unknown>>; evidence?: Array<Record<string, unknown>>; events?: Array<Record<string, unknown>>; tasks?: Array<Record<string, unknown>>; attack_matrix?: AttackMatrix }
export type Report = { id: string; format: 'pdf' | 'json'; investigation_id: string | null; incident_id: string | null; report_type?: 'investigation' | 'incident' | 'posture'; created_at: string; created_by: string; is_demo: boolean; sha256: string; download_url: string }
export type SpamhausDropStatus = {
  id: string; name: string; enabled: boolean; mode: 'demo' | 'live'; freshness: string
  snapshot_id: string | null; content_sha256: string | null; parser_version: string; record_count: number
  retrieved_at: string | null; published_at: string | null; last_successful_revalidation_at: string | null
  snapshot_age_seconds: number | null; freshness_limit_seconds: number; next_refresh_at: string | null
  metadata: Record<string, unknown> | null; attribution: string
  latest_attempt: { id: string; trigger_kind: string; status: string; requested_at: string; started_at: string | null; completed_at: string | null; snapshot_id: string | null; error_code: string | null } | null
  coverage_note: string
}
export type CinsArmyStatus = SpamhausDropStatus & { integrity_valid?: boolean | null }
export type OpenPhishStatus = SpamhausDropStatus & {
  configuration_state: string
  configuration_reason: string
  access_scope: string
  integrity_valid?: boolean | null
}
export type IpIntelligenceSource = {
  collector: string; source: string; collector_status: string; state: string; result: string
  freshness: string; snapshot_id: string | null; content_sha256: string | null
  observed_at: string | null; evidence_id: string | null; evidence: Record<string, unknown>
  classification?: string; reason?: string | null; investigation_id?: string
  investigation_created_at?: string
}
export type IpIntelligence = {
  asset_ip: string; sources: IpIntelligenceSource[]; listed_sources: string[]
  corroboration_label: string; corroboration_note: string; history: IpIntelligenceSource[]
}
export type PostureMetricState = 'available' | 'partial' | 'stale' | 'unavailable' | 'empty'
export type PostureMetric = { state: PostureMetricState; scope: string; range_days: number; window_start: string; window_end: string; note: string | null }
export type PostureRiskTrendPoint = { period_start: string; average_score: number; asset_count: number; policy_versions?: string[] }
export type PostureWorkflowTrendPoint = { period_start: string; investigations: Record<string, number>; monitoring_runs: Record<string, number> }
export type PostureProvider = { id: string; name: string; state: PostureMetricState; configured: boolean; eligible_asset_count: number; provider_status: string | string[] | null; source: string | null; last_observed_at: string | null; freshness: string; data_mode: 'demo' | 'live' | null; note: string | null }
export type PostureScorecard = {
  schema_version: string; generated_at: string; range_days: 7 | 30 | 90 | 365; window_start: string; window_end: string
  data_scope: { source: string; asset_count: number; investigation_count: number; data_modes: Array<'demo' | 'live'> }
  overall_risk: PostureMetric & { average_score: number | null; band: string | null; assets_in_scope: number; assets_with_score: number; assessments_used: number }
  assessment_coverage: PostureMetric & { assessed_category_slots: number; expected_category_slots: number; coverage_percent: number | null; assets_in_scope: number; assets_with_recent_assessment: number; assets_with_score: number; unassessed_category_slots: number }
  unassessed_categories: PostureMetric & { counts: Record<string, number>; assets_without_recent_assessment: number; total_unassessed_category_slots: number }
  high_critical_findings: PostureMetric & { high: number | null; critical: number | null; total: number | null; open_high: number | null; open_critical: number | null; open_total: number | null; open_counts_available: boolean; assets_with_recent_observation: number; assets_in_scope: number; lifecycle_status_available: boolean }
  repeated_findings: PostureMetric & { repeated_finding_count: number | null; repeated_observation_count: number | null; distinct_finding_identities: number | null; investigations_in_scope: number }
  risk_trend: PostureMetric & { interval: 'day' | 'week' | 'month'; points: PostureRiskTrendPoint[]; assessments_in_scope: number }
  workflow_trend: PostureMetric & { interval: 'day' | 'week' | 'month'; points: PostureWorkflowTrendPoint[]; investigations_count: number; monitoring_run_count: number }
  incident_timings: PostureMetric & { incident_count: number; triaged_count: number; triage_pending_or_unrecorded_count: number; triage_mean_seconds: number | null; triage_median_seconds: number | null; resolved_count: number; unresolved_or_unrecorded_count: number; resolution_mean_seconds: number | null; resolution_median_seconds: number | null }
  provider_health: PostureMetric & { providers: PostureProvider[] }
  asset_criticality: PostureMetric & { counts: Record<string, number>; asset_count: number }
  security_control_coverage: PostureMetric & { findings_in_scope: number; findings_with_mapping: number | null; findings_with_validated_mapping: number | null; mapped_finding_percent: number | null; validated_finding_percent: number | null; catalog_version: string; catalog_control_count: number; controls_with_validated_findings: number | null }
}
export type IntegrityState = 'verified' | 'failed' | 'unavailable' | 'incomplete'
export type AuditChainIntegrity = { state: IntegrityState; checked_at: string; event_count: number; verified_count: number; last_sequence: number | null; last_hash: string | null; failed_sequence: number | null; message: string }
export type EvidenceIntegrity = { evidence_id: string; state: IntegrityState; source: string | null; observed_at: string | null; stored_sha256: string | null; calculated_sha256: string | null; is_synthetic: boolean | null; message?: string | null }
export type IntegritySummary = { state: IntegrityState; checked_at: string; audit_chain: AuditChainIntegrity; evidence: { state: IntegrityState; total: number; checked: number; counts: Record<IntegrityState, number> } }
export type RemediationStatus = 'proposed' | 'planned' | 'implemented' | 'validated' | 'rejected' | 'not_applicable'
export type SecurityControl = { id: string; title: string; objective: string; guidance: string; frameworks: string[]; finding_categories: string[]; catalog_version: string }
export type VerificationEvidence = { id: string; source: string; observed_at: string; sha256: string; is_synthetic: boolean }
export type RemediationAction = { id: string; plan_id: string; title: string; description: string; action_type: string; owner_id: string | null; priority: string; due_at: string | null; status: RemediationStatus; assumptions: string[]; verification_instructions: string; notes: string | null; verification_evidence_id: string | null; validated_by: string | null; validated_at: string | null; created_by: string; created_at: string; updated_at: string }
export type FindingControlMapping = { id: string; finding_id: string; control_id: string; catalog_version: string; rationale: string; confidence: number; status: RemediationStatus; verification_evidence_id: string | null; validated_by: string | null; validated_at: string | null; created_by: string; created_at: string; updated_at: string; control: SecurityControl; verification_evidence: VerificationEvidence | null }
export type RemediationPlan = { id: string; title: string; description: string; action_type: string; finding_id: string | null; incident_id: string | null; playbook_task_id: string | null; owner_id: string | null; priority: string; due_at: string | null; status: RemediationStatus; assumptions: string[]; notes: string | null; created_by: string; created_at: string; updated_at: string; actions: RemediationAction[]; control_mappings: FindingControlMapping[]; verification_evidence: VerificationEvidence[] }

const apiBase = import.meta.env.VITE_API_BASE_URL ?? '/api/v1'

export class ApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message)
    this.name = 'ApiError'
  }
}

function csrfCookie(): string {
  return document.cookie.split('; ').find((part) => part.startsWith('cyberlens_csrf='))?.split('=').slice(1).join('=') ?? ''
}

export async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const method = (options.method ?? 'GET').toUpperCase()
  const headers = new Headers(options.headers)
  if (options.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) headers.set('X-CSRF-Token', csrfCookie())
  const response = await fetch(`${apiBase}${path}`, { ...options, method, headers, credentials: 'include' })
  if (!response.ok) {
    let message = `API returned ${response.status}`
    try {
      const body = await response.json() as { detail?: unknown }
      if (typeof body.detail === 'string') message = body.detail
      else if (body.detail) message = JSON.stringify(body.detail)
    } catch { /* keep the HTTP status message */ }
    throw new ApiError(message, response.status)
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

export async function getReadiness(signal?: AbortSignal): Promise<Readiness> {
  return request<Readiness>(readinessRoute.replace('/api/v1', ''), { signal })
}

export async function login(username: string, password: string): Promise<User> {
  const csrf = await request<{ csrf_token: string }>('/auth/csrf')
  const response = await fetch(`${apiBase}/auth/login`, { method: 'POST', credentials: 'include',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf.csrf_token }, body: JSON.stringify({ username, password }) })
  if (!response.ok) throw new Error(response.status === 401 ? 'Username or password is incorrect' : `Sign in failed (${response.status})`)
  return (await response.json() as { user: User }).user
}

export async function downloadReport(reportId: string): Promise<void> {
  const response = await fetch(`${apiBase}/reports/${reportId}/download`, { credentials: 'include' })
  if (!response.ok) throw new Error(`Download failed (${response.status})`)
  const blob = await response.blob()
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = `cyberlens-${reportId}.${response.headers.get('content-type')?.includes('pdf') ? 'pdf' : 'json'}`
  link.click()
  window.setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export async function downloadAuditExport(): Promise<void> {
  const response = await fetch(`${apiBase}/integrity/audit-export`, { credentials: 'include' })
  if (!response.ok) throw new Error(response.status === 403 ? 'Audit export requires an Analyst or Administrator role' : `Audit export failed (${response.status})`)
  const blob = await response.blob()
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = 'cyberlens-audit.jsonl'
  link.click()
  window.setTimeout(() => URL.revokeObjectURL(url), 1000)
}
