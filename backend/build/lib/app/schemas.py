from datetime import datetime
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from app.package_names import normalize_package_name


class UserOut(BaseModel):
    id: str
    username: str
    email: str | None
    role: str
    is_active: bool
    must_change_password: bool
    model_config = ConfigDict(from_attributes=True)


class AuditEventOut(BaseModel):
    id: str
    event_sequence: int
    previous_hash: str
    current_hash: str
    actor_id: str | None
    actor: str | None
    action: str
    entity_type: str
    entity_id: str
    details: dict[str, Any]
    metadata: dict[str, Any]
    created_at: datetime


IntegrityState = Literal["verified", "failed", "unavailable", "incomplete"]


class AuditChainIntegrityOut(BaseModel):
    state: IntegrityState
    checked_at: datetime
    event_count: int
    verified_count: int
    last_sequence: int | None
    last_hash: str | None
    failed_sequence: int | None
    message: str


class EvidenceIntegrityOut(BaseModel):
    evidence_id: str
    state: IntegrityState
    source: str | None
    observed_at: datetime | None
    stored_sha256: str | None
    calculated_sha256: str | None
    is_synthetic: bool | None
    message: str | None = None


class IntegritySummaryOut(BaseModel):
    state: IntegrityState
    checked_at: datetime
    audit_chain: AuditChainIntegrityOut
    evidence: dict[str, Any]


class ReportIntegrityOut(IntegritySummaryOut):
    evidence: dict[str, Any]
    limitation: str


class IncidentSummaryOut(BaseModel):
    id: str
    title: str
    summary: str
    classification: str
    status: str
    priority: str
    owner_id: str | None
    owner: str | None
    asset_id: str
    asset_identifier: str | None
    investigation_id: str | None
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None
    resolution_summary: str | None


class ReportOut(BaseModel):
    id: str
    format: Literal["pdf", "json"]
    investigation_id: str | None
    incident_id: str | None
    report_type: Literal["investigation", "incident", "posture"]
    created_at: str
    created_by: str
    is_demo: bool
    sha256: str
    download_url: str


PostureMetricState = Literal["available", "partial", "stale", "unavailable", "empty"]


class PostureMetricOut(BaseModel):
    state: PostureMetricState
    scope: str
    range_days: int
    window_start: datetime
    window_end: datetime
    note: str | None


class PostureOverallRiskOut(PostureMetricOut):
    average_score: float | None
    band: str | None
    assets_in_scope: int
    assets_with_score: int
    assessments_used: int


class PostureAssessmentCoverageOut(PostureMetricOut):
    assessed_category_slots: int
    expected_category_slots: int
    coverage_percent: float | None
    assets_in_scope: int
    assets_with_recent_assessment: int
    assets_with_score: int
    unassessed_category_slots: int


class PostureUnassessedCategoriesOut(PostureMetricOut):
    counts: dict[str, int]
    assets_without_recent_assessment: int
    total_unassessed_category_slots: int


class PostureHighCriticalFindingsOut(PostureMetricOut):
    high: int | None
    critical: int | None
    total: int | None
    open_high: int | None
    open_critical: int | None
    open_total: int | None
    open_counts_available: bool
    assets_with_recent_observation: int
    assets_in_scope: int
    lifecycle_status_available: bool


class PostureRepeatedFindingsOut(PostureMetricOut):
    repeated_finding_count: int | None
    repeated_observation_count: int | None
    distinct_finding_identities: int | None
    investigations_in_scope: int


class PostureRiskTrendPointOut(BaseModel):
    period_start: str
    average_score: float
    asset_count: int
    policy_versions: list[str] = Field(default_factory=list)


class PostureRiskTrendOut(PostureMetricOut):
    interval: Literal["day", "week", "month"]
    points: list[PostureRiskTrendPointOut]
    assessments_in_scope: int


class PostureWorkflowTrendPointOut(BaseModel):
    period_start: str
    investigations: dict[str, int]
    monitoring_runs: dict[str, int]


class PostureWorkflowTrendOut(PostureMetricOut):
    interval: Literal["day", "week", "month"]
    points: list[PostureWorkflowTrendPointOut]
    investigations_count: int
    monitoring_run_count: int


class PostureIncidentTimingsOut(PostureMetricOut):
    incident_count: int
    triaged_count: int
    triage_pending_or_unrecorded_count: int
    triage_mean_seconds: float | None
    triage_median_seconds: float | None
    resolved_count: int
    unresolved_or_unrecorded_count: int
    resolution_mean_seconds: float | None
    resolution_median_seconds: float | None


class PostureProviderOut(BaseModel):
    id: str
    name: str
    state: PostureMetricState
    configured: bool
    eligible_asset_count: int
    provider_status: str | list[str] | None
    source: str | None
    last_observed_at: datetime | None
    freshness: str
    data_mode: Literal["demo", "live"] | None
    note: str | None


class PostureProviderHealthOut(PostureMetricOut):
    providers: list[PostureProviderOut]


class PostureAssetCriticalityOut(PostureMetricOut):
    counts: dict[str, int]
    asset_count: int


class PostureSecurityControlCoverageOut(PostureMetricOut):
    findings_in_scope: int
    findings_with_mapping: int | None
    findings_with_validated_mapping: int | None
    mapped_finding_percent: float | None
    validated_finding_percent: float | None
    catalog_version: str
    catalog_control_count: int
    controls_with_validated_findings: int | None


class PostureDataScopeOut(BaseModel):
    source: str
    asset_count: int
    investigation_count: int
    data_modes: list[Literal["demo", "live"]]


class PostureScorecardOut(BaseModel):
    schema_version: str
    generated_at: datetime
    range_days: Literal[7, 30, 90, 365]
    window_start: datetime
    window_end: datetime
    data_scope: PostureDataScopeOut
    overall_risk: PostureOverallRiskOut
    assessment_coverage: PostureAssessmentCoverageOut
    unassessed_categories: PostureUnassessedCategoriesOut
    high_critical_findings: PostureHighCriticalFindingsOut
    repeated_findings: PostureRepeatedFindingsOut
    risk_trend: PostureRiskTrendOut
    workflow_trend: PostureWorkflowTrendOut
    incident_timings: PostureIncidentTimingsOut
    provider_health: PostureProviderHealthOut
    asset_criticality: PostureAssetCriticalityOut
    security_control_coverage: PostureSecurityControlCoverageOut


class PostureReportCreate(BaseModel):
    format: Literal["pdf", "json"]
    range_days: Literal[7, 30, 90, 365] = 30


class LoginInput(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=256)


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=80, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=12, max_length=256)
    email: str | None = Field(default=None, max_length=320)
    role: Literal["admin", "analyst", "viewer"] = "analyst"

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value.strip()):
            raise ValueError("Enter a valid email address")
        return value.strip().lower() if value else value


class UserRoleUpdate(BaseModel):
    role: Literal["admin", "analyst", "viewer"]


class AdminPasswordReset(BaseModel):
    new_password: str = Field(min_length=12, max_length=256)


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


class AssetCreate(BaseModel):
    kind: Literal["domain", "ip", "url", "email", "application"]
    identifier: str = Field(min_length=1, max_length=2048)
    notes: str = Field(default="", max_length=10000)


class AssetUpdate(BaseModel):
    notes: str = Field(max_length=10000)


class URLRetentionConfirmation(BaseModel):
    identifier: str = Field(min_length=1, max_length=2048)


class AuthorizationInput(BaseModel):
    authorized: Literal[True]
    note: str = Field(min_length=8, max_length=1000)
    expires_in_days: int = Field(default=30, ge=1, le=365)


class WebsiteAuthorizationOut(BaseModel):
    id: str
    asset_id: str
    authorized_by: str | None
    note: str
    created_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    revoked_by: str | None

    model_config = ConfigDict(from_attributes=True)


class ComponentOut(BaseModel):
    id: str
    asset_id: str
    vendor: str
    product: str
    version: str
    cpe_name: str | None
    package_ecosystem: Literal["npm", "PyPI"] | None = None
    package_name: str | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AssetOut(BaseModel):
    id: str
    kind: str
    identifier: str
    url_retention_complete: bool
    notes: str
    criticality: Literal["unknown", "low", "medium", "high", "critical"]
    data_classification: Literal["unknown", "public", "internal", "confidential", "restricted"]
    trust_zone: Literal["unknown", "untrusted", "external", "partner", "internal", "restricted"]
    exposure_classification: Literal["unknown", "internet_facing", "partner_facing", "internal", "isolated"]
    business_owner: str | None
    protection_requirements: list[str]
    authorized_at: datetime | None
    authorization_note: str | None
    authorization_id: str | None
    authorization_expires_at: datetime | None
    email_breach_authorization_id: str | None = None
    email_breach_authorization_expires_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
    components: list[ComponentOut]

    model_config = ConfigDict(from_attributes=True)


class ComponentCreate(BaseModel):
    vendor: str = Field(min_length=1, max_length=200)
    product: str = Field(min_length=1, max_length=200)
    version: str = Field(min_length=1, max_length=100)
    cpe_name: str | None = Field(default=None, max_length=1024)
    package_ecosystem: Literal["npm", "PyPI"] | None = None
    package_name: str | None = Field(default=None, max_length=214)

    @field_validator("vendor", "product", "version")
    @classmethod
    def require_non_whitespace(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Value cannot be blank")
        return value.strip()

    @model_validator(mode="after")
    def validate_package_identity(self):
        if (self.package_ecosystem is None) != (self.package_name is None):
            raise ValueError("Package ecosystem and package name must be supplied together")
        if self.package_ecosystem is not None and self.package_name is not None:
            self.package_name = normalize_package_name(self.package_ecosystem, self.package_name)
        return self


class InvestigationCreate(BaseModel):
    asset_id: str
    scenario: Literal[
        "routine_website", "suspicious_website", "exposed_email", "vulnerable_application", "provider_outage",
        "ip_cins_only", "ip_overlap", "ip_no_match", "ip_provider_outage",
        "openphish_match", "openphish_overlap", "openphish_no_match", "openphish_outage",
    ] | None = None
    # Omission preserves the existing HIBP behavior for email investigations.
    email_breach_provider: Literal["hibp", "xposedornot"] | None = None
    xposedornot_authorization_confirmed: bool = False


class InvestigationQueuedOut(BaseModel):
    id: str
    status: str
    progress: int
    mode: Literal["demo", "live"]
    scenario: str | None
    attempt_id: str
    attempt_number: int


class EmailBreachAuthorizationOut(BaseModel):
    id: str
    asset_id: str
    provider: Literal["xposedornot"]
    authorized_by: str | None
    consent_version: str
    created_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    revoked_by: str | None

    model_config = ConfigDict(from_attributes=True)


class InvestigationRetryOut(BaseModel):
    id: str
    status: str
    progress: int
    retry: bool
    attempt_id: str
    attempt_number: int


class MonitoringScheduleCreate(BaseModel):
    asset_id: str
    authorization_id: str
    cadence: Literal["daily", "weekly"]


class MonitoringScheduleResume(BaseModel):
    authorization_id: str | None = None


class MonitoringScheduleOut(BaseModel):
    id: str
    asset_id: str
    authorization_id: str
    owner_id: str
    mode: Literal["demo", "live"]
    cadence: Literal["daily", "weekly"]
    status: Literal["active", "paused", "failed", "completed"]
    next_run_at: datetime | None
    last_run_at: datetime | None
    failure_code: str | None
    failure_detail: str | None
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None


class MonitoringRunOut(BaseModel):
    id: str
    schedule_id: str
    investigation_id: str
    previous_investigation_id: str | None
    scheduled_for: datetime
    status: Literal["queued", "running", "completed", "partial", "failed"]
    started_at: datetime | None
    finished_at: datetime | None
    failure_detail: str | None
    mode: Literal["demo", "live"]
    created_at: datetime


class InvestigationAttemptOut(BaseModel):
    id: str
    attempt_number: int
    retry_kind: Literal["initial", "manual", "automatic", "recovery"]
    status: str
    progress: int
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime
    error_summary: str | None


class CollectorRunOut(BaseModel):
    id: str
    collector: str
    status: str
    source: str
    error_explanation: str | None
    record_count: int
    attempt_id: str | None
    attempt_number: int | None
    feed_snapshot_id: str | None = None
    started_at: datetime | None
    finished_at: datetime | None


class ThreatFeedRefreshAttemptOut(BaseModel):
    id: str
    trigger_kind: Literal["scheduled", "admin"]
    status: str
    requested_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    snapshot_id: str | None
    error_code: str | None


class SpamhausDropStatusOut(BaseModel):
    id: str
    name: str
    enabled: bool
    mode: Literal["demo", "live"]
    freshness: str
    snapshot_id: str | None
    content_sha256: str | None
    parser_version: str
    record_count: int
    retrieved_at: datetime | None
    published_at: datetime | None
    last_successful_revalidation_at: datetime | None
    snapshot_age_seconds: int | None
    freshness_limit_seconds: int
    next_refresh_at: datetime | None
    metadata: dict[str, Any] | None
    attribution: str
    latest_attempt: ThreatFeedRefreshAttemptOut | None
    coverage_note: str


class CinsArmyStatusOut(SpamhausDropStatusOut):
    """Status for the shared feed snapshot infrastructure's CINS Army source."""
    integrity_valid: bool | None = None


class OpenPhishStatusOut(SpamhausDropStatusOut):
    """OpenPhish status includes operator access scope without exposing feed indicators."""
    configuration_state: str
    configuration_reason: str
    access_scope: str
    integrity_valid: bool | None = None


class ThreatFeedRefreshQueuedOut(BaseModel):
    id: str
    status: str
    trigger_kind: Literal["scheduled", "admin"]
    requested_at: datetime
    next_refresh_at: datetime
    message: str


class InvestigationRiskOut(BaseModel):
    version: str
    score: float | None
    band: str
    assessed_categories: list[str]
    excluded_categories: list[str]
    category_scores: dict[str, Any]
    contributing_finding_ids: list[str]
    explanation: dict[str, Any]


class RiskAssessmentRevisionOut(BaseModel):
    id: str
    investigation_id: str
    revision_number: int
    input_fingerprint: str
    version: str
    score: float | None
    band: str
    weights: dict[str, Any]
    assessed_categories: list[str]
    excluded_categories: list[str]
    category_scores: dict[str, Any]
    contributing_finding_ids: list[str]
    explanation: dict[str, Any]
    created_at: datetime


class RiskSensitivityOut(BaseModel):
    version: str
    baseline_score: float | None
    variants: list[dict[str, Any]]


RiskSimulationAction = Literal[
    "patch_applicable_cve",
    "fix_security_headers",
    "replace_expired_or_mismatched_certificate",
    "fix_spf_or_dmarc",
    "resolve_validated_reputation_finding",
    "resolve_verified_breach_issue",
]


class RiskSimulationInput(BaseModel):
    action: RiskSimulationAction
    finding_id: str = Field(min_length=1, max_length=36)


class RiskSimulationOptionOut(BaseModel):
    action: RiskSimulationAction
    label: str
    finding_id: str
    finding_title: str
    category: str
    evidence_id: str
    evidence_source: str
    evidence_observed_at: datetime


class RiskSimulationScoreOut(BaseModel):
    policy_version: str
    score: float | None
    band: str
    category_scores: dict[str, Any]
    assessed_categories: list[str]
    excluded_categories: list[str]


class RiskSimulationCategoryChangeOut(BaseModel):
    category: str
    baseline_score: float | None
    projected_score: float | None
    change: float | None


class RiskSimulationAffectedOut(BaseModel):
    finding_id: str
    title: str
    category: str
    severity: str
    source: str
    evidence_id: str
    evidence_source: str
    evidence_observed_at: datetime
    evidence_sha256: str
    evidence_synthetic: bool


class RiskSimulationOut(BaseModel):
    investigation_id: str
    action: RiskSimulationAction
    action_label: str
    risk_policy_version: str
    baseline: RiskSimulationScoreOut
    projected: RiskSimulationScoreOut
    category_changes: list[RiskSimulationCategoryChangeOut]
    affected: RiskSimulationAffectedOut
    assumptions: list[str]


class InvestigationSummaryOut(BaseModel):
    id: str
    asset_id: str
    asset_kind: str | None
    asset_identifier: str | None
    mode: Literal["demo", "live"]
    demo_data: bool
    scenario: str | None
    email_breach_provider: Literal["hibp", "xposedornot"] | None = None
    email_breach_authorization_id: str | None = None
    status: str
    progress: int
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime
    error_summary: str | None
    attempt_number: int | None
    risk: InvestigationRiskOut | None


class InvestigationComponentOut(BaseModel):
    id: str
    vendor: str
    product: str
    version: str
    cpe_name: str | None
    package_ecosystem: Literal["npm", "PyPI"] | None = None
    package_name: str | None = None


class InvestigationAssetDetailOut(BaseModel):
    id: str
    kind: str
    identifier: str
    notes: str
    authorized_at: datetime | None
    authorization_note: str | None
    authorization_id: str | None
    authorization_expires_at: datetime | None
    components: list[InvestigationComponentOut]


class EvidenceSnapshotOut(BaseModel):
    id: str
    source: str
    observed_at: datetime
    evidence_json: dict[str, Any]
    sha256: str
    is_synthetic: bool


class ApplicabilityInput(BaseModel):
    applicability: Literal["applies", "does_not_apply", "needs_review"]
    reason: str = Field(min_length=5, max_length=2000)


class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=300)
    summary: str = Field(default="", max_length=10000)
    asset_id: str
    investigation_id: str | None = None
    finding_ids: list[str] = Field(default_factory=list, max_length=100)
    priority: Literal["low", "medium", "high", "critical"] = "medium"
    classification: Literal["suspected_incident", "confirmed_incident", "security_issue", "false_positive"] = "suspected_incident"


class IncidentUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=300)
    summary: str | None = Field(default=None, max_length=10000)
    owner_id: str | None = None
    priority: Literal["low", "medium", "high", "critical"] | None = None
    classification: Literal["suspected_incident", "confirmed_incident", "security_issue", "false_positive"] | None = None
    status: Literal["new", "triaged", "responding", "resolved", "closed"] | None = None
    resolution_summary: str | None = Field(default=None, max_length=10000)
    reason: str | None = Field(default=None, max_length=2000)


class EventCreate(BaseModel):
    message: str = Field(min_length=1, max_length=10000)
    event_type: str = Field(default="note", max_length=40)


class TaskUpdate(BaseModel):
    status: Literal["pending", "in_progress", "completed", "skipped"]
    notes: str | None = Field(default=None, max_length=4000)


class ReportCreate(BaseModel):
    format: Literal["json", "pdf"]
    investigation_id: str | None = None
    incident_id: str | None = None


ThreatStride = Literal["spoofing", "tampering", "repudiation", "information_disclosure", "denial_of_service", "elevation_of_privilege"]
ThreatReviewStatus = Literal["draft", "needs_review", "confirmed", "rejected"]


class ThreatProfileUpdate(BaseModel):
    criticality: Literal["unknown", "low", "medium", "high", "critical"] | None = None
    data_classification: Literal["unknown", "public", "internal", "confidential", "restricted"] | None = None
    trust_zone: Literal["unknown", "untrusted", "external", "partner", "internal", "restricted"] | None = None
    exposure_classification: Literal["unknown", "internet_facing", "partner_facing", "internal", "isolated"] | None = None
    business_owner: str | None = Field(default=None, max_length=200)
    protection_requirements: list[str] | None = Field(default=None, max_length=30)


class AssetThreatProfileOut(BaseModel):
    id: str
    kind: str
    identifier: str
    criticality: Literal["unknown", "low", "medium", "high", "critical"]
    data_classification: Literal["unknown", "public", "internal", "confidential", "restricted"]
    trust_zone: Literal["unknown", "untrusted", "external", "partner", "internal", "restricted"]
    exposure_classification: Literal["unknown", "internet_facing", "partner_facing", "internal", "isolated"]
    business_owner: str | None
    protection_requirements: list[str]


class ThreatModelOwnerOut(BaseModel):
    id: str
    username: str
    role: Literal["admin", "analyst", "viewer"]


class ThreatScenarioCreate(BaseModel):
    asset_id: str
    finding_id: str | None = None
    investigation_id: str | None = None
    incident_id: str | None = None
    stride_category: ThreatStride
    title: str = Field(min_length=3, max_length=300)
    description: str = Field(default="", max_length=10000)
    likelihood: int = Field(ge=1, le=5)
    business_impact: int = Field(ge=1, le=5)
    confidence: int = Field(ge=1, le=5)
    assumptions: list[str] = Field(default_factory=list, max_length=30)
    unconfirmed_information: list[str] = Field(default_factory=list, max_length=30)
    owner_id: str | None = None
    review_status: ThreatReviewStatus = "draft"


class ThreatScenarioUpdate(BaseModel):
    finding_id: str | None = None
    investigation_id: str | None = None
    incident_id: str | None = None
    stride_category: ThreatStride | None = None
    title: str | None = Field(default=None, min_length=3, max_length=300)
    description: str | None = Field(default=None, max_length=10000)
    likelihood: int | None = Field(default=None, ge=1, le=5)
    business_impact: int | None = Field(default=None, ge=1, le=5)
    confidence: int | None = Field(default=None, ge=1, le=5)
    assumptions: list[str] | None = Field(default=None, max_length=30)
    unconfirmed_information: list[str] | None = Field(default=None, max_length=30)
    owner_id: str | None = None
    review_status: ThreatReviewStatus | None = None


class ThreatScenarioOut(BaseModel):
    id: str
    asset_id: str
    finding_id: str | None
    investigation_id: str | None
    incident_id: str | None
    stride_category: ThreatStride
    title: str
    description: str
    likelihood: int
    business_impact: int
    confidence: int
    assumptions: list[str]
    unconfirmed_information: list[str]
    owner_id: str | None
    review_status: ThreatReviewStatus
    business_impact_score: int
    calculation_explanation: str
    score_notice: str
    created_by: str
    created_at: datetime
    updated_at: datetime


RemediationStatus = Literal["proposed", "planned", "implemented", "validated", "rejected", "not_applicable"]
RemediationPriority = Literal["low", "medium", "high", "critical"]


class RemediationPlanCreate(BaseModel):
    title: str = Field(min_length=3, max_length=300)
    description: str = Field(default="", max_length=10000)
    action_type: str = Field(min_length=2, max_length=80)
    finding_id: str | None = None
    incident_id: str | None = None
    playbook_task_id: str | None = None
    owner_id: str | None = None
    priority: RemediationPriority = "medium"
    due_at: datetime | None = None
    status: RemediationStatus = "proposed"
    assumptions: list[str] = Field(default_factory=list, max_length=50)
    notes: str | None = Field(default=None, max_length=4000)


class RemediationPlanUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=300)
    description: str | None = Field(default=None, max_length=10000)
    action_type: str | None = Field(default=None, min_length=2, max_length=80)
    finding_id: str | None = None
    incident_id: str | None = None
    playbook_task_id: str | None = None
    owner_id: str | None = None
    priority: RemediationPriority | None = None
    due_at: datetime | None = None
    status: RemediationStatus | None = None
    assumptions: list[str] | None = Field(default=None, max_length=50)
    notes: str | None = Field(default=None, max_length=4000)


class RemediationActionCreate(BaseModel):
    title: str = Field(min_length=3, max_length=300)
    description: str = Field(default="", max_length=10000)
    action_type: str = Field(min_length=2, max_length=80)
    owner_id: str | None = None
    priority: RemediationPriority = "medium"
    due_at: datetime | None = None
    status: RemediationStatus = "proposed"
    assumptions: list[str] = Field(default_factory=list, max_length=50)
    verification_instructions: str = Field(default="", max_length=10000)
    notes: str | None = Field(default=None, max_length=4000)
    verification_evidence_id: str | None = None


class RemediationActionUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=300)
    description: str | None = Field(default=None, max_length=10000)
    action_type: str | None = Field(default=None, min_length=2, max_length=80)
    owner_id: str | None = None
    priority: RemediationPriority | None = None
    due_at: datetime | None = None
    status: RemediationStatus | None = None
    assumptions: list[str] | None = Field(default=None, max_length=50)
    verification_instructions: str | None = Field(default=None, max_length=10000)
    notes: str | None = Field(default=None, max_length=4000)
    verification_evidence_id: str | None = None


class FindingControlMappingCreate(BaseModel):
    control_id: str = Field(min_length=2, max_length=80)
    rationale: str = Field(min_length=8, max_length=4000)
    confidence: float = Field(ge=0, le=1)
    status: RemediationStatus = "proposed"
    verification_evidence_id: str | None = None


class FindingControlMappingUpdate(BaseModel):
    rationale: str | None = Field(default=None, min_length=8, max_length=4000)
    confidence: float | None = Field(default=None, ge=0, le=1)
    status: RemediationStatus | None = None
    verification_evidence_id: str | None = None


class SecurityControlOut(BaseModel):
    id: str
    title: str
    objective: str
    guidance: str
    frameworks: list[str]
    finding_categories: list[str]
    catalog_version: str


class VerificationEvidenceOut(BaseModel):
    id: str
    source: str
    observed_at: datetime
    sha256: str
    is_synthetic: bool


class RemediationActionOut(BaseModel):
    id: str
    plan_id: str
    title: str
    description: str
    action_type: str
    owner_id: str | None
    priority: str
    due_at: datetime | None
    status: str
    assumptions: list[str]
    verification_instructions: str
    notes: str | None
    verification_evidence_id: str | None
    validated_by: str | None
    validated_at: datetime | None
    created_by: str
    created_at: datetime
    updated_at: datetime


class FindingControlMappingOut(BaseModel):
    id: str
    finding_id: str
    control_id: str
    catalog_version: str
    rationale: str
    confidence: float
    status: str
    verification_evidence_id: str | None
    validated_by: str | None
    validated_at: datetime | None
    created_by: str
    created_at: datetime
    updated_at: datetime
    control: SecurityControlOut
    verification_evidence: VerificationEvidenceOut | None


class RemediationPlanOut(BaseModel):
    id: str
    title: str
    description: str
    action_type: str
    finding_id: str | None
    incident_id: str | None
    playbook_task_id: str | None
    owner_id: str | None
    priority: str
    due_at: datetime | None
    status: str
    assumptions: list[str]
    notes: str | None
    created_by: str
    created_at: datetime
    updated_at: datetime
    actions: list[RemediationActionOut] = Field(default_factory=list)
    control_mappings: list[FindingControlMappingOut] = Field(default_factory=list)
    verification_evidence: list[VerificationEvidenceOut] = Field(default_factory=list)


class OsvFindingOut(BaseModel):
    advisory_id: str
    aliases: list[str]
    ecosystem: Literal["npm", "PyPI"]
    package_name: str
    package_version: str
    affected: list[dict[str, Any]]
    fixed_versions: list[str]
    references: list[dict[str, str]]
    severity_metadata: list[dict[str, str]]
    published: str | None
    modified: str | None
    withdrawn: str | None
    observed_at: datetime
    provider_status: str
    freshness: str
    provider_version: str
    advisory_status: str
    evidence_id: str | None


class FindingOut(BaseModel):
    id: str
    asset_id: str
    investigation_id: str
    evidence_id: str | None
    category: str
    severity: str
    title: str
    explanation: str
    recommendation: str
    source: str
    observed_at: datetime
    applicability: str
    applicability_reason: str | None
    cvss_version: str | None
    cvss_score: float | None
    cvss_vector: str | None
    kev: bool | None
    epss_score: float | None
    epss_percentile: float | None
    epss_observed_at: datetime | None
    epss_provider_status: str | None
    epss_freshness: str | None
    is_synthetic: bool
    details_json: dict[str, Any]
    osv: OsvFindingOut | None = None
    model_config = ConfigDict(from_attributes=True)


class AttackMappingCreate(BaseModel):
    finding_id: str | None = None
    incident_id: str | None = None
    catalog_version: str | None = Field(default=None, min_length=1, max_length=128)
    technique_id: str = Field(min_length=3, max_length=20)
    tactic: str = Field(min_length=2, max_length=80)
    evidence_id: str = Field(min_length=1, max_length=36)
    rationale: str = Field(min_length=8, max_length=4000)
    confidence: float = Field(ge=0, le=1)
    evidence_role: Literal["direct", "contextual"] = "contextual"

    @model_validator(mode="after")
    def exactly_one_target(self):
        if bool(self.finding_id) == bool(self.incident_id):
            raise ValueError("Provide exactly one finding_id or incident_id")
        return self


class AttackMappingDecision(BaseModel):
    decision: Literal["approved", "rejected", "overridden"]
    technique_id: str | None = Field(default=None, min_length=3, max_length=20)
    tactic: str | None = Field(default=None, min_length=2, max_length=80)
    evidence_id: str | None = Field(default=None, min_length=1, max_length=36)
    rationale: str | None = Field(default=None, min_length=8, max_length=4000)
    confidence: float | None = Field(default=None, ge=0, le=1)
    evidence_role: Literal["direct", "contextual"] | None = None

    @model_validator(mode="after")
    def override_requires_a_technique(self):
        if self.decision == "overridden" and (not self.technique_id or not self.tactic or not self.rationale):
            raise ValueError("An override requires a known technique, tactic, and rationale")
        if (self.technique_id is None) != (self.tactic is None):
            raise ValueError("technique_id and tactic must be provided together")
        return self


class AttackTechniqueOut(BaseModel):
    id: str
    name: str
    tactics: list[str]
    url: str
    external_id: str | None = None
    stix_id: str | None = None
    description: str | None = None
    tactic_ids: list[str] = Field(default_factory=list)
    selectable_tactics: list[str] = Field(default_factory=list)
    references: list[dict[str, str]] = Field(default_factory=list)
    created: str | None = None
    modified: str | None = None
    revoked: bool = False
    deprecated: bool = False
    is_subtechnique: bool = False
    parent_id: str | None = None
    selectable: bool = True


class AttackCatalogOut(BaseModel):
    catalog_version: str
    framework: str
    snapshot_date: str
    source_url: str
    techniques: list[AttackTechniqueOut]
    release_version: str | None = None
    source: str | None = None
    source_reference: str | None = None
    retrieved_at: datetime | None = None
    checksum: str | None = None
    import_status: str = "active"
    active: bool = True
    tactics: list[dict[str, Any]] = Field(default_factory=list)
    relationships: list[dict[str, Any]] = Field(default_factory=list)
    attribution: str | None = None


class AttackCatalogVersionOut(BaseModel):
    id: str
    catalog_version: str
    source: str
    release_version: str | None
    source_reference: str | None
    retrieved_at: datetime | None
    checksum: str | None
    import_status: Literal["queued", "dispatched", "downloading", "validating", "active", "available", "failed", "duplicate"]
    active: bool
    technique_count: int
    tactic_count: int
    subtechnique_count: int
    revoked_count: int
    deprecated_count: int
    error_summary: str | None
    duplicate_of: str | None
    requested_by: str | None
    created_at: datetime
    completed_at: datetime | None


class AttackCatalogVersionsOut(BaseModel):
    active_catalog_version: str | None
    active: AttackCatalogVersionOut | None
    versions: list[AttackCatalogVersionOut]
    attribution: str
    checksum_notice: str


class AttackMappingOut(BaseModel):
    id: str
    finding_id: str | None
    incident_id: str | None
    technique_id: str
    technique_name: str
    tactic: str
    catalog_version: str
    catalog_release_version: str | None = None
    catalog_source: str | None = None
    catalog_source_reference: str | None = None
    catalog_checksum: str | None = None
    catalog_attribution: str | None = None
    rationale: str
    confidence: float
    source: str
    evidence_role: Literal["direct", "contextual"]
    evidence_id: str
    evidence_source: str
    evidence_observed_at: datetime | None
    decision: Literal["proposed", "approved", "rejected", "overridden"]
    analyst_confirmed: bool
    created_by: str
    reviewed_by: str | None
    reviewed_at: datetime | None
    created_at: datetime
    updated_at: datetime


class AttackSuggestionOut(BaseModel):
    finding_id: str
    incident_id: str | None
    technique_id: str
    technique_name: str
    tactic: str
    catalog_version: str
    rationale: str
    confidence: float
    source: str
    evidence_role: Literal["direct", "contextual"]
    evidence_id: str
    decision: Literal["suggested"]
    notice: str


class AttackTacticMatrixOut(BaseModel):
    tactic: str
    mappings: list[AttackMappingOut]


class AttackIncidentMatrixOut(BaseModel):
    incident_id: str
    catalog_version: str
    tactics: list[AttackTacticMatrixOut]
    mappings: list[AttackMappingOut]
    suggestions: list[AttackSuggestionOut]
    unmapped: list[dict[str, Any]]
    notice: str


class InvestigationDetailOut(InvestigationSummaryOut):
    asset: InvestigationAssetDetailOut
    attempts: list[InvestigationAttemptOut]
    collector_runs: list[CollectorRunOut]
    findings: list[FindingOut]
    evidence: list[EvidenceSnapshotOut]
    ip_intelligence: dict[str, Any] | None = None


GraphNodeType = Literal[
    "asset", "domain", "ip", "certificate", "software", "cve", "finding",
    "investigation", "incident", "playbook_task",
]
GraphRelationshipType = Literal[
    "investigated_in", "identifies_domain", "identifies_ip", "resolves_to",
    "redirects_to", "presents_certificate", "includes_software", "has_finding",
    "concerns_software", "references_cve", "potentially_affected_by",
    "concerns_asset", "tracks_finding", "belongs_to_incident",
]


class EvidenceGraphNodeOut(BaseModel):
    id: str
    type: GraphNodeType
    label: str
    details: dict[str, Any]


class EvidenceGraphEdgeOut(BaseModel):
    id: str
    from_node_id: str
    from_node_type: GraphNodeType
    to_node_id: str
    to_node_type: GraphNodeType
    relationship_type: GraphRelationshipType
    evidence_role: Literal["direct", "contextual"]
    collector: str
    source: str
    evidence_id: str
    observed_at: datetime
    data_mode: Literal["live", "demo"]
    details: dict[str, Any]


class EvidenceGraphOut(BaseModel):
    investigation_id: str
    generated_at: datetime
    nodes: list[EvidenceGraphNodeOut]
    edges: list[EvidenceGraphEdgeOut]


class EvidenceGraphChangeOut(BaseModel):
    status: Literal["new", "changed", "no_longer_observed", "unknown"]
    edge: EvidenceGraphEdgeOut
    previous_edge: EvidenceGraphEdgeOut | None
    reason: str


class EvidenceGraphChangesOut(BaseModel):
    current_investigation_id: str
    previous_investigation_id: str
    changes: list[EvidenceGraphChangeOut]
    counts: dict[str, int]


class HealthLiveOut(BaseModel):
    status: Literal["alive"]
    service: str


class PostgresReadyOut(BaseModel):
    status: Literal["ready"]
    postgres: bool


class RedisReadyOut(BaseModel):
    status: Literal["ready"]
    redis: bool


class WorkerReadyOut(BaseModel):
    status: Literal["ready"]
    worker: bool


class HealthDependenciesOut(BaseModel):
    database: bool
    redis: bool
    worker: bool


class ReadinessOut(BaseModel):
    status: Literal["ready"]
    service: str
    mode: Literal["demo", "live"]
    demo_data: bool
    dependencies: HealthDependenciesOut


class MetricsOut(BaseModel):
    generated_at: datetime
    requests: dict[str, int | float]
    queue_depth: int | None
    job_duration_ms: float | None
    worker_ready: bool
    worker_heartbeat_ttl_seconds: int | None
    provider_status: dict[str, dict[str, int]]
