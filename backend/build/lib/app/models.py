from datetime import datetime, timezone
import uuid

from sqlalchemy import Boolean, CheckConstraint, DateTime, Float, ForeignKey, Index, Integer, JSON, LargeBinary, String, Text, UniqueConstraint, false, text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return str(uuid.uuid4())


class WorkspaceMetadata(Base):
    __tablename__ = "workspace_metadata"
    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True, nullable=False)
    email: Mapped[str | None] = mapped_column(String(320), unique=True)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="analyst")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)


class UserSession(Base):
    __tablename__ = "sessions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    csrf_token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("kind", "normalized_identifier", name="uq_asset_kind_identifier"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    kind: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    identifier: Mapped[str] = mapped_column(String(2048), nullable=False)
    normalized_identifier: Mapped[str] = mapped_column(String(2048), nullable=False)
    url_retention_complete: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=false())
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    criticality: Mapped[str] = mapped_column(String(20), nullable=False, default="unknown", server_default="unknown")
    data_classification: Mapped[str] = mapped_column(String(20), nullable=False, default="unknown", server_default="unknown")
    trust_zone: Mapped[str] = mapped_column(String(30), nullable=False, default="unknown", server_default="unknown")
    exposure_classification: Mapped[str] = mapped_column(String(30), nullable=False, default="unknown", server_default="unknown")
    business_owner: Mapped[str | None] = mapped_column(String(200))
    protection_requirements: Mapped[list] = mapped_column(JSON, nullable=False, default=list, server_default=text("'[]'"))
    authorized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    authorization_note: Mapped[str | None] = mapped_column(Text)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    demo_scenario: Mapped[str | None] = mapped_column(String(40))
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc, nullable=False)


class WebsiteAuthorization(Base):
    __tablename__ = "website_authorizations"
    __table_args__ = (Index("ix_website_authorizations_asset_active", "asset_id", "revoked_at", "expires_at"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True, nullable=False)
    authorized_by: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    note: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_by: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class EmailBreachAuthorization(Base):
    """Time-limited analyst authorization for a named email breach provider."""
    __tablename__ = "email_breach_authorizations"
    __table_args__ = (
        CheckConstraint("provider = 'xposedornot'", name="ck_email_breach_authorization_provider"),
        Index("ix_email_breach_authorizations_asset_active", "asset_id", "revoked_at", "expires_at"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True, nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    authorized_by: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    consent_version: Mapped[str] = mapped_column(String(40), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_by: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class MonitoringSchedule(Base):
    """An analyst-controlled recurring investigation for one authorized website."""
    __tablename__ = "monitoring_schedules"
    __table_args__ = (
        CheckConstraint("mode IN ('demo', 'live')", name="ck_monitoring_schedule_mode"),
        CheckConstraint("cadence IN ('daily', 'weekly')", name="ck_monitoring_schedule_cadence"),
        CheckConstraint("status IN ('active', 'paused', 'failed', 'completed')", name="ck_monitoring_schedule_status"),
        Index("ix_monitoring_schedule_due", "status", "next_run_at"),
        Index("ix_monitoring_schedule_asset", "asset_id"),
        Index("ix_monitoring_schedule_owner", "owner_id"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="RESTRICT"), nullable=False)
    authorization_id: Mapped[str] = mapped_column(ForeignKey("website_authorizations.id", ondelete="RESTRICT"), nullable=False)
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    mode: Mapped[str] = mapped_column(String(8), nullable=False, default="demo", server_default="demo")
    cadence: Mapped[str] = mapped_column(String(12), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active", server_default="active")
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    failure_code: Mapped[str | None] = mapped_column(String(60))
    failure_detail: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc, nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class MonitoringRun(Base):
    """One scheduled occurrence, linked to an immutable investigation record."""
    __tablename__ = "monitoring_runs"
    __table_args__ = (
        UniqueConstraint("schedule_id", "scheduled_for", name="uq_monitoring_run_schedule_slot"),
        UniqueConstraint("investigation_id", name="uq_monitoring_run_investigation"),
        CheckConstraint("status IN ('queued', 'running', 'completed', 'partial', 'failed')", name="ck_monitoring_run_status"),
        Index("ix_monitoring_run_schedule_time", "schedule_id", "scheduled_for"),
        Index("ix_monitoring_run_status", "status"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    schedule_id: Mapped[str] = mapped_column(ForeignKey("monitoring_schedules.id", ondelete="CASCADE"), nullable=False)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="RESTRICT"), nullable=False)
    previous_investigation_id: Mapped[str | None] = mapped_column(ForeignKey("investigations.id", ondelete="SET NULL"))
    scheduled_for: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued", server_default="queued")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failure_detail: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)


class SoftwareComponent(Base):
    __tablename__ = "software_components"
    __table_args__ = (CheckConstraint(
        "(package_ecosystem IS NULL AND package_name IS NULL) OR "
        "(package_ecosystem IN ('npm', 'PyPI') AND package_name IS NOT NULL)",
        name="ck_software_component_package_identity",
    ),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True, nullable=False)
    vendor: Mapped[str] = mapped_column(String(200), nullable=False)
    product: Mapped[str] = mapped_column(String(200), nullable=False)
    version: Mapped[str] = mapped_column(String(100), nullable=False)
    cpe_name: Mapped[str | None] = mapped_column(String(1024))
    package_ecosystem: Mapped[str | None] = mapped_column(String(12))
    package_name: Mapped[str | None] = mapped_column(String(214))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)


class Investigation(Base):
    __tablename__ = "investigations"
    __table_args__ = (Index("ix_investigation_asset_created", "asset_id", "created_at"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True, nullable=False)
    requested_by: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    mode: Mapped[str] = mapped_column(String(10), nullable=False)
    scenario: Mapped[str | None] = mapped_column(String(40))
    email_breach_provider: Mapped[str | None] = mapped_column(String(32))
    email_breach_authorization_id: Mapped[str | None] = mapped_column(
        ForeignKey("email_breach_authorizations.id", ondelete="SET NULL")
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="queued", index=True)
    progress: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_summary: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)


class InvestigationAttempt(Base):
    __tablename__ = "investigation_attempts"
    __table_args__ = (
        UniqueConstraint("investigation_id", "attempt_number", name="uq_investigation_attempt_number"),
        Index("ix_investigation_attempts_investigation_id", "investigation_id"),
        Index("ix_investigation_attempts_status_heartbeat", "status", "heartbeat_at"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    retry_kind: Mapped[str] = mapped_column(String(20), nullable=False, default="initial")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="queued", index=True)
    progress: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_summary: Mapped[str | None] = mapped_column(Text)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lease_token: Mapped[str | None] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)


class InvestigationOutbox(Base):
    __tablename__ = "investigation_outbox"
    __table_args__ = (
        UniqueConstraint("attempt_id", name="uq_investigation_outbox_attempt"),
        Index("ix_investigation_outbox_status_available", "status", "available_at"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    attempt_id: Mapped[str] = mapped_column(ForeignKey("investigation_attempts.id", ondelete="CASCADE"), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending", index=True)
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
    dispatch_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error: Mapped[str | None] = mapped_column(Text)
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc, nullable=False)


class CollectorRun(Base):
    __tablename__ = "collector_runs"
    __table_args__ = (UniqueConstraint("attempt_id", "collector", name="uq_collector_run_attempt"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True, nullable=False)
    attempt_id: Mapped[str | None] = mapped_column(
        ForeignKey("investigation_attempts.id", ondelete="SET NULL", name="fk_collector_runs_attempt_id"), index=True
    )
    feed_snapshot_id: Mapped[str | None] = mapped_column(
        ForeignKey("threat_feed_snapshots.id", ondelete="RESTRICT"), index=True
    )
    collector: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="queued")
    source: Mapped[str] = mapped_column(String(200), nullable=False)
    error_explanation: Mapped[str | None] = mapped_column(Text)
    record_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class EvidenceSnapshot(Base):
    __tablename__ = "evidence_snapshots"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True, nullable=False)
    collector_run_id: Mapped[str | None] = mapped_column(ForeignKey("collector_runs.id", ondelete="SET NULL"))
    source: Mapped[str] = mapped_column(String(200), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
    evidence_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class EvidenceRelationship(Base):
    """A temporal, evidence-backed edge in the PostgreSQL graph projection."""
    __tablename__ = "evidence_relationships"
    __table_args__ = (
        UniqueConstraint(
            "evidence_id", "from_node_id", "to_node_id", "relationship_type",
            name="uq_evidence_relationship_observation",
        ),
        Index("ix_evidence_relationships_investigation_observed", "investigation_id", "observed_at"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True, nullable=False)
    from_node_type: Mapped[str] = mapped_column(String(32), nullable=False)
    from_node_id: Mapped[str] = mapped_column(String(300), nullable=False)
    to_node_type: Mapped[str] = mapped_column(String(32), nullable=False)
    to_node_id: Mapped[str] = mapped_column(String(300), nullable=False)
    relationship_type: Mapped[str] = mapped_column(String(48), nullable=False)
    evidence_role: Mapped[str] = mapped_column(String(16), nullable=False)
    collector: Mapped[str] = mapped_column(String(80), nullable=False)
    source: Mapped[str] = mapped_column(String(200), nullable=False)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidence_snapshots.id", ondelete="CASCADE"), index=True, nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    data_mode: Mapped[str] = mapped_column(String(10), nullable=False)
    details_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (Index("ix_finding_investigation_category", "investigation_id", "category"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True, nullable=False)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True, nullable=False)
    evidence_id: Mapped[str | None] = mapped_column(ForeignKey("evidence_snapshots.id", ondelete="SET NULL"))
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    recommendation: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(200), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
    applicability: Mapped[str] = mapped_column(String(20), nullable=False, default="applies")
    applicability_reason: Mapped[str | None] = mapped_column(Text)
    epss_score: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    epss_observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    epss_provider_status: Mapped[str | None] = mapped_column(String(32))
    epss_freshness: Mapped[str | None] = mapped_column(String(24))
    is_synthetic: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    details_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), unique=True, nullable=False)
    version: Mapped[str] = mapped_column(String(40), nullable=False)
    score: Mapped[float | None] = mapped_column(Float)
    band: Mapped[str] = mapped_column(String(30), nullable=False)
    weights_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict, server_default=text("'{}'"))
    assessed_categories: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    excluded_categories: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    category_scores: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    contributing_finding_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    explanation_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)


class RiskAssessmentRevision(Base):
    """Immutable, input-addressed risk assessment history."""
    __tablename__ = "risk_assessment_revisions"
    __table_args__ = (
        UniqueConstraint("investigation_id", "revision_number", name="uq_risk_assessment_revision_number"),
        UniqueConstraint("investigation_id", "input_fingerprint", name="uq_risk_assessment_revision_input"),
        Index("ix_risk_assessment_revisions_investigation_created", "investigation_id", "created_at"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True, nullable=False)
    revision_number: Mapped[int] = mapped_column(Integer, nullable=False)
    input_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    version: Mapped[str] = mapped_column(String(40), nullable=False)
    score: Mapped[float | None] = mapped_column(Float)
    band: Mapped[str] = mapped_column(String(30), nullable=False)
    weights_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict, server_default=text("'{}'"))
    assessed_categories: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    excluded_categories: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    category_scores: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    contributing_finding_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    explanation_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    classification: Mapped[str] = mapped_column(String(40), nullable=False, default="suspected_incident")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="new", index=True)
    priority: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")
    owner_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), nullable=False, index=True)
    investigation_id: Mapped[str | None] = mapped_column(ForeignKey("investigations.id"))
    resolution_summary: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc, nullable=False)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class IncidentFinding(Base):
    __tablename__ = "incident_findings"
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), primary_key=True)


class IncidentEvent(Base):
    __tablename__ = "incident_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True, nullable=False)
    actor_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    event_type: Mapped[str] = mapped_column(String(40), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    details_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)


class PlaybookTask(Base):
    __tablename__ = "playbook_tasks"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True, nullable=False)
    playbook_id: Mapped[str] = mapped_column(String(80), nullable=False)
    playbook_version: Mapped[str] = mapped_column(String(20), nullable=False)
    title: Mapped[str] = mapped_column(String(250), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    stage: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    completed_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    notes: Mapped[str | None] = mapped_column(Text)
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class RemediationPlan(Base):
    """Analyst-owned remediation tracking; it never mutates its source finding."""
    __tablename__ = "remediation_plans"
    __table_args__ = (
        Index("ix_remediation_plans_status_due", "status", "due_at"),
        Index("ix_remediation_plans_incident", "incident_id"),
        Index("ix_remediation_plans_finding", "finding_id"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    action_type: Mapped[str] = mapped_column(String(80), nullable=False)
    finding_id: Mapped[str | None] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"))
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"))
    playbook_task_id: Mapped[str | None] = mapped_column(ForeignKey("playbook_tasks.id", ondelete="SET NULL"), index=True)
    owner_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    priority: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="proposed", index=True)
    assumptions_json: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    notes: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc, nullable=False)


class RemediationAction(Base):
    __tablename__ = "remediation_actions"
    __table_args__ = (
        Index("ix_remediation_actions_plan_status", "plan_id", "status"),
        Index("ix_remediation_actions_due", "due_at"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    plan_id: Mapped[str] = mapped_column(ForeignKey("remediation_plans.id", ondelete="CASCADE"), index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    action_type: Mapped[str] = mapped_column(String(80), nullable=False)
    owner_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    priority: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="proposed", index=True)
    assumptions_json: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    verification_instructions: Mapped[str] = mapped_column(Text, nullable=False, default="")
    notes: Mapped[str | None] = mapped_column(Text)
    verification_evidence_id: Mapped[str | None] = mapped_column(ForeignKey("evidence_snapshots.id", ondelete="SET NULL"))
    validated_by: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc, nullable=False)


class FindingControlMapping(Base):
    __tablename__ = "finding_control_mappings"
    __table_args__ = (
        UniqueConstraint("finding_id", "control_id", "catalog_version", name="uq_finding_control_catalog"),
        Index("ix_finding_control_mappings_finding", "finding_id"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True, nullable=False)
    control_id: Mapped[str] = mapped_column(String(80), nullable=False)
    catalog_version: Mapped[str] = mapped_column(String(40), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="proposed", index=True)
    verification_evidence_id: Mapped[str | None] = mapped_column(ForeignKey("evidence_snapshots.id", ondelete="SET NULL"))
    validated_by: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc, nullable=False)


class ThreatScenario(Base):
    """Analyst-authored STRIDE scenario, separate from technical findings and risk scores."""
    __tablename__ = "threat_scenarios"
    __table_args__ = (
        Index("ix_threat_scenarios_asset_review", "asset_id", "review_status"),
        Index("ix_threat_scenarios_finding", "finding_id"),
        Index("ix_threat_scenarios_investigation", "investigation_id"),
        Index("ix_threat_scenarios_incident", "incident_id"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True, nullable=False)
    finding_id: Mapped[str | None] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"))
    investigation_id: Mapped[str | None] = mapped_column(ForeignKey("investigations.id", ondelete="SET NULL"))
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"))
    stride_category: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    likelihood: Mapped[int] = mapped_column(Integer, nullable=False)
    business_impact: Mapped[int] = mapped_column(Integer, nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False)
    assumptions_json: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    unconfirmed_information_json: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    owner_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    review_status: Mapped[str] = mapped_column(String(24), nullable=False, default="draft", index=True)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc, nullable=False)


class AttackMapping(Base):
    """An analyst-reviewed, evidence-linked mapping to the local ATT&CK subset."""
    __tablename__ = "attack_mappings"
    __table_args__ = (
        CheckConstraint("(finding_id IS NOT NULL AND incident_id IS NULL) OR (finding_id IS NULL AND incident_id IS NOT NULL)", name="ck_attack_mapping_target"),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="ck_attack_mapping_confidence"),
        CheckConstraint("decision IN ('proposed', 'approved', 'rejected', 'overridden')", name="ck_attack_mapping_decision"),
        CheckConstraint("evidence_role IN ('direct', 'contextual')", name="ck_attack_mapping_evidence_role"),
        Index("ix_attack_mappings_finding", "finding_id"),
        Index("ix_attack_mappings_incident", "incident_id"),
        Index("ix_attack_mappings_technique", "technique_id"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    finding_id: Mapped[str | None] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"))
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"))
    technique_id: Mapped[str] = mapped_column(String(20), nullable=False)
    technique_name: Mapped[str] = mapped_column(String(200), nullable=False)
    tactic: Mapped[str] = mapped_column(String(80), nullable=False)
    catalog_version: Mapped[str] = mapped_column(String(60), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    source: Mapped[str] = mapped_column(String(80), nullable=False)
    evidence_role: Mapped[str] = mapped_column(String(16), nullable=False, default="contextual")
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidence_snapshots.id", ondelete="CASCADE"), nullable=False)
    decision: Mapped[str] = mapped_column(String(20), nullable=False, default="proposed", index=True)
    analyst_confirmed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    reviewed_by: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc, nullable=False)


class AttackCatalogVersion(Base):
    """A validated immutable ATT&CK catalog snapshot or a sync attempt."""
    __tablename__ = "attack_catalog_versions"
    __table_args__ = (
        CheckConstraint(
            "import_status IN ('queued', 'dispatched', 'downloading', 'validating', 'active', 'available', 'failed', 'duplicate')",
            name="ck_attack_catalog_import_status",
        ),
        Index("uq_attack_catalog_single_active", "active", unique=True,
              sqlite_where=text("active = 1"), postgresql_where=text("active = true")),
        Index("ix_attack_catalog_created", "created_at"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    catalog_version: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    source: Mapped[str] = mapped_column(String(160), nullable=False)
    release_version: Mapped[str | None] = mapped_column(String(40))
    source_reference: Mapped[str | None] = mapped_column(Text)
    retrieved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    checksum: Mapped[str | None] = mapped_column(String(64))
    import_status: Mapped[str] = mapped_column(String(20), nullable=False, default="queued")
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    available_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    dispatch_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    catalog_json: Mapped[dict | None] = mapped_column(JSON)
    result_json: Mapped[dict | None] = mapped_column(JSON)
    error_summary: Mapped[str | None] = mapped_column(Text)
    duplicate_of: Mapped[str | None] = mapped_column(String(128))
    requested_by: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc, nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ThreatFeedSource(Base):
    """Durable refresh state for a fixed, approved public threat-feed source."""
    __tablename__ = "threat_feed_sources"
    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(160), nullable=False)
    source_urls_json: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    active_snapshot_id: Mapped[str | None] = mapped_column(
        ForeignKey("threat_feed_snapshots.id", name="fk_threat_feed_source_active_snapshot",
                   ondelete="SET NULL", use_alter=True)
    )
    personal_owner_user_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True,
    )
    validators_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    last_successful_revalidation_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_refresh_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    dispatch_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc, nullable=False)


class ThreatFeedSnapshot(Base):
    """Immutable validated payload for a feed source."""
    __tablename__ = "threat_feed_snapshots"
    __table_args__ = (
        UniqueConstraint("source_id", "content_sha256", name="uq_threat_feed_snapshot_content"),
        Index("ix_threat_feed_snapshots_source_retrieved", "source_id", "retrieved_at"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source_id: Mapped[str] = mapped_column(ForeignKey("threat_feed_sources.id", ondelete="RESTRICT"), nullable=False)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    parser_version: Mapped[str] = mapped_column(String(40), nullable=False)
    record_count: Mapped[int] = mapped_column(Integer, nullable=False)
    retrieved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    metadata_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class ThreatFeedNetwork(Base):
    """Canonical feed indicators retained with the immutable snapshot.

    ``network`` stores a strict CIDR when ``indicator_type`` is ``network``;
    for ``ip`` indicators it stores the canonical bare IP address, without an
    inferred prefix. ``sbl_id`` is empty when the provider supplies no record ID.
    """
    __tablename__ = "threat_feed_networks"
    __table_args__ = (
        UniqueConstraint("snapshot_id", "address_family", "network", "sbl_id", name="uq_threat_feed_network_record"),
        Index("ix_threat_feed_networks_snapshot_family", "snapshot_id", "address_family"),
        Index("ix_threat_feed_networks_snapshot_indicator", "snapshot_id", "indicator_type", "network"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    snapshot_id: Mapped[str] = mapped_column(ForeignKey("threat_feed_snapshots.id", ondelete="RESTRICT"), nullable=False)
    address_family: Mapped[int] = mapped_column(Integer, nullable=False)
    network: Mapped[str] = mapped_column(String(64), nullable=False)
    sbl_id: Mapped[str] = mapped_column(String(40), nullable=False)
    indicator_type: Mapped[str] = mapped_column(String(16), nullable=False, default="network", server_default="network")


class ThreatFeedUrl(Base):
    """Exact URL indicators retained in a shared feed snapshot.

    URLs are indexed by a digest so long query strings do not become large
    PostgreSQL B-tree entries. The full canonical URL is compared after lookup.
    """
    __tablename__ = "threat_feed_urls"
    __table_args__ = (
        UniqueConstraint("snapshot_id", "canonical_sha256", name="uq_threat_feed_url_digest"),
        Index("ix_threat_feed_urls_snapshot_hostname", "snapshot_id", "hostname"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    snapshot_id: Mapped[str] = mapped_column(
        ForeignKey("threat_feed_snapshots.id", ondelete="RESTRICT"), nullable=False, index=True,
    )
    canonical_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    canonical_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    hostname: Mapped[str] = mapped_column(String(253), nullable=False)


class ThreatFeedRefreshAttempt(Base):
    """A durable refresh request/result, separate from immutable content snapshots."""
    __tablename__ = "threat_feed_refresh_attempts"
    __table_args__ = (
        CheckConstraint("status IN ('queued', 'dispatched', 'running', 'succeeded', 'unchanged', 'failed')",
                        name="ck_threat_feed_refresh_status"),
        CheckConstraint("trigger_kind IN ('scheduled', 'admin')", name="ck_threat_feed_refresh_trigger"),
        Index("ix_threat_feed_refresh_source_created", "source_id", "created_at"),
        Index("ix_threat_feed_refresh_pending", "status", "available_at"),
        Index("uq_threat_feed_refresh_single_open", "source_id", unique=True,
              sqlite_where=text("status IN ('queued', 'dispatched', 'running')"),
              postgresql_where=text("status IN ('queued', 'dispatched', 'running')")),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source_id: Mapped[str] = mapped_column(ForeignKey("threat_feed_sources.id", ondelete="RESTRICT"), nullable=False)
    trigger_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    requested_by: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="queued", index=True)
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
    dispatch_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_code: Mapped[str | None] = mapped_column(String(80))
    http_status_v4: Mapped[int | None] = mapped_column(Integer)
    http_status_v6: Mapped[int | None] = mapped_column(Integer)
    snapshot_id: Mapped[str | None] = mapped_column(ForeignKey("threat_feed_snapshots.id", ondelete="SET NULL"))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc, nullable=False)


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str | None] = mapped_column(ForeignKey("investigations.id"))
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id"))
    format: Mapped[str] = mapped_column(String(10), nullable=False)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    is_demo: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    snapshot_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    content: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        Index("uq_audit_events_sequence", "event_sequence", unique=True),
        CheckConstraint("event_sequence > 0", name="ck_audit_events_sequence_positive"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    event_sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    current_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    action: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    entity_type: Mapped[str] = mapped_column(String(80), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(36), nullable=False)
    details_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)


class AuditChainHead(Base):
    __tablename__ = "audit_chain_heads"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_sequence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    current_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)


# Register centrally so direct AuditEvent writes in API routes, workers, and the
# Demo CLI all receive the same transactional chain treatment.
from app.audit_chain import install_audit_event_hooks as _install_audit_event_hooks

_install_audit_event_hooks()
