"""Shared read scope for user-facing workspace projections.

Historical Demo records remain stored with their original provenance. In Live
mode, normal application projections include only real assets and Live
investigations; no rows or saved reports are rewritten by these filters.
"""

from sqlalchemy import and_, exists, or_, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import (
    Asset,
    AttackMapping,
    AuditEvent,
    CollectorRun,
    EmailBreachAuthorization,
    EvidenceSnapshot,
    Finding,
    FindingControlMapping,
    Incident,
    IncidentEvent,
    IncidentFinding,
    Investigation,
    InvestigationAttempt,
    MonitoringRun,
    MonitoringSchedule,
    PlaybookTask,
    RemediationAction,
    RemediationPlan,
    Report,
    RiskAssessment,
    RiskAssessmentRevision,
    SoftwareComponent,
    ThreatScenario,
    WebsiteAuthorization,
)


def live_projection() -> bool:
    return get_settings().app_mode == "live"


def visible_assets(db: Session):
    query = db.query(Asset)
    if live_projection():
        query = query.filter(Asset.is_synthetic.is_(False))
    return query


def visible_investigations(db: Session):
    query = db.query(Investigation).join(Asset, Asset.id == Investigation.asset_id)
    if live_projection():
        query = query.filter(Investigation.mode == "live", Asset.is_synthetic.is_(False))
    return query


def visible_findings(db: Session):
    query = db.query(Finding)
    if live_projection():
        query = query.filter(
            Finding.is_synthetic.is_(False),
            exists(select(1).select_from(Investigation).where(
                Investigation.id == Finding.investigation_id,
                Investigation.mode == "live",
            )),
            exists(select(1).select_from(Asset).where(
                Asset.id == Finding.asset_id,
                Asset.is_synthetic.is_(False),
            )),
        )
    return query


def visible_incidents(db: Session):
    query = db.query(Incident)
    if not live_projection():
        return query

    hidden_asset = exists(select(1).select_from(Asset).where(
        Asset.id == Incident.asset_id,
        Asset.is_synthetic.is_(True),
    ))
    hidden_investigation = exists(select(1).select_from(Investigation).where(
        Investigation.id == Incident.investigation_id,
        Investigation.mode != "live",
    ))
    hidden_finding = exists(
        select(1)
        .select_from(IncidentFinding)
        .join(Finding, Finding.id == IncidentFinding.finding_id)
        .join(Investigation, Investigation.id == Finding.investigation_id)
        .join(Asset, Asset.id == Finding.asset_id)
        .where(IncidentFinding.incident_id == Incident.id)
        .where(or_(
            Finding.is_synthetic.is_(True),
            Investigation.mode != "live",
            Asset.is_synthetic.is_(True),
        ))
    )
    return query.filter(~hidden_asset, ~hidden_investigation, ~hidden_finding)


def visible_reports(db: Session):
    query = db.query(Report)
    if live_projection():
        investigation_ids = visible_investigations(db).with_entities(Investigation.id)
        incident_ids = visible_incidents(db).with_entities(Incident.id)
        query = query.filter(
            Report.is_demo.is_(False),
            or_(Report.investigation_id.is_(None), Report.investigation_id.in_(investigation_ids)),
            or_(Report.incident_id.is_(None), Report.incident_id.in_(incident_ids)),
        )
    return query


def visible_monitoring_schedules(db: Session):
    query = db.query(MonitoringSchedule).join(Asset, Asset.id == MonitoringSchedule.asset_id)
    query = query.filter(MonitoringSchedule.mode == get_settings().app_mode)
    if live_projection():
        query = query.filter(Asset.is_synthetic.is_(False))
    return query


def visible_evidence(db: Session):
    query = db.query(EvidenceSnapshot)
    if live_projection():
        query = query.filter(
            EvidenceSnapshot.is_synthetic.is_(False),
            exists(select(1).select_from(Investigation).where(
                Investigation.id == EvidenceSnapshot.investigation_id,
                Investigation.mode == "live",
            )),
            exists(select(1).select_from(Asset).join(
                Investigation, Investigation.asset_id == Asset.id
            ).where(
                Investigation.id == EvidenceSnapshot.investigation_id,
                Asset.is_synthetic.is_(False),
            )),
        )
    return query


def visible_remediation_plans(db: Session):
    query = db.query(RemediationPlan)
    if live_projection():
        finding_ids = visible_findings(db).with_entities(Finding.id)
        incident_ids = visible_incidents(db).with_entities(Incident.id)
        task_ids = (db.query(PlaybookTask.id)
                    .filter(PlaybookTask.incident_id.in_(incident_ids)))
        query = query.filter(
            or_(RemediationPlan.finding_id.is_(None), RemediationPlan.finding_id.in_(finding_ids)),
            or_(RemediationPlan.incident_id.is_(None), RemediationPlan.incident_id.in_(incident_ids)),
            or_(RemediationPlan.playbook_task_id.is_(None), RemediationPlan.playbook_task_id.in_(task_ids)),
        )
    return query


def visible_threat_scenarios(db: Session):
    query = db.query(ThreatScenario)
    if live_projection():
        asset_ids = visible_assets(db).with_entities(Asset.id)
        finding_ids = visible_findings(db).with_entities(Finding.id)
        investigation_ids = visible_investigations(db).with_entities(Investigation.id)
        incident_ids = visible_incidents(db).with_entities(Incident.id)
        query = query.filter(
            ThreatScenario.asset_id.in_(asset_ids),
            or_(ThreatScenario.finding_id.is_(None), ThreatScenario.finding_id.in_(finding_ids)),
            or_(ThreatScenario.investigation_id.is_(None), ThreatScenario.investigation_id.in_(investigation_ids)),
            or_(ThreatScenario.incident_id.is_(None), ThreatScenario.incident_id.in_(incident_ids)),
        )
    return query


def visible_attack_mappings(db: Session):
    query = db.query(AttackMapping)
    if live_projection():
        finding_ids = visible_findings(db).with_entities(Finding.id)
        incident_ids = visible_incidents(db).with_entities(Incident.id)
        query = query.filter(
            or_(AttackMapping.finding_id.is_(None), AttackMapping.finding_id.in_(finding_ids)),
            or_(AttackMapping.incident_id.is_(None), AttackMapping.incident_id.in_(incident_ids)),
        )
    return query


def visible_audit_events(db: Session):
    """Hide Demo-linked activity in the ordinary event list.

    Integrity verification and the full audit export continue to use the
    complete append-only chain, including its historical Demo events.
    """
    query = db.query(AuditEvent)
    if not live_projection():
        return query
    hidden = {
        "asset": db.query(Asset.id).filter(Asset.is_synthetic.is_(True)),
        "software_component": db.query(SoftwareComponent.id).join(Asset).filter(Asset.is_synthetic.is_(True)),
        "website_authorization": db.query(WebsiteAuthorization.id).join(Asset).filter(Asset.is_synthetic.is_(True)),
        "email_breach_authorization": db.query(EmailBreachAuthorization.id).join(Asset).filter(Asset.is_synthetic.is_(True)),
        "investigation": db.query(Investigation.id).filter(Investigation.mode != "live"),
        "investigation_attempt": db.query(InvestigationAttempt.id).join(Investigation).filter(Investigation.mode != "live"),
        "collector_run": db.query(CollectorRun.id).join(Investigation).filter(Investigation.mode != "live"),
        "evidence_snapshot": db.query(EvidenceSnapshot.id).join(Investigation).filter(Investigation.mode != "live"),
        "finding": db.query(Finding.id).join(Investigation).join(Asset, Asset.id == Finding.asset_id).filter(or_(
            Finding.is_synthetic.is_(True), Investigation.mode != "live", Asset.is_synthetic.is_(True))),
        "risk_assessment": db.query(RiskAssessment.id).join(Investigation).filter(Investigation.mode != "live"),
        "risk_assessment_revision": db.query(RiskAssessmentRevision.id).join(Investigation).filter(Investigation.mode != "live"),
        "incident": db.query(Incident.id).filter(~Incident.id.in_(visible_incidents(db).with_entities(Incident.id))),
        "incident_event": db.query(IncidentEvent.id).filter(~IncidentEvent.incident_id.in_(visible_incidents(db).with_entities(Incident.id))),
        "playbook_task": db.query(PlaybookTask.id).filter(~PlaybookTask.incident_id.in_(visible_incidents(db).with_entities(Incident.id))),
        "monitoring_schedule": db.query(MonitoringSchedule.id).filter(
            ~MonitoringSchedule.id.in_(visible_monitoring_schedules(db).with_entities(MonitoringSchedule.id))
        ),
        "monitoring_run": db.query(MonitoringRun.id).join(
            Investigation, Investigation.id == MonitoringRun.investigation_id
        ).filter(Investigation.mode != "live"),
        "report": db.query(Report.id).filter(~Report.id.in_(visible_reports(db).with_entities(Report.id))),
        "remediation_plan": db.query(RemediationPlan.id).filter(~RemediationPlan.id.in_(visible_remediation_plans(db).with_entities(RemediationPlan.id))),
        "remediation_action": db.query(RemediationAction.id).filter(~RemediationAction.plan_id.in_(visible_remediation_plans(db).with_entities(RemediationPlan.id))),
        "finding_control_mapping": db.query(FindingControlMapping.id).filter(~FindingControlMapping.finding_id.in_(visible_findings(db).with_entities(Finding.id))),
        "threat_scenario": db.query(ThreatScenario.id).filter(~ThreatScenario.id.in_(visible_threat_scenarios(db).with_entities(ThreatScenario.id))),
        "attack_mapping": db.query(AttackMapping.id).filter(~AttackMapping.id.in_(visible_attack_mappings(db).with_entities(AttackMapping.id))),
    }
    query = query.filter(~AuditEvent.action.like("demo.%"))
    for entity_type, hidden_ids in hidden.items():
        query = query.filter(~and_(AuditEvent.entity_type == entity_type,
                                  AuditEvent.entity_id.in_(hidden_ids)))
    return query


def visible_row(db: Session, model, identifier: str):
    """Return one record through the same projection as its collection route."""
    query_for_model = {
        Asset: visible_assets,
        Investigation: visible_investigations,
        Finding: visible_findings,
        Incident: visible_incidents,
        Report: visible_reports,
        MonitoringSchedule: visible_monitoring_schedules,
        EvidenceSnapshot: visible_evidence,
        RemediationPlan: visible_remediation_plans,
        ThreatScenario: visible_threat_scenarios,
        AttackMapping: visible_attack_mappings,
    }.get(model)
    if query_for_model is None:
        raise ValueError(f"No Live projection is defined for {model.__name__}")
    return query_for_model(db).filter(model.id == identifier).first()
