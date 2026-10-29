from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Literal

from fastapi import Response
from sqlalchemy.orm import Session

from app.config import get_settings
from app.authorization import active_website_authorization
from app.database import get_db
from app.dependencies import get_current_user, require_csrf, require_roles_csrf
from app.graph import compare as compare_evidence_graph, projection as evidence_graph_projection
from app.ip_intelligence import build_ip_intelligence_history
from datetime import timedelta

from app.models import Asset, AuditEvent, CollectorRun, EmailBreachAuthorization, EvidenceSnapshot, Finding, Investigation, InvestigationAttempt, RiskAssessment, RiskAssessmentRevision, SoftwareComponent, User, new_id, now_utc
from app.pagination import Page, apply_page, page_params
from app.orchestration import create_attempt
from app.osv import osv_finding_payload
from app.schemas import (EvidenceGraphChangesOut, EvidenceGraphOut, InvestigationCreate, InvestigationDetailOut,
                         InvestigationQueuedOut, InvestigationRetryOut, InvestigationSummaryOut, RiskAssessmentRevisionOut,
                         RiskSensitivityOut, RiskSimulationInput, RiskSimulationOptionOut, RiskSimulationOut)
from app.services.risk import assess_investigation, investigation_inputs, sensitivity_analysis
from app.services.risk_simulation import SimulationError, simulate_remediation, simulation_options
from app.visibility import visible_evidence, visible_findings, visible_investigations, visible_row

router = APIRouter(prefix="/investigations", tags=["investigations"])
FINISHED = {"completed", "partial", "failed"}


@router.post("", status_code=202, response_model=InvestigationQueuedOut)
def start_investigation(payload: InvestigationCreate, user: User = Depends(require_roles_csrf("admin", "analyst")), db: Session = Depends(get_db)) -> dict:
    asset = visible_row(db, Asset, payload.asset_id)
    if asset is None:
        raise HTTPException(404, "Asset not found")
    settings = get_settings()
    if settings.app_mode == "live" and asset.is_synthetic:
        raise HTTPException(404, "Asset not found")
    if settings.app_mode == "live" and payload.scenario:
        raise HTTPException(422, "Synthetic scenarios are available only in demo mode")
    provider = payload.email_breach_provider
    if provider is not None and asset.kind != "email":
        raise HTTPException(422, "An email breach provider can only be selected for an email asset")
    if payload.xposedornot_authorization_confirmed and provider != "xposedornot":
        raise HTTPException(422, "Authorization confirmation applies only to an explicitly selected XposedOrNot lookup")
    email_authorization = None
    if settings.app_mode == "live" and provider == "xposedornot":
        if not settings.xposedornot_enabled or not settings.xposedornot_community_use_ack:
            raise HTTPException(503, "XposedOrNot community lookup is disabled by the operator")
        if not payload.xposedornot_authorization_confirmed:
            raise HTTPException(422, "Confirm that you are authorized to send this email address to XposedOrNot for a breach lookup")
        created_at = now_utc()
        for prior in (db.query(EmailBreachAuthorization)
                      .filter(EmailBreachAuthorization.asset_id == asset.id,
                              EmailBreachAuthorization.provider == "xposedornot",
                              EmailBreachAuthorization.revoked_at.is_(None),
                              EmailBreachAuthorization.expires_at > created_at)
                      .with_for_update().all()):
            prior.revoked_at = created_at
            prior.revoked_by = user.id
            db.add(AuditEvent(actor_id=user.id, action="email_breach.authorization_revoked",
                entity_type="email_breach_authorization", entity_id=prior.id,
                details_json={"provider": "xposedornot", "outcome": "revoked",
                              "reason": "superseded_by_new_consent"}))
        email_authorization = EmailBreachAuthorization(
            id=new_id(), asset_id=asset.id, provider="xposedornot", authorized_by=user.id,
            consent_version="xon-email-lookup-v1", created_at=created_at,
            expires_at=created_at + timedelta(days=30),
        )
        db.add(email_authorization)
        db.flush()
        db.add(AuditEvent(actor_id=user.id, action="email_breach.authorization_granted",
            entity_type="email_breach_authorization", entity_id=email_authorization.id,
            details_json={"provider": "xposedornot", "outcome": "authorized",
                          "reason": "analyst_confirmed_third_party_email_lookup",
                          "expires_at": email_authorization.expires_at.isoformat()}))
    if settings.app_mode == "demo":
        scenario = payload.scenario or {"domain": "routine_website", "url": "routine_website", "email": "exposed_email", "application": "vulnerable_application", "ip": "routine_website"}[asset.kind]
    else:
        scenario = None
    investigation = Investigation(id=new_id(), asset_id=asset.id, requested_by=user.id, mode=settings.app_mode, scenario=scenario,
        email_breach_provider=provider, email_breach_authorization_id=email_authorization.id if email_authorization else None)
    db.add(investigation)
    db.flush()
    attempt = create_attempt(db, investigation, "initial")
    db.add(AuditEvent(actor_id=user.id, action="investigation.started", entity_type="investigation", entity_id=investigation.id,
                      details_json={"asset_id": asset.id, "mode": settings.app_mode, "scenario": scenario,
                                    "email_breach_provider": provider,
                                    "email_breach_authorization_id": email_authorization.id if email_authorization else None}))
    db.commit()
    return {"id": investigation.id, "status": investigation.status, "progress": investigation.progress,
            "mode": investigation.mode, "scenario": investigation.scenario,
            "attempt_id": attempt.id, "attempt_number": attempt.attempt_number}


@router.post("/{investigation_id}/retry", status_code=202, response_model=InvestigationRetryOut)
def retry_investigation(investigation_id: str, user: User = Depends(require_roles_csrf("admin", "analyst")), db: Session = Depends(get_db)) -> dict:
    investigation = visible_row(db, Investigation, investigation_id)
    if investigation is None: raise HTTPException(404, "Investigation not found")
    if investigation.status not in FINISHED:
        raise HTTPException(409, "Only finished investigations can be retried")
    investigation.status = "queued"
    investigation.progress = 0
    investigation.started_at = None
    investigation.finished_at = None
    investigation.error_summary = None
    attempt = create_attempt(db, investigation, "manual")
    db.add(AuditEvent(actor_id=user.id, action="investigation.retried", entity_type="investigation", entity_id=investigation.id))
    db.commit()
    return {"id": investigation.id, "status": investigation.status, "progress": investigation.progress,
            "retry": True, "attempt_id": attempt.id, "attempt_number": attempt.attempt_number}


@router.get("", response_model=list[InvestigationSummaryOut])
def list_investigations(_user: User = Depends(get_current_user), db: Session = Depends(get_db), response: Response = None,
                        asset_id: str | None = None, status: str | None = None, mode: str | None = None,
                        q: str | None = None, limit: int | None = Query(default=None, ge=1, le=250),
                        sort: Literal["created_at", "finished_at", "status", "progress"] = "created_at",
                        order: Literal["asc", "desc"] = "desc", page: Page = Depends(page_params)) -> list[dict]:
    query = visible_investigations(db)
    if asset_id: query = query.filter(Investigation.asset_id == asset_id)
    if status: query = query.filter(Investigation.status == status)
    if mode: query = query.filter(Investigation.mode == mode)
    if q: query = query.filter(Investigation.scenario.ilike(f"%{q.strip()}%"))
    sort_column = {"created_at": Investigation.created_at, "finished_at": Investigation.finished_at,
                   "status": Investigation.status, "progress": Investigation.progress}[sort]
    ordering = sort_column.asc() if order == "asc" else sort_column.desc()
    if limit is not None:
        page = Page(page.number, limit)
    rows = apply_page(query.order_by(ordering, Investigation.id.asc()), page, response)
    ids = [item.id for item in rows]
    assets = {asset.id: asset for asset in db.query(Asset).filter(Asset.id.in_({item.asset_id for item in rows})).all()} if rows else {}
    risks = {risk.investigation_id: risk for risk in db.query(RiskAssessment).filter(RiskAssessment.investigation_id.in_(ids)).all()} if ids else {}
    attempts = {}
    if ids:
        for attempt in (db.query(InvestigationAttempt).filter(InvestigationAttempt.investigation_id.in_(ids))
                        .order_by(InvestigationAttempt.attempt_number.desc(), InvestigationAttempt.id.desc()).all()):
            attempts.setdefault(attempt.investigation_id, attempt)
    return [_summary(db, item, asset=assets.get(item.asset_id), risk=risks.get(item.id), latest_attempt=attempts.get(item.id)) for item in rows]


@router.get("/{investigation_id}", response_model=InvestigationDetailOut)
def get_investigation(investigation_id: str, _user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    investigation = visible_row(db, Investigation, investigation_id)
    if investigation is None:
        raise HTTPException(404, "Investigation not found")
    asset = db.get(Asset, investigation.asset_id)
    asset_payload = _asset_payload(asset, db)
    asset_payload["components"] = [{"id": row.id, "vendor": row.vendor, "product": row.product, "version": row.version,
                                    "cpe_name": row.cpe_name, "package_ecosystem": row.package_ecosystem,
                                    "package_name": row.package_name} for row in db.query(SoftwareComponent).filter_by(asset_id=asset.id).all()]
    attempts = (db.query(InvestigationAttempt).filter_by(investigation_id=investigation.id)
                .order_by(InvestigationAttempt.attempt_number).all())
    attempt_numbers = {attempt.id: attempt.attempt_number for attempt in attempts}
    runs = (db.query(CollectorRun).filter_by(investigation_id=investigation.id)
            .order_by(CollectorRun.started_at).all())
    return {**_summary(db, investigation), "asset": asset_payload,
        "attempts": [_attempt_payload(attempt) for attempt in attempts],
        "collector_runs": [_run_payload(run, attempt_numbers.get(run.attempt_id)) for run in runs],
        "findings": [_finding_payload(item) for item in visible_findings(db).filter_by(investigation_id=investigation.id).order_by(Finding.severity.desc(), Finding.observed_at.desc()).all()],
        "evidence": [_evidence_payload(item) for item in visible_evidence(db).filter_by(investigation_id=investigation.id).order_by(EvidenceSnapshot.observed_at.desc()).all()],
        "risk": _risk_payload(db.query(RiskAssessment).filter_by(investigation_id=investigation.id).first()),
        "ip_intelligence": build_ip_intelligence_history(db, investigation),
    }


@router.get("/{investigation_id}/graph", response_model=EvidenceGraphOut)
def get_evidence_graph(investigation_id: str, _user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    investigation = visible_row(db, Investigation, investigation_id)
    if investigation is None:
        raise HTTPException(404, "Investigation not found")
    return evidence_graph_projection(db, investigation)


@router.get("/{investigation_id}/risk/revisions", response_model=list[RiskAssessmentRevisionOut])
def list_risk_revisions(investigation_id: str, _user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[dict]:
    if visible_row(db, Investigation, investigation_id) is None:
        raise HTTPException(404, "Investigation not found")
    return [_risk_revision_payload(item) for item in db.query(RiskAssessmentRevision)
            .filter_by(investigation_id=investigation_id)
            .order_by(RiskAssessmentRevision.revision_number).all()]


@router.get("/{investigation_id}/risk/sensitivity", response_model=RiskSensitivityOut)
def risk_sensitivity(investigation_id: str, _user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    investigation = visible_row(db, Investigation, investigation_id)
    if investigation is None:
        raise HTTPException(404, "Investigation not found")
    findings, statuses, evidence = investigation_inputs(db, investigation)
    return sensitivity_analysis(findings, statuses, evidence)


@router.get("/{investigation_id}/risk/simulation-options", response_model=list[RiskSimulationOptionOut])
def risk_simulation_options(investigation_id: str, _user: User = Depends(get_current_user),
                            db: Session = Depends(get_db)) -> list[dict]:
    investigation = visible_row(db, Investigation, investigation_id)
    if investigation is None:
        raise HTTPException(404, "Investigation not found")
    if investigation.status not in FINISHED:
        raise HTTPException(409, "Remediation simulations require a finished investigation")
    return simulation_options(db, investigation)


@router.post("/{investigation_id}/risk/simulate", response_model=RiskSimulationOut)
def risk_simulation(investigation_id: str, payload: RiskSimulationInput,
                    _user: User = Depends(require_csrf), db: Session = Depends(get_db)) -> dict:
    investigation = visible_row(db, Investigation, investigation_id)
    if investigation is None:
        raise HTTPException(404, "Investigation not found")
    if investigation.status not in FINISHED:
        raise HTTPException(409, "Remediation simulations require a finished investigation")
    if visible_findings(db).filter_by(id=payload.finding_id, investigation_id=investigation.id).first() is None:
        raise HTTPException(404, "Finding not found in this investigation")
    try:
        return simulate_remediation(db, investigation, payload.action, payload.finding_id)
    except SimulationError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.get("/{investigation_id}/changes/{previous_id}", response_model=EvidenceGraphChangesOut)
def compare_evidence_graphs(investigation_id: str, previous_id: str,
                            _user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    current, previous = (visible_row(db, Investigation, investigation_id),
                         visible_row(db, Investigation, previous_id))
    if current is None or previous is None or current.asset_id != previous.asset_id or current.id == previous.id:
        raise HTTPException(404, "Two distinct investigations for the same asset are required")
    if current.status not in FINISHED or previous.status not in FINISHED:
        raise HTTPException(409, "Investigation changes are available after both investigations finish")
    return compare_evidence_graph(db, current, previous)


@router.get("/{investigation_id}/compare/{other_id}")
def compare_investigations(investigation_id: str, other_id: str, _user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    current, previous = (visible_row(db, Investigation, investigation_id),
                         visible_row(db, Investigation, other_id))
    if current is None or previous is None or current.asset_id != previous.asset_id:
        raise HTTPException(404, "Both investigations for the same asset are required")
    new = {item.fingerprint: item for item in visible_findings(db).filter_by(investigation_id=current.id).all()}
    old = {item.fingerprint: item for item in visible_findings(db).filter_by(investigation_id=previous.id).all()}
    current_risk = db.query(RiskAssessment).filter_by(investigation_id=current.id).first()
    previous_risk = db.query(RiskAssessment).filter_by(investigation_id=previous.id).first()
    current_evidence = {row.sha256: row for row in db.query(EvidenceSnapshot).filter_by(investigation_id=current.id).all()}
    previous_evidence = {row.sha256: row for row in db.query(EvidenceSnapshot).filter_by(investigation_id=previous.id).all()}
    return {"current": _summary(db, current), "previous": _summary(db, previous),
        "new_findings": [_finding_payload(item) for key, item in new.items() if key not in old],
        "no_longer_observed": [_finding_payload(item) for key, item in old.items() if key not in new],
        "new_evidence": [_evidence_payload(item) for key, item in current_evidence.items() if key not in previous_evidence],
        "changed_scoring_rules": current_risk.version != previous_risk.version if current_risk and previous_risk else current_risk is not previous_risk,
        "coverage_changed": (current_risk.assessed_categories, current_risk.excluded_categories) !=
            (previous_risk.assessed_categories, previous_risk.excluded_categories) if current_risk and previous_risk else current_risk is not previous_risk,
        "score_changed": current_risk.score != previous_risk.score if current_risk and previous_risk else current_risk is not previous_risk}


def _summary(db: Session, item: Investigation, *, asset: Asset | None = None, risk: RiskAssessment | None = None,
             latest_attempt: InvestigationAttempt | None = None) -> dict:
    asset = asset if asset is not None else db.get(Asset, item.asset_id)
    risk = risk if risk is not None else db.query(RiskAssessment).filter_by(investigation_id=item.id).first()
    latest_attempt = latest_attempt if latest_attempt is not None else (db.query(InvestigationAttempt).filter_by(investigation_id=item.id)
                      .order_by(InvestigationAttempt.attempt_number.desc()).first())
    return {"id": item.id, "asset_id": item.asset_id, "asset_kind": asset.kind if asset else None,
        "asset_identifier": asset.identifier if asset else None, "mode": item.mode, "demo_data": item.mode == "demo",
        "scenario": item.scenario,
        "email_breach_provider": (item.email_breach_provider or "hibp") if asset and asset.kind == "email" else None,
        "email_breach_authorization_id": item.email_breach_authorization_id,
        "status": item.status, "progress": item.progress, "started_at": item.started_at,
        "finished_at": item.finished_at, "created_at": item.created_at, "error_summary": item.error_summary,
        "attempt_number": latest_attempt.attempt_number if latest_attempt else None,
        "risk": _risk_payload(risk)}


def _asset_payload(asset: Asset | None, db: Session) -> dict | None:
    if asset is None: return None
    authorization = active_website_authorization(db, asset.id)
    return {"id": asset.id, "kind": asset.kind, "identifier": asset.identifier, "notes": asset.notes,
        "authorized_at": authorization.created_at if authorization else None,
        "authorization_note": authorization.note if authorization else None,
        "authorization_id": authorization.id if authorization else None,
        "authorization_expires_at": authorization.expires_at if authorization else None,
        "components": []}


def _attempt_payload(item: InvestigationAttempt) -> dict:
    return {"id": item.id, "attempt_number": item.attempt_number, "retry_kind": item.retry_kind,
        "status": item.status, "progress": item.progress, "started_at": item.started_at,
        "finished_at": item.finished_at, "created_at": item.created_at, "error_summary": item.error_summary}


def _run_payload(item: CollectorRun, attempt_number: int | None = None) -> dict:
    return {"id": item.id, "collector": item.collector, "status": item.status, "source": item.source,
        "error_explanation": item.error_explanation, "record_count": item.record_count,
        "attempt_id": item.attempt_id, "attempt_number": attempt_number,
        "feed_snapshot_id": item.feed_snapshot_id,
        "started_at": item.started_at, "finished_at": item.finished_at}


def _finding_payload(item: Finding) -> dict:
    details = item.details_json or {}
    return {"id": item.id, "asset_id": item.asset_id, "investigation_id": item.investigation_id,
        "evidence_id": item.evidence_id, "category": item.category, "severity": item.severity, "title": item.title,
        "explanation": item.explanation, "recommendation": item.recommendation, "source": item.source,
        "observed_at": item.observed_at, "applicability": item.applicability,
        "cvss_version": details.get("cvss_version"), "cvss_score": details.get("cvss_score"),
        "cvss_vector": details.get("vector"), "kev": details.get("kev"),
        "applicability_reason": item.applicability_reason, "epss_score": item.epss_score,
        "epss_percentile": item.epss_percentile, "epss_observed_at": item.epss_observed_at,
        "epss_provider_status": item.epss_provider_status, "epss_freshness": item.epss_freshness,
        "is_synthetic": item.is_synthetic, "details_json": item.details_json,
        "osv": osv_finding_payload(details, item.evidence_id)}


def _evidence_payload(item: EvidenceSnapshot) -> dict:
    return {"id": item.id, "source": item.source, "observed_at": item.observed_at,
        "evidence_json": item.evidence_json, "sha256": item.sha256, "is_synthetic": item.is_synthetic}


def _risk_payload(item: RiskAssessment | None) -> dict | None:
    if item is None: return None
    return {"version": item.version, "score": item.score, "band": item.band,
        "assessed_categories": item.assessed_categories, "excluded_categories": item.excluded_categories,
        "category_scores": item.category_scores, "contributing_finding_ids": item.contributing_finding_ids,
        "explanation": item.explanation_json}


def _risk_revision_payload(item: RiskAssessmentRevision) -> dict:
    return {"id": item.id, "investigation_id": item.investigation_id, "revision_number": item.revision_number,
            "input_fingerprint": item.input_fingerprint, "version": item.version, "score": item.score,
            "band": item.band, "weights": item.weights_json, "assessed_categories": item.assessed_categories,
            "excluded_categories": item.excluded_categories, "category_scores": item.category_scores,
            "contributing_finding_ids": item.contributing_finding_ids, "explanation": item.explanation_json,
            "created_at": item.created_at}
