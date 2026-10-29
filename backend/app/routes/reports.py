import hashlib
import io
import json
from typing import Literal
from datetime import timezone
from xml.sax.saxutils import escape

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Flowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.database import get_db
from app.authorization import active_website_authorization
from app.dependencies import get_current_user, require_roles_csrf
from app.models import (Asset, AttackMapping, AuditEvent, CollectorRun, EvidenceSnapshot, Finding, FindingControlMapping,
                        Incident, Investigation, InvestigationAttempt, RemediationPlan, Report, RiskAssessment, ThreatScenario, User, new_id)
from app.integrity import report_integrity
from app.osv import osv_finding_payload
from app.ip_intelligence import build_ip_intelligence_history
from app.pagination import Page, apply_page, page_params
from app.routes.incidents import _detail as incident_detail
from app.schemas import PostureReportCreate, ReportCreate, ReportOut
from app.routes.remediation import _mapping_payloads, _plan_payloads
from app.services.attack import mapping_payloads, mappings_for_targets
from app.services.posture import build_scorecard
from app.visibility import visible_evidence, visible_findings, visible_reports, visible_row
from app.visibility import visible_remediation_plans, visible_threat_scenarios

router = APIRouter(prefix="/reports", tags=["reports"])


@router.post("", status_code=201)
def create_report(payload: ReportCreate, user: User = Depends(require_roles_csrf("admin", "analyst")), db: Session = Depends(get_db)) -> dict:
    if bool(payload.investigation_id) == bool(payload.incident_id):
        raise HTTPException(422, "Provide exactly one investigation_id or incident_id")
    if payload.investigation_id:
        investigation = visible_row(db, Investigation, payload.investigation_id)
        if investigation is None: raise HTTPException(404, "Investigation not found")
        if investigation.status not in {"completed", "partial", "failed"}: raise HTTPException(409, "Wait until the investigation finishes before exporting")
        snapshot = _investigation_snapshot(db, investigation)
        demo = investigation.mode == "demo"
    else:
        incident = visible_row(db, Incident, payload.incident_id)
        if incident is None: raise HTTPException(404, "Incident not found")
        snapshot = _incident_snapshot(db, incident)
        demo = any(item.get("is_synthetic") for item in snapshot.get("evidence", []))
    if demo:
        snapshot["report_label"] = "DEMO DATA — synthetic fixtures; not a real security assessment"
    content = _json_bytes(snapshot) if payload.format == "json" else _pdf_bytes(snapshot)
    report = Report(id=new_id(), investigation_id=payload.investigation_id, incident_id=payload.incident_id,
        format=payload.format, created_by=user.id, is_demo=demo, snapshot_json=snapshot,
        content=content, sha256=hashlib.sha256(content).hexdigest())
    db.add(report)
    db.add(AuditEvent(actor_id=user.id, action="report.generated", entity_type="report", entity_id=report.id,
        details_json={"format": payload.format, "is_demo": demo, "sha256": report.sha256}))
    db.commit()
    db.refresh(report)
    return _report_payload(report)


@router.post("/posture", status_code=201, response_model=ReportOut)
def create_posture_report(
    payload: PostureReportCreate,
    user: User = Depends(require_roles_csrf("admin", "analyst")),
    db: Session = Depends(get_db),
) -> dict:
    scorecard = build_scorecard(db, payload.range_days)
    snapshot = {"report_type": "posture", "created_at": _iso_now(), "scorecard": scorecard}
    provider_modes = {item.get("data_mode") for item in scorecard["provider_health"]["providers"]}
    contains_demo = "demo" in scorecard["data_scope"]["data_modes"] or "demo" in provider_modes
    if contains_demo:
        snapshot["report_label"] = "Contains synthetic Demo observations; scorecard values retain their individual data states and scopes."
    content = _json_bytes(snapshot) if payload.format == "json" else _pdf_bytes(snapshot)
    report = Report(
        id=new_id(), investigation_id=None, incident_id=None, format=payload.format,
        created_by=user.id, is_demo=contains_demo, snapshot_json=snapshot, content=content,
        sha256=hashlib.sha256(content).hexdigest(),
    )
    db.add(report)
    db.add(AuditEvent(actor_id=user.id, action="report.posture_generated", entity_type="report", entity_id=report.id,
                      details_json={"format": payload.format, "range_days": payload.range_days,
                                    "is_demo": contains_demo, "sha256": report.sha256}))
    db.commit()
    db.refresh(report)
    return _report_payload(report)


@router.get("", response_model=list[ReportOut])
def list_reports(_user: User = Depends(get_current_user), db: Session = Depends(get_db), response: Response = None,
                 format: str | None = Query(default=None), investigation_id: str | None = Query(default=None),
                 incident_id: str | None = Query(default=None), is_demo: bool | None = Query(default=None),
                 q: str | None = Query(default=None, max_length=200),
                 sort: Literal["created_at", "format"] = Query(default="created_at"),
                 order: Literal["asc", "desc"] = Query(default="desc"), page: Page = Depends(page_params)) -> list[dict]:
    query = visible_reports(db)
    if format: query = query.filter(Report.format == format)
    if investigation_id: query = query.filter(Report.investigation_id == investigation_id)
    if incident_id: query = query.filter(Report.incident_id == incident_id)
    if is_demo is not None: query = query.filter(Report.is_demo == is_demo)
    if q: query = query.filter(Report.sha256.ilike(f"%{q.strip()}%"))
    sort_column = {"created_at": Report.created_at, "format": Report.format}[sort]
    ordering = sort_column.asc() if order == "asc" else sort_column.desc()
    return [_report_payload(item) for item in apply_page(query.order_by(ordering, Report.id.asc()), page, response)]


@router.get("/{report_id}")
def get_report(report_id: str, _user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    item = visible_row(db, Report, report_id)
    if item is None: raise HTTPException(404, "Report not found")
    return {**_report_payload(item), "snapshot": item.snapshot_json}


@router.get("/{report_id}/download")
def download_report(report_id: str, _user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> Response:
    item = visible_row(db, Report, report_id)
    if item is None: raise HTTPException(404, "Report not found")
    media = "application/pdf" if item.format == "pdf" else "application/json"
    return Response(content=item.content, media_type=media,
        headers={"Content-Disposition": f'attachment; filename="cyberlens-{item.id}.{item.format}"', "X-Content-SHA256": item.sha256})


def _investigation_snapshot(db: Session, investigation: Investigation) -> dict:
    asset = db.get(Asset, investigation.asset_id)
    findings = visible_findings(db).filter_by(investigation_id=investigation.id).order_by(Finding.severity.desc(), Finding.observed_at).all()
    evidence = visible_evidence(db).filter_by(investigation_id=investigation.id).order_by(EvidenceSnapshot.observed_at).all()
    risk = db.query(RiskAssessment).filter_by(investigation_id=investigation.id).first()
    runs = db.query(CollectorRun).filter_by(investigation_id=investigation.id).order_by(CollectorRun.started_at).all()
    attempts = (db.query(InvestigationAttempt).filter_by(investigation_id=investigation.id)
                .order_by(InvestigationAttempt.attempt_number).all())
    snapshot = {"report_type": "investigation", "created_at": _iso_now(), "investigation": {
        "id": investigation.id, "status": investigation.status, "mode": investigation.mode, "scenario": investigation.scenario,
        "email_breach_provider": investigation.email_breach_provider or ("hibp" if asset.kind == "email" else None),
        "created_at": _iso(investigation.created_at), "started_at": _iso(investigation.started_at), "finished_at": _iso(investigation.finished_at)},
        "attempts": [{"id": attempt.id, "attempt_number": attempt.attempt_number,
            "retry_kind": attempt.retry_kind, "status": attempt.status,
            "started_at": _iso(attempt.started_at), "finished_at": _iso(attempt.finished_at),
            "error_summary": attempt.error_summary} for attempt in attempts],
        "scope": {"asset_id": asset.id, "kind": asset.kind, "identifier": asset.identifier,
                  "authorization_recorded": active_website_authorization(db, asset.id) is not None,
                  "threat_context": _asset_threat_context(asset)},
        "collector_runs": [{"collector": run.collector, "attempt_id": run.attempt_id,
            "attempt_number": next((attempt.attempt_number for attempt in attempts if attempt.id == run.attempt_id), None),
            "source": run.source, "status": run.status, "feed_snapshot_id": run.feed_snapshot_id,
            "error_explanation": run.error_explanation, "started_at": _iso(run.started_at), "finished_at": _iso(run.finished_at)} for run in runs],
        "findings": [_finding(item) for item in findings], "risk": _risk(risk),
        "ip_intelligence": build_ip_intelligence_history(db, investigation),
        "assessment_gaps": risk.excluded_categories if risk else ["risk assessment unavailable"],
        "evidence": [_evidence(item) for item in evidence],
        "recommendations": list(dict.fromkeys(item.recommendation for item in findings))}
    evidence_by_run = {item.collector_run_id: item for item in evidence if item.collector_run_id}
    snapshot["threat_feed_snapshots"] = [
        {
            "collector_run_id": run.id,
            "source": run.source,
            "collector_status": run.status,
            "snapshot_id": run.feed_snapshot_id or ((evidence_by_run[run.id].evidence_json or {}).get("snapshot_id") if run.id in evidence_by_run else None),
            "evidence_id": evidence_by_run[run.id].id if run.id in evidence_by_run else None,
            "evidence": (evidence_by_run[run.id].evidence_json or {}) if run.id in evidence_by_run else {},
        }
        for run in runs if run.collector in {"spamhaus_drop", "cins_army", "openphish"}
    ]
    openphish_run = next((run for run in runs if run.collector == "openphish"), None)
    if openphish_run:
        snapshot["openphish_use_notice"] = (
            "This report contains an OpenPhish Community Feed lookup. The provider's current terms limit community-feed use "
            "to personal, academic, or independent research that does not support an organization's business operations. "
            "Business use requires prior written consent, and third-party disclosure or distribution requires express permission. "
            "The operator's configuration acknowledgement does not grant those rights. Review the provider's current terms before use or sharing."
        )
        snapshot["openphish_terms_url"] = "https://www.openphish.com/terms.html"
    if asset.kind == "email":
        breach_run = next((item for item in reversed(runs) if item.collector in {"hibp", "xposedornot"}), None)
        breach_evidence = next((item for item in reversed(evidence)
                                if breach_run is not None and item.collector_run_id == breach_run.id), None)
        provider = investigation.email_breach_provider or "hibp"
        evidence_json = breach_evidence.evidence_json if breach_evidence else {}
        snapshot["email_breach_lookup"] = {
            "provider": provider,
            "source": breach_run.source if breach_run else None,
            "status": breach_run.status if breach_run else "not_run",
            "observed_at": _iso(breach_evidence.observed_at) if breach_evidence else None,
            "evidence_id": breach_evidence.id if breach_evidence else None,
            "no_match_message": evidence_json.get("no_match_message"),
            "coverage_note": evidence_json.get("coverage_note") or (
                "XposedOrNot has a separate community dataset and does not have identical coverage to HIBP."
                if provider == "xposedornot" else None),
            "notice": "Historical provider records do not establish current account compromise.",
        }
    finding_ids = {item.id for item in findings}
    incident_ids = {row.id for row in db.query(Incident).filter_by(investigation_id=investigation.id).all()}
    filters = []
    if finding_ids: filters.append(RemediationPlan.finding_id.in_(finding_ids))
    if incident_ids: filters.append(RemediationPlan.incident_id.in_(incident_ids))
    plans = visible_remediation_plans(db).filter(or_(*filters)).order_by(RemediationPlan.created_at, RemediationPlan.id).all() if filters else []
    mappings = (db.query(FindingControlMapping).filter(FindingControlMapping.finding_id.in_(finding_ids))
                .order_by(FindingControlMapping.created_at, FindingControlMapping.id).all()) if finding_ids else []
    attack_mappings = mapping_payloads(db, mappings_for_targets(db, finding_ids, incident_ids))
    snapshot["remediation_plans"] = _plan_payloads(db, plans)
    snapshot["control_mappings"] = _mapping_payloads(db, mappings)
    snapshot["attack_mappings"] = attack_mappings
    snapshot["threat_scenarios"] = _threat_scenarios(db, asset.id)
    snapshot["integrity"] = report_integrity(db, evidence)
    return _json_safe(snapshot)


def _incident_snapshot(db: Session, incident: Incident) -> dict:
    detail = _json_safe(incident_detail(db, incident))
    plans = (visible_remediation_plans(db).filter_by(incident_id=incident.id)
             .order_by(RemediationPlan.created_at, RemediationPlan.id).all())
    finding_ids = {item.get("id") for item in detail.get("findings", []) if item.get("id")}
    mappings = (db.query(FindingControlMapping).filter(FindingControlMapping.finding_id.in_(finding_ids))
                .order_by(FindingControlMapping.created_at, FindingControlMapping.id).all()) if finding_ids else []
    attack_rows = mappings_for_targets(db, finding_ids, {incident.id})
    evidence_ids = {item.get("id") for item in detail.get("evidence", []) if item.get("id")}
    evidence_rows = db.query(EvidenceSnapshot).filter(EvidenceSnapshot.id.in_(evidence_ids)).all() if evidence_ids else []
    feed_evidence = [item for item in detail.get("evidence", [])
                     if item.get("source") in {"Spamhaus Project DROP", "CINS Army", "OpenPhish Community Feed"}]
    threat_feed_snapshots = [{
        "source": item.get("source"),
        "collector_run_id": item.get("collector_run_id"),
        "collector_status": (item.get("evidence_json") or {}).get("provenance", {}).get("status", "unknown"),
        "snapshot_id": (item.get("evidence_json") or {}).get("snapshot_id"),
        "evidence_id": item.get("id"),
        "evidence": item.get("evidence_json") or {},
    } for item in feed_evidence]
    linked_investigation = db.get(Investigation, incident.investigation_id) if incident.investigation_id else None
    return _json_safe({"report_type": "incident", "created_at": _iso_now(), "incident": detail,
        "evidence": detail.get("evidence", []), "timeline": detail.get("events", []), "response_tasks": detail.get("tasks", []),
        "threat_feed_snapshots": threat_feed_snapshots,
        "ip_intelligence": build_ip_intelligence_history(db, linked_investigation) if linked_investigation else None,
        "remediation_plans": _plan_payloads(db, plans), "control_mappings": _mapping_payloads(db, mappings),
        "attack_mappings": mapping_payloads(db, attack_rows),
        "threat_scenarios": _threat_scenarios(db, incident.asset_id),
        "asset_threat_context": _asset_threat_context(db.get(Asset, incident.asset_id)),
        "integrity": report_integrity(db, evidence_rows),
        **({"openphish_use_notice": (
                "This report contains an OpenPhish Community Feed lookup. The provider's current terms limit community-feed use "
                "to personal, academic, or independent research that does not support an organization's business operations. "
                "Business use requires prior written consent, and third-party disclosure or distribution requires express permission. "
                "The operator's configuration acknowledgement does not grant those rights. Review the provider's current terms before use or sharing."
            ), "openphish_terms_url": "https://www.openphish.com/terms.html"}
           if any(item.get("source") == "OpenPhish Community Feed" for item in detail.get("evidence", [])) else {})})


def _asset_threat_context(asset: Asset | None) -> dict:
    if asset is None:
        return {}
    return {"criticality": asset.criticality, "data_classification": asset.data_classification,
        "trust_zone": asset.trust_zone, "exposure_classification": asset.exposure_classification,
        "business_owner": asset.business_owner, "protection_requirements": asset.protection_requirements or []}


def _threat_scenarios(db: Session, asset_id: str) -> list[dict]:
    rows = visible_threat_scenarios(db).filter_by(asset_id=asset_id).order_by(ThreatScenario.created_at, ThreatScenario.id).all()
    return [{"id": item.id, "asset_id": item.asset_id, "finding_id": item.finding_id,
        "investigation_id": item.investigation_id, "incident_id": item.incident_id,
        "stride_category": item.stride_category, "title": item.title, "description": item.description,
        "likelihood": item.likelihood, "business_impact": item.business_impact, "confidence": item.confidence,
        "business_impact_score": item.likelihood * item.business_impact,
        "calculation_explanation": (f"Likelihood ({item.likelihood}/5) × business impact "
            f"({item.business_impact}/5) = {item.likelihood * item.business_impact}/25. Confidence is recorded separately."),
        "assumptions": item.assumptions_json or [], "unconfirmed_information": item.unconfirmed_information_json or [],
        "owner_id": item.owner_id, "review_status": item.review_status,
        "score_notice": "Business-impact scenario prioritization only; separate from technical severity and the CyberLens technical risk score."}
        for item in rows]


def _json_safe(value):
    from datetime import date, datetime
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    return value


def _finding(item: Finding) -> dict:
    details = item.details_json or {}
    return {"id": item.id, "category": item.category, "severity": item.severity, "title": item.title,
        "explanation": item.explanation, "recommendation": item.recommendation, "source": item.source,
        "observed_at": _iso(item.observed_at), "applicability": item.applicability,
        "applicability_reason": item.applicability_reason, "is_synthetic": item.is_synthetic,
        "cvss": {"version": details.get("cvss_version"), "score": details.get("cvss_score"),
                 "severity": item.severity, "vector": details.get("vector")},
        "kev": details.get("kev"),
        "epss": {"score": item.epss_score, "percentile": item.epss_percentile,
                 "observed_at": _iso(item.epss_observed_at), "provider_status": item.epss_provider_status,
                 "freshness": item.epss_freshness, "provider": details.get("epss_provider"),
                 "provider_version": details.get("epss_provider_version"),
                 "source_date": details.get("epss_source_date")},
        "osv": osv_finding_payload(details, item.evidence_id),
        "evidence_id": item.evidence_id, "details": details}


def _evidence(item: EvidenceSnapshot) -> dict:
    return {"id": item.id, "source": item.source, "observed_at": _iso(item.observed_at),
        "sha256": item.sha256, "is_synthetic": item.is_synthetic, "evidence": item.evidence_json}


def _risk(item: RiskAssessment | None) -> dict | None:
    if not item: return None
    return {"version": item.version, "score": item.score, "band": item.band, "category_scores": item.category_scores,
        "assessed_categories": item.assessed_categories, "excluded_categories": item.excluded_categories,
        "contributing_finding_ids": item.contributing_finding_ids, "explanation": item.explanation_json}


def _report_payload(item: Report) -> dict:
    report_type = (item.snapshot_json or {}).get("report_type")
    if report_type not in {"investigation", "incident", "posture"}:
        report_type = "incident" if item.incident_id else "investigation"
    return {"id": item.id, "format": item.format, "investigation_id": item.investigation_id,
        "report_type": report_type,
        "incident_id": item.incident_id, "created_at": _iso(item.created_at), "created_by": item.created_by,
        "is_demo": item.is_demo, "sha256": item.sha256, "download_url": f"/api/v1/reports/{item.id}/download"}


def _iso(value):
    if value is None: return None
    if value.tzinfo is None: value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _iso_now():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _json_bytes(snapshot: dict) -> bytes:
    return json.dumps(snapshot, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")


class _CyberLensBrandHeader(Flowable):
    """Small local vector lockup for newly generated PDF reports."""

    def wrap(self, available_width: float, available_height: float) -> tuple[float, float]:
        self.width = min(available_width, 250)
        self.height = 43
        return self.width, self.height

    def draw(self) -> None:
        canvas = self.canv
        canvas.saveState()
        canvas.translate(0, 34)
        canvas.scale(0.5, -0.5)
        lens = canvas.beginPath()
        lens.moveTo(47, 12.5)
        lens.curveTo(42.8, 8.4, 36.9, 6, 30, 6)
        lens.curveTo(16.7, 6, 6, 17.6, 6, 32)
        lens.curveTo(6, 46.4, 16.7, 58, 30, 58)
        lens.curveTo(36.9, 58, 42.8, 55.6, 47, 51.5)
        canvas.setLineCap(1)
        canvas.setLineJoin(1)
        canvas.setStrokeColor(colors.HexColor("#596FE3"))
        canvas.setLineWidth(7.5)
        canvas.drawPath(lens, stroke=1, fill=0)
        canvas.setStrokeColor(colors.HexColor("#7186F4"))
        canvas.setLineWidth(3.4)
        canvas.line(40, 32, 48.5, 32)
        canvas.setFillColor(colors.HexColor("#6B7EED"))
        canvas.setStrokeColor(colors.HexColor("#4F5FC8"))
        canvas.setLineWidth(2)
        canvas.circle(53, 32, 4.2, stroke=1, fill=1)
        canvas.restoreState()
        canvas.setFillColor(colors.HexColor("#222A43"))
        canvas.setFont("Helvetica-Bold", 22)
        canvas.drawString(43, 18, "CyberLens")
        canvas.setFillColor(colors.HexColor("#68738D"))
        canvas.setFont("Helvetica-Bold", 6.5)
        canvas.drawString(44, 6, "SECURITY ANALYSIS WORKSPACE")


def _pdf_bytes(snapshot: dict) -> bytes:
    output = io.BytesIO()
    document = SimpleDocTemplate(output, pagesize=letter, title="CyberLens report", author="CyberLens")
    styles = getSampleStyleSheet()
    story = []
    title_by_type = {"investigation": "Investigation Report", "incident": "Incident Report",
                     "posture": "Security Posture Scorecard"}
    title = title_by_type.get(snapshot.get("report_type"), "Report")
    story.extend([_CyberLensBrandHeader(), Spacer(1, 3), Paragraph(escape(title), styles["Title"]), Spacer(1, 10)])
    if snapshot.get("report_label"):
        story.extend([Paragraph(escape(snapshot["report_label"]), styles["Heading2"]), Spacer(1, 8)])
    rows = [["Report type", snapshot["report_type"]], ["Generated", snapshot["created_at"]],
            ["Integrity SHA-256", hashlib.sha256(_json_bytes(snapshot)).hexdigest()]]
    scope = snapshot.get("scope", {})
    if scope:
        rows.extend([["Asset type", scope.get("kind", "")], ["Asset", scope.get("identifier", "")]])
    incident_info = snapshot.get("incident", {})
    if incident_info:
        rows.extend([["Case", incident_info.get("title", "")], ["Classification", incident_info.get("classification", "")],
                     ["Priority / status", f"{incident_info.get('priority', '')} / {incident_info.get('status', '')}"],
                     ["Closure summary", incident_info.get("resolution_summary", "") or "Not closed"]])
    table = Table([[Paragraph(escape(str(cell)), styles["BodyText"]) for cell in row] for row in rows], colWidths=[130, 390])
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e9eff3")), ("GRID", (0, 0), (-1, -1), 0.3, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.extend([table, Spacer(1, 14)])
    scorecard = snapshot.get("scorecard")
    if scorecard:
        _append_posture_pdf(story, styles, scorecard)
        document.build(story)
        return output.getvalue()
    threat_context = scope.get("threat_context") or snapshot.get("asset_threat_context") or {}
    if threat_context:
        story.append(Paragraph("Asset business context", styles["Heading2"]))
        context_line = (f"Criticality: {threat_context.get('criticality', 'unknown')} · Data classification: {threat_context.get('data_classification', 'unknown')} · "
                        f"Trust zone: {threat_context.get('trust_zone', 'unknown')} · Exposure: {threat_context.get('exposure_classification', 'unknown')} · "
                        f"Business owner: {threat_context.get('business_owner') or 'not recorded'}")
        story.append(Paragraph(escape(context_line), styles["BodyText"]))
        requirements = threat_context.get("protection_requirements", [])
        story.append(Paragraph(escape("Protection requirements: " + ("; ".join(requirements) if requirements else "none recorded")), styles["BodyText"]))
        story.append(Spacer(1, 8))
    risk = snapshot.get("risk")
    if risk:
        story.append(Paragraph("Risk assessment", styles["Heading2"]))
        value = "Insufficient data" if risk.get("score") is None else f"{risk.get('score')} / 100 · {risk.get('band')}"
        story.append(Paragraph(escape(value), styles["BodyText"]))
        story.append(Paragraph(escape(risk.get("explanation", {}).get("metric_notice", "")), styles["BodyText"]))
        story.append(Spacer(1, 10))
    integrity = snapshot.get("integrity", {})
    if integrity:
        chain = integrity.get("audit_chain", {})
        evidence_integrity = integrity.get("evidence", {})
        story.append(Paragraph("Integrity verification", styles["Heading2"]))
        story.append(Paragraph(escape(
            f"State: {integrity.get('state', 'unavailable')} · Audit chain: {chain.get('state', 'unavailable')} "
            f"through event {chain.get('last_sequence') or 0} · Evidence checks: {evidence_integrity.get('state', 'incomplete')} "
            f"({evidence_integrity.get('counts', {})})"), styles["BodyText"]))
        if integrity.get("limitation"):
            story.append(Paragraph(escape(integrity["limitation"]), styles["BodyText"]))
        for item in evidence_integrity.get("items", []):
            story.append(Paragraph(escape(
                f"Evidence {item.get('evidence_id')} · {item.get('state')} · stored {item.get('stored_sha256')} · "
                f"calculated {item.get('calculated_sha256')}"), styles["BodyText"]))
        story.append(Spacer(1, 8))
    feed_snapshots = snapshot.get("threat_feed_snapshots", [])
    if feed_snapshots:
        story.append(Paragraph("Threat-feed snapshot evidence", styles["Heading2"]))
        story.append(Paragraph(
            "Each source is compared independently with its pinned local snapshot. A non-match is not a safety verdict or proof of remediation.",
            styles["BodyText"]))
        for item in feed_snapshots:
            feed_evidence = item.get("evidence") or {}
            result = feed_evidence.get("result") or feed_evidence.get("provider_status") or item.get("collector_status")
            provider_date = ("not supplied by this feed" if item.get("source") == "CINS Army" else
                             feed_evidence.get("provider_published_at") or "unavailable")
            line = (f"{item.get('source') or feed_evidence.get('provider') or 'Threat feed'} · snapshot {item.get('snapshot_id') or 'unavailable'} · {result} · freshness {feed_evidence.get('freshness', 'unknown')} · "
                    f"observed {feed_evidence.get('observed_at') or feed_evidence.get('snapshot_retrieved_at') or 'unavailable'} · "
                    f"provider date {provider_date} · "
                    f"SHA-256 {feed_evidence.get('content_sha256') or 'unavailable'} · evidence {item.get('evidence_id') or 'unavailable'}")
            story.append(Paragraph(escape(line), styles["BodyText"]))
            if feed_evidence.get("attribution"):
                story.append(Paragraph(escape(str(feed_evidence["attribution"])), styles["BodyText"]))
            feed_metadata = feed_evidence.get("feed_metadata") or {}
            for family, label in (("ipv4", "IPv4"), ("ipv6", "IPv6")):
                entry = feed_metadata.get("feeds", {}).get(family, {}) if isinstance(feed_metadata, dict) else {}
                provider_metadata = entry.get("provider_metadata", {}) if isinstance(entry, dict) else {}
                if provider_metadata:
                    story.append(Paragraph(escape(
                        f"{label} · {provider_metadata.get('copyright', 'Copyright unavailable')} · publication timestamp {entry.get('published_at', 'unavailable')}"),
                        styles["BodyText"]))
            matched = feed_evidence.get("matched_networks") or []
            if matched:
                story.append(Paragraph(escape("Matched networks: " + "; ".join(
                    f"{row.get('network')} ({row.get('sbl_id')})" for row in matched)), styles["BodyText"]))
            if feed_evidence.get("matched_ip"):
                story.append(Paragraph(escape(f"Exact IP indicator: {feed_evidence['matched_ip']}"), styles["BodyText"]))
        story.append(Spacer(1, 8))
    ip_intelligence = snapshot.get("ip_intelligence")
    if isinstance(ip_intelligence, dict):
        story.extend([Paragraph("IP source comparison and listing history", styles["Heading2"]),
                      Paragraph(escape(f"{ip_intelligence.get('asset_ip')} · {ip_intelligence.get('corroboration_label')}"), styles["BodyText"]),
                      Paragraph(escape(str(ip_intelligence.get("corroboration_note", ""))), styles["BodyText"]),
                      Paragraph("CINS Army, Spamhaus DROP, and VirusTotal evidence remain separate records with separate observation times. List overlap does not automatically increase severity.", styles["BodyText"])])
        for event in ip_intelligence.get("history", []):
            story.append(Paragraph(escape(
                f"{event.get('source')} · {event.get('classification')} · {event.get('result')} · "
                f"investigation {event.get('investigation_created_at')} · observed {event.get('observed_at') or 'unavailable'} · "
                f"snapshot {event.get('snapshot_id') or 'unavailable'} · "
                f"evidence {event.get('evidence_id') or 'unavailable'} · {event.get('reason') or ''}"), styles["BodyText"]))
        story.append(Spacer(1, 8))
    story.append(Paragraph("Findings", styles["Heading2"]))
    report_findings = snapshot.get("findings", incident_info.get("findings", []))
    for item in report_findings:
        epss = item.get("epss") or {}
        cvss = item.get("cvss") or {}
        epss_score = "Unavailable" if epss.get("score") is None else f"{float(epss['score']) * 100:.1f}%"
        epss_percentile = "Unavailable" if epss.get("percentile") is None else f"{float(epss['percentile']) * 100:.1f}th percentile"
        epss_line = f"EPSS: {epss_score} probability over the next 30 days · {epss_percentile} · status {epss.get('provider_status') or 'not assessed'} · freshness {epss.get('freshness') or 'unknown'} (predictive estimate; not proof of exploitation or compromise)"
        cvss_line = f"CVSS: {cvss.get('score') if cvss.get('score') is not None else 'Unavailable'} · KEV: {item.get('kev') if item.get('kev') is not None else 'Unknown'} · Applicability: {item.get('applicability', 'unknown')}"
        osv = item.get("osv") or {}
        osv_line = ""
        if osv:
            aliases = ", ".join(osv.get("aliases", [])) or "No aliases"
            fixed = ", ".join(osv.get("fixed_versions", [])) or "No fixed version documented"
            severity_metadata = "; ".join(
                f"{entry.get('type', 'Source')}: {entry.get('score', 'Unknown')}"
                for entry in osv.get("severity_metadata", []) if isinstance(entry, dict)
            ) or "Unknown"
            osv_line = (f"<br/><font size='8'>OSV advisory: {escape(str(osv.get('advisory_id')))} · aliases {escape(aliases)} · "
                        f"{escape(str(osv.get('ecosystem')))} {escape(str(osv.get('package_name')))}@{escape(str(osv.get('package_version')))} · "
                        f"provider {escape(str(osv.get('provider_status')))} / {escape(str(osv.get('freshness')))} · "
                        f"severity metadata: {escape(severity_metadata)} · observed {escape(str(osv.get('observed_at')))} · fixed: {escape(fixed)} · "
                        f"evidence {escape(str(osv.get('evidence_id') or 'unavailable'))}</font>")
        block = f"<b>{escape(str(item.get('severity', '')))} · {escape(str(item.get('title', '')))}</b><br/>{escape(str(item.get('explanation', '')))}<br/><b>Recommendation:</b> {escape(str(item.get('recommendation', '')))}<br/><font size='8'>Source: {escape(str(item.get('source', '')))} · {escape(cvss_line)}<br/>{escape(epss_line)}</font>{osv_line}"
        story.extend([Paragraph(block, styles["BodyText"]), Spacer(1, 7)])
    breach_lookup = snapshot.get("email_breach_lookup")
    if breach_lookup:
        story.extend([Spacer(1, 8), Paragraph("Email breach provider lookup", styles["Heading2"])])
        details = (f"Provider: {breach_lookup.get('source') or breach_lookup.get('provider')} · "
                   f"Status: {breach_lookup.get('status')} · Observed: {breach_lookup.get('observed_at') or 'not observed'} · "
                   f"Evidence ID: {breach_lookup.get('evidence_id') or 'unavailable'}")
        story.append(Paragraph(escape(details), styles["BodyText"]))
        if breach_lookup.get("no_match_message"):
            story.append(Paragraph(escape(str(breach_lookup["no_match_message"])), styles["BodyText"]))
        if breach_lookup.get("coverage_note"):
            story.append(Paragraph(escape(str(breach_lookup["coverage_note"])), styles["BodyText"]))
        story.append(Paragraph(escape(str(breach_lookup.get("notice") or "")), styles["BodyText"]))
    if not report_findings:
        story.append(Paragraph("No findings were recorded. This does not imply that all risks were assessed.", styles["BodyText"]))
    attack_mappings = snapshot.get("attack_mappings", [])
    if attack_mappings:
        story.extend([Spacer(1, 8), Paragraph("MITRE ATT&CK mappings", styles["Heading2"]),
                      Paragraph("A mapping is an analyst-reviewed hypothesis. Candidate context does not establish adversary behavior or attribution.", styles["BodyText"])])
        for item in attack_mappings:
            line = (f"{item.get('tactic')} · {item.get('technique_id')} {item.get('technique_name')} · "
                    f"{item.get('decision')} · confidence {item.get('confidence')} · {item.get('evidence_role')} evidence "
                    f"{item.get('evidence_id')} ({item.get('evidence_source')}) · catalog "
                    f"{item.get('catalog_release_version') or item.get('catalog_version')}")
            story.append(Paragraph(escape(line), styles["BodyText"]))
            story.append(Paragraph(escape(f"Rationale: {item.get('rationale', '')} · source {item.get('source')} · confirmed {item.get('analyst_confirmed')} · reviewed {item.get('reviewed_at') or 'not reviewed'}"), styles["BodyText"]))
            catalog_source = item.get("catalog_source")
            catalog_reference = item.get("catalog_source_reference")
            if catalog_source or catalog_reference:
                story.append(Paragraph(escape(f"Catalog source: {catalog_source or 'MITRE ATT&CK'} · {catalog_reference or ''}"), styles["BodyText"]))
        attribution = next((item.get("catalog_attribution") for item in attack_mappings if item.get("catalog_attribution")), None)
        if attribution:
            story.append(Paragraph(escape(str(attribution)), styles["BodyText"]))
    sources = sorted({str(item.get("source", "")) for item in report_findings if item.get("source")})
    if snapshot.get("collector_runs"):
        sources = sorted(set(sources) | {str(item.get("source", "")) for item in snapshot["collector_runs"] if item.get("source")})
    if sources:
        story.extend([Spacer(1, 8), Paragraph("Sources", styles["Heading2"]), Paragraph(escape(" · ".join(sources)), styles["BodyText"])])
    gaps = snapshot.get("assessment_gaps", [])
    if gaps:
        story.extend([Spacer(1, 8), Paragraph("Assessment gaps", styles["Heading2"]), Paragraph(escape(", ".join(map(str, gaps))), styles["BodyText"])])
    if incident_info:
        story.extend([Spacer(1, 8), Paragraph("Incident timeline", styles["Heading2"])])
        for event in incident_info.get("events", []):
            story.append(Paragraph(escape(f"{event.get('created_at')} · {event.get('actor')} · {event.get('event_type')}: {event.get('message')}"), styles["BodyText"]))
        story.extend([Spacer(1, 8), Paragraph("Response tasks", styles["Heading2"])])
        for task in incident_info.get("tasks", []):
            story.append(Paragraph(escape(f"{task.get('status')} · {task.get('title')} · {task.get('completed_by') or 'not completed'}"), styles["BodyText"]))
    plans = snapshot.get("remediation_plans", [])
    mappings = snapshot.get("control_mappings", [])
    if plans or mappings:
        story.extend([Spacer(1, 8), Paragraph("Remediation tracking", styles["Heading2"])])
        for plan in plans:
            details = f"{plan.get('status')} · {plan.get('priority')} · {plan.get('title')} · {plan.get('action_type')} · owner {plan.get('owner_id') or 'unassigned'}"
            if plan.get("due_at"): details += f" · due {plan.get('due_at')}"
            story.append(Paragraph(escape(details), styles["BodyText"]))
            if plan.get("description"):
                story.append(Paragraph(escape(f"Description: {plan.get('description')}"), styles["BodyText"]))
            if plan.get("assumptions"):
                story.append(Paragraph(escape("Assumptions: " + " · ".join(map(str, plan["assumptions"]))), styles["BodyText"]))
            if plan.get("notes"):
                story.append(Paragraph(escape(f"Notes: {plan.get('notes')}"), styles["BodyText"]))
            for action in plan.get("actions", []):
                evidence_id = action.get("verification_evidence_id") or "no verification evidence"
                action_details = f"Action: {action.get('status')} · {action.get('priority')} · {action.get('title')} · {action.get('action_type')} · owner {action.get('owner_id') or 'unassigned'}"
                if action.get("due_at"): action_details += f" · due {action.get('due_at')}"
                story.append(Paragraph(escape(action_details), styles["BodyText"]))
                if action.get("description"):
                    story.append(Paragraph(escape(str(action.get("description"))), styles["BodyText"]))
                if action.get("verification_instructions"):
                    story.append(Paragraph(escape(f"Verification: {action.get('verification_instructions')}"), styles["BodyText"]))
                if action.get("assumptions"):
                    story.append(Paragraph(escape("Action assumptions: " + " · ".join(map(str, action["assumptions"]))), styles["BodyText"]))
                if action.get("notes"):
                    story.append(Paragraph(escape(f"Action notes: {action.get('notes')}"), styles["BodyText"]))
                story.append(Paragraph(escape(f"Verification evidence ID: {evidence_id}"), styles["BodyText"]))
        for mapping in mappings:
            control = mapping.get("control", {})
            story.append(Paragraph(escape(f"Control mapping: {control.get('id')} {control.get('title')} · {mapping.get('status')} · confidence {mapping.get('confidence')} · evidence {mapping.get('verification_evidence_id') or 'not validated'}"), styles["BodyText"]))
            story.append(Paragraph(escape(f"Rationale: {mapping.get('rationale', '')}"), styles["BodyText"]))
    threat_scenarios = snapshot.get("threat_scenarios", [])
    if threat_scenarios:
        story.extend([Spacer(1, 8), Paragraph("Threat-model scenarios", styles["Heading2"]),
                      Paragraph("Business-impact estimates are analyst assessments and are separate from technical severity and the technical risk score.", styles["BodyText"])])
        for scenario in threat_scenarios:
            story.append(Paragraph(escape(f"{scenario.get('stride_category')} · {scenario.get('title')} · review {scenario.get('review_status')}"), styles["BodyText"]))
            story.append(Paragraph(escape(scenario.get("calculation_explanation", "")), styles["BodyText"]))
            story.append(Paragraph(escape(f"Confidence: {scenario.get('confidence')}/5 · assumptions: {'; '.join(scenario.get('assumptions', [])) or 'none recorded'} · unconfirmed: {'; '.join(scenario.get('unconfirmed_information', [])) or 'none recorded'}"), styles["BodyText"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Evidence", styles["Heading2"]))
    for item in snapshot.get("evidence", []):
        story.append(Paragraph(escape(f"{item.get('source')} · {item.get('observed_at')} · SHA-256 {item.get('sha256')}"), styles["BodyText"]))
    document.build(story)
    return output.getvalue()


def _append_posture_pdf(story: list, styles, scorecard: dict) -> None:
    story.append(Paragraph("Scorecard scope", styles["Heading2"]))
    scope = scorecard.get("data_scope", {})
    story.append(Paragraph(escape(
        f"Range: {scorecard.get('range_days')} days ({scorecard.get('window_start')} to {scorecard.get('window_end')}) · "
        f"Assets: {scope.get('asset_count')} · Investigations in range: {scope.get('investigation_count')} · "
        f"Data modes: {', '.join(scope.get('data_modes', [])) or 'none recorded'} · Source: {scope.get('source')}"), styles["BodyText"]))
    metric_labels = {
        "overall_risk": "Overall risk",
        "assessment_coverage": "Assessment coverage",
        "unassessed_categories": "Unassessed categories",
        "high_critical_findings": "Latest-observed high/critical findings",
        "repeated_findings": "Repeated finding identities",
        "incident_timings": "Incident triage and resolution timing",
        "asset_criticality": "Asset criticality distribution",
        "security_control_coverage": "Security-control mapping coverage",
    }
    for key, label in metric_labels.items():
        metric = scorecard.get(key, {})
        if key == "overall_risk":
            value = "Unavailable" if metric.get("average_score") is None else f"{metric.get('average_score')} / 100 · {metric.get('band')}"
        elif key == "assessment_coverage":
            percent = metric.get("coverage_percent")
            value = "Unavailable" if percent is None else f"{percent}% · {metric.get('assessed_category_slots')} / {metric.get('expected_category_slots')} category slots"
        elif key == "unassessed_categories":
            value = ", ".join(f"{name}: {count}" for name, count in metric.get("counts", {}).items()) or "No applicable categories in scope"
        elif key == "high_critical_findings":
            value = "Unavailable" if metric.get("total") is None else f"High {metric.get('high')} · Critical {metric.get('critical')} · {metric.get('note')}"
        elif key == "repeated_findings":
            value = "Unavailable" if metric.get("repeated_finding_count") is None else f"{metric.get('repeated_finding_count')} repeated identities across {metric.get('investigations_in_scope')} investigations"
        elif key == "incident_timings":
            triage = metric.get("triage_median_seconds")
            resolution = metric.get("resolution_median_seconds")
            value = f"Median triage: {triage if triage is not None else 'Unavailable'} seconds · median resolution: {resolution if resolution is not None else 'Unavailable'} seconds"
        elif key == "asset_criticality":
            value = ", ".join(f"{name}: {count}" for name, count in metric.get("counts", {}).items())
        else:
            value = "Unavailable" if metric.get("validated_finding_percent") is None else f"{metric.get('validated_finding_percent')}% of latest-observed findings have validated mappings; {metric.get('controls_with_validated_findings')} catalog controls represented"
        story.append(Paragraph(escape(f"{label} · {metric.get('state', 'unavailable')}: {value}"), styles["BodyText"]))
        story.append(Paragraph(escape(f"Scope: {metric.get('scope', '')} Range: {metric.get('range_days')} days. {metric.get('note') or ''}"), styles["BodyText"]))
        story.append(Spacer(1, 4))

    risk_trend = scorecard.get("risk_trend", {})
    story.append(Paragraph("Risk trend", styles["Heading2"]))
    if risk_trend.get("points"):
        for point in risk_trend["points"]:
            story.append(Paragraph(escape(f"{point.get('period_start')} · average {point.get('average_score')} · {point.get('asset_count')} assets"), styles["BodyText"]))
    else:
        story.append(Paragraph(escape(f"{risk_trend.get('state')}: no numeric risk revisions are available in this range."), styles["BodyText"]))
    story.append(Paragraph(escape(f"Scope: {risk_trend.get('scope', '')} Range: {risk_trend.get('range_days')} days."), styles["BodyText"]))

    workflow = scorecard.get("workflow_trend", {})
    story.append(Paragraph("Investigation and monitoring trend", styles["Heading2"]))
    if workflow.get("points"):
        for point in workflow["points"]:
            story.append(Paragraph(escape(f"{point.get('period_start')} · investigations {point.get('investigations', {})} · monitoring runs {point.get('monitoring_runs', {})}"), styles["BodyText"]))
    else:
        story.append(Paragraph(escape(f"{workflow.get('state')}: no saved investigations or monitoring runs in this range."), styles["BodyText"]))
    story.append(Paragraph(escape(f"Scope: {workflow.get('scope', '')} Range: {workflow.get('range_days')} days."), styles["BodyText"]))

    providers = scorecard.get("provider_health", {})
    story.append(Paragraph("Provider status and freshness", styles["Heading2"]))
    for provider in providers.get("providers", []):
        story.append(Paragraph(escape(
            f"{provider.get('name')} · state {provider.get('state')} · last status {provider.get('provider_status') or 'not observed'} · "
            f"freshness {provider.get('freshness')} · last observed {provider.get('last_observed_at') or 'not observed'} · "
            f"mode {provider.get('data_mode') or 'unknown'} · configured {provider.get('configured')}"), styles["BodyText"]))
    story.append(Paragraph(escape(
        f"Provider metric state: {providers.get('state', 'unavailable')} · scope: {providers.get('scope', '')} · "
        f"freshness window: {providers.get('range_days')} days ({providers.get('window_start')} to {providers.get('window_end')}). "
        f"{providers.get('note') or ''}"), styles["BodyText"]))
    story.append(Paragraph(escape(f"Scope: {providers.get('scope', '')} Range: {providers.get('range_days')} days. {providers.get('note') or ''}"), styles["BodyText"]))
