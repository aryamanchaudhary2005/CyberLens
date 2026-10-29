from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user, require_roles_csrf
from app.models import AuditEvent, Finding, Investigation, User
from app.osv import osv_finding_payload
from app.pagination import Page, apply_page, page_params
from app.schemas import ApplicabilityInput, FindingOut
from app.services.risk import assess_investigation
from app.visibility import visible_findings, visible_row

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("", response_model=list[FindingOut])
def list_findings(_user: User = Depends(get_current_user), db: Session = Depends(get_db), response: Response = None,
                  investigation_id: str | None = Query(default=None), asset_id: str | None = Query(default=None),
                  category: str | None = Query(default=None), applicability: str | None = Query(default=None),
                  severity: str | None = Query(default=None), q: str | None = Query(default=None, max_length=200),
                  limit: int | None = Query(default=None, ge=1, le=500),
                  sort: Literal["observed_at", "severity", "title", "category"] = Query(default="observed_at"),
                  order: Literal["asc", "desc"] = Query(default="desc"), page: Page = Depends(page_params)) -> list[dict]:
    query = visible_findings(db)
    if investigation_id: query = query.filter_by(investigation_id=investigation_id)
    if asset_id: query = query.filter_by(asset_id=asset_id)
    if category: query = query.filter(Finding.category == category)
    if applicability: query = query.filter(Finding.applicability == applicability)
    if severity: query = query.filter(Finding.severity == severity.lower())
    if q: query = query.filter(Finding.title.ilike(f"%{q.strip()}%"))
    sort_column = {"observed_at": Finding.observed_at, "severity": Finding.severity,
                   "title": Finding.title, "category": Finding.category}[sort]
    ordering = sort_column.asc() if order == "asc" else sort_column.desc()
    if limit is not None:
        page = Page(page.number, limit)
    return [_payload(item) for item in apply_page(query.order_by(ordering, Finding.id.asc()), page, response)]


@router.get("/{finding_id}")
def get_finding(finding_id: str, _user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    item = visible_row(db, Finding, finding_id)
    if item is None:
        raise HTTPException(404, "Finding not found")
    return _payload(item)


@router.patch("/{finding_id}/applicability")
def set_applicability(finding_id: str, payload: ApplicabilityInput,
                      user: User = Depends(require_roles_csrf("admin", "analyst")), db: Session = Depends(get_db)) -> dict:
    item = visible_row(db, Finding, finding_id)
    if item is None: raise HTTPException(404, "Finding not found")
    if item.category != "vulnerabilities":
        raise HTTPException(422, "Analyst applicability decisions are available for vulnerability candidates")
    item.applicability = payload.applicability
    item.applicability_reason = payload.reason.strip()
    db.add(AuditEvent(actor_id=user.id, action="finding.applicability_decided", entity_type="finding", entity_id=item.id,
                      details_json={"applicability": item.applicability, "reason": item.applicability_reason}))
    investigation = db.get(Investigation, item.investigation_id)
    assess_investigation(db, investigation)
    db.commit()
    db.refresh(item)
    return _payload(item)


def _payload(item: Finding) -> dict:
    details = item.details_json or {}
    return {"id": item.id, "asset_id": item.asset_id, "investigation_id": item.investigation_id,
        "evidence_id": item.evidence_id, "category": item.category, "severity": item.severity, "title": item.title,
        "explanation": item.explanation, "recommendation": item.recommendation, "source": item.source,
        "observed_at": item.observed_at, "applicability": item.applicability, "applicability_reason": item.applicability_reason,
        "cvss_version": details.get("cvss_version"), "cvss_score": details.get("cvss_score"),
        "cvss_vector": details.get("vector"), "kev": details.get("kev"),
        "epss_score": item.epss_score, "epss_percentile": item.epss_percentile,
        "epss_observed_at": item.epss_observed_at, "epss_provider_status": item.epss_provider_status,
        "epss_freshness": item.epss_freshness,
        "is_synthetic": item.is_synthetic, "details_json": item.details_json,
        "osv": osv_finding_payload(details, item.evidence_id)}
