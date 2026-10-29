from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user, require_roles_csrf
from app.models import Asset, AuditEvent, Finding, Incident, Investigation, ThreatScenario, User, new_id, now_utc
from app.pagination import Page, apply_page, page_params
from app.schemas import AssetThreatProfileOut, ThreatModelOwnerOut, ThreatProfileUpdate, ThreatScenarioCreate, ThreatScenarioOut, ThreatScenarioUpdate
from app.visibility import visible_row, visible_threat_scenarios

router = APIRouter(prefix="/threat-model", tags=["threat-model"])
STRIDE = {"spoofing", "tampering", "repudiation", "information_disclosure", "denial_of_service", "elevation_of_privilege"}
REVIEW_STATES = {"draft", "needs_review", "confirmed", "rejected"}
SCORE_NOTICE = "Business-impact scenario prioritization only; separate from technical severity and the CyberLens technical risk score."


def calculate_scenario_score(likelihood: int, business_impact: int) -> tuple[int, str]:
    """Return a transparent 1–25 scenario score; confidence is deliberately excluded."""
    if not 1 <= likelihood <= 5 or not 1 <= business_impact <= 5:
        raise ValueError("Likelihood and business impact must be between 1 and 5")
    score = likelihood * business_impact
    return score, f"Likelihood ({likelihood}/5) × business impact ({business_impact}/5) = {score}/25. Confidence is recorded separately and does not change this score."


@router.patch("/assets/{asset_id}", response_model=AssetThreatProfileOut)
def update_asset_profile(asset_id: str, payload: ThreatProfileUpdate,
                         user: User = Depends(require_roles_csrf("admin", "analyst")),
                         db: Session = Depends(get_db)) -> dict:
    asset = visible_row(db, Asset, asset_id)
    if asset is None:
        raise HTTPException(404, "Asset not found")
    changes = payload.model_dump(exclude_unset=True)
    protected = {"criticality", "data_classification", "trust_zone", "exposure_classification", "protection_requirements"}
    if any(key in changes and changes[key] is None for key in protected):
        raise HTTPException(422, "Asset classifications and protection requirements cannot be cleared; use 'unknown' where appropriate")
    before = {"criticality": asset.criticality, "data_classification": asset.data_classification,
              "trust_zone": asset.trust_zone, "exposure_classification": asset.exposure_classification,
              "business_owner": asset.business_owner, "protection_requirements": asset.protection_requirements or []}
    if "criticality" in changes: asset.criticality = changes["criticality"]
    if "data_classification" in changes: asset.data_classification = changes["data_classification"]
    if "trust_zone" in changes: asset.trust_zone = changes["trust_zone"]
    if "exposure_classification" in changes: asset.exposure_classification = changes["exposure_classification"]
    if "business_owner" in changes:
        value = changes["business_owner"]
        asset.business_owner = value.strip() if value and value.strip() else None
    if "protection_requirements" in changes:
        asset.protection_requirements = _clean_list(changes["protection_requirements"] or [])
    if changes:
        asset.updated_at = now_utc()
    after = {"criticality": asset.criticality, "data_classification": asset.data_classification,
             "trust_zone": asset.trust_zone, "exposure_classification": asset.exposure_classification,
             "business_owner": asset.business_owner, "protection_requirements": asset.protection_requirements}
    changed_fields = [key for key in before if before[key] != after[key]]
    if changed_fields:
        db.add(AuditEvent(actor_id=user.id, action="threat_model.asset_profile_updated", entity_type="asset",
                          entity_id=asset.id, details_json={"changed_fields": changed_fields}))
    db.commit()
    return _asset_profile(asset)


@router.get("/owners", response_model=list[ThreatModelOwnerOut])
def list_threat_model_owners(_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[dict]:
    return [{"id": user.id, "username": user.username, "role": user.role}
            for user in db.query(User).filter_by(is_active=True).order_by(User.username, User.id).all()]


@router.get("/scenarios", response_model=list[ThreatScenarioOut])
def list_scenarios(_user: User = Depends(get_current_user), db: Session = Depends(get_db),
                   response: Response = None, asset_id: str | None = Query(default=None),
                   finding_id: str | None = Query(default=None), investigation_id: str | None = Query(default=None),
                   incident_id: str | None = Query(default=None), review_status: str | None = Query(default=None),
                   stride_category: str | None = Query(default=None), q: str | None = Query(default=None, max_length=200),
                   sort: Literal["created_at", "updated_at", "likelihood", "business_impact", "confidence", "title"] = Query(default="updated_at"),
                   order: Literal["asc", "desc"] = Query(default="desc"), page: Page = Depends(page_params)) -> list[dict]:
    query = visible_threat_scenarios(db)
    for value, column in ((asset_id, ThreatScenario.asset_id), (finding_id, ThreatScenario.finding_id),
                          (investigation_id, ThreatScenario.investigation_id), (incident_id, ThreatScenario.incident_id)):
        if value:
            query = query.filter(column == value)
    if review_status:
        if review_status not in REVIEW_STATES:
            raise HTTPException(422, "Unknown scenario review status")
        query = query.filter(ThreatScenario.review_status == review_status)
    if stride_category:
        if stride_category not in STRIDE:
            raise HTTPException(422, "Unknown STRIDE category")
        query = query.filter(ThreatScenario.stride_category == stride_category)
    if q:
        needle = f"%{q.strip()}%"
        query = query.filter(ThreatScenario.title.ilike(needle) | ThreatScenario.description.ilike(needle))
    column = {"created_at": ThreatScenario.created_at, "updated_at": ThreatScenario.updated_at,
              "likelihood": ThreatScenario.likelihood, "business_impact": ThreatScenario.business_impact,
              "confidence": ThreatScenario.confidence, "title": ThreatScenario.title}[sort]
    ordered = column.asc() if order == "asc" else column.desc()
    return [_scenario_payload(item) for item in apply_page(query.order_by(ordered, ThreatScenario.id.asc()), page, response)]


@router.post("/scenarios", status_code=201, response_model=ThreatScenarioOut)
def create_scenario(payload: ThreatScenarioCreate, user: User = Depends(require_roles_csrf("admin", "analyst")),
                    db: Session = Depends(get_db)) -> dict:
    _validate_links(db, payload.asset_id, payload.finding_id, payload.investigation_id, payload.incident_id, payload.owner_id)
    _check_review(payload.review_status, payload.unconfirmed_information)
    item = ThreatScenario(id=new_id(), asset_id=payload.asset_id, finding_id=payload.finding_id,
        investigation_id=payload.investigation_id, incident_id=payload.incident_id, stride_category=payload.stride_category,
        title=payload.title.strip(), description=payload.description.strip(), likelihood=payload.likelihood,
        business_impact=payload.business_impact, confidence=payload.confidence,
        assumptions_json=_clean_list(payload.assumptions), unconfirmed_information_json=_clean_list(payload.unconfirmed_information),
        owner_id=payload.owner_id, review_status=payload.review_status, created_by=user.id)
    db.add(item)
    db.flush()
    db.add(AuditEvent(actor_id=user.id, action="threat_model.scenario_created", entity_type="threat_scenario",
        entity_id=item.id, details_json={"asset_id": item.asset_id, "stride_category": item.stride_category,
        "review_status": item.review_status, "business_impact_score": item.likelihood * item.business_impact}))
    db.commit()
    db.refresh(item)
    return _scenario_payload(item)


@router.get("/scenarios/{scenario_id}", response_model=ThreatScenarioOut)
def get_scenario(scenario_id: str, _user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    item = visible_row(db, ThreatScenario, scenario_id)
    if item is None:
        raise HTTPException(404, "Threat scenario not found")
    return _scenario_payload(item)


@router.patch("/scenarios/{scenario_id}", response_model=ThreatScenarioOut)
def update_scenario(scenario_id: str, payload: ThreatScenarioUpdate,
                    user: User = Depends(require_roles_csrf("admin", "analyst")), db: Session = Depends(get_db)) -> dict:
    item = visible_row(db, ThreatScenario, scenario_id)
    if item is None:
        raise HTTPException(404, "Threat scenario not found")
    changes = payload.model_dump(exclude_unset=True)
    required = {"stride_category", "title", "description", "likelihood", "business_impact", "confidence", "review_status"}
    if any(key in changes and changes[key] is None for key in required):
        raise HTTPException(422, "Required scenario fields cannot be cleared")
    finding_id = changes.get("finding_id", item.finding_id)
    investigation_id = changes.get("investigation_id", item.investigation_id)
    incident_id = changes.get("incident_id", item.incident_id)
    owner_id = changes.get("owner_id", item.owner_id)
    _validate_links(db, item.asset_id, finding_id, investigation_id, incident_id, owner_id)
    unconfirmed = changes.get("unconfirmed_information", item.unconfirmed_information_json or [])
    status = changes.get("review_status", item.review_status)
    _check_review(status, unconfirmed)
    for key, value in changes.items():
        field = {"assumptions": "assumptions_json", "unconfirmed_information": "unconfirmed_information_json"}.get(key, key)
        if key in {"assumptions", "unconfirmed_information"}:
            value = _clean_list(value or [])
        elif key in {"title", "description"} and value is not None:
            value = value.strip()
        setattr(item, field, value)
    item.updated_at = now_utc()
    db.add(AuditEvent(actor_id=user.id, action="threat_model.scenario_updated", entity_type="threat_scenario",
        entity_id=item.id, details_json={"changed_fields": sorted(changes), "review_status": item.review_status}))
    db.commit()
    db.refresh(item)
    return _scenario_payload(item)


def _validate_links(db: Session, asset_id: str, finding_id: str | None, investigation_id: str | None,
                    incident_id: str | None, owner_id: str | None) -> None:
    asset = visible_row(db, Asset, asset_id)
    if asset is None:
        raise HTTPException(422, "Threat scenario asset does not exist")
    finding = visible_row(db, Finding, finding_id) if finding_id else None
    if finding_id and (finding is None or finding.asset_id != asset_id):
        raise HTTPException(422, "Linked finding must belong to the selected asset")
    investigation = visible_row(db, Investigation, investigation_id) if investigation_id else None
    if investigation_id and (investigation is None or investigation.asset_id != asset_id):
        raise HTTPException(422, "Linked investigation must belong to the selected asset")
    incident = visible_row(db, Incident, incident_id) if incident_id else None
    if incident_id and (incident is None or incident.asset_id != asset_id):
        raise HTTPException(422, "Linked incident must belong to the selected asset")
    if finding and investigation_id and finding.investigation_id != investigation_id:
        raise HTTPException(422, "Linked finding must belong to the selected investigation")
    if finding and incident and incident.investigation_id and finding.investigation_id != incident.investigation_id:
        raise HTTPException(422, "Linked finding must belong to the linked incident investigation")
    if incident and investigation_id and incident.investigation_id and incident.investigation_id != investigation_id:
        raise HTTPException(422, "Linked incident must belong to the selected investigation")
    if owner_id:
        owner = db.get(User, owner_id)
        if owner is None or not owner.is_active:
            raise HTTPException(422, "Scenario owner must be an active workspace user")


def _check_review(status: str, unconfirmed: list[str]) -> None:
    if status not in REVIEW_STATES:
        raise HTTPException(422, "Unknown scenario review status")
    if status == "confirmed" and _clean_list(unconfirmed):
        raise HTTPException(422, "Resolve or remove unconfirmed information before confirming this scenario")


def _clean_list(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value.strip() for value in values if value and value.strip()))


def _scenario_payload(item: ThreatScenario) -> dict:
    score, explanation = calculate_scenario_score(item.likelihood, item.business_impact)
    return {"id": item.id, "asset_id": item.asset_id, "finding_id": item.finding_id,
        "investigation_id": item.investigation_id, "incident_id": item.incident_id,
        "stride_category": item.stride_category, "title": item.title, "description": item.description,
        "likelihood": item.likelihood, "business_impact": item.business_impact, "confidence": item.confidence,
        "assumptions": item.assumptions_json or [], "unconfirmed_information": item.unconfirmed_information_json or [],
        "owner_id": item.owner_id, "review_status": item.review_status, "business_impact_score": score,
        "calculation_explanation": explanation, "score_notice": SCORE_NOTICE,
        "created_by": item.created_by, "created_at": item.created_at, "updated_at": item.updated_at}


def _asset_profile(asset: Asset) -> dict:
    return {"id": asset.id, "kind": asset.kind, "identifier": asset.identifier, "criticality": asset.criticality,
        "data_classification": asset.data_classification, "trust_zone": asset.trust_zone,
        "exposure_classification": asset.exposure_classification, "business_owner": asset.business_owner,
        "protection_requirements": asset.protection_requirements or []}
