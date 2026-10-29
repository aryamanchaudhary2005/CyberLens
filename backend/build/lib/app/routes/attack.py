from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.dependencies import get_current_user, require_roles_csrf
from app.models import AttackMapping, AuditEvent, Finding, Incident, IncidentEvent, IncidentFinding, User, new_id, now_utc
from app.schemas import (
    AttackCatalogOut, AttackCatalogVersionOut, AttackCatalogVersionsOut, AttackIncidentMatrixOut,
    AttackMappingCreate, AttackMappingDecision, AttackMappingOut, AttackSuggestionOut,
)
from app.services.attack import (
    attack_catalog, catalog_version, evidence_ids_for_finding, incident_matrix, mapping_payload, mapping_payloads,
    suggestions_for_finding, suggestions_for_incident, technique,
)
from app.services.attack_catalog_sync import catalog_versions_payload, queue_catalog_sync, version_payload
from app.visibility import visible_attack_mappings, visible_row

router = APIRouter(prefix="/attack", tags=["mitre-attack"])


@router.get("/catalog", response_model=AttackCatalogOut)
def get_catalog(_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    return attack_catalog(db)


@router.get("/catalog/versions", response_model=AttackCatalogVersionsOut)
def get_catalog_versions(_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    return catalog_versions_payload(db)


@router.post("/catalog/sync", status_code=status.HTTP_202_ACCEPTED, response_model=AttackCatalogVersionOut)
def start_catalog_sync(
    user: User = Depends(require_roles_csrf("admin")), db: Session = Depends(get_db),
) -> dict:
    if get_settings().app_mode == "demo":
        raise HTTPException(409, "ATT&CK synchronization is disabled in Demo mode; the bundled catalog remains available.")
    row = queue_catalog_sync(db, user)
    return version_payload(row)


@router.get("/suggestions", response_model=list[AttackSuggestionOut])
def get_suggestions(
    _user: User = Depends(get_current_user), db: Session = Depends(get_db),
    finding_id: str | None = Query(default=None), incident_id: str | None = Query(default=None),
) -> list[dict]:
    if bool(finding_id) == bool(incident_id):
        raise HTTPException(422, "Provide exactly one finding_id or incident_id")
    if finding_id:
        finding = visible_row(db, Finding, finding_id)
        if finding is None:
            raise HTTPException(404, "Finding not found")
        return suggestions_for_finding(db, finding)
    incident = visible_row(db, Incident, incident_id)
    if incident is None:
        raise HTTPException(404, "Incident not found")
    return suggestions_for_incident(db, incident)


@router.get("/mappings", response_model=list[AttackMappingOut])
def list_mappings(
    _user: User = Depends(get_current_user), db: Session = Depends(get_db),
    finding_id: str | None = Query(default=None), incident_id: str | None = Query(default=None),
) -> list[dict]:
    if bool(finding_id) == bool(incident_id):
        raise HTTPException(422, "Provide exactly one finding_id or incident_id")
    if finding_id:
        if visible_row(db, Finding, finding_id) is None:
            raise HTTPException(404, "Finding not found")
        rows = visible_attack_mappings(db).filter_by(finding_id=finding_id).order_by(AttackMapping.created_at, AttackMapping.id).all()
    else:
        if visible_row(db, Incident, incident_id) is None:
            raise HTTPException(404, "Incident not found")
        rows = visible_attack_mappings(db).filter_by(incident_id=incident_id).order_by(AttackMapping.created_at, AttackMapping.id).all()
    return mapping_payloads(db, rows)


@router.post("/mappings", status_code=201, response_model=AttackMappingOut)
def create_mapping(
    payload: AttackMappingCreate,
    user: User = Depends(require_roles_csrf("admin", "analyst")), db: Session = Depends(get_db),
) -> dict:
    active_version = catalog_version(db)
    if payload.catalog_version is not None and payload.catalog_version != active_version:
        raise HTTPException(409, "The ATT&CK catalog changed. Refresh the catalog and review the mapping again.")
    selected = technique(payload.technique_id, db=db)
    if selected is None:
        raise HTTPException(422, "Technique ID is not in the current local ATT&CK catalog")
    if payload.tactic not in (selected.get("selectable_tactics") or selected["tactics"]):
        raise HTTPException(422, "Tactic is not associated with this technique in the local catalog")
    if payload.finding_id:
        finding = visible_row(db, Finding, payload.finding_id)
        if finding is None:
            raise HTTPException(404, "Finding not found")
        valid_evidence = set(evidence_ids_for_finding(db, finding))
        incident_id = None
    else:
        incident = visible_row(db, Incident, payload.incident_id)
        if incident is None:
            raise HTTPException(404, "Incident not found")
        valid_evidence = _incident_evidence_ids(db, incident)
        finding = None
        incident_id = incident.id
    if payload.evidence_id not in valid_evidence:
        raise HTTPException(422, "Evidence must be saved and linked to the selected finding or incident")
    duplicate_query = db.query(AttackMapping).filter(
        AttackMapping.technique_id == payload.technique_id,
        AttackMapping.evidence_id == payload.evidence_id,
    )
    duplicate_query = duplicate_query.filter_by(finding_id=finding.id) if finding else duplicate_query.filter_by(incident_id=incident_id)
    if duplicate_query.first() is not None:
        raise HTTPException(409, "This technique is already mapped to the selected evidence")
    rule = _matching_suggestion(db, finding, incident_id, payload.technique_id, payload.evidence_id)
    item = AttackMapping(
        id=new_id(), finding_id=finding.id if finding else None, incident_id=incident_id,
        technique_id=selected["id"], technique_name=selected["name"], tactic=payload.tactic,
        catalog_version=active_version, rationale=payload.rationale.strip(), confidence=payload.confidence,
        source=rule["source"] if rule else "analyst-selection", evidence_role=payload.evidence_role,
        evidence_id=payload.evidence_id, decision="proposed", analyst_confirmed=False, created_by=user.id,
        created_at=now_utc(), updated_at=now_utc(),
    )
    db.add(item)
    db.flush()
    db.add(AuditEvent(actor_id=user.id, action="attack.mapping_created", entity_type="attack_mapping", entity_id=item.id,
                      details_json={"technique_id": item.technique_id, "tactic": item.tactic, "evidence_id": item.evidence_id,
                                    "finding_id": item.finding_id, "incident_id": item.incident_id, "source": item.source}))
    _record_incident_event(db, item, user, f"ATT&CK mapping proposed: {item.technique_id} {item.technique_name}.")
    db.commit()
    db.refresh(item)
    return mapping_payload(db, item)


@router.patch("/mappings/{mapping_id}", response_model=AttackMappingOut)
def decide_mapping(
    mapping_id: str, payload: AttackMappingDecision,
    user: User = Depends(require_roles_csrf("admin", "analyst")), db: Session = Depends(get_db),
) -> dict:
    item = visible_row(db, AttackMapping, mapping_id)
    if item is None:
        raise HTTPException(404, "ATT&CK mapping not found")
    if payload.decision == "overridden":
        selected = technique(payload.technique_id or "", db=db, version=item.catalog_version)
        if selected is None:
            raise HTTPException(422, "Override technique ID is not selectable in the mapping's catalog version")
        if payload.tactic not in (selected.get("selectable_tactics") or selected["tactics"]):
            raise HTTPException(422, "Tactic is not associated with this technique in the local catalog")
        item.technique_id = selected["id"]
        item.technique_name = selected["name"]
        item.tactic = payload.tactic
        item.rationale = payload.rationale.strip()
        item.source = "analyst-override"
    elif payload.technique_id is not None:
        raise HTTPException(422, "A technique can only be changed with decision='overridden'")
    target_finding = visible_row(db, Finding, item.finding_id) if item.finding_id else None
    target_incident = visible_row(db, Incident, item.incident_id) if item.incident_id else None
    valid_evidence = set(evidence_ids_for_finding(db, target_finding)) if target_finding else _incident_evidence_ids(db, target_incident)
    if payload.evidence_id is not None:
        if payload.evidence_id not in valid_evidence:
            raise HTTPException(422, "Evidence must be saved and linked to the selected finding or incident")
        item.evidence_id = payload.evidence_id
    if payload.rationale is not None:
        item.rationale = payload.rationale.strip()
    if payload.confidence is not None:
        item.confidence = payload.confidence
    if payload.evidence_role is not None:
        item.evidence_role = payload.evidence_role
    duplicate_query = db.query(AttackMapping).filter(
        AttackMapping.id != item.id, AttackMapping.technique_id == item.technique_id,
        AttackMapping.evidence_id == item.evidence_id,
    )
    duplicate_query = duplicate_query.filter_by(finding_id=item.finding_id) if item.finding_id else duplicate_query.filter_by(incident_id=item.incident_id)
    if duplicate_query.first() is not None:
        raise HTTPException(409, "This technique is already mapped to the selected evidence")
    item.decision = payload.decision
    item.analyst_confirmed = payload.decision in {"approved", "overridden"}
    item.reviewed_by = user.id
    item.reviewed_at = now_utc()
    item.updated_at = item.reviewed_at
    db.add(AuditEvent(actor_id=user.id, action="attack.mapping_reviewed", entity_type="attack_mapping", entity_id=item.id,
                      details_json={"decision": item.decision, "technique_id": item.technique_id, "tactic": item.tactic,
                                    "analyst_confirmed": item.analyst_confirmed, "evidence_id": item.evidence_id}))
    _record_incident_event(db, item, user, f"ATT&CK mapping {item.decision}: {item.technique_id} {item.technique_name}.")
    db.commit()
    db.refresh(item)
    return mapping_payload(db, item)


@router.get("/incidents/{incident_id}/matrix", response_model=AttackIncidentMatrixOut)
def get_incident_matrix(
    incident_id: str, _user: User = Depends(get_current_user), db: Session = Depends(get_db),
) -> dict:
    incident = visible_row(db, Incident, incident_id)
    if incident is None:
        raise HTTPException(404, "Incident not found")
    return incident_matrix(db, incident)


def _incident_evidence_ids(db: Session, incident: Incident | None) -> set[str]:
    if incident is None:
        return set()
    links = db.query(IncidentFinding).filter_by(incident_id=incident.id).all()
    result: set[str] = set()
    for link in links:
        finding = visible_row(db, Finding, link.finding_id)
        if finding is not None:
            result.update(evidence_ids_for_finding(db, finding))
    return result


def _matching_suggestion(db: Session, finding: Finding | None, incident_id: str | None,
                         technique_id: str, evidence_id: str) -> dict | None:
    rows = suggestions_for_finding(db, finding) if finding else []
    if incident_id:
        incident = visible_row(db, Incident, incident_id)
        rows = suggestions_for_incident(db, incident) if incident else []
    return next((row for row in rows if row["technique_id"] == technique_id and row["evidence_id"] == evidence_id), None)


def _record_incident_event(db: Session, item: AttackMapping, user: User, message: str) -> None:
    if not item.incident_id:
        return
    incident = visible_row(db, Incident, item.incident_id)
    if incident:
        incident.updated_at = now_utc()
        db.add(IncidentEvent(incident_id=incident.id, actor_id=user.id, event_type="attack_mapping_updated",
                             message=message, details_json={"mapping_id": item.id, "technique_id": item.technique_id,
                                                           "decision": item.decision, "evidence_id": item.evidence_id}))
