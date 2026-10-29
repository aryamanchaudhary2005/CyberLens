from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user, require_roles_csrf
from app.models import (
    AuditEvent, EvidenceSnapshot, Finding, FindingControlMapping, Incident, PlaybookTask,
    RemediationAction, RemediationPlan, User, new_id, now_utc,
)
from app.pagination import Page, apply_page, page_params
from app.schemas import (
    FindingControlMappingCreate, FindingControlMappingOut, FindingControlMappingUpdate,
    RemediationActionCreate, RemediationActionOut, RemediationActionUpdate,
    RemediationPlanCreate, RemediationPlanOut, RemediationPlanUpdate,
    SecurityControlOut, VerificationEvidenceOut,
)
from app.services.security_controls import CATALOG_VERSION, control_catalog, get_control
from app.visibility import visible_remediation_plans, visible_row
from app.visibility import visible_evidence

router = APIRouter(prefix="/remediation", tags=["remediation"])
STATUSES = {"proposed", "planned", "implemented", "validated", "rejected", "not_applicable"}
PRIORITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


@router.get("/controls", response_model=list[SecurityControlOut])
def list_security_controls(_user: User = Depends(get_current_user)) -> list[dict]:
    return control_catalog()


@router.get("/plans", response_model=list[RemediationPlanOut])
def list_remediation_plans(
    _user: User = Depends(get_current_user), db: Session = Depends(get_db), response: Response = None,
    status: str | None = Query(default=None), priority: str | None = Query(default=None),
    finding_id: str | None = Query(default=None), incident_id: str | None = Query(default=None),
    q: str | None = Query(default=None, max_length=200),
    sort: Literal["created_at", "updated_at", "due_at", "priority", "status"] = Query(default="updated_at"),
    order: Literal["asc", "desc"] = Query(default="desc"), page: Page = Depends(page_params),
) -> list[dict]:
    query = visible_remediation_plans(db)
    if status:
        if status not in STATUSES: raise HTTPException(422, "Unknown remediation status")
        query = query.filter(RemediationPlan.status == status)
    if priority:
        if priority not in PRIORITY_ORDER: raise HTTPException(422, "Unknown remediation priority")
        query = query.filter(RemediationPlan.priority == priority)
    if finding_id: query = query.filter(RemediationPlan.finding_id == finding_id)
    if incident_id: query = query.filter(RemediationPlan.incident_id == incident_id)
    if q:
        needle = f"%{q.strip()}%"
        query = query.filter(RemediationPlan.title.ilike(needle) | RemediationPlan.description.ilike(needle))
    column = {"created_at": RemediationPlan.created_at, "updated_at": RemediationPlan.updated_at,
              "due_at": RemediationPlan.due_at, "priority": RemediationPlan.priority,
              "status": RemediationPlan.status}[sort]
    ordered = column.asc() if order == "asc" else column.desc()
    rows = apply_page(query.order_by(ordered, RemediationPlan.id.asc()), page, response)
    return _plan_payloads(db, rows)


@router.post("/plans", status_code=201, response_model=RemediationPlanOut)
def create_remediation_plan(
    payload: RemediationPlanCreate,
    user: User = Depends(require_roles_csrf("admin", "analyst")), db: Session = Depends(get_db),
) -> dict:
    refs = _validate_plan_links(db, payload.finding_id, payload.incident_id, payload.playbook_task_id, payload.owner_id)
    item = RemediationPlan(
        id=new_id(), title=payload.title.strip(), description=payload.description.strip(), action_type=payload.action_type.strip(),
        finding_id=payload.finding_id, incident_id=refs["incident_id"], playbook_task_id=payload.playbook_task_id,
        owner_id=payload.owner_id, priority=payload.priority, due_at=payload.due_at, status=payload.status,
        assumptions_json=[value.strip() for value in payload.assumptions if value.strip()], notes=payload.notes.strip() if payload.notes else None,
        created_by=user.id,
    )
    db.add(item)
    db.flush()
    db.add(AuditEvent(actor_id=user.id, action="remediation.plan_created", entity_type="remediation_plan", entity_id=item.id,
                      details_json={"finding_id": item.finding_id, "incident_id": item.incident_id, "status": item.status}))
    db.commit()
    db.refresh(item)
    return _plan_payloads(db, [item], include_candidate_evidence=True)[0]


@router.get("/plans/{plan_id}", response_model=RemediationPlanOut)
def get_remediation_plan(plan_id: str, _user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    item = visible_row(db, RemediationPlan, plan_id)
    if item is None: raise HTTPException(404, "Remediation plan not found")
    return _plan_payloads(db, [item], include_candidate_evidence=True)[0]


@router.patch("/plans/{plan_id}", response_model=RemediationPlanOut)
def update_remediation_plan(
    plan_id: str, payload: RemediationPlanUpdate,
    user: User = Depends(require_roles_csrf("admin", "analyst")), db: Session = Depends(get_db),
) -> dict:
    item = visible_row(db, RemediationPlan, plan_id)
    if item is None: raise HTTPException(404, "Remediation plan not found")
    changes = payload.model_dump(exclude_unset=True)
    _reject_null_required(changes, {"title", "description", "action_type", "priority", "status", "assumptions"})
    finding_id = changes.get("finding_id", item.finding_id)
    incident_id = changes.get("incident_id", item.incident_id)
    task_id = changes.get("playbook_task_id", item.playbook_task_id)
    owner_id = changes.get("owner_id", item.owner_id)
    refs = _validate_plan_links(db, finding_id, incident_id, task_id, owner_id)
    if "finding_id" in changes: item.finding_id = finding_id
    if "incident_id" in changes or "playbook_task_id" in changes: item.incident_id = refs["incident_id"]
    if "playbook_task_id" in changes: item.playbook_task_id = task_id
    if "owner_id" in changes: item.owner_id = owner_id
    for field, value in changes.items():
        if field in {"finding_id", "incident_id", "playbook_task_id", "owner_id"}: continue
        target = "assumptions_json" if field == "assumptions" else field
        if field == "assumptions": value = [part.strip() for part in value if part.strip()]
        elif isinstance(value, str): value = value.strip()
        setattr(item, target, value)
    item.updated_at = now_utc()
    db.add(AuditEvent(actor_id=user.id, action="remediation.plan_updated", entity_type="remediation_plan", entity_id=item.id,
                      details_json={"fields": sorted(changes)}))
    db.commit()
    db.refresh(item)
    return _plan_payloads(db, [item], include_candidate_evidence=True)[0]


@router.post("/plans/{plan_id}/actions", status_code=201, response_model=RemediationActionOut)
def create_remediation_action(
    plan_id: str, payload: RemediationActionCreate,
    user: User = Depends(require_roles_csrf("admin", "analyst")), db: Session = Depends(get_db),
) -> dict:
    plan = visible_row(db, RemediationPlan, plan_id)
    if plan is None: raise HTTPException(404, "Remediation plan not found")
    _validate_owner(db, payload.owner_id)
    _validate_verification(db, plan, payload.status, payload.verification_evidence_id)
    item = RemediationAction(
        id=new_id(), plan_id=plan.id, title=payload.title.strip(), description=payload.description.strip(),
        action_type=payload.action_type.strip(), owner_id=payload.owner_id, priority=payload.priority,
        due_at=payload.due_at, status=payload.status, assumptions_json=[value.strip() for value in payload.assumptions if value.strip()],
        verification_instructions=payload.verification_instructions.strip(), notes=payload.notes.strip() if payload.notes else None,
        verification_evidence_id=payload.verification_evidence_id, validated_by=user.id if payload.status == "validated" else None,
        validated_at=now_utc() if payload.status == "validated" else None, created_by=user.id,
    )
    db.add(item)
    db.flush()
    db.add(AuditEvent(actor_id=user.id, action="remediation.action_created", entity_type="remediation_action", entity_id=item.id,
                      details_json={"plan_id": plan.id, "status": item.status, "verification_evidence_id": item.verification_evidence_id}))
    db.commit()
    db.refresh(item)
    return _action_payload(item)


@router.patch("/plans/{plan_id}/actions/{action_id}", response_model=RemediationActionOut)
def update_remediation_action(
    plan_id: str, action_id: str, payload: RemediationActionUpdate,
    user: User = Depends(require_roles_csrf("admin", "analyst")), db: Session = Depends(get_db),
) -> dict:
    plan = visible_row(db, RemediationPlan, plan_id)
    if plan is None: raise HTTPException(404, "Remediation plan not found")
    item = db.query(RemediationAction).filter_by(id=action_id, plan_id=plan_id).first()
    if item is None: raise HTTPException(404, "Remediation action not found")
    changes = payload.model_dump(exclude_unset=True)
    _reject_null_required(changes, {"title", "description", "action_type", "priority", "status", "assumptions", "verification_instructions"})
    next_status = changes.get("status", item.status)
    evidence_id = changes.get("verification_evidence_id", item.verification_evidence_id)
    _validate_owner(db, changes.get("owner_id", item.owner_id))
    _validate_verification(db, plan, next_status, evidence_id)
    for field, value in changes.items():
        target = "assumptions_json" if field == "assumptions" else field
        if field == "assumptions": value = [part.strip() for part in value if part.strip()]
        elif isinstance(value, str): value = value.strip()
        setattr(item, target, value)
    if next_status == "validated" and ("status" in changes or "verification_evidence_id" in changes):
        item.validated_by = user.id
        item.validated_at = now_utc()
    elif next_status != "validated":
        item.validated_by = None
        item.validated_at = None
    item.updated_at = now_utc()
    db.add(AuditEvent(actor_id=user.id, action="remediation.action_updated", entity_type="remediation_action", entity_id=item.id,
                      details_json={"plan_id": plan.id, "fields": sorted(changes), "status": item.status,
                                    "verification_evidence_id": item.verification_evidence_id}))
    db.commit()
    db.refresh(item)
    return _action_payload(item)


@router.get("/findings/{finding_id}/controls", response_model=list[FindingControlMappingOut])
def list_finding_controls(finding_id: str, _user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[dict]:
    finding = visible_row(db, Finding, finding_id)
    if finding is None: raise HTTPException(404, "Finding not found")
    rows = db.query(FindingControlMapping).filter_by(finding_id=finding_id).order_by(FindingControlMapping.created_at, FindingControlMapping.id).all()
    return _mapping_payloads(db, rows)


@router.post("/findings/{finding_id}/controls", status_code=201, response_model=FindingControlMappingOut)
def create_finding_control_mapping(
    finding_id: str, payload: FindingControlMappingCreate,
    user: User = Depends(require_roles_csrf("admin", "analyst")), db: Session = Depends(get_db),
) -> dict:
    finding = visible_row(db, Finding, finding_id)
    if finding is None: raise HTTPException(404, "Finding not found")
    control = get_control(payload.control_id)
    if control is None: raise HTTPException(422, "Control is not in the current local catalog")
    _validate_evidence_for_investigation(db, finding.investigation_id, payload.status, payload.verification_evidence_id)
    existing = db.query(FindingControlMapping).filter_by(finding_id=finding.id, control_id=payload.control_id,
                                                           catalog_version=CATALOG_VERSION).first()
    if existing is not None: raise HTTPException(409, "This finding already has a mapping to that catalog control")
    item = FindingControlMapping(
        id=new_id(), finding_id=finding.id, control_id=payload.control_id, catalog_version=CATALOG_VERSION,
        rationale=payload.rationale.strip(), confidence=payload.confidence, status=payload.status,
        verification_evidence_id=payload.verification_evidence_id,
        validated_by=user.id if payload.status == "validated" else None,
        validated_at=now_utc() if payload.status == "validated" else None, created_by=user.id,
    )
    db.add(item)
    db.flush()
    db.add(AuditEvent(actor_id=user.id, action="remediation.control_mapping_created", entity_type="finding_control_mapping", entity_id=item.id,
                      details_json={"finding_id": finding.id, "control_id": item.control_id,
                                    "catalog_version": item.catalog_version, "confidence": item.confidence,
                                    "status": item.status, "verification_evidence_id": item.verification_evidence_id}))
    db.commit()
    db.refresh(item)
    return _mapping_payloads(db, [item])[0]


@router.patch("/findings/{finding_id}/controls/{mapping_id}", response_model=FindingControlMappingOut)
def update_finding_control_mapping(
    finding_id: str, mapping_id: str, payload: FindingControlMappingUpdate,
    user: User = Depends(require_roles_csrf("admin", "analyst")), db: Session = Depends(get_db),
) -> dict:
    if visible_row(db, Finding, finding_id) is None:
        raise HTTPException(404, "Finding not found")
    item = db.query(FindingControlMapping).filter_by(id=mapping_id, finding_id=finding_id).first()
    if item is None: raise HTTPException(404, "Finding control mapping not found")
    changes = payload.model_dump(exclude_unset=True)
    _reject_null_required(changes, {"rationale", "confidence", "status"})
    finding = visible_row(db, Finding, item.finding_id)
    if finding is None: raise HTTPException(404, "Finding not found")
    next_status = changes.get("status", item.status)
    evidence_id = changes.get("verification_evidence_id", item.verification_evidence_id)
    _validate_evidence_for_investigation(db, finding.investigation_id, next_status, evidence_id)
    for field, value in changes.items():
        if isinstance(value, str): value = value.strip()
        setattr(item, field, value)
    if next_status == "validated" and ("status" in changes or "verification_evidence_id" in changes):
        item.validated_by = user.id
        item.validated_at = now_utc()
    elif next_status != "validated":
        item.validated_by = None
        item.validated_at = None
    item.updated_at = now_utc()
    db.add(AuditEvent(actor_id=user.id, action="remediation.control_mapping_updated", entity_type="finding_control_mapping", entity_id=item.id,
                      details_json={"finding_id": item.finding_id, "control_id": item.control_id,
                                    "fields": sorted(changes), "status": item.status,
                                    "verification_evidence_id": item.verification_evidence_id}))
    db.commit()
    db.refresh(item)
    return _mapping_payloads(db, [item])[0]


def _validate_owner(db: Session, owner_id: str | None) -> None:
    if owner_id is None: return
    owner = db.get(User, owner_id)
    if owner is None or not owner.is_active: raise HTTPException(422, "Owner must be an active workspace user")


def _validate_plan_links(db: Session, finding_id: str | None, incident_id: str | None,
                         playbook_task_id: str | None, owner_id: str | None) -> dict:
    _validate_owner(db, owner_id)
    finding = visible_row(db, Finding, finding_id) if finding_id else None
    if finding_id and finding is None: raise HTTPException(422, "Finding does not exist")
    incident = visible_row(db, Incident, incident_id) if incident_id else None
    if incident_id and incident is None: raise HTTPException(422, "Incident does not exist")
    task = db.get(PlaybookTask, playbook_task_id) if playbook_task_id else None
    if playbook_task_id and task is None: raise HTTPException(422, "Playbook task does not exist")
    if task:
        if incident and incident.id != task.incident_id: raise HTTPException(422, "Playbook task must belong to the linked incident")
        if incident is None: incident = visible_row(db, Incident, task.incident_id)
        if incident is None: raise HTTPException(422, "Playbook task belongs to an unavailable incident")
    if finding and incident:
        if finding.asset_id != incident.asset_id: raise HTTPException(422, "Finding and incident must belong to the same asset")
        if incident.investigation_id and incident.investigation_id != finding.investigation_id:
            raise HTTPException(422, "Finding and incident must belong to the same investigation")
    return {"incident_id": incident.id if incident else None}


def _validate_evidence_for_investigation(db: Session, investigation_id: str, status: str,
                                         evidence_id: str | None) -> EvidenceSnapshot | None:
    if status != "validated":
        if evidence_id:
            evidence = visible_row(db, EvidenceSnapshot, evidence_id)
            if evidence is None or evidence.investigation_id != investigation_id:
                raise HTTPException(422, "Verification evidence must belong to the finding's investigation")
            return evidence
        return None
    if not evidence_id: raise HTTPException(422, "Verification evidence is required before validation")
    evidence = visible_row(db, EvidenceSnapshot, evidence_id)
    if evidence is None or evidence.investigation_id != investigation_id:
        raise HTTPException(422, "Verification evidence must belong to the finding's investigation")
    return evidence


def _validate_verification(db: Session, plan: RemediationPlan, status: str, evidence_id: str | None) -> None:
    if status not in STATUSES: raise HTTPException(422, "Unknown remediation status")
    investigation_id = None
    if plan.finding_id:
        finding = visible_row(db, Finding, plan.finding_id)
        investigation_id = finding.investigation_id if finding else None
    if investigation_id is None and plan.incident_id:
        incident = visible_row(db, Incident, plan.incident_id)
        investigation_id = incident.investigation_id if incident else None
    if status == "validated" and investigation_id is None:
        raise HTTPException(422, "A linked finding or incident investigation is required to validate with evidence")
    if evidence_id:
        evidence = visible_row(db, EvidenceSnapshot, evidence_id)
        if evidence is None or (investigation_id and evidence.investigation_id != investigation_id):
            raise HTTPException(422, "Verification evidence must belong to the plan's investigation")
    elif status == "validated":
        raise HTTPException(422, "Verification evidence is required before validation")


def _reject_null_required(changes: dict, required: set[str]) -> None:
    if any(field in changes and changes[field] is None for field in required):
        raise HTTPException(422, "Required remediation fields cannot be cleared")


def _evidence_out(item: EvidenceSnapshot | None) -> dict | None:
    if item is None: return None
    return {"id": item.id, "source": item.source, "observed_at": item.observed_at, "sha256": item.sha256,
            "is_synthetic": item.is_synthetic}


def _action_payload(item: RemediationAction) -> dict:
    return {"id": item.id, "plan_id": item.plan_id, "title": item.title, "description": item.description,
            "action_type": item.action_type, "owner_id": item.owner_id, "priority": item.priority, "due_at": item.due_at,
            "status": item.status, "assumptions": item.assumptions_json or [],
            "verification_instructions": item.verification_instructions, "notes": item.notes,
            "verification_evidence_id": item.verification_evidence_id, "validated_by": item.validated_by,
            "validated_at": item.validated_at, "created_by": item.created_by, "created_at": item.created_at,
            "updated_at": item.updated_at}


def _mapping_payloads(db: Session, rows: list[FindingControlMapping]) -> list[dict]:
    evidence_ids = {row.verification_evidence_id for row in rows if row.verification_evidence_id}
    evidence = {item.id: item for item in db.query(EvidenceSnapshot).filter(EvidenceSnapshot.id.in_(evidence_ids)).all()} if evidence_ids else {}
    values = []
    for row in rows:
        control = get_control(row.control_id, row.catalog_version)
        if control is None:
            control = {"id": row.control_id, "title": "Retired catalog control", "objective": "Catalog version unavailable.",
                       "guidance": "Review the archived catalog documentation.", "frameworks": [],
                       "finding_categories": [], "catalog_version": row.catalog_version}
        values.append({"id": row.id, "finding_id": row.finding_id, "control_id": row.control_id,
                       "catalog_version": row.catalog_version, "rationale": row.rationale, "confidence": row.confidence,
                       "status": row.status, "verification_evidence_id": row.verification_evidence_id,
                       "validated_by": row.validated_by, "validated_at": row.validated_at, "created_by": row.created_by,
                       "created_at": row.created_at, "updated_at": row.updated_at, "control": control,
                       "verification_evidence": _evidence_out(evidence.get(row.verification_evidence_id))})
    return values


def _plan_payloads(db: Session, plans: list[RemediationPlan], include_candidate_evidence: bool = False) -> list[dict]:
    if not plans: return []
    plan_ids = {item.id for item in plans}
    finding_ids = {item.finding_id for item in plans if item.finding_id}
    actions = db.query(RemediationAction).filter(RemediationAction.plan_id.in_(plan_ids)).order_by(
        RemediationAction.created_at, RemediationAction.id).all()
    mappings = db.query(FindingControlMapping).filter(FindingControlMapping.finding_id.in_(finding_ids)).order_by(
        FindingControlMapping.created_at, FindingControlMapping.id).all() if finding_ids else []
    evidence_ids = {item.verification_evidence_id for item in actions if item.verification_evidence_id}
    evidence_ids.update(item.verification_evidence_id for item in mappings if item.verification_evidence_id)
    evidence_by_id = {item.id: item for item in db.query(EvidenceSnapshot).filter(EvidenceSnapshot.id.in_(evidence_ids)).all()} if evidence_ids else {}
    actions_by_plan: dict[str, list[dict]] = {}
    for item in actions: actions_by_plan.setdefault(item.plan_id, []).append(_action_payload(item))
    mappings_by_finding: dict[str, list[dict]] = {}
    serialized_mappings = _mapping_payloads(db, mappings) if mappings else []
    for item, value in zip(mappings, serialized_mappings): mappings_by_finding.setdefault(item.finding_id, []).append(value)

    investigation_ids: set[str] = set()
    if include_candidate_evidence:
        for finding_id in finding_ids:
            finding = db.get(Finding, finding_id)
            if finding: investigation_ids.add(finding.investigation_id)
        incident_ids = {item.incident_id for item in plans if item.incident_id}
        if incident_ids:
            for incident in db.query(Incident).filter(Incident.id.in_(incident_ids)).all():
                if incident.investigation_id: investigation_ids.add(incident.investigation_id)
    candidate_evidence = visible_evidence(db).filter(EvidenceSnapshot.investigation_id.in_(investigation_ids)).order_by(
        EvidenceSnapshot.observed_at.desc(), EvidenceSnapshot.id).all() if investigation_ids else []

    result = []
    for item in plans:
        plan_evidence_ids = {action["verification_evidence_id"] for action in actions_by_plan.get(item.id, []) if action["verification_evidence_id"]}
        plan_evidence_ids.update(mapping["verification_evidence_id"] for mapping in mappings_by_finding.get(item.finding_id, []) if mapping["verification_evidence_id"])
        if include_candidate_evidence:
            plan_investigation_ids = set(investigation_ids)
            plan_evidence = [row for row in candidate_evidence if row.investigation_id in plan_investigation_ids]
        else:
            plan_evidence = []
        for evidence_id in plan_evidence_ids:
            evidence = evidence_by_id.get(evidence_id)
            if evidence and all(candidate.id != evidence.id for candidate in plan_evidence): plan_evidence.append(evidence)
        result.append({"id": item.id, "title": item.title, "description": item.description, "action_type": item.action_type,
                       "finding_id": item.finding_id, "incident_id": item.incident_id, "playbook_task_id": item.playbook_task_id,
                       "owner_id": item.owner_id, "priority": item.priority, "due_at": item.due_at, "status": item.status,
                       "assumptions": item.assumptions_json or [], "notes": item.notes, "created_by": item.created_by,
                       "created_at": item.created_at, "updated_at": item.updated_at,
                       "actions": actions_by_plan.get(item.id, []),
                       "control_mappings": mappings_by_finding.get(item.finding_id, []) if item.finding_id else [],
                       "verification_evidence": [_evidence_out(row) for row in plan_evidence]})
    return result
