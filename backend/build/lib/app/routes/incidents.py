from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user, require_roles_csrf
from app.graph import ensure_relationships
from app.models import Asset, AuditEvent, EvidenceSnapshot, Finding, Incident, IncidentEvent, IncidentFinding, Investigation, PlaybookTask, User, new_id, now_utc
from app.osv import osv_finding_payload
from app.pagination import Page, apply_page, page_params
from app.schemas import EventCreate, IncidentCreate, IncidentSummaryOut, IncidentUpdate, TaskUpdate
from app.services.attack import incident_matrix
from app.services.playbooks import PLAYBOOKS, PLAYBOOK_VERSION, select_playbook
from app.visibility import visible_assets, visible_findings, visible_incidents, visible_row

router = APIRouter(prefix="/incidents", tags=["incidents"])
ALLOWED_TRANSITIONS = {"new": {"triaged"}, "triaged": {"responding", "resolved"}, "responding": {"resolved"}, "resolved": {"closed"}, "closed": set()}


@router.post("", status_code=201)
def create_incident(payload: IncidentCreate, user: User = Depends(require_roles_csrf("admin", "analyst")), db: Session = Depends(get_db)) -> dict:
    asset = visible_row(db, Asset, payload.asset_id)
    if asset is None: raise HTTPException(404, "Asset not found")
    if not payload.finding_ids:
        raise HTTPException(422, "Select at least one finding to preserve its evidence context in the case")
    finding_rows = []
    if payload.finding_ids:
        finding_rows = visible_findings(db).filter(Finding.id.in_(payload.finding_ids), Finding.asset_id == asset.id).all()
        if len(finding_rows) != len(set(payload.finding_ids)):
            raise HTTPException(422, "Every selected finding must belong to this asset")
        if len({row.investigation_id for row in finding_rows}) > 1:
            raise HTTPException(422, "Selected findings must belong to one investigation")
    investigation = None
    if payload.investigation_id:
        investigation = visible_row(db, Investigation, payload.investigation_id)
        if investigation is None or investigation.asset_id != asset.id: raise HTTPException(422, "Investigation must belong to the selected asset")
        if finding_rows and any(row.investigation_id != investigation.id for row in finding_rows):
            raise HTTPException(422, "Selected findings must belong to the linked investigation")
    incident = Incident(id=new_id(), title=payload.title.strip(), summary=payload.summary.strip(),
        classification=payload.classification, priority=payload.priority, asset_id=asset.id,
        investigation_id=investigation.id if investigation else (finding_rows[0].investigation_id if finding_rows else None),
        owner_id=user.id, created_by=user.id)
    db.add(incident)
    db.flush()
    for finding_row in finding_rows:
        db.add(IncidentFinding(incident_id=incident.id, finding_id=finding_row.id))
    evidence = []
    for row in finding_rows:
        if row.evidence_id: evidence.append(row.evidence_id)
        evidence.extend(row.details_json.get("additional_evidence_ids", []))
    db.add(IncidentEvent(incident_id=incident.id, actor_id=user.id, event_type="created", message="Incident case created.",
        details_json={"evidence_ids": sorted(set(evidence)), "finding_ids": [row.id for row in finding_rows]}))
    playbook_id = select_playbook(asset.kind, finding_rows)
    for order, (stage, title, description) in enumerate(PLAYBOOKS[playbook_id]):
        db.add(PlaybookTask(incident_id=incident.id, playbook_id=playbook_id, playbook_version=PLAYBOOK_VERSION,
            title=title, description=description, stage=stage, sort_order=order))
    db.add(AuditEvent(actor_id=user.id, action="incident.created", entity_type="incident", entity_id=incident.id,
        details_json={"playbook_id": playbook_id, "finding_count": len(finding_rows)}))
    db.flush()
    if incident.investigation_id:
        linked_investigation = db.get(Investigation, incident.investigation_id)
        if linked_investigation:
            ensure_relationships(db, linked_investigation)
    db.commit()
    db.refresh(incident)
    return _detail(db, incident)


@router.get("", response_model=list[IncidentSummaryOut])
def list_incidents(_user: User = Depends(get_current_user), db: Session = Depends(get_db), response: Response = None,
                   status: str | None = Query(default=None), priority: str | None = Query(default=None),
                   asset_id: str | None = Query(default=None), q: str | None = Query(default=None, max_length=200),
                   sort: Literal["updated_at", "created_at", "priority", "status"] = Query(default="updated_at"),
                   order: Literal["asc", "desc"] = Query(default="desc"), page: Page = Depends(page_params)) -> list[dict]:
    query = visible_incidents(db)
    if status: query = query.filter(Incident.status == status)
    if priority: query = query.filter(Incident.priority == priority)
    if asset_id: query = query.filter(Incident.asset_id == asset_id)
    if q:
        needle = f"%{q.strip()}%"
        query = query.filter(Incident.title.ilike(needle) | Incident.summary.ilike(needle))
    sort_column = {"updated_at": Incident.updated_at, "created_at": Incident.created_at,
                   "priority": Incident.priority, "status": Incident.status}[sort]
    ordering = sort_column.asc() if order == "asc" else sort_column.desc()
    rows = apply_page(query.order_by(ordering, Incident.id.asc()), page, response)
    asset_ids = {item.asset_id for item in rows if item.asset_id}
    owner_ids = {item.owner_id for item in rows if item.owner_id}
    assets = {item.id: item for item in visible_assets(db).filter(Asset.id.in_(asset_ids)).all()} if asset_ids else {}
    owners = {item.id: item for item in db.query(User).filter(User.id.in_(owner_ids)).all()} if owner_ids else {}
    return [_summary(db, item, asset=assets.get(item.asset_id), owner=owners.get(item.owner_id)) for item in rows]


@router.get("/{incident_id}")
def get_incident(incident_id: str, _user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    incident = visible_row(db, Incident, incident_id)
    if incident is None: raise HTTPException(404, "Incident not found")
    return _detail(db, incident)


@router.patch("/{incident_id}")
def update_incident(incident_id: str, payload: IncidentUpdate,
                    user: User = Depends(require_roles_csrf("admin", "analyst")), db: Session = Depends(get_db)) -> dict:
    incident = visible_row(db, Incident, incident_id)
    if incident is None: raise HTTPException(404, "Incident not found")
    changes = payload.model_dump(exclude_unset=True)
    requested_status = changes.pop("status", None)
    reason = changes.pop("reason", None)
    previous_status = incident.status
    if incident.status == "closed" and requested_status == "triaged":
        if not reason or len(reason.strip()) < 8: raise HTTPException(422, "A reason of at least 8 characters is required to reopen a case")
        incident.status = "triaged"
        incident.closed_at = None
        db.add(IncidentEvent(incident_id=incident.id, actor_id=user.id, event_type="reopened", message=reason.strip()))
    elif requested_status and requested_status != incident.status:
        if requested_status not in ALLOWED_TRANSITIONS.get(incident.status, set()):
            raise HTTPException(409, f"Invalid status transition from {incident.status} to {requested_status}")
        if requested_status == "closed" and not (changes.get("resolution_summary") or incident.resolution_summary or "").strip():
            raise HTTPException(422, "A resolution summary is required before closure")
        incident.status = requested_status
        if requested_status == "closed": incident.closed_at = now_utc()
        db.add(IncidentEvent(incident_id=incident.id, actor_id=user.id, event_type="status_changed",
            message=f"Status changed from {previous_status} to {requested_status}.", details_json={"from": previous_status, "to": requested_status}))
    if "owner_id" in changes and changes["owner_id"]:
        owner = db.get(User, changes["owner_id"])
        if owner is None or not owner.is_active: raise HTTPException(422, "Owner must be an active workspace user")
    for key, value in changes.items():
        if value is not None: setattr(incident, key, value.strip() if isinstance(value, str) else value)
    incident.updated_at = now_utc()
    db.add(AuditEvent(actor_id=user.id, action="incident.updated", entity_type="incident", entity_id=incident.id,
        details_json={"fields": sorted(changes.keys()), "status": requested_status}))
    db.commit()
    return _detail(db, incident)


@router.post("/{incident_id}/events", status_code=201)
def add_event(incident_id: str, payload: EventCreate, user: User = Depends(require_roles_csrf("admin", "analyst")), db: Session = Depends(get_db)) -> dict:
    incident = visible_row(db, Incident, incident_id)
    if incident is None: raise HTTPException(404, "Incident not found")
    event = IncidentEvent(incident_id=incident.id, actor_id=user.id, event_type=payload.event_type, message=payload.message.strip())
    db.add(event)
    incident.updated_at = now_utc()
    db.add(AuditEvent(actor_id=user.id, action="incident.event_added", entity_type="incident", entity_id=incident.id))
    db.commit()
    return _event_payload(event, user.username)


@router.patch("/{incident_id}/tasks/{task_id}")
def update_task(incident_id: str, task_id: str, payload: TaskUpdate,
                user: User = Depends(require_roles_csrf("admin", "analyst")), db: Session = Depends(get_db)) -> dict:
    incident = visible_row(db, Incident, incident_id)
    if incident is None: raise HTTPException(404, "Incident not found")
    task = db.query(PlaybookTask).filter_by(id=task_id, incident_id=incident_id).first()
    if task is None: raise HTTPException(404, "Playbook task not found")
    task.status = payload.status
    task.notes = payload.notes.strip() if payload.notes else None
    task.completed_by = user.id if payload.status == "completed" else None
    task.completed_at = now_utc() if payload.status == "completed" else None
    incident.updated_at = now_utc()
    db.add(IncidentEvent(incident_id=incident_id, actor_id=user.id, event_type="playbook_task_updated",
        message=f"Task {task.title}: {task.status}" + (f" — {task.notes}" if task.notes else ""),
        details_json={"task_id": task.id, "status": task.status, "completed_at": task.completed_at.isoformat() if task.completed_at else None}))
    db.add(AuditEvent(actor_id=user.id, action="incident.task_updated", entity_type="incident", entity_id=incident_id,
        details_json={"task_id": task.id, "status": task.status}))
    db.commit()
    return _task_payload(task, user.username if task.completed_by else None)


def _summary(db: Session, item: Incident, *, asset: Asset | None = None, owner: User | None = None) -> dict:
    asset = asset if asset is not None else db.get(Asset, item.asset_id)
    owner = owner if owner is not None else (db.get(User, item.owner_id) if item.owner_id else None)
    return {"id": item.id, "title": item.title, "summary": item.summary, "classification": item.classification,
        "status": item.status, "priority": item.priority, "owner_id": item.owner_id, "owner": owner.username if owner else None,
        "asset_id": item.asset_id, "asset_identifier": asset.identifier if asset else None,
        "investigation_id": item.investigation_id, "created_at": item.created_at, "updated_at": item.updated_at,
        "closed_at": item.closed_at, "resolution_summary": item.resolution_summary}


def _detail(db: Session, incident: Incident) -> dict:
    value = _summary(db, incident)
    links = db.query(IncidentFinding).filter_by(incident_id=incident.id).all()
    finding_ids = {link.finding_id for link in links}
    finding_rows = db.query(Finding).filter(Finding.id.in_(finding_ids)).all() if finding_ids else []
    findings = [row for row in finding_rows if row is not None]
    evidence_ids = set()
    for row in findings:
        if row and row.evidence_id: evidence_ids.add(row.evidence_id)
        if row: evidence_ids.update(row.details_json.get("additional_evidence_ids", []))
    evidence = db.query(EvidenceSnapshot).filter(EvidenceSnapshot.id.in_(evidence_ids)).all() if evidence_ids else []
    value["findings"] = [{"id": row.id, "title": row.title, "severity": row.severity, "category": row.category,
        "evidence_id": row.evidence_id, "source": row.source, "applicability": row.applicability,
        "cvss": {"version": row.details_json.get("cvss_version"), "score": row.details_json.get("cvss_score"),
                 "severity": row.severity, "vector": row.details_json.get("vector")},
        "kev": row.details_json.get("kev"),
        "epss": {"score": row.epss_score, "percentile": row.epss_percentile,
                 "observed_at": row.epss_observed_at, "provider_status": row.epss_provider_status,
                 "freshness": row.epss_freshness, "provider": row.details_json.get("epss_provider"),
                 "provider_version": row.details_json.get("epss_provider_version"),
                 "source_date": row.details_json.get("epss_source_date")},
        "osv": osv_finding_payload(row.details_json, row.evidence_id)} for row in findings if row]
    value["evidence"] = [{"id": row.id, "source": row.source, "observed_at": row.observed_at, "sha256": row.sha256,
        "is_synthetic": row.is_synthetic, "evidence_json": row.evidence_json} for row in evidence]
    events = db.query(IncidentEvent).filter_by(incident_id=incident.id).order_by(IncidentEvent.created_at).all()
    event_actor_ids = {item.actor_id for item in events if item.actor_id}
    event_actors = {item.id: item for item in db.query(User).filter(User.id.in_(event_actor_ids)).all()} if event_actor_ids else {}
    value["events"] = [_event_payload(item, event_actors[item.actor_id].username if item.actor_id in event_actors else "unknown") for item in events]
    tasks = db.query(PlaybookTask).filter_by(incident_id=incident.id).order_by(PlaybookTask.sort_order).all()
    task_user_ids = {item.completed_by for item in tasks if item.completed_by}
    task_users = {item.id: item for item in db.query(User).filter(User.id.in_(task_user_ids)).all()} if task_user_ids else {}
    value["tasks"] = [_task_payload(item, task_users[item.completed_by].username if item.completed_by in task_users else None) for item in tasks]
    value["attack_matrix"] = incident_matrix(db, incident)
    return value


def _event_payload(item: IncidentEvent, actor: str) -> dict:
    return {"id": item.id, "event_type": item.event_type, "message": item.message, "actor": actor,
        "details": item.details_json, "created_at": item.created_at}


def _task_payload(item: PlaybookTask, completed_by: str | None) -> dict:
    return {"id": item.id, "playbook_id": item.playbook_id, "playbook_version": item.playbook_version,
        "title": item.title, "description": item.description, "stage": item.stage, "status": item.status,
        "notes": item.notes, "completed_by": completed_by, "completed_at": item.completed_at, "sort_order": item.sort_order}
