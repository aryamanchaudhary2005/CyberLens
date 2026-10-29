from datetime import timedelta

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from app.authorization import active_website_authorization
from app.config import get_settings
from app.database import get_db
from app.dependencies import get_current_user, require_roles_csrf
from app.graph import compare as compare_evidence_graph
from app.models import Asset, AuditEvent, Investigation, MonitoringRun, MonitoringSchedule, User, WebsiteAuthorization, new_id, now_utc
from app.pagination import Page, apply_page, page_params
from app.schemas import EvidenceGraphChangesOut, MonitoringRunOut, MonitoringScheduleCreate, MonitoringScheduleOut, MonitoringScheduleResume
from sqlalchemy import func
from app.visibility import live_projection, visible_monitoring_schedules, visible_row

router = APIRouter(prefix="/monitoring", tags=["monitoring"])


def _schedule_payload(item: MonitoringSchedule, *, last_run_at=None) -> dict:
    return {
        "id": item.id, "asset_id": item.asset_id, "authorization_id": item.authorization_id,
        "owner_id": item.owner_id, "mode": item.mode, "cadence": item.cadence, "status": item.status,
        "next_run_at": item.next_run_at, "last_run_at": last_run_at if live_projection() else item.last_run_at,
        "failure_code": item.failure_code, "failure_detail": item.failure_detail,
        "created_at": item.created_at, "updated_at": item.updated_at, "completed_at": item.completed_at,
    }


def _run_payload(item: MonitoringRun, investigation: Investigation | None = None) -> dict:
    return {
        "id": item.id, "schedule_id": item.schedule_id, "investigation_id": item.investigation_id,
        "previous_investigation_id": item.previous_investigation_id, "scheduled_for": item.scheduled_for,
        "status": investigation.status if investigation else item.status,
        "started_at": investigation.started_at if investigation else item.started_at,
        "finished_at": investigation.finished_at if investigation else item.finished_at,
        "failure_detail": (investigation.error_summary if investigation and investigation.status == "failed"
                           else item.failure_detail),
        "mode": investigation.mode if investigation else "demo",
        "created_at": item.created_at,
    }


def _active_authorization(db: Session, asset_id: str, authorization_id: str) -> WebsiteAuthorization | None:
    return db.query(WebsiteAuthorization).filter(
        WebsiteAuthorization.id == authorization_id,
        WebsiteAuthorization.asset_id == asset_id,
        WebsiteAuthorization.revoked_at.is_(None),
        WebsiteAuthorization.expires_at > now_utc(),
    ).first()


@router.post("", status_code=201, response_model=MonitoringScheduleOut)
def create_schedule(payload: MonitoringScheduleCreate,
                    user: User = Depends(require_roles_csrf("admin", "analyst")),
                    db: Session = Depends(get_db)) -> dict:
    asset = visible_row(db, Asset, payload.asset_id)
    if asset is None:
        raise HTTPException(404, "Asset not found")
    if asset.kind not in {"domain", "url"}:
        raise HTTPException(422, "Continuous monitoring is available only for website assets")
    if _active_authorization(db, asset.id, payload.authorization_id) is None:
        raise HTTPException(422, "An active authorization for this exact website is required")
    created_at = now_utc()
    mode = get_settings().app_mode
    schedule = MonitoringSchedule(
        id=new_id(), asset_id=asset.id, authorization_id=payload.authorization_id,
        owner_id=user.id, mode=mode, cadence=payload.cadence, status="active",
        next_run_at=created_at + timedelta(days=1 if payload.cadence == "daily" else 7),
        created_at=created_at, updated_at=created_at,
    )
    db.add(schedule)
    db.flush()
    db.add(AuditEvent(actor_id=user.id, action="monitoring.schedule_created", entity_type="monitoring_schedule",
                      entity_id=schedule.id, details_json={"asset_id": asset.id,
                      "authorization_id": schedule.authorization_id, "cadence": schedule.cadence}))
    db.commit()
    return _schedule_payload(schedule)


@router.get("", response_model=list[MonitoringScheduleOut])
def list_schedules(asset_id: str | None = Query(default=None),
                   status: Literal["active", "paused", "failed", "completed"] | None = Query(default=None),
                   cadence: Literal["daily", "weekly"] | None = Query(default=None),
                   _user: User = Depends(get_current_user), db: Session = Depends(get_db),
                   response: Response = None, page: Page = Depends(page_params)) -> list[dict]:
    query = visible_monitoring_schedules(db)
    if asset_id:
        query = query.filter(MonitoringSchedule.asset_id == asset_id)
    if status:
        query = query.filter(MonitoringSchedule.status == status)
    if cadence:
        query = query.filter(MonitoringSchedule.cadence == cadence)
    rows = apply_page(query.order_by(MonitoringSchedule.created_at.desc(), MonitoringSchedule.id), page, response)
    latest_live = {}
    if live_projection() and rows:
        values = (db.query(MonitoringRun.schedule_id, func.max(MonitoringRun.finished_at))
                  .join(Investigation, Investigation.id == MonitoringRun.investigation_id)
                  .filter(MonitoringRun.schedule_id.in_([item.id for item in rows]), Investigation.mode == "live")
                  .group_by(MonitoringRun.schedule_id).all())
        latest_live = dict(values)
    return [_schedule_payload(item, last_run_at=latest_live.get(item.id)) for item in rows]


@router.get("/{schedule_id}", response_model=MonitoringScheduleOut)
def get_schedule(schedule_id: str, _user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    item = visible_row(db, MonitoringSchedule, schedule_id)
    if item is None:
        raise HTTPException(404, "Monitoring schedule not found")
    latest = None
    if live_projection():
        latest = (db.query(func.max(MonitoringRun.finished_at)).join(Investigation, Investigation.id == MonitoringRun.investigation_id)
                  .filter(MonitoringRun.schedule_id == item.id, Investigation.mode == "live").scalar())
    return _schedule_payload(item, last_run_at=latest)


@router.get("/{schedule_id}/history", response_model=list[MonitoringRunOut])
def schedule_history(schedule_id: str, _user: User = Depends(get_current_user), db: Session = Depends(get_db),
                     response: Response = None, page: Page = Depends(page_params)) -> list[dict]:
    if visible_row(db, MonitoringSchedule, schedule_id) is None:
        raise HTTPException(404, "Monitoring schedule not found")
    rows = (db.query(MonitoringRun, Investigation)
            .join(Investigation, Investigation.id == MonitoringRun.investigation_id)
            .filter(MonitoringRun.schedule_id == schedule_id)
            .order_by(MonitoringRun.scheduled_for.desc(), MonitoringRun.id.desc()))
    if live_projection():
        rows = rows.filter(Investigation.mode == "live")
    rows = apply_page(rows, page, response)
    return [_run_payload(item, investigation) for item, investigation in rows]


@router.get("/{schedule_id}/runs/{run_id}/changes", response_model=EvidenceGraphChangesOut)
def schedule_run_changes(schedule_id: str, run_id: str,
                         _user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    if visible_row(db, MonitoringSchedule, schedule_id) is None:
        raise HTTPException(404, "Monitoring schedule not found")
    run_query = (db.query(MonitoringRun).join(Investigation, Investigation.id == MonitoringRun.investigation_id)
                 .filter(MonitoringRun.id == run_id, MonitoringRun.schedule_id == schedule_id))
    if live_projection():
        run_query = run_query.filter(Investigation.mode == "live")
    item = run_query.first()
    if item is None or item.previous_investigation_id is None:
        raise HTTPException(404, "No prior completed monitoring investigation is available for comparison")
    current = visible_row(db, Investigation, item.investigation_id)
    previous = visible_row(db, Investigation, item.previous_investigation_id)
    if current is None or previous is None or current.status not in {"completed", "partial", "failed"} or previous.status not in {"completed", "partial"}:
        raise HTTPException(409, "Both monitoring investigations must be complete before comparison")
    return compare_evidence_graph(db, current, previous)


@router.post("/{schedule_id}/pause", response_model=MonitoringScheduleOut)
def pause_schedule(schedule_id: str, user: User = Depends(require_roles_csrf("admin", "analyst")),
                   db: Session = Depends(get_db)) -> dict:
    item = visible_row(db, MonitoringSchedule, schedule_id)
    if item is None:
        raise HTTPException(404, "Monitoring schedule not found")
    if item.status != "active":
        raise HTTPException(409, "Only an active monitoring schedule can be paused")
    item.status = "paused"
    item.updated_at = now_utc()
    db.add(AuditEvent(actor_id=user.id, action="monitoring.schedule_paused", entity_type="monitoring_schedule",
                      entity_id=item.id, details_json={"asset_id": item.asset_id}))
    db.commit()
    latest = None
    if live_projection():
        latest = (db.query(func.max(MonitoringRun.finished_at)).join(Investigation, Investigation.id == MonitoringRun.investigation_id)
                  .filter(MonitoringRun.schedule_id == item.id, Investigation.mode == "live").scalar())
    return _schedule_payload(item, last_run_at=latest)


@router.post("/{schedule_id}/resume", response_model=MonitoringScheduleOut)
def resume_schedule(schedule_id: str, payload: MonitoringScheduleResume | None = None,
                    user: User = Depends(require_roles_csrf("admin", "analyst")),
                    db: Session = Depends(get_db)) -> dict:
    item = visible_row(db, MonitoringSchedule, schedule_id)
    if item is None:
        raise HTTPException(404, "Monitoring schedule not found")
    if item.status not in {"paused", "failed"}:
        raise HTTPException(409, "Only a paused or failed monitoring schedule can be resumed")
    authorization_id = payload.authorization_id if payload and payload.authorization_id else item.authorization_id
    if _active_authorization(db, item.asset_id, authorization_id) is None:
        current = active_website_authorization(db, item.asset_id)
        if current is None or (payload and payload.authorization_id and current.id != payload.authorization_id):
            raise HTTPException(409, "Resume requires an active authorization for this website")
        authorization_id = current.id
    now = now_utc()
    item.authorization_id = authorization_id
    item.status = "active"
    item.next_run_at = now + timedelta(days=1 if item.cadence == "daily" else 7)
    item.failure_code = None
    item.failure_detail = None
    item.completed_at = None
    item.updated_at = now
    db.add(AuditEvent(actor_id=user.id, action="monitoring.schedule_resumed", entity_type="monitoring_schedule",
                      entity_id=item.id, details_json={"authorization_id": item.authorization_id}))
    db.commit()
    latest = None
    if live_projection():
        latest = (db.query(func.max(MonitoringRun.finished_at)).join(Investigation, Investigation.id == MonitoringRun.investigation_id)
                  .filter(MonitoringRun.schedule_id == item.id, Investigation.mode == "live").scalar())
    return _schedule_payload(item, last_run_at=latest)


@router.post("/{schedule_id}/cancel", response_model=MonitoringScheduleOut)
def cancel_schedule(schedule_id: str, user: User = Depends(require_roles_csrf("admin", "analyst")),
                    db: Session = Depends(get_db)) -> dict:
    item = visible_row(db, MonitoringSchedule, schedule_id)
    if item is None:
        raise HTTPException(404, "Monitoring schedule not found")
    if item.status == "completed":
        raise HTTPException(409, "Monitoring schedule is already completed")
    now = now_utc()
    item.status = "completed"
    item.completed_at = now
    item.next_run_at = None
    item.failure_code = None
    item.failure_detail = None
    item.updated_at = now
    db.add(AuditEvent(actor_id=user.id, action="monitoring.schedule_cancelled", entity_type="monitoring_schedule",
                      entity_id=item.id, details_json={"asset_id": item.asset_id}))
    db.commit()
    latest = None
    if live_projection():
        latest = (db.query(func.max(MonitoringRun.finished_at)).join(Investigation, Investigation.id == MonitoringRun.investigation_id)
                  .filter(MonitoringRun.schedule_id == item.id, Investigation.mode == "live").scalar())
    return _schedule_payload(item, last_run_at=latest)
