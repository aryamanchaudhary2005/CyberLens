from typing import Literal

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user
from app.models import AuditEvent, User
from app.pagination import Page, apply_page, page_params
from app.schemas import AuditEventOut
from app.visibility import visible_audit_events

router = APIRouter(prefix="/audit-events", tags=["audit"])


@router.get("", response_model=list[AuditEventOut])
def list_audit_events(
    _user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    response: Response = None,
    action: str | None = Query(default=None, max_length=80),
    entity_type: str | None = Query(default=None, max_length=80),
    actor_id: str | None = Query(default=None),
    q: str | None = Query(default=None, max_length=200),
    sort: Literal["created_at", "action", "entity_type"] = Query(default="created_at"),
    order: Literal["asc", "desc"] = Query(default="desc"),
    page: Page = Depends(page_params),
) -> list[dict]:
    query = visible_audit_events(db)
    if action:
        query = query.filter(AuditEvent.action == action)
    if entity_type:
        query = query.filter(AuditEvent.entity_type == entity_type)
    if actor_id:
        query = query.filter(AuditEvent.actor_id == actor_id)
    if q:
        needle = f"%{q.strip()}%"
        query = query.filter(
            AuditEvent.action.ilike(needle)
            | AuditEvent.entity_type.ilike(needle)
            | AuditEvent.entity_id.ilike(needle)
        )
    sort_column = {"created_at": AuditEvent.created_at, "action": AuditEvent.action,
                   "entity_type": AuditEvent.entity_type}[sort]
    ordering = sort_column.asc() if order == "asc" else sort_column.desc()
    rows = apply_page(query.order_by(ordering, AuditEvent.id.asc()), page, response)
    actor_ids = {row.actor_id for row in rows if row.actor_id}
    actors = {row.id: row for row in db.query(User).filter(User.id.in_(actor_ids)).all()} if actor_ids else {}
    return [{"id": row.id, "event_sequence": row.event_sequence,
             "previous_hash": row.previous_hash, "current_hash": row.current_hash,
             "actor_id": row.actor_id,
             "actor": actors[row.actor_id].username if row.actor_id in actors else None,
             "action": row.action, "entity_type": row.entity_type, "entity_id": row.entity_id,
             "details": row.details_json or {}, "metadata": row.details_json or {}, "created_at": row.created_at} for row in rows]
