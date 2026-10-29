"""Authorization-bound continuous monitoring on the investigation outbox."""

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import (
    Asset,
    AuditEvent,
    Investigation,
    MonitoringRun,
    MonitoringSchedule,
    WebsiteAuthorization,
    new_id,
    now_utc,
)
from app.orchestration import create_attempt
from app.visibility import live_projection


CADENCE_DAYS = {"daily": 1, "weekly": 7}
FINISHED_INVESTIGATIONS = {"completed", "partial", "failed"}


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def schedule_authorization_is_active(db: Session, schedule: MonitoringSchedule,
                                    at: datetime | None = None) -> bool:
    current = _utc(at or now_utc())
    return db.query(WebsiteAuthorization.id).filter(
        WebsiteAuthorization.id == schedule.authorization_id,
        WebsiteAuthorization.asset_id == schedule.asset_id,
        WebsiteAuthorization.revoked_at.is_(None),
        WebsiteAuthorization.expires_at > current,
    ).first() is not None


def _demo_scenario(asset: Asset) -> str | None:
    if asset.kind in {"domain", "url"}:
        return "routine_website"
    return None


def _next_occurrence(cadence: str, scheduled_for: datetime, now: datetime) -> datetime:
    step = timedelta(days=CADENCE_DAYS[cadence])
    next_run = scheduled_for + step
    # A delayed dispatcher performs one catch-up run, then skips missed slots
    # so it cannot flood Redis with a burst of old investigations.
    while next_run <= now:
        next_run += step
    return next_run


def enqueue_due_schedules(db: Session, *, now: datetime | None = None, limit: int = 50) -> int:
    """Atomically materialize due schedule slots as investigations and outbox rows."""
    current = _utc(now or now_utc())
    settings = get_settings()
    schedule_query = (
        db.query(MonitoringSchedule)
        .join(Asset, Asset.id == MonitoringSchedule.asset_id)
        .filter(MonitoringSchedule.mode == settings.app_mode,
                MonitoringSchedule.status == "active", MonitoringSchedule.next_run_at <= current)
    )
    if live_projection():
        schedule_query = schedule_query.filter(Asset.is_synthetic.is_(False))
    schedules = (schedule_query.order_by(MonitoringSchedule.next_run_at, MonitoringSchedule.id)
        .limit(max(1, min(limit, 500)))
        .with_for_update(skip_locked=True)
        .all())
    created = 0
    for schedule in schedules:
        scheduled_for = _utc(schedule.next_run_at)
        if scheduled_for is None:
            continue
        if not schedule_authorization_is_active(db, schedule, current):
            schedule.status = "failed"
            schedule.next_run_at = None
            schedule.failure_code = "authorization_inactive"
            schedule.failure_detail = "The linked authorization expired or was revoked before this run."
            schedule.updated_at = current
            db.add(AuditEvent(
                actor_id=None, action="monitoring.schedule_failed", entity_type="monitoring_schedule",
                entity_id=schedule.id, details_json={"reason": schedule.failure_code},
            ))
            continue

        duplicate = db.query(MonitoringRun).filter_by(schedule_id=schedule.id, scheduled_for=scheduled_for).first()
        if duplicate is None:
            asset = db.get(Asset, schedule.asset_id)
            if asset is None or asset.kind not in {"domain", "url"}:
                schedule.status = "failed"
                schedule.next_run_at = None
                schedule.failure_code = "asset_unavailable"
                schedule.failure_detail = "The authorized website asset is no longer available."
                schedule.updated_at = current
                db.add(AuditEvent(
                    actor_id=None, action="monitoring.schedule_failed", entity_type="monitoring_schedule",
                    entity_id=schedule.id, details_json={"reason": schedule.failure_code},
                ))
                continue

            previous = (
                db.query(MonitoringRun)
                .join(Investigation, Investigation.id == MonitoringRun.investigation_id)
                .filter(
                    MonitoringRun.schedule_id == schedule.id,
                    MonitoringRun.scheduled_for < scheduled_for,
                    Investigation.mode == settings.app_mode,
                    Investigation.status.in_(("completed", "partial")),
                )
                .order_by(MonitoringRun.scheduled_for.desc(), MonitoringRun.id.desc())
                .first()
            )
            investigation = Investigation(
                id=new_id(), asset_id=asset.id, requested_by=schedule.owner_id,
                mode=settings.app_mode,
                scenario=_demo_scenario(asset) if settings.app_mode == "demo" else None,
                status="queued", progress=0, created_at=current,
            )
            db.add(investigation)
            db.flush()
            run = MonitoringRun(
                id=new_id(), schedule_id=schedule.id, investigation_id=investigation.id,
                previous_investigation_id=previous.investigation_id if previous else None,
                scheduled_for=scheduled_for, status="queued", created_at=current,
            )
            db.add(run)
            create_attempt(db, investigation, "initial", created_at=current)
            db.add(AuditEvent(
                actor_id=None, action="monitoring.run_scheduled", entity_type="monitoring_run",
                entity_id=run.id, details_json={
                    "schedule_id": schedule.id, "investigation_id": investigation.id,
                    "scheduled_for": scheduled_for.isoformat(), "mode": investigation.mode,
                },
            ))
            created += 1

        schedule.next_run_at = _next_occurrence(schedule.cadence, scheduled_for, current)
        schedule.updated_at = current
        schedule.failure_code = None
        schedule.failure_detail = None

    if schedules:
        db.commit()
    return created


def sync_monitoring_runs(db: Session) -> int:
    """Reflect investigation lifecycle state into monitoring history and schedules."""
    pending_query = (
        db.query(MonitoringRun, Investigation, MonitoringSchedule)
        .join(Investigation, Investigation.id == MonitoringRun.investigation_id)
        .join(MonitoringSchedule, MonitoringSchedule.id == MonitoringRun.schedule_id)
        .filter(MonitoringRun.status.in_(("queued", "running")))
    )
    settings = get_settings()
    pending = pending_query.filter(
        Investigation.mode == settings.app_mode,
        MonitoringSchedule.mode == settings.app_mode,
    ).all()
    changed = 0
    for run, investigation, schedule in pending:
        if run.status != investigation.status:
            run.status = investigation.status
            changed += 1
        run.started_at = investigation.started_at
        if investigation.status in FINISHED_INVESTIGATIONS:
            run.finished_at = investigation.finished_at or now_utc()
            run.failure_detail = investigation.error_summary if investigation.status == "failed" else None
            schedule.last_run_at = run.finished_at
            schedule.updated_at = run.finished_at
            if investigation.status == "failed" and schedule.status == "active":
                schedule.status = "failed"
                schedule.failure_code = "investigation_failed"
                schedule.failure_detail = investigation.error_summary or "The scheduled investigation failed."
                db.add(AuditEvent(
                    actor_id=None, action="monitoring.schedule_failed", entity_type="monitoring_schedule",
                    entity_id=schedule.id, details_json={"reason": schedule.failure_code,
                                                        "monitoring_run_id": run.id},
                ))
        elif investigation.started_at is not None:
            run.started_at = investigation.started_at
    if changed:
        db.commit()
    return changed
