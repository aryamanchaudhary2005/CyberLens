"""Durable outbox delivery and investigation recovery helpers."""

from datetime import datetime, timedelta, timezone
import logging

from redis import Redis
from rq import Queue
from rq.exceptions import DuplicateJobError
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import SessionLocal
from app.models import (
    AuditEvent,
    CollectorRun,
    Investigation,
    InvestigationAttempt,
    InvestigationOutbox,
    new_id,
    now_utc,
)

logger = logging.getLogger("cyberlens.orchestration")

MAX_AUTOMATIC_RETRIES = 2
RETRY_BASE_SECONDS = 5
RETRY_MAX_SECONDS = 60
STALE_AFTER_SECONDS = 15 * 60
WORKER_HEARTBEAT_KEY = "cyberlens:worker:heartbeat"
WORKER_HEARTBEAT_TTL_SECONDS = 45


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def create_attempt(
    db: Session,
    investigation: Investigation,
    retry_kind: str,
    *,
    available_at: datetime | None = None,
    created_at: datetime | None = None,
) -> InvestigationAttempt:
    """Add an attempt and its delivery intent to the caller's transaction."""
    created_at = created_at or now_utc()
    next_number = (db.query(func.max(InvestigationAttempt.attempt_number))
                   .filter(InvestigationAttempt.investigation_id == investigation.id).scalar() or 0) + 1
    attempt = InvestigationAttempt(
        id=new_id(), investigation_id=investigation.id, attempt_number=next_number,
        retry_kind=retry_kind, status="queued", progress=0, created_at=created_at,
    )
    db.add(attempt)
    db.flush()
    db.add(InvestigationOutbox(
        id=new_id(), attempt_id=attempt.id, status="pending",
        available_at=available_at or created_at, created_at=created_at, updated_at=created_at,
    ))
    return attempt


def _automatic_retries_since_manual(db: Session, investigation_id: str) -> int:
    attempts = (db.query(InvestigationAttempt)
                .filter_by(investigation_id=investigation_id)
                .order_by(InvestigationAttempt.attempt_number.desc()).all())
    count = 0
    for attempt in attempts:
        if attempt.retry_kind in {"initial", "manual"}:
            break
        if attempt.retry_kind in {"automatic", "recovery"}:
            count += 1
    return count


def automatic_retry_delay(db: Session, investigation_id: str) -> int:
    retries_already_scheduled = _automatic_retries_since_manual(db, investigation_id)
    return min(RETRY_BASE_SECONDS * (2 ** retries_already_scheduled), RETRY_MAX_SECONDS)


def _is_transient_evidence(value: object) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {"http_status", "status_code", "status"} and isinstance(item, int):
                if item in {408, 425, 429} or 500 <= item <= 599:
                    return True
            if key in {"provider_status", "error"} and isinstance(item, str):
                normalized = item.casefold()
                if any(token in normalized for token in (
                    "timeout", "timedout", "connection", "connecterror", "socket", "networkerror",
                    "econn", "temporar",
                    "servfail", "nonameservers", "simulated_rate_limit", "simulated_timeout",
                )):
                    return True
            if _is_transient_evidence(item):
                return True
    elif isinstance(value, list):
        return any(_is_transient_evidence(item) for item in value)
    return False


def _sync_parent_to_attempt(investigation: Investigation, attempt: InvestigationAttempt) -> None:
    investigation.status = attempt.status
    investigation.progress = attempt.progress
    investigation.started_at = attempt.started_at
    investigation.finished_at = attempt.finished_at
    investigation.error_summary = attempt.error_summary


def _queue_automatic_retry(
    db: Session,
    investigation: Investigation,
    attempt: InvestigationAttempt,
    *,
    retry_kind: str = "automatic",
    now: datetime | None = None,
) -> bool:
    if _automatic_retries_since_manual(db, investigation.id) >= MAX_AUTOMATIC_RETRIES:
        return False
    now = now or now_utc()
    delay = automatic_retry_delay(db, investigation.id)
    investigation.status = "queued"
    investigation.progress = 0
    investigation.started_at = None
    investigation.finished_at = None
    investigation.error_summary = None
    create_attempt(db, investigation, retry_kind, available_at=now + timedelta(seconds=delay), created_at=now)
    return True


def dispatch_pending_outbox(db: Session, limit: int = 50, *, queue=None, now: datetime | None = None) -> int:
    """Publish committed outbox records; stable RQ ids make redelivery safe."""
    now = now or now_utc()
    app_mode = get_settings().app_mode
    events = (db.query(InvestigationOutbox)
              .join(InvestigationAttempt, InvestigationAttempt.id == InvestigationOutbox.attempt_id)
              .join(Investigation, Investigation.id == InvestigationAttempt.investigation_id)
              .filter(InvestigationOutbox.status == "pending", InvestigationOutbox.available_at <= now)
              .filter(Investigation.mode == app_mode)
              .order_by(InvestigationOutbox.available_at, InvestigationOutbox.created_at)
              .limit(max(1, min(limit, 500))).with_for_update(skip_locked=True).all())
    if not events:
        return 0

    owned_connection = None
    if queue is None:
        settings = get_settings()
        owned_connection = Redis.from_url(settings.redis_url, socket_timeout=2)
        queue = Queue("investigations", connection=owned_connection,
                      default_timeout=max(120, int(settings.collector_timeout_seconds * 20)))

    delivered = 0
    try:
        for event in events:
            attempt = db.get(InvestigationAttempt, event.attempt_id)
            investigation = db.get(Investigation, attempt.investigation_id) if attempt else None
            if attempt is None or investigation is None or attempt.status != "queued":
                event.status = "dispatched"
                event.dispatched_at = now
                event.updated_at = now
                db.commit()
                continue
            job_id = f"investigation-attempt-{attempt.id}"
            try:
                queue.enqueue(
                    "app.jobs.run_investigation_attempt", investigation.id, attempt.id,
                    job_id=job_id, retry=None,
                )
            except DuplicateJobError:
                # A prior publish may have succeeded immediately before the dispatcher crashed.
                pass
            except Exception as exc:
                event.dispatch_attempts += 1
                event.last_error = type(exc).__name__[:500]
                delay = min(2 ** min(max(event.dispatch_attempts - 1, 0), 6), RETRY_MAX_SECONDS)
                event.available_at = now + timedelta(seconds=delay)
                event.updated_at = now
                db.commit()
                logger.warning("outbox delivery failed", extra={"attempt_id": attempt.id,
                                                                  "exception_type": type(exc).__name__})
                continue
            event.status = "dispatched"
            event.dispatch_attempts += 1
            event.last_error = None
            event.dispatched_at = now
            event.updated_at = now
            db.commit()
            delivered += 1
    finally:
        if owned_connection is not None:
            owned_connection.close()
    return delivered


def fail_attempt(
    investigation_id: str,
    attempt_id: str | None,
    reason: str,
    *,
    transient: bool,
) -> None:
    db = SessionLocal()
    try:
        investigation = db.get(Investigation, investigation_id)
        if investigation is None:
            return
        if investigation.mode != get_settings().app_mode:
            return
        if attempt_id:
            attempt = db.get(InvestigationAttempt, attempt_id)
        else:
            attempt = (db.query(InvestigationAttempt)
                       .filter_by(investigation_id=investigation_id)
                       .order_by(InvestigationAttempt.attempt_number.desc()).first())
        if attempt is None or attempt.investigation_id != investigation.id or attempt.status not in {"queued", "running"}:
            return
        now = now_utc()
        attempt.status = "failed"
        attempt.progress = 100
        attempt.error_summary = reason
        attempt.finished_at = now
        attempt.heartbeat_at = now
        attempt.lease_token = new_id()
        if transient and _queue_automatic_retry(db, investigation, attempt, now=now):
            db.add(AuditEvent(actor_id=None, action="investigation.retry_scheduled", entity_type="investigation",
                              entity_id=investigation.id, details_json={"attempt_id": attempt.id, "reason": "worker_failure"}))
        else:
            _sync_parent_to_attempt(investigation, attempt)
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("could not persist failed investigation attempt")
    finally:
        db.close()


def reconcile_stale_investigations(db: Session, *, now: datetime | None = None,
                                   stale_after_seconds: int | None = None) -> dict[str, int]:
    """Redeliver lost queued work and fence workers whose running lease expired."""
    now = now or now_utc()
    stale_after_seconds = stale_after_seconds if stale_after_seconds is not None else STALE_AFTER_SECONDS
    cutoff = now - timedelta(seconds=max(0, stale_after_seconds))
    queued_recovered = 0
    running_recovered = 0

    queued = (db.query(InvestigationAttempt)
              .join(Investigation, Investigation.id == InvestigationAttempt.investigation_id)
              .filter(Investigation.mode == get_settings().app_mode,
                      InvestigationAttempt.status == "queued", InvestigationAttempt.created_at <= cutoff).all())
    for attempt in queued:
        outbox = db.query(InvestigationOutbox).filter_by(attempt_id=attempt.id).one_or_none()
        if outbox is None:
            db.add(InvestigationOutbox(attempt_id=attempt.id, status="pending", available_at=now,
                                       created_at=now, updated_at=now))
            queued_recovered += 1
        elif outbox.status == "dispatched" and _as_utc(outbox.dispatched_at) is not None and _as_utc(outbox.dispatched_at) <= cutoff:
            outbox.status = "pending"
            outbox.available_at = now
            outbox.dispatched_at = None
            outbox.updated_at = now
            queued_recovered += 1

    running = (db.query(InvestigationAttempt)
               .join(Investigation, Investigation.id == InvestigationAttempt.investigation_id)
               .filter(Investigation.mode == get_settings().app_mode,
                       InvestigationAttempt.status == "running")
               .with_for_update(skip_locked=True).all())
    for attempt in running:
        heartbeat = _as_utc(attempt.heartbeat_at or attempt.started_at or attempt.created_at)
        if heartbeat is None or heartbeat > cutoff:
            continue
        investigation = db.get(Investigation, attempt.investigation_id)
        if investigation is None:
            attempt.status = "failed"
            attempt.error_summary = "Investigation was removed while its worker was running."
            attempt.finished_at = now
            attempt.lease_token = new_id()
            running_recovered += 1
            continue
        reason = "The worker stopped responding; this attempt was fenced and recovered."
        for collector_run in db.query(CollectorRun).filter_by(attempt_id=attempt.id, status="running").all():
            collector_run.status = "failed"
            collector_run.error_explanation = reason
            collector_run.finished_at = now
        attempt.status = "failed"
        attempt.error_summary = reason
        attempt.progress = 100
        attempt.finished_at = now
        attempt.heartbeat_at = now
        attempt.lease_token = new_id()
        if _queue_automatic_retry(db, investigation, attempt, retry_kind="recovery", now=now):
            db.add(AuditEvent(actor_id=None, action="investigation.recovered", entity_type="investigation",
                              entity_id=investigation.id, details_json={"attempt_id": attempt.id}))
        else:
            _sync_parent_to_attempt(investigation, attempt)
        running_recovered += 1

    db.commit()
    return {"queued": queued_recovered, "running": running_recovered}


def publish_worker_heartbeat(redis_client, worker_id: str) -> None:
    redis_client.set(WORKER_HEARTBEAT_KEY, worker_id, ex=WORKER_HEARTBEAT_TTL_SECONDS)


def worker_is_ready(redis_client) -> bool:
    if not redis_client.exists(WORKER_HEARTBEAT_KEY):
        return False
    try:
        return int(redis_client.ttl(WORKER_HEARTBEAT_KEY)) > 0
    except (AttributeError, TypeError, ValueError):
        # Lightweight test doubles and older Redis clients may not expose TTL;
        # existence is the safest compatibility fallback for those callers.
        return True


def worker_heartbeat_loop(redis_client, worker_id: str, stop_event, interval_seconds: int = 10) -> None:
    while not stop_event.is_set():
        try:
            publish_worker_heartbeat(redis_client, worker_id)
        except Exception:
            logger.exception("worker heartbeat update failed")
        stop_event.wait(interval_seconds)

