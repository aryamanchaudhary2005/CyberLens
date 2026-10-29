"""Small dependency-free operational metrics snapshot.

The counters are intentionally process-local; queue, worker, provider, and job
values are read from shared Redis/PostgreSQL so an operator can distinguish
local request traffic from shared work state without adding a metrics service.
"""

from collections import Counter
from datetime import datetime, timezone
from threading import Lock

from redis import Redis
from rq import Queue
from sqlalchemy.orm import Session

from app.models import CollectorRun, InvestigationAttempt
from app.orchestration import WORKER_HEARTBEAT_KEY, worker_is_ready

_lock = Lock()
_request_count = 0
_request_errors = 0
_request_duration_ms = 0.0


def record_request(duration_ms: float, status_code: int) -> None:
    global _request_count, _request_errors, _request_duration_ms
    with _lock:
        _request_count += 1
        _request_duration_ms += duration_ms
        if status_code >= 500:
            _request_errors += 1


def request_snapshot() -> dict[str, int | float]:
    with _lock:
        return {
            "count": _request_count,
            "errors": _request_errors,
            "duration_ms_total": round(_request_duration_ms, 3),
        }


def snapshot(db: Session, redis: Redis) -> dict:
    queue_depth = None
    worker_ready = False
    heartbeat_ttl = None
    try:
        queue_depth = int(Queue("investigations", connection=redis).count)
        worker_ready = worker_is_ready(redis)
        heartbeat_ttl = int(redis.ttl(WORKER_HEARTBEAT_KEY))
    except Exception:
        # Metrics must not turn an otherwise healthy API into a failing request.
        pass

    durations = []
    attempts = (db.query(InvestigationAttempt)
                .filter(InvestigationAttempt.finished_at.is_not(None))
                .order_by(InvestigationAttempt.finished_at.desc()).limit(100).all())
    for attempt in attempts:
        if attempt.started_at and attempt.finished_at:
            durations.append(max(0.0, (attempt.finished_at - attempt.started_at).total_seconds() * 1000))

    provider_status: dict[str, dict[str, int]] = {}
    runs = (db.query(CollectorRun)
            .filter(CollectorRun.finished_at.is_not(None))
            .order_by(CollectorRun.finished_at.desc()).limit(200).all())
    for run in runs:
        bucket = provider_status.setdefault(run.source or run.collector, Counter())
        bucket[run.status] += 1
    return {
        "generated_at": datetime.now(timezone.utc),
        "requests": request_snapshot(),
        "queue_depth": queue_depth,
        "job_duration_ms": round(sum(durations) / len(durations), 3) if durations else None,
        "worker_ready": worker_ready,
        "worker_heartbeat_ttl_seconds": heartbeat_ttl,
        "provider_status": {name: dict(values) for name, values in provider_status.items()},
    }
