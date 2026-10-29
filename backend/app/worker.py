"""RQ worker entry point with an independent Redis heartbeat."""

import logging
import threading
import uuid

from redis import Redis
from rq import Queue, Worker

from app.config import get_settings
from app.logging_config import configure_logging
from app.orchestration import fail_attempt, worker_heartbeat_loop


def _mark_failed(job, reason: str, *, transient: bool) -> None:
    if getattr(job, "func_name", "") in {"app.jobs.refresh_spamhaus_drop", "app.jobs.refresh_threat_feed"}:
        try:
            from app.services.threat_feeds import mark_refresh_failed

            mark_refresh_failed(job.args[0], "worker_terminated")
        except Exception:
            logging.getLogger("cyberlens.worker").exception("could not record failed threat-feed refresh")
        return
    if getattr(job, "func_name", "") == "app.jobs.sync_attack_catalog":
        try:
            from app.services.attack_catalog_sync import mark_catalog_sync_failed

            mark_catalog_sync_failed(job.args[0], reason)
        except Exception:
            logging.getLogger("cyberlens.worker").exception("could not record failed ATT&CK catalog job")
        return
    try:
        investigation_id = job.args[0]
        attempt_id = job.args[1] if len(job.args) > 1 else None
    except Exception:
        return
    fail_attempt(investigation_id, attempt_id, reason, transient=transient)


def handle_job_failure(job, exc_type, exc_value, traceback):
    _mark_failed(job, "The background job raised an unexpected error. Review worker logs and retry.", transient=False)
    return True


def handle_workhorse_killed(job, ret_pid, ret_val, usage):
    _mark_failed(job, "The worker process stopped before the job completed; recovery was scheduled.", transient=True)


def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    logger = logging.getLogger("cyberlens.worker")
    connection = Redis.from_url(settings.redis_url)
    stop_event = threading.Event()
    worker_id = str(uuid.uuid4())
    heartbeat = threading.Thread(
        target=worker_heartbeat_loop, args=(connection, worker_id, stop_event),
        name="cyberlens-worker-heartbeat", daemon=True,
    )
    heartbeat.start()
    queues = [Queue("investigations", connection=connection), Queue("attack-catalog", connection=connection),
              Queue("threat-feeds", connection=connection)]
    logger.info("CyberLens worker started; waiting for investigation and catalog jobs")
    try:
        Worker(queues, connection=connection, exception_handlers=[handle_job_failure],
               work_horse_killed_handler=handle_workhorse_killed).work()
    finally:
        stop_event.set()
        heartbeat.join(timeout=2)
        connection.close()


if __name__ == "__main__":
    main()
