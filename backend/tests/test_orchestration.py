from datetime import timedelta, timezone

from rq.exceptions import DuplicateJobError

from app import jobs
from app.collectors.types import CollectorResult
from app.config import get_settings
from app.models import (
    Asset,
    AuditEvent,
    CollectorRun,
    EvidenceSnapshot,
    Finding,
    Investigation,
    InvestigationAttempt,
    InvestigationOutbox,
    User,
    new_id,
    now_utc,
)
from app.orchestration import (
    WORKER_HEARTBEAT_KEY,
    create_attempt,
    dispatch_pending_outbox,
    publish_worker_heartbeat,
    reconcile_stale_investigations,
    worker_is_ready,
)

from conftest import csrf, login


def _use_live_test_settings(monkeypatch):
    monkeypatch.setenv("APP_MODE", "live")
    monkeypatch.setenv("COOKIE_SECURE", "true")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://test-user:test-password@localhost/cyberlens")
    monkeypatch.setenv("REDIS_PASSWORD", "test-redis-password")
    monkeypatch.setenv("REDIS_URL", "redis://:test-redis-password@localhost:6379/0")
    get_settings.cache_clear()


class FakeQueue:
    def __init__(self, *, duplicate=False, fail=False):
        self.jobs = []
        self.duplicate = duplicate
        self.fail = fail

    def enqueue(self, *args, **kwargs):
        self.jobs.append((args, kwargs))
        if self.duplicate:
            raise DuplicateJobError()
        if self.fail:
            raise ConnectionError("queue unavailable")


class FakeHeartbeatRedis:
    def __init__(self):
        self.values = {}
        self.expiries = {}

    def set(self, key, value, ex):
        self.values[key] = value
        self.expiries[key] = ex

    def exists(self, key):
        return int(key in self.values)


def _add_investigation(factory, *, mode=None, status="queued"):
    mode = mode or get_settings().app_mode
    db = factory()
    user = db.query(User).filter_by(username="admin").one()
    asset = Asset(kind="application", identifier=f"Orchestration {new_id()}",
                  normalized_identifier=f"orchestration-{new_id()}", created_by=user.id)
    db.add(asset)
    db.flush()
    investigation = Investigation(asset_id=asset.id, requested_by=user.id, mode=mode, status=status)
    db.add(investigation)
    db.flush()
    attempt = create_attempt(db, investigation, "initial")
    db.commit()
    result = (investigation.id, attempt.id, asset.id)
    db.close()
    return result


def _result(status="success", evidence=None):
    return CollectorResult(
        status=status,
        source="test collector",
        evidence=evidence or {"observed": True},
        findings=[{
            "category": "test", "severity": "low", "title": "Stable finding",
            "explanation": "Test result.", "recommendation": "Review it.",
            "source": "test collector", "details": {"stable_key": "one"},
        }],
    )


def test_api_commit_leaves_durable_outbox_for_dispatcher(workspace):
    client, factory = workspace
    login(client)
    asset = client.post("/api/v1/assets", headers=csrf(client),
                        json={"kind": "application", "identifier": "Outbox crash test"}).json()

    response = client.post("/api/v1/investigations", headers=csrf(client), json={"asset_id": asset["id"]})

    assert response.status_code == 202
    payload = response.json()
    db = factory()
    attempt = db.get(InvestigationAttempt, payload["attempt_id"])
    outbox = db.query(InvestigationOutbox).filter_by(attempt_id=payload["attempt_id"]).one()
    assert attempt.investigation_id == payload["id"]
    assert attempt.status == "queued"
    assert outbox.status == "pending"
    db.close()

    queue = FakeQueue()
    db = factory()
    assert dispatch_pending_outbox(db, queue=queue) == 1
    db.close()
    assert queue.jobs[0][0][0] == "app.jobs.run_investigation_attempt"
    assert queue.jobs[0][1]["job_id"] == f"investigation-attempt-{payload['attempt_id']}"


def test_failed_outbox_delivery_stays_pending_with_backoff(workspace):
    _client, factory = workspace
    _investigation_id, attempt_id, _asset_id = _add_investigation(factory)
    queue = FakeQueue(fail=True)
    db = factory()

    assert dispatch_pending_outbox(db, queue=queue) == 0

    outbox = db.query(InvestigationOutbox).filter_by(attempt_id=attempt_id).one()
    assert outbox.status == "pending"
    assert outbox.dispatch_attempts == 1
    assert outbox.last_error == "ConnectionError"
    available_at = outbox.available_at.replace(tzinfo=timezone.utc) if outbox.available_at.tzinfo is None else outbox.available_at
    assert available_at >= now_utc() + timedelta(milliseconds=500)
    db.close()


def test_duplicate_outbox_delivery_and_rq_execution_are_idempotent(workspace, monkeypatch):
    client, factory = workspace
    login(client)
    asset = client.post("/api/v1/assets", headers=csrf(client),
                        json={"kind": "application", "identifier": "Duplicate delivery test"}).json()
    started = client.post("/api/v1/investigations", headers=csrf(client), json={"asset_id": asset["id"]}).json()
    attempt_id = started["attempt_id"]

    # Simulate a dispatcher crash after Redis accepted the message but before
    # the database commit that records delivery.
    db = factory()
    duplicate_queue = FakeQueue(duplicate=True)
    assert dispatch_pending_outbox(db, queue=duplicate_queue) == 1
    assert db.query(InvestigationOutbox).filter_by(attempt_id=attempt_id).one().status == "dispatched"
    db.close()

    collector_calls = []
    monkeypatch.setattr(jobs, "SessionLocal", factory)
    monkeypatch.setattr(jobs, "_run_collector", lambda name, *_args, **_kwargs: (collector_calls.append(name) or _result()))
    jobs.run_investigation_attempt(started["id"], attempt_id)
    jobs.run_investigation_attempt(started["id"], attempt_id)

    expected_collectors = ["nvd_kev", "osv"]
    assert collector_calls == expected_collectors
    db = factory()
    assert {run.collector for run in db.query(CollectorRun).filter_by(attempt_id=attempt_id)} == set(expected_collectors)
    assert db.query(CollectorRun).filter_by(attempt_id=attempt_id).count() == len(expected_collectors)
    assert db.query(EvidenceSnapshot).filter_by(investigation_id=started["id"]).count() == len(expected_collectors)
    assert db.query(Finding).filter_by(investigation_id=started["id"]).count() == 1
    db.close()


def test_manual_retry_has_distinct_attempt_and_collector_history(workspace, monkeypatch):
    client, factory = workspace
    login(client)
    asset = client.post("/api/v1/assets", headers=csrf(client),
                        json={"kind": "application", "identifier": "Retry history test"}).json()
    started = client.post("/api/v1/investigations", headers=csrf(client), json={"asset_id": asset["id"]}).json()
    monkeypatch.setattr(jobs, "SessionLocal", factory)
    monkeypatch.setattr(jobs, "_run_collector", lambda *_args, **_kwargs: _result())
    jobs.run_investigation_attempt(started["id"], started["attempt_id"])

    retried = client.post(f"/api/v1/investigations/{started['id']}/retry", headers=csrf(client))
    assert retried.status_code == 202
    second_attempt_id = retried.json()["attempt_id"]
    assert second_attempt_id != started["attempt_id"]
    jobs.run_investigation_attempt(started["id"], second_attempt_id)

    detail = client.get(f"/api/v1/investigations/{started['id']}").json()
    assert [item["attempt_number"] for item in detail["attempts"]] == [1, 2]
    assert {item["attempt_id"] for item in detail["collector_runs"]} == {started["attempt_id"], second_attempt_id}
    assert {(run["attempt_number"], run["collector"]) for run in detail["collector_runs"]} == {
        (1, "nvd_kev"), (1, "osv"), (2, "nvd_kev"), (2, "osv"),
    }
    assert len(detail["collector_runs"]) == 4
    assert len(detail["findings"]) == 1
    assert len(detail["evidence"]) == 4


def test_worker_restart_refreshes_independent_heartbeat():
    redis = FakeHeartbeatRedis()
    publish_worker_heartbeat(redis, "worker-before-restart")
    assert worker_is_ready(redis)
    assert redis.expiries[WORKER_HEARTBEAT_KEY] > 0

    publish_worker_heartbeat(redis, "worker-after-restart")

    assert worker_is_ready(redis)
    assert redis.values[WORKER_HEARTBEAT_KEY] == "worker-after-restart"


def test_transient_failure_schedules_bounded_backoff_attempt(workspace, monkeypatch):
    _use_live_test_settings(monkeypatch)
    _client, factory = workspace
    investigation_id, first_id, _asset_id = _add_investigation(factory)
    monkeypatch.setattr(jobs, "SessionLocal", factory)
    monkeypatch.setattr(jobs, "_run_collector", lambda *_args, **_kwargs: _result("unavailable", {"http_status": 429}))

    jobs.run_investigation_attempt(investigation_id, first_id)

    db = factory()
    attempts = db.query(InvestigationAttempt).filter_by(investigation_id=investigation_id).order_by(InvestigationAttempt.attempt_number).all()
    assert len(attempts) == 2
    assert attempts[0].status == "failed"
    assert attempts[1].retry_kind == "automatic"
    outbox = db.query(InvestigationOutbox).filter_by(attempt_id=attempts[1].id).one()
    available_at = outbox.available_at.replace(tzinfo=timezone.utc) if outbox.available_at.tzinfo is None else outbox.available_at
    assert available_at >= now_utc() + timedelta(seconds=4)
    second_attempt_id = attempts[1].id
    db.close()

    jobs.run_investigation_attempt(investigation_id, second_attempt_id)
    db = factory()
    attempts = db.query(InvestigationAttempt).filter_by(investigation_id=investigation_id).order_by(InvestigationAttempt.attempt_number).all()
    assert len(attempts) == 3
    third_outbox = db.query(InvestigationOutbox).filter_by(attempt_id=attempts[2].id).one()
    second_backoff = third_outbox.available_at.replace(tzinfo=timezone.utc) if third_outbox.available_at.tzinfo is None else third_outbox.available_at
    assert second_backoff >= now_utc() + timedelta(seconds=9)
    third_attempt_id = attempts[2].id
    db.close()

    jobs.run_investigation_attempt(investigation_id, third_attempt_id)
    db = factory()
    assert db.query(InvestigationAttempt).filter_by(investigation_id=investigation_id).count() == 3
    assert db.get(Investigation, investigation_id).status == "failed"
    db.close()


def test_permanent_failure_does_not_schedule_retry(workspace, monkeypatch):
    _client, factory = workspace
    investigation_id, attempt_id, _asset_id = _add_investigation(factory)
    monkeypatch.setattr(jobs, "SessionLocal", factory)
    monkeypatch.setattr(jobs, "_run_collector", lambda *_args, **_kwargs: _result("unavailable", {"http_status": 403}))

    jobs.run_investigation_attempt(investigation_id, attempt_id)

    db = factory()
    assert db.query(InvestigationAttempt).filter_by(investigation_id=investigation_id).count() == 1
    assert db.get(Investigation, investigation_id).status == "failed"
    db.close()


def test_stale_queued_attempt_is_redelivered(workspace):
    _client, factory = workspace
    investigation_id, attempt_id, _asset_id = _add_investigation(factory)
    old = now_utc() + timedelta(minutes=5)
    db = factory()
    outbox = db.query(InvestigationOutbox).filter_by(attempt_id=attempt_id).one()
    outbox.status = "dispatched"
    outbox.dispatched_at = now_utc() - timedelta(minutes=10)
    db.commit()

    recovered = reconcile_stale_investigations(db, now=old, stale_after_seconds=60)

    assert recovered["queued"] == 1
    assert db.query(InvestigationOutbox).filter_by(attempt_id=attempt_id).one().status == "pending"
    db.close()


def test_stale_running_attempt_is_fenced_and_retried(workspace):
    _client, factory = workspace
    investigation_id, attempt_id, _asset_id = _add_investigation(factory)
    db = factory()
    attempt = db.get(InvestigationAttempt, attempt_id)
    attempt.status = "running"
    attempt.started_at = now_utc() - timedelta(hours=1)
    attempt.heartbeat_at = now_utc() - timedelta(hours=1)
    attempt.lease_token = "old-lease"
    investigation = db.get(Investigation, investigation_id)
    investigation.status = "running"
    db.add(CollectorRun(investigation_id=investigation_id, attempt_id=attempt_id, collector="nvd_kev",
                        status="running", source="test"))
    db.commit()

    recovered = reconcile_stale_investigations(db, now=now_utc(), stale_after_seconds=60)

    assert recovered["running"] == 1
    assert attempt.status == "failed"
    assert attempt.lease_token != "old-lease"
    assert db.query(CollectorRun).filter_by(attempt_id=attempt_id).one().status == "failed"
    assert db.get(Investigation, investigation_id).status == "queued"
    new_attempt = db.query(InvestigationAttempt).filter_by(investigation_id=investigation_id).order_by(InvestigationAttempt.attempt_number.desc()).first()
    assert new_attempt.retry_kind == "recovery"
    assert db.query(AuditEvent).filter_by(action="investigation.recovered", entity_id=investigation_id).count() == 1
    db.close()
