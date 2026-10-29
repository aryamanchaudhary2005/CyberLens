from datetime import timedelta

import pytest
from fastapi import HTTPException, Response
from fastapi.routing import APIRoute
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import jobs
from app.config import get_settings
from app.database import Base
from app.dependencies import require_csrf, require_roles
from app.models import (
    Asset,
    AuditEvent,
    CollectorRun,
    EvidenceSnapshot,
    Investigation,
    InvestigationAttempt,
    InvestigationOutbox,
    MonitoringRun,
    MonitoringSchedule,
    User,
    WebsiteAuthorization,
    new_id,
    now_utc,
)
from app.monitoring import enqueue_due_schedules, sync_monitoring_runs
from app.orchestration import dispatch_pending_outbox
from app.pagination import Page
from app.routes import monitoring as monitoring_routes
from app.schemas import MonitoringScheduleCreate, MonitoringScheduleResume


class _RecordingQueue:
    def __init__(self):
        self.jobs = []

    def enqueue(self, *args, **kwargs):
        self.jobs.append((args, kwargs))
from app.graph import ensure_relationships


@pytest.fixture
def monitoring_workspace(monkeypatch):
    monkeypatch.setenv("APP_MODE", "demo")
    get_settings.cache_clear()
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    with factory() as db:
        admin = User(username="monitor-admin", password_hash="unused", role="admin", must_change_password=False)
        viewer = User(username="monitor-viewer", password_hash="unused", role="viewer", must_change_password=False)
        db.add_all([admin, viewer])
        db.commit()
        ids = (admin.id, viewer.id)
    yield factory, ids
    Base.metadata.drop_all(engine)
    engine.dispose()
    get_settings.cache_clear()


def _authorized_website(db, owner, *, kind="domain"):
    suffix = new_id()[:8]
    asset = Asset(kind=kind, identifier=f"monitor-{suffix}.example.test", normalized_identifier=f"monitor-{suffix}.example.test",
                  created_by=owner.id)
    db.add(asset)
    db.flush()
    authorization = WebsiteAuthorization(asset_id=asset.id, authorized_by=owner.id, note="Written monitoring permission",
                                         expires_at=now_utc() + timedelta(days=30))
    db.add(authorization)
    db.commit()
    return asset, authorization


def _create_schedule(db, owner, asset, authorization, cadence="daily"):
    return monitoring_routes.create_schedule(
        MonitoringScheduleCreate(asset_id=asset.id, authorization_id=authorization.id, cadence=cadence),
        owner, db,
    )


def test_schedule_requires_active_explicit_website_authorization(monitoring_workspace):
    factory, (admin_id, _viewer_id) = monitoring_workspace
    with factory() as db:
        admin = db.get(User, admin_id)
        asset = Asset(kind="domain", identifier="needs-authorization.example.test",
                      normalized_identifier="needs-authorization.example.test", created_by=admin.id)
        db.add(asset)
        db.commit()
        with pytest.raises(HTTPException) as no_auth:
            monitoring_routes.create_schedule(MonitoringScheduleCreate(asset_id=asset.id,
                authorization_id="missing", cadence="daily"), admin, db)
        assert no_auth.value.status_code == 422
        assert "active authorization" in no_auth.value.detail

        application = Asset(kind="application", identifier="application", normalized_identifier="application",
                            created_by=admin.id)
        db.add(application)
        db.commit()
        with pytest.raises(HTTPException) as wrong_kind:
            monitoring_routes.create_schedule(MonitoringScheduleCreate(asset_id=application.id,
                authorization_id="missing", cadence="weekly"), admin, db)
        assert wrong_kind.value.status_code == 422
        assert "website assets" in wrong_kind.value.detail


def test_daily_weekly_schedules_are_owned_and_mutations_are_role_protected(monitoring_workspace):
    factory, (admin_id, viewer_id) = monitoring_workspace
    with factory() as db:
        admin = db.get(User, admin_id)
        asset, authorization = _authorized_website(db, admin)
        daily = _create_schedule(db, admin, asset, authorization, "daily")
        weekly = _create_schedule(db, admin, asset, authorization, "weekly")
        assert daily["status"] == "active" and daily["owner_id"] == admin.id
        assert weekly["status"] == "active"
        assert daily["authorization_id"] == authorization.id
        assert timedelta(hours=23) < daily["next_run_at"] - daily["created_at"] < timedelta(hours=25)
        assert timedelta(days=6) < weekly["next_run_at"] - weekly["created_at"] < timedelta(days=8)
        assert any(row.action == "monitoring.schedule_created" for row in db.query(AuditEvent).all())

        viewer = db.get(User, viewer_id)
        with pytest.raises(HTTPException) as denied:
            require_roles("admin", "analyst")(viewer)
        assert denied.value.status_code == 403
        admin_gate = require_roles("admin", "analyst")
        assert admin_gate(admin) is admin
        page_response = Response()
        page_rows = monitoring_routes.list_schedules(asset_id=None, status=None, cadence=None, _user=admin,
                                                     db=db, response=page_response, page=Page(1, 1))
        assert len(page_rows) == 1
        assert page_response.headers["X-Total-Count"] == "2"
        assert page_response.headers["X-Has-Next"] == "true"


def test_due_slot_creates_one_outbox_backed_investigation_and_preserves_history(monitoring_workspace):
    factory, (admin_id, _viewer_id) = monitoring_workspace
    with factory() as db:
        admin = db.get(User, admin_id)
        asset, authorization = _authorized_website(db, admin)
        schedule = _create_schedule(db, admin, asset, authorization)
        now = now_utc()
        row = db.get(MonitoringSchedule, schedule["id"])
        row.next_run_at = now - timedelta(hours=1)
        db.commit()
        assert enqueue_due_schedules(db, now=now) == 1
        first = db.query(MonitoringRun).filter_by(schedule_id=row.id).one()
        first_investigation = db.get(Investigation, first.investigation_id)
        attempt = db.query(InvestigationAttempt).filter_by(investigation_id=first.investigation_id).one()
        outbox = db.query(InvestigationOutbox).filter_by(attempt_id=attempt.id).one()
        assert first.status == "queued"
        assert outbox.status == "pending"
        assert first_investigation.mode == "demo"
        assert first_investigation.scenario == "routine_website"
        assert enqueue_due_schedules(db, now=now) == 0
        assert db.query(MonitoringRun).filter_by(schedule_id=row.id).count() == 1
        queue = _RecordingQueue()
        assert dispatch_pending_outbox(db, queue=queue, now=now + timedelta(seconds=1)) == 1
        assert queue.jobs[0][0] == ("app.jobs.run_investigation_attempt", first.investigation_id, attempt.id)
        assert queue.jobs[0][1]["job_id"] == f"investigation-attempt-{attempt.id}"
        assert dispatch_pending_outbox(db, queue=queue, now=now + timedelta(seconds=2)) == 0
        assert len(queue.jobs) == 1

        first_investigation.status = "completed"
        first_investigation.progress = 100
        first_investigation.finished_at = now
        db.commit()
        assert sync_monitoring_runs(db) == 1
        row.next_run_at = now - timedelta(minutes=1)
        db.commit()
        assert enqueue_due_schedules(db, now=now) == 1
        history = db.query(MonitoringRun).filter_by(schedule_id=row.id).order_by(MonitoringRun.scheduled_for).all()
        assert len(history) == 2
        assert history[0].investigation_id != history[1].investigation_id
        assert history[1].previous_investigation_id == first.investigation_id
        api_history = monitoring_routes.schedule_history(row.id, admin, db, page=Page())
        assert len(api_history) == 2
        assert api_history[0]["previous_investigation_id"] == first.investigation_id


def test_revoked_authorization_fails_schedule_before_run_and_resume_requires_authority(monitoring_workspace):
    factory, (admin_id, _viewer_id) = monitoring_workspace
    with factory() as db:
        admin = db.get(User, admin_id)
        asset, authorization = _authorized_website(db, admin)
        schedule = _create_schedule(db, admin, asset, authorization)
        authorization.revoked_at = now_utc()
        row = db.get(MonitoringSchedule, schedule["id"])
        row.next_run_at = now_utc() - timedelta(seconds=1)
        db.commit()
        assert enqueue_due_schedules(db, now=now_utc()) == 0
        db.refresh(row)
        assert row.status == "failed"
        assert row.failure_code == "authorization_inactive"
        assert row.next_run_at is None
        assert db.query(MonitoringRun).filter_by(schedule_id=row.id).count() == 0
        with pytest.raises(HTTPException) as denied:
            monitoring_routes.resume_schedule(row.id, MonitoringScheduleResume(), admin, db)
        assert denied.value.status_code == 409
        renewed = WebsiteAuthorization(asset_id=asset.id, authorized_by=admin.id, note="Renewed monitoring permission",
                                       expires_at=now_utc() + timedelta(days=30))
        db.add(renewed)
        db.commit()
        resumed = monitoring_routes.resume_schedule(row.id, MonitoringScheduleResume(authorization_id=renewed.id), admin, db)
        assert resumed["status"] == "active"
        assert resumed["authorization_id"] == renewed.id


def test_expired_authorization_fails_a_due_schedule(monitoring_workspace):
    factory, (admin_id, _viewer_id) = monitoring_workspace
    with factory() as db:
        admin = db.get(User, admin_id)
        asset, authorization = _authorized_website(db, admin)
        schedule = _create_schedule(db, admin, asset, authorization)
        authorization.expires_at = now_utc() - timedelta(seconds=1)
        row = db.get(MonitoringSchedule, schedule["id"])
        row.next_run_at = now_utc() - timedelta(seconds=1)
        db.commit()
        assert enqueue_due_schedules(db, now=now_utc()) == 0
        db.refresh(row)
        assert row.status == "failed"
        assert row.failure_code == "authorization_inactive"
        assert db.query(MonitoringRun).filter_by(schedule_id=row.id).count() == 0


def test_pause_resume_cancel_only_control_future_runs(monitoring_workspace):
    factory, (admin_id, _viewer_id) = monitoring_workspace
    with factory() as db:
        admin = db.get(User, admin_id)
        asset, authorization = _authorized_website(db, admin)
        schedule = _create_schedule(db, admin, asset, authorization, "weekly")
        row = db.get(MonitoringSchedule, schedule["id"])
        paused = monitoring_routes.pause_schedule(row.id, admin, db)
        assert paused["status"] == "paused"
        row.next_run_at = now_utc() - timedelta(days=10)
        db.commit()
        assert enqueue_due_schedules(db, now=now_utc()) == 0
        assert db.query(MonitoringRun).filter_by(schedule_id=row.id).count() == 0

        resumed = monitoring_routes.resume_schedule(row.id, MonitoringScheduleResume(), admin, db)
        assert resumed["status"] == "active"
        assert resumed["next_run_at"] > now_utc() + timedelta(days=6)
        cancelled = monitoring_routes.cancel_schedule(row.id, admin, db)
        assert cancelled["status"] == "completed" and cancelled["next_run_at"] is None
        with pytest.raises(HTTPException) as terminal:
            monitoring_routes.resume_schedule(row.id, MonitoringScheduleResume(), admin, db)
        assert terminal.value.status_code == 409


def test_worker_rechecks_the_exact_authorization_before_collecting(monitoring_workspace, monkeypatch):
    factory, (admin_id, _viewer_id) = monitoring_workspace
    with factory() as db:
        admin = db.get(User, admin_id)
        asset, authorization = _authorized_website(db, admin)
        schedule = _create_schedule(db, admin, asset, authorization)
        schedule_row = db.get(MonitoringSchedule, schedule["id"])
        schedule_row.next_run_at = now_utc() - timedelta(seconds=1)
        db.commit()
        assert enqueue_due_schedules(db, now=now_utc()) == 1
        run = db.query(MonitoringRun).filter_by(schedule_id=schedule_row.id).one()
        attempt = db.query(InvestigationAttempt).filter_by(investigation_id=run.investigation_id).one()
        run_id, investigation_id, attempt_id, schedule_id = run.id, run.investigation_id, attempt.id, schedule_row.id
        authorization.revoked_at = now_utc()
        db.commit()

    monkeypatch.setattr(jobs, "SessionLocal", factory)
    monkeypatch.setattr(jobs, "_collectors", lambda _asset: ["web_tls"])
    monkeypatch.setattr(jobs, "collect_website", lambda _asset: (_ for _ in ()).throw(AssertionError("check should not run")))
    jobs.run_investigation_attempt(investigation_id, attempt_id)
    with factory() as db:
        run = db.get(MonitoringRun, run_id)
        attempt = db.get(InvestigationAttempt, attempt_id)
        schedule_row = db.get(MonitoringSchedule, schedule_id)
        assert run.status == "failed"
        assert attempt.status == "failed"
        assert schedule_row.failure_code == "authorization_inactive"
        assert db.query(AuditEvent).filter_by(action="monitoring.run_blocked").count() == 1
        assert db.query(InvestigationOutbox).filter_by(attempt_id=attempt.id).one().status == "pending"


def test_monitoring_routes_register_read_and_write_endpoints():
    routes = [route for route in monitoring_routes.router.routes if isinstance(route, APIRoute)]
    paths = {(route.path, method) for route in routes for method in route.methods}
    assert ("/monitoring", "POST") in paths
    assert ("/monitoring", "GET") in paths
    assert ("/monitoring/{schedule_id}/history", "GET") in paths
    assert ("/monitoring/{schedule_id}/runs/{run_id}/changes", "GET") in paths
    assert ("/monitoring/{schedule_id}/pause", "POST") in paths
    assert ("/monitoring/{schedule_id}/resume", "POST") in paths
    assert ("/monitoring/{schedule_id}/cancel", "POST") in paths
    assert all(route.response_model is not None for route in routes)
    write_routes = [route for route in routes if "POST" in route.methods]
    for route in write_routes:
        guard = route.dependant.dependencies[0]
        assert guard.call.__name__ == "dependency"
        assert any(item.call is require_csrf for item in guard.dependencies)


def test_monitoring_change_radar_keeps_failed_provider_coverage_unknown(monitoring_workspace):
    factory, (admin_id, _viewer_id) = monitoring_workspace
    with factory() as db:
        admin = db.get(User, admin_id)
        asset, authorization = _authorized_website(db, admin)
        schedule = _create_schedule(db, admin, asset, authorization)
        observed_at = now_utc()
        previous = Investigation(asset_id=asset.id, requested_by=admin.id, mode="live", status="completed",
                                 progress=100, created_at=observed_at, started_at=observed_at, finished_at=observed_at)
        current = Investigation(asset_id=asset.id, requested_by=admin.id, mode="live", status="partial",
                                progress=100, created_at=observed_at + timedelta(minutes=1),
                                started_at=observed_at + timedelta(minutes=1), finished_at=observed_at + timedelta(minutes=2))
        db.add_all([previous, current])
        db.flush()
        previous_attempt = InvestigationAttempt(investigation_id=previous.id, attempt_number=1, retry_kind="initial",
            status="completed", progress=100, created_at=observed_at, started_at=observed_at, finished_at=observed_at)
        current_attempt = InvestigationAttempt(investigation_id=current.id, attempt_number=1, retry_kind="initial",
            status="partial", progress=100, created_at=current.created_at, started_at=current.started_at, finished_at=current.finished_at)
        db.add_all([previous_attempt, current_attempt])
        db.flush()
        prior_collector = CollectorRun(investigation_id=previous.id, attempt_id=previous_attempt.id,
            collector="dns_rdap", status="success", source="DNS fixture", record_count=1,
            started_at=observed_at, finished_at=observed_at)
        failed_collector = CollectorRun(investigation_id=current.id, attempt_id=current_attempt.id,
            collector="dns_rdap", status="unavailable", source="DNS fixture", record_count=0,
            started_at=current.started_at, finished_at=current.finished_at)
        db.add_all([prior_collector, failed_collector])
        db.flush()
        db.add(EvidenceSnapshot(investigation_id=previous.id, collector_run_id=prior_collector.id,
            source="DNS fixture", observed_at=observed_at,
            evidence_json={"submitted_host": asset.identifier, "records": {"A": {"status": "success", "values": ["192.0.2.44"]}}},
            sha256="a" * 64, is_synthetic=False))
        db.add(EvidenceSnapshot(investigation_id=current.id, collector_run_id=failed_collector.id,
            source="DNS fixture", observed_at=current.finished_at,
            evidence_json={"submitted_host": asset.identifier, "records": {"A": {"status": "failed", "values": [], "error": "ProviderUnavailable"}}},
            sha256="b" * 64, is_synthetic=False))
        db.flush()
        ensure_relationships(db, previous)
        schedule_row = db.get(MonitoringSchedule, schedule["id"])
        run = MonitoringRun(schedule_id=schedule_row.id, investigation_id=current.id,
            previous_investigation_id=previous.id, scheduled_for=current.created_at, status="partial", created_at=current.created_at)
        db.add(run)
        db.commit()

        changes = monitoring_routes.schedule_run_changes(schedule_row.id, run.id, admin, db)
        statuses = {change["status"] for change in changes["changes"]}
        assert "unknown" in statuses
        assert "no_longer_observed" not in statuses
