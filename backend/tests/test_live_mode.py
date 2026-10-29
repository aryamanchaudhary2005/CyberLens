"""Live projections leave historical Demo records stored and out of workspace views."""

import hashlib
from datetime import timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import get_settings
from app.database import Base
from app.models import (Asset, AuditEvent, Finding, Incident, Investigation, InvestigationAttempt,
                        InvestigationOutbox, MonitoringSchedule, Report, User, UserSession,
                        WebsiteAuthorization, now_utc)
from app.security import hash_password, token_digest
from app.services.posture import build_scorecard
from app.visibility import (visible_assets, visible_audit_events, visible_findings, visible_incidents,
                            visible_investigations, visible_monitoring_schedules, visible_reports)
from conftest import cookie_value, csrf, login


def _use_live_test_settings(monkeypatch) -> None:
    monkeypatch.setenv("APP_MODE", "live")
    monkeypatch.setenv("COOKIE_SECURE", "true")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://test-user:test-password@localhost/cyberlens")
    monkeypatch.setenv("REDIS_PASSWORD", "test-redis-password")
    monkeypatch.setenv("REDIS_URL", "redis://:test-redis-password@localhost:6379/0")
    get_settings.cache_clear()


@pytest.fixture
def live_scope_db(monkeypatch):
    _use_live_test_settings(monkeypatch)
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    with factory() as db:
        yield db
    Base.metadata.drop_all(engine)
    engine.dispose()


def test_live_collections_details_scorecard_and_reports_exclude_demo_rows(workspace, monkeypatch):
    client, factory = workspace
    login(client)
    db = factory()
    admin = db.query(User).filter_by(username="admin").one()
    now = now_utc()
    live_asset = Asset(kind="domain", identifier="live.example.invalid", normalized_identifier="live.example.invalid",
                       notes="", created_by=admin.id, is_synthetic=False, created_at=now, updated_at=now)
    demo_asset = Asset(kind="domain", identifier="sample.example.test", normalized_identifier="sample.example.test",
                       notes="synthetic fixture", created_by=admin.id, is_synthetic=True,
                       demo_scenario="routine_website", created_at=now, updated_at=now)
    db.add_all([live_asset, demo_asset])
    db.flush()
    live_investigation = Investigation(asset_id=live_asset.id, requested_by=admin.id, mode="live", status="completed",
                                       progress=100, created_at=now, finished_at=now)
    demo_investigation = Investigation(asset_id=demo_asset.id, requested_by=admin.id, mode="demo",
                                       scenario="routine_website", status="completed", progress=100,
                                       created_at=now, finished_at=now)
    db.add_all([live_investigation, demo_investigation])
    db.flush()
    live_finding = Finding(asset_id=live_asset.id, investigation_id=live_investigation.id, fingerprint="a" * 64,
        category="reputation", severity="low", title="Live saved observation", explanation="Real record",
        recommendation="Review", source="synthetic test fixture", observed_at=now, applicability="applies",
        is_synthetic=False, details_json={})
    demo_finding = Finding(asset_id=demo_asset.id, investigation_id=demo_investigation.id, fingerprint="b" * 64,
        category="reputation", severity="critical", title="Demo saved observation", explanation="Fixture",
        recommendation="Review", source="synthetic test fixture", observed_at=now, applicability="applies",
        is_synthetic=True, details_json={})
    db.add_all([live_finding, demo_finding])
    live_report_bytes = b"saved-live-report-v1"
    demo_report_bytes = b"saved-demo-report-v1"
    live_report = Report(investigation_id=live_investigation.id, format="json", created_by=admin.id,
        is_demo=False, snapshot_json={"marker": "live"}, content=live_report_bytes,
        sha256=hashlib.sha256(live_report_bytes).hexdigest())
    demo_report = Report(investigation_id=demo_investigation.id, format="json", created_by=admin.id,
        is_demo=True, snapshot_json={"marker": "demo"}, content=demo_report_bytes,
        sha256=hashlib.sha256(demo_report_bytes).hexdigest())
    db.add_all([live_report, demo_report])
    db.commit()
    ids = {"demo_asset": demo_asset.id, "live_asset": live_asset.id,
           "demo_investigation": demo_investigation.id, "live_investigation": live_investigation.id,
           "demo_finding": demo_finding.id, "live_finding": live_finding.id,
           "demo_report": demo_report.id, "live_report": live_report.id}
    preserved = {row.id: (row.snapshot_json, row.content, row.sha256)
                 for row in db.query(Report).order_by(Report.id).all()}
    db.close()

    _use_live_test_settings(monkeypatch)

    assets = client.get("/api/v1/assets").json()
    assert [row["id"] for row in assets] == [ids["live_asset"]]
    assert client.get(f"/api/v1/assets/{ids['demo_asset']}").status_code == 404

    investigations = client.get("/api/v1/investigations?mode=demo").json()
    assert investigations == []
    assert client.get(f"/api/v1/investigations/{ids['demo_investigation']}").status_code == 404
    findings = client.get("/api/v1/findings").json()
    assert [row["id"] for row in findings] == [ids["live_finding"]]
    assert client.get(f"/api/v1/findings/{ids['demo_finding']}").status_code == 404

    reports = client.get("/api/v1/reports").json()
    assert [row["id"] for row in reports] == [ids["live_report"]]
    assert client.get(f"/api/v1/reports/{ids['demo_report']}").status_code == 404
    assert client.get(f"/api/v1/reports/{ids['demo_report']}/download").status_code == 404

    scorecard = client.get("/api/v1/posture/scorecard").json()
    assert scorecard["data_scope"]["asset_count"] == 1
    assert scorecard["data_scope"]["data_modes"] == ["live"]
    assert scorecard["high_critical_findings"]["critical"] == 0

    db = factory()
    after = {row.id: (row.snapshot_json, row.content, row.sha256)
             for row in db.query(Report).order_by(Report.id).all()}
    assert after == preserved
    assert set(after) == {ids["live_report"], ids["demo_report"]}
    db.close()


def test_bootstrap_rotation_revokes_shared_demo_admin_sessions(workspace):
    from app.bootstrap import require_live_admin_rotation

    client, factory = workspace
    db = factory()
    admin = db.query(User).filter_by(username="admin").one()
    admin.password_hash = hash_password("CyberLens-Demo-Only-2026!")
    active = UserSession(user_id=admin.id, token_hash=token_digest("synthetic-pre-rotation-session"),
        csrf_token_hash=token_digest("synthetic-pre-rotation-csrf"), expires_at=now_utc() + timedelta(hours=1))
    db.add(active)
    db.commit()
    assert require_live_admin_rotation(db) == 1
    db.refresh(admin)
    db.refresh(active)
    assert admin.must_change_password is True
    assert active.revoked_at is not None
    assert db.query(UserSession).filter_by(user_id=admin.id, revoked_at=None).count() == 0
    assert db.query(AuditEvent).filter_by(
        action="user.shared_demo_password_rotation_required", entity_id=admin.id).count() == 1
    db.close()


def test_password_rotation_gate_allows_only_account_recovery_until_changed(workspace):
    client, factory = workspace
    db = factory()
    admin = db.query(User).filter_by(username="admin").one()
    admin.password_hash = hash_password("CyberLens-Demo-Only-2026!")
    admin.must_change_password = True
    db.commit()
    db.close()

    client.cookies.clear()
    login(client, "admin", "CyberLens-Demo-Only-2026!")
    assert client.get("/api/v1/auth/me").status_code == 200
    assert client.get("/api/v1/assets").status_code == 403
    old_token = cookie_value(client, "cyberlens_session")
    changed = client.post("/api/v1/auth/change-password", headers=csrf(client), json={
        "current_password": "CyberLens-Demo-Only-2026!",
        "new_password": "Rotated-Admin-Password-2026!",
    })
    assert changed.status_code == 200, changed.text
    assert changed.json()["must_change_password"] is False
    assert cookie_value(client, "cyberlens_session") != old_token
    assert client.get("/api/v1/assets").status_code == 200


def test_live_dispatcher_leaves_queued_demo_investigations_unchanged(workspace, monkeypatch):
    from app.orchestration import dispatch_pending_outbox

    _client, factory = workspace
    _use_live_test_settings(monkeypatch)
    db = factory()
    admin = db.query(User).filter_by(username="admin").one()
    asset = Asset(kind="domain", identifier="sample-queue.example.test", normalized_identifier="sample-queue.example.test",
                  notes="", created_by=admin.id, is_synthetic=True)
    db.add(asset)
    db.flush()
    investigation = Investigation(asset_id=asset.id, requested_by=admin.id, mode="demo", scenario="routine_website",
                                  status="queued", progress=0)
    db.add(investigation)
    db.flush()
    attempt = InvestigationAttempt(investigation_id=investigation.id, attempt_number=1, retry_kind="initial", status="queued")
    db.add(attempt)
    db.flush()
    outbox = InvestigationOutbox(attempt_id=attempt.id, status="pending", available_at=now_utc())
    db.add(outbox)
    db.commit()

    class QueueSpy:
        called = False

        def enqueue(self, *_args, **_kwargs):
            self.called = True

    queue = QueueSpy()
    assert dispatch_pending_outbox(db, queue=queue) == 0
    db.refresh(investigation)
    db.refresh(attempt)
    db.refresh(outbox)
    assert queue.called is False
    assert (investigation.mode, investigation.status, attempt.status, outbox.status) == (
        "demo", "queued", "queued", "pending",
    )
    db.close()


def test_demo_seed_refuses_live_mode_without_writing(workspace, monkeypatch):
    from app.cli import seed_demo

    _client, factory = workspace
    _use_live_test_settings(monkeypatch)
    db = factory()
    before = db.query(Asset).count()
    try:
        seed_demo(db)
    except RuntimeError as exc:
        assert "APP_MODE=demo" in str(exc)
    else:
        raise AssertionError("seed_demo should refuse Live mode")
    assert db.query(Asset).count() == before
    db.close()


def test_live_scope_query_builders_and_scorecard_hide_demo_rows(live_scope_db):
    db = live_scope_db
    user = User(username="scope-admin", password_hash="unused", role="admin")
    db.add(user)
    db.flush()
    live_asset = Asset(kind="domain", identifier="scoped-live.example.invalid", normalized_identifier="scoped-live.example.invalid",
                       notes="", created_by=user.id, is_synthetic=False)
    demo_asset = Asset(kind="domain", identifier="scoped-demo.example.test", normalized_identifier="scoped-demo.example.test",
                       notes="synthetic", created_by=user.id, is_synthetic=True, demo_scenario="routine_website")
    db.add_all([live_asset, demo_asset])
    db.flush()
    live_inv = Investigation(asset_id=live_asset.id, requested_by=user.id, mode="live", status="completed", progress=100,
                             finished_at=now_utc())
    demo_inv = Investigation(asset_id=demo_asset.id, requested_by=user.id, mode="demo", scenario="routine_website",
                             status="completed", progress=100, finished_at=now_utc())
    db.add_all([live_inv, demo_inv])
    db.flush()
    db.add_all([
        Finding(asset_id=live_asset.id, investigation_id=live_inv.id, fingerprint="c" * 64, category="reputation",
                severity="low", title="Live finding", explanation="Saved", recommendation="Review", source="fixture",
                observed_at=now_utc(), applicability="applies", is_synthetic=False, details_json={}),
        Finding(asset_id=demo_asset.id, investigation_id=demo_inv.id, fingerprint="d" * 64, category="reputation",
                severity="critical", title="Demo finding", explanation="Saved", recommendation="Review", source="fixture",
                observed_at=now_utc(), applicability="applies", is_synthetic=True, details_json={}),
    ])
    db.add_all([
        Incident(title="Live case", summary="", classification="suspected_incident", priority="low",
                 asset_id=live_asset.id, created_by=user.id),
        Incident(title="Demo case", summary="", classification="suspected_incident", priority="critical",
                 asset_id=demo_asset.id, created_by=user.id),
    ])
    live_content, demo_content = b"live-report", b"demo-report"
    db.add_all([
        Report(investigation_id=live_inv.id, format="json", created_by=user.id, is_demo=False,
               snapshot_json={"scope": "live"}, content=live_content, sha256=hashlib.sha256(live_content).hexdigest()),
        Report(investigation_id=demo_inv.id, format="json", created_by=user.id, is_demo=True,
               snapshot_json={"scope": "demo"}, content=demo_content, sha256=hashlib.sha256(demo_content).hexdigest()),
        AuditEvent(actor_id=user.id, action="asset.created", entity_type="asset", entity_id=live_asset.id, details_json={}),
        AuditEvent(actor_id=user.id, action="asset.created", entity_type="asset", entity_id=demo_asset.id, details_json={}),
    ])
    db.commit()

    assert [row.id for row in visible_assets(db).all()] == [live_asset.id]
    assert [row.id for row in visible_investigations(db).all()] == [live_inv.id]
    assert [row.title for row in visible_findings(db).all()] == ["Live finding"]
    assert [row.title for row in visible_incidents(db).all()] == ["Live case"]
    assert len(visible_reports(db).all()) == 1
    assert [row.entity_id for row in visible_audit_events(db).all()] == [live_asset.id]
    report_snapshots_before = {row.id: (row.snapshot_json, row.content) for row in db.query(Report).all()}
    scorecard = build_scorecard(db, now=now_utc())
    assert scorecard["data_scope"]["asset_count"] == 1
    assert scorecard["data_scope"]["data_modes"] == ["live"]
    assert scorecard["high_critical_findings"]["critical"] == 0
    assert {row.id: (row.snapshot_json, row.content) for row in db.query(Report).all()} == report_snapshots_before


def test_live_scheduler_does_not_promote_demo_monitoring_schedule(live_scope_db):
    from app.monitoring import enqueue_due_schedules

    db = live_scope_db
    owner = User(username="schedule-owner", password_hash="unused", role="analyst")
    db.add(owner)
    db.flush()
    asset = Asset(kind="domain", identifier="monitor.example.invalid", normalized_identifier="monitor.example.invalid",
                  notes="", created_by=owner.id, is_synthetic=False)
    db.add(asset)
    db.flush()
    authorization = WebsiteAuthorization(
        asset_id=asset.id, authorized_by=owner.id, note="test permission",
        expires_at=now_utc() + timedelta(days=30),
    )
    db.add(authorization)
    db.flush()
    past_due = now_utc() - timedelta(minutes=1)
    demo_schedule = MonitoringSchedule(
        asset_id=asset.id, authorization_id=authorization.id, owner_id=owner.id,
        mode="demo", cadence="daily", status="active", next_run_at=past_due,
    )
    live_schedule = MonitoringSchedule(
        asset_id=asset.id, authorization_id=authorization.id, owner_id=owner.id,
        mode="live", cadence="daily", status="active", next_run_at=past_due,
    )
    db.add_all([demo_schedule, live_schedule])
    db.commit()

    assert enqueue_due_schedules(db) == 1
    db.refresh(demo_schedule)
    db.refresh(live_schedule)
    assert demo_schedule.mode == "demo" and demo_schedule.next_run_at.replace(tzinfo=past_due.tzinfo) == past_due
    next_live_run = live_schedule.next_run_at
    if next_live_run.tzinfo is None:
        next_live_run = next_live_run.replace(tzinfo=now_utc().tzinfo)
    assert live_schedule.mode == "live" and next_live_run > now_utc()
    assert [item.id for item in visible_monitoring_schedules(db).all()] == [live_schedule.id]
    created = db.query(Investigation).filter_by(asset_id=asset.id).all()
    assert len(created) == 1 and created[0].mode == "live"

