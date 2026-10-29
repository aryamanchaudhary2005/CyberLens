from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.dependencies import require_roles
from app.database import Base
from app.models import (
    Asset,
    AuditEvent,
    CollectorRun,
    EvidenceSnapshot,
    Finding,
    FindingControlMapping,
    Incident,
    IncidentEvent,
    Investigation,
    MonitoringRun,
    MonitoringSchedule,
    Report,
    RiskAssessmentRevision,
    User,
    WebsiteAuthorization,
    new_id,
)
from app.routes.posture import get_posture_scorecard
from app.routes.reports import create_posture_report
from app.schemas import PostureReportCreate, PostureScorecardOut, ReportOut
from app.services.posture import build_scorecard
from conftest import login


NOW = datetime(2026, 10, 17, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def posture_db(monkeypatch):
    monkeypatch.setenv("APP_MODE", "demo")
    from app.config import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    with factory() as db:
        analyst = User(username="posture-analyst", password_hash="unused", role="analyst", must_change_password=False)
        viewer = User(username="posture-viewer", password_hash="unused", role="viewer", must_change_password=False)
        db.add_all([analyst, viewer])
        db.commit()
        ids = analyst.id, viewer.id
    yield factory, ids
    Base.metadata.drop_all(engine)
    engine.dispose()
    get_settings.cache_clear()


def _seed_scorecard(db, ids):
    analyst_id, _ = ids
    asset = Asset(
        kind="domain", identifier="posture.example.test", normalized_identifier="posture.example.test",
        created_by=analyst_id, criticality="high", created_at=NOW - timedelta(days=40),
    )
    uncovered = Asset(
        kind="domain", identifier="unassessed.example.test", normalized_identifier="unassessed.example.test",
        created_by=analyst_id, criticality="unknown", created_at=NOW - timedelta(days=40),
    )
    db.add_all([asset, uncovered])
    db.flush()

    investigations = []
    for number, age_days, score in ((1, 2, 48.0), (2, 1, 72.0)):
        finished = NOW - timedelta(days=age_days)
        investigation = Investigation(
            asset_id=asset.id, requested_by=analyst_id, mode="live", scenario="routine_website",
            status="completed", progress=100, created_at=finished - timedelta(minutes=5), finished_at=finished,
        )
        db.add(investigation)
        db.flush()
        revision = RiskAssessmentRevision(
            investigation_id=investigation.id, revision_number=1, input_fingerprint=f"fingerprint-{number}",
            version="cyberlens-academic-1.0", score=score, band="medium", weights_json={"reputation": 30},
            assessed_categories=["reputation", "tls_web", "dns_email"], excluded_categories=[],
            category_scores={"reputation": 50}, contributing_finding_ids=[], explanation_json={"rule_version": "cyberlens-academic-1.0"},
            created_at=finished,
        )
        db.add(revision)
        investigations.append(investigation)

    evidence = EvidenceSnapshot(
        investigation_id=investigations[-1].id, collector_run_id=None, source="fixture:website",
        observed_at=NOW - timedelta(days=1), evidence_json={"fixture": True}, sha256="a" * 64, is_synthetic=False,
    )
    db.add(evidence)
    db.flush()
    previous = Finding(
        asset_id=asset.id, investigation_id=investigations[0].id, evidence_id=None, fingerprint="f" * 64,
        category="tls_web", severity="high", title="Observed certificate issue", explanation="Saved fixture",
        recommendation="Review certificate", source="fixture:website", observed_at=NOW - timedelta(days=2),
        applicability="applies", is_synthetic=False, details_json={},
    )
    current = Finding(
        asset_id=asset.id, investigation_id=investigations[1].id, evidence_id=evidence.id, fingerprint="f" * 64,
        category="tls_web", severity="high", title="Observed certificate issue", explanation="Saved fixture",
        recommendation="Review certificate", source="fixture:website", observed_at=NOW - timedelta(days=1),
        applicability="applies", is_synthetic=False, details_json={},
    )
    duplicate = Finding(
        asset_id=asset.id, investigation_id=investigations[1].id, evidence_id=evidence.id, fingerprint="f" * 64,
        category="tls_web", severity="critical", title="Later duplicate", explanation="Same identity",
        recommendation="Review certificate", source="fixture:website", observed_at=NOW - timedelta(hours=20),
        applicability="applies", is_synthetic=False, details_json={},
    )
    not_applicable = Finding(
        asset_id=asset.id, investigation_id=investigations[1].id, evidence_id=evidence.id, fingerprint="n" * 64,
        category="reputation", severity="critical", title="Excluded observation", explanation="Not applicable",
        recommendation="None", source="fixture:reputation", observed_at=NOW - timedelta(hours=2),
        applicability="not_applicable", is_synthetic=False, details_json={},
    )
    db.add_all([previous, current, duplicate, not_applicable])
    db.flush()
    # Point-in-time mapping coverage counts a rejected proposal as no active mapping.
    db.add_all([
        FindingControlMapping(
            finding_id=duplicate.id, control_id="SC-8", catalog_version="cyberlens-controls-1.0",
            rationale="Evidence-backed fixture", confidence=0.9, status="validated",
            verification_evidence_id=evidence.id, validated_by=analyst_id, validated_at=NOW - timedelta(hours=1),
            created_by=analyst_id, created_at=NOW - timedelta(days=1), updated_at=NOW - timedelta(hours=1),
        ),
        FindingControlMapping(
            finding_id=not_applicable.id, control_id="SC-7", catalog_version="cyberlens-controls-1.0",
            rationale="Rejected fixture", confidence=0.2, status="rejected", verification_evidence_id=None,
            validated_by=None, validated_at=None, created_by=analyst_id,
            created_at=NOW - timedelta(days=1), updated_at=NOW - timedelta(hours=1),
        ),
    ])

    authorization = WebsiteAuthorization(
        asset_id=asset.id, authorized_by=analyst_id, note="Fixture authorization", created_at=NOW - timedelta(days=20),
        expires_at=NOW + timedelta(days=10),
    )
    db.add(authorization)
    db.flush()
    schedule = MonitoringSchedule(
        asset_id=asset.id, authorization_id=authorization.id, owner_id=analyst_id, cadence="daily", status="active",
        next_run_at=NOW + timedelta(days=1), created_at=NOW - timedelta(days=10), updated_at=NOW - timedelta(days=10),
    )
    db.add(schedule)
    db.flush()
    db.add(MonitoringRun(
        schedule_id=schedule.id, investigation_id=investigations[1].id, previous_investigation_id=investigations[0].id,
        scheduled_for=NOW - timedelta(days=1), status="completed", started_at=NOW - timedelta(days=1),
        finished_at=NOW - timedelta(days=1), created_at=NOW - timedelta(days=1),
    ))
    db.add(CollectorRun(
        investigation_id=investigations[1].id, attempt_id=None, collector="dns_rdap", status="success",
        source="fixture:dns", record_count=1, started_at=NOW - timedelta(days=1), finished_at=NOW - timedelta(days=1),
    ))
    db.add(CollectorRun(
        investigation_id=investigations[1].id, attempt_id=None, collector="reputation", status="failed",
        source="fixture:reputation", error_explanation="Provider unavailable", record_count=0,
        started_at=NOW - timedelta(hours=3), finished_at=NOW - timedelta(hours=3),
    ))
    incident = Incident(
        title="Timing fixture", summary="", classification="security_issue", status="resolved", priority="high",
        asset_id=asset.id, created_by=analyst_id, created_at=NOW - timedelta(days=5), updated_at=NOW,
    )
    pending_incident = Incident(
        title="Pending fixture", summary="", classification="security_issue", status="new", priority="medium",
        asset_id=asset.id, created_by=analyst_id, created_at=NOW - timedelta(days=3), updated_at=NOW - timedelta(days=3),
    )
    db.add_all([incident, pending_incident])
    db.flush()
    db.add_all([
        IncidentEvent(incident_id=incident.id, actor_id=analyst_id, event_type="status_changed", message="triaged",
                     details_json={"from": "new", "to": "triaged"}, created_at=NOW - timedelta(days=5) + timedelta(hours=1)),
        IncidentEvent(incident_id=incident.id, actor_id=analyst_id, event_type="status_changed", message="resolved",
                     details_json={"from": "responding", "to": "resolved"}, created_at=NOW),
    ])
    db.flush()
    return asset, uncovered, investigations, incident, evidence


def test_scorecard_aggregates_saved_records_and_exposes_scopes(posture_db):
    factory, ids = posture_db
    with factory() as db:
        _seed_scorecard(db, ids)
        scorecard = build_scorecard(db, 30, now=NOW)
        validated = PostureScorecardOut.model_validate(scorecard)

        assert validated.overall_risk.average_score == 72
        assert validated.overall_risk.state == "partial"
        assert validated.overall_risk.assets_in_scope == 2
        assert validated.assessment_coverage.expected_category_slots == 6
        assert validated.assessment_coverage.assessed_category_slots == 3
        assert validated.unassessed_categories.counts == {"dns_email": 1, "reputation": 1, "tls_web": 1}
        assert validated.high_critical_findings.high == 0
        assert validated.high_critical_findings.critical == 1
        assert validated.high_critical_findings.lifecycle_status_available is False
        assert validated.high_critical_findings.open_counts_available is False
        assert validated.high_critical_findings.open_total is None
        assert "not verified unresolved" in validated.high_critical_findings.note
        assert validated.repeated_findings.repeated_finding_count == 1
        assert validated.repeated_findings.repeated_observation_count == 2
        assert len(validated.risk_trend.points) == 2
        assert validated.workflow_trend.investigations_count == 2
        assert validated.workflow_trend.monitoring_run_count == 1
        assert validated.incident_timings.triage_median_seconds == 3600
        assert validated.incident_timings.resolution_median_seconds == 432000
        assert validated.incident_timings.unresolved_or_unrecorded_count == 1
        assert validated.asset_criticality.counts == {"critical": 0, "high": 1, "medium": 0, "low": 0, "unknown": 1}
        assert validated.security_control_coverage.findings_with_validated_mapping == 1
        assert validated.security_control_coverage.findings_with_mapping == 1
        providers = {provider.id: provider for provider in validated.provider_health.providers}
        assert providers["reputation"].state == "unavailable"
        assert providers["reputation"].provider_status == "failed"
        assert providers["dns_rdap"].state == "available"
        assert providers["web_tls"].state == "unavailable"
        assert validated.provider_health.state == "partial"
        metrics = (
            validated.overall_risk, validated.assessment_coverage, validated.unassessed_categories,
            validated.high_critical_findings, validated.repeated_findings, validated.risk_trend,
            validated.workflow_trend, validated.incident_timings, validated.provider_health,
            validated.asset_criticality, validated.security_control_coverage,
        )
        assert all(metric.range_days == 30 and metric.window_start < metric.window_end and metric.scope for metric in metrics)
        assert [point.average_score for point in validated.risk_trend.points] == [48, 72]
        assert [point.policy_versions for point in validated.risk_trend.points] == [
            ["cyberlens-academic-1.0"], ["cyberlens-academic-1.0"],
        ]


def test_risk_trend_exposes_policy_versions_without_rewriting_saved_revisions(posture_db):
    factory, ids = posture_db
    with factory() as db:
        _seed_scorecard(db, ids)
        revisions = db.query(RiskAssessmentRevision).order_by(RiskAssessmentRevision.created_at.asc()).all()
        revisions[0].version = "legacy-policy"
        revisions[0].explanation_json = {"rule_version": "legacy-policy"}
        legacy_values = [(revision.id, revision.score, revision.version) for revision in revisions]

        scorecard = PostureScorecardOut.model_validate(build_scorecard(db, 30, now=NOW))

        assert [point.policy_versions for point in scorecard.risk_trend.points] == [
            ["legacy-policy"], ["cyberlens-academic-1.0"],
        ]
        assert [(revision.id, revision.score, revision.version) for revision in revisions] == legacy_values


def test_empty_workspace_and_aged_assessment_do_not_turn_missing_data_into_zero(posture_db):
    factory, ids = posture_db
    with factory() as db:
        empty = PostureScorecardOut.model_validate(build_scorecard(db, 7, now=NOW))
        assert empty.overall_risk.state == "empty" and empty.overall_risk.average_score is None
        assert empty.assessment_coverage.coverage_percent is None
        assert empty.high_critical_findings.total is None
        assert empty.high_critical_findings.open_high is None
        assert empty.repeated_findings.repeated_finding_count is None
        assert empty.asset_criticality.state == "empty"

        asset = Asset(kind="application", identifier="old.example.test", normalized_identifier="old.example.test",
                      created_by=ids[0], criticality="unknown", created_at=NOW - timedelta(days=100))
        db.add(asset)
        db.flush()
        investigation = Investigation(asset_id=asset.id, requested_by=ids[0], mode="live", status="completed",
                                      progress=100, created_at=NOW - timedelta(days=50), finished_at=NOW - timedelta(days=50))
        db.add(investigation)
        db.flush()
        db.add(RiskAssessmentRevision(
            investigation_id=investigation.id, revision_number=1, input_fingerprint="old-revision",
            version="cyberlens-academic-1.0", score=33, band="low", weights_json={}, assessed_categories=["vulnerabilities"],
            excluded_categories=[], category_scores={}, contributing_finding_ids=[], explanation_json={},
            created_at=NOW - timedelta(days=50),
        ))
        db.flush()
        aged = PostureScorecardOut.model_validate(build_scorecard(db, 7, now=NOW))
        assert aged.overall_risk.state == "stale" and aged.overall_risk.average_score is None
        assert aged.high_critical_findings.state == "stale" and aged.high_critical_findings.total is None
        assert aged.assessment_coverage.unassessed_category_slots == 1
        assert aged.overall_risk.assets_with_score == 0


def test_authenticated_viewers_can_read_but_cannot_export_posture(posture_db):
    factory, (analyst_id, viewer_id) = posture_db
    with factory() as db:
        viewer = db.get(User, viewer_id)
        view_data = get_posture_scorecard(7, viewer, db)
        assert view_data["range_days"] == 7
        analyst_gate = require_roles("admin", "analyst")
        assert analyst_gate(db.get(User, analyst_id)).id == analyst_id
        with pytest.raises(HTTPException) as denied:
            analyst_gate(viewer)
        assert denied.value.status_code == 403


def test_scorecard_http_accepts_supported_integer_query_strings(workspace):
    client, _factory = workspace
    assert client.get("/api/v1/posture/scorecard?range_days=30").status_code == 401
    login(client, "viewer", "Test-Viewer-Password-2026!")
    default = client.get("/api/v1/posture/scorecard")
    assert default.status_code == 200, default.text
    assert default.json()["range_days"] == 30
    for range_days in (7, 30, 90, 365):
        response = client.get(f"/api/v1/posture/scorecard?range_days={range_days}")
        assert response.status_code == 200, response.text
        scorecard = response.json()
        assert scorecard["range_days"] == range_days
        assert scorecard["overall_risk"]["range_days"] == range_days
        assert scorecard["overall_risk"]["average_score"] is None


def test_scorecard_http_rejects_unsupported_or_malformed_range_queries(workspace):
    client, _factory = workspace
    login(client)
    for value in ("0", "14", "366", "invalid", "30.5", ""):
        response = client.get("/api/v1/posture/scorecard", params={"range_days": value})
        assert response.status_code == 422, (value, response.text)
        assert response.json()["detail"][0]["loc"] == ["query", "range_days"]


def test_posture_report_is_an_immutable_snapshot_and_existing_reports_are_unchanged(posture_db):
    factory, (analyst_id, _) = posture_db
    with factory() as db:
        _seed_scorecard(db, (analyst_id, "viewer-unused"))
        legacy_snapshot = {"report_type": "investigation", "finding": "unchanged"}
        legacy = Report(id=new_id(), investigation_id=None, incident_id=None, format="json", created_by=analyst_id,
                       is_demo=False, snapshot_json=legacy_snapshot, content=b"legacy-report-bytes", sha256="b" * 64)
        db.add(legacy)
        db.commit()
        before_bytes, before_snapshot = legacy.content, dict(legacy.snapshot_json)

        payload = PostureReportCreate(format="json", range_days=30)
        result = create_posture_report(payload, db.get(User, analyst_id), db)
        typed = ReportOut.model_validate(result)
        saved = db.get(Report, typed.id)
        assert typed.report_type == "posture"
        assert saved.snapshot_json["report_type"] == "posture"
        assert saved.snapshot_json["scorecard"]["schema_version"] == "cyberlens-posture-1.0"
        assert saved.content.startswith(b"{")
        assert len(saved.sha256) == 64
        assert saved.is_demo is False
        assert db.get(Report, legacy.id).content == before_bytes
        assert db.get(Report, legacy.id).snapshot_json == before_snapshot
        assert db.query(AuditEvent).filter_by(action="report.posture_generated", entity_id=saved.id).count() == 1

        pdf_result = create_posture_report(PostureReportCreate(format="pdf", range_days=30), db.get(User, analyst_id), db)
        pdf_report = db.get(Report, pdf_result["id"])
        assert pdf_result["report_type"] == "posture"
        assert pdf_report.content.startswith(b"%PDF")
        assert pdf_report.snapshot_json["scorecard"]["high_critical_findings"]["open_counts_available"] is False
        assert db.get(Report, legacy.id).content == before_bytes
        assert db.get(Report, legacy.id).snapshot_json == before_snapshot
