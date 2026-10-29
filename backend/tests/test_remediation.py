from copy import deepcopy
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.models import (
    Asset, AuditEvent, EvidenceSnapshot, Finding, Incident, Investigation, PlaybookTask,
    RemediationAction, RemediationPlan, RiskAssessment, RiskAssessmentRevision, Report, User,
)
from app.routes import remediation
from app.routes.reports import _incident_snapshot, _investigation_snapshot, _json_bytes, _pdf_bytes
from app.schemas import (FindingControlMappingCreate, FindingControlMappingOut, FindingControlMappingUpdate,
                         RemediationActionCreate, RemediationActionOut, RemediationActionUpdate,
                         RemediationPlanCreate, RemediationPlanOut, RemediationPlanUpdate)
from app.services.security_controls import CATALOG_VERSION, control_catalog
from conftest import csrf, login
from app.dependencies import require_roles


@pytest.fixture
def db_session():
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = Session(engine, autoflush=False, expire_on_commit=False)
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(engine)
        engine.dispose()


def records(db: Session):
    user = User(username="remediation-analyst", password_hash="unused", role="analyst")
    db.add(user); db.flush()
    asset = Asset(kind="application", identifier="Remediation test", normalized_identifier="remediation-test",
                  created_by=user.id)
    db.add(asset); db.flush()
    investigation = Investigation(asset_id=asset.id, requested_by=user.id, mode="demo", status="completed", progress=100)
    db.add(investigation); db.flush()
    evidence = EvidenceSnapshot(investigation_id=investigation.id, source="Fixture source", evidence_json={"state": "observed"},
                                sha256="a" * 64, is_synthetic=True)
    db.add(evidence); db.flush()
    finding = Finding(asset_id=asset.id, investigation_id=investigation.id, evidence_id=evidence.id,
        fingerprint="b" * 64, category="vulnerabilities", severity="high", title="Applicable vulnerability",
        explanation="saved explanation", recommendation="saved recommendation", source="NVD", applicability="applies",
        details_json={"cve_id": "CVE-2024-1000"}, is_synthetic=True)
    db.add(finding); db.flush()
    risk = RiskAssessment(investigation_id=investigation.id, version="cyberlens-academic-1.0", score=74.0,
        band="high", weights_json={"vulnerabilities": 35}, assessed_categories=["vulnerabilities"],
        excluded_categories=[], category_scores={"vulnerabilities": 80}, contributing_finding_ids=[finding.id],
        explanation_json={"contributors": [{"finding_id": finding.id}]})
    db.add(risk)
    risk_revision = RiskAssessmentRevision(investigation_id=investigation.id, revision_number=1,
        input_fingerprint="e" * 64, version=risk.version, score=risk.score, band=risk.band,
        weights_json=risk.weights_json, assessed_categories=risk.assessed_categories, excluded_categories=[],
        category_scores=risk.category_scores, contributing_finding_ids=[finding.id],
        explanation_json=risk.explanation_json)
    db.add(risk_revision)
    incident = Incident(title="Remediation incident", summary="saved summary", asset_id=asset.id,
                        investigation_id=investigation.id, created_by=user.id)
    db.add(incident); db.flush()
    task = PlaybookTask(incident_id=incident.id, playbook_id="application", playbook_version="1.0",
                        title="Apply vendor fix", description="Complete the approved change", stage="remediation")
    db.add(task); db.flush()
    report = Report(investigation_id=investigation.id, incident_id=incident.id, format="json", created_by=user.id,
                    is_demo=True, snapshot_json={"saved": "snapshot"}, content=b"saved report", sha256="c" * 64)
    db.add(report); db.commit()
    return SimpleNamespace(user=user, asset=asset, investigation=investigation, evidence=evidence,
                           finding=finding, risk=risk, risk_revision=risk_revision,
                           incident=incident, task=task, report=report)


def test_versioned_catalog_and_mapping_validation_requires_same_investigation_evidence(db_session):
    scene = records(db_session)
    catalog = control_catalog()
    assert len(catalog) >= 5
    assert all(item["catalog_version"] == CATALOG_VERSION for item in catalog)
    assert any(item["id"] == "SI-2" for item in catalog)

    invalid = FindingControlMappingCreate(control_id="SI-2", rationale="Patch the affected component and verify it.",
                                          confidence=0.9, status="validated")
    with pytest.raises(HTTPException) as missing:
        remediation.create_finding_control_mapping(scene.finding.id, invalid, scene.user, db_session)
    assert missing.value.status_code == 422
    valid = FindingControlMappingCreate(control_id="SI-2", rationale="Patch the affected component and verify it.",
                                        confidence=0.9, status="validated", verification_evidence_id=scene.evidence.id)
    mapped = remediation.create_finding_control_mapping(scene.finding.id, valid, scene.user, db_session)
    FindingControlMappingOut.model_validate(mapped)
    assert mapped["status"] == "validated"
    assert mapped["verification_evidence"]["id"] == scene.evidence.id
    assert mapped["control"]["catalog_version"] == CATALOG_VERSION
    assert db_session.query(AuditEvent).filter_by(entity_type="finding_control_mapping", entity_id=mapped["id"]).one().action == "remediation.control_mapping_created"
    remediation.update_finding_control_mapping(scene.finding.id, mapped["id"], FindingControlMappingUpdate(status="planned"), scene.user, db_session)

    other_investigation = Investigation(asset_id=scene.asset.id, requested_by=scene.user.id, mode="demo", status="completed")
    db_session.add(other_investigation); db_session.flush()
    other_evidence = EvidenceSnapshot(investigation_id=other_investigation.id, source="Other fixture", evidence_json={}, sha256="d" * 64)
    db_session.add(other_evidence); db_session.commit()
    update = FindingControlMappingUpdate(status="validated", verification_evidence_id=other_evidence.id)
    with pytest.raises(HTTPException) as cross_scope:
        remediation.update_finding_control_mapping(scene.finding.id, mapped["id"], update, scene.user, db_session)
    assert cross_scope.value.status_code == 422
    assert {row.action for row in db_session.query(AuditEvent).filter_by(entity_type="finding_control_mapping", entity_id=mapped["id"])} == {
        "remediation.control_mapping_created", "remediation.control_mapping_updated",
    }


def test_actions_require_evidence_to_validate_and_audit_lifecycle(db_session):
    scene = records(db_session)
    created = remediation.create_remediation_plan(RemediationPlanCreate(
        title="Patch vulnerable application", description="Deploy the approved vendor fix.", action_type="patch",
        finding_id=scene.finding.id, incident_id=scene.incident.id, playbook_task_id=scene.task.id,
        owner_id=scene.user.id, priority="high", assumptions=["The vendor package is supported."],
    ), scene.user, db_session)
    assert created["incident_id"] == scene.incident.id
    assert created["playbook_task_id"] == scene.task.id
    assert created["status"] == "proposed"
    RemediationPlanOut.model_validate(created)
    delegate = User(username="remediation-delegate", password_hash="unused", role="analyst")
    db_session.add(delegate); db_session.flush()
    reassigned = remediation.update_remediation_plan(created["id"], RemediationPlanUpdate(owner_id=delegate.id), scene.user, db_session)
    assert reassigned["owner_id"] == delegate.id
    assert {row.action for row in db_session.query(AuditEvent).filter_by(entity_type="remediation_plan", entity_id=created["id"])} == {
        "remediation.plan_created", "remediation.plan_updated",
    }

    no_evidence = RemediationActionCreate(title="Deploy patch", action_type="patch", status="validated")
    with pytest.raises(HTTPException, match="Verification evidence") as rejected:
        remediation.create_remediation_action(created["id"], no_evidence, scene.user, db_session)
    assert rejected.value.status_code == 422

    action = remediation.create_remediation_action(created["id"], RemediationActionCreate(
        title="Deploy patch", description="Deploy in the approved maintenance window.", action_type="patch",
        priority="high", verification_instructions="Rescan and confirm the affected version is no longer present.",
    ), scene.user, db_session)
    RemediationActionOut.model_validate(action)
    updated = remediation.update_remediation_action(created["id"], action["id"], RemediationActionUpdate(
        status="validated", verification_evidence_id=scene.evidence.id, notes="Rescan completed."), scene.user, db_session)
    assert updated["status"] == "validated"
    assert updated["verification_evidence_id"] == scene.evidence.id
    assert updated["validated_by"] == scene.user.id
    audit = db_session.query(AuditEvent).filter_by(entity_type="remediation_action", entity_id=action["id"]).order_by(AuditEvent.created_at).all()
    assert [item.action for item in audit] == ["remediation.action_created", "remediation.action_updated"]


def test_remediation_preserves_findings_risk_and_existing_report_snapshots(db_session):
    scene = records(db_session)
    before = {
        "finding": (scene.finding.title, scene.finding.applicability, deepcopy(scene.finding.details_json), scene.finding.evidence_id),
        "risk": (scene.risk.score, scene.risk.version, deepcopy(scene.risk.explanation_json)),
        "risk_revision": (scene.risk_revision.revision_number, scene.risk_revision.input_fingerprint,
                          scene.risk_revision.score, deepcopy(scene.risk_revision.explanation_json)),
        "report": (deepcopy(scene.report.snapshot_json), scene.report.content, scene.report.sha256),
    }
    plan = remediation.create_remediation_plan(RemediationPlanCreate(
        title="Investigate vulnerability", action_type="triage", finding_id=scene.finding.id,
        incident_id=scene.incident.id,
    ), scene.user, db_session)
    remediation.create_remediation_action(plan["id"], RemediationActionCreate(
        title="Review vendor advisory", action_type="analysis", verification_instructions="Confirm the advisory applies.",
    ), scene.user, db_session)
    mapped = remediation.create_finding_control_mapping(scene.finding.id, FindingControlMappingCreate(
        control_id="SI-2", rationale="Confirm patch availability and verify the deployed version.", confidence=0.85,
    ), scene.user, db_session)
    db_session.expire_all()
    finding = db_session.get(Finding, scene.finding.id)
    risk = db_session.get(RiskAssessment, scene.risk.id)
    revision = db_session.get(RiskAssessmentRevision, scene.risk_revision.id)
    report = db_session.get(Report, scene.report.id)
    after = {
        "finding": (finding.title, finding.applicability, finding.details_json, finding.evidence_id),
        "risk": (risk.score, risk.version, risk.explanation_json),
        "risk_revision": (revision.revision_number, revision.input_fingerprint, revision.score, revision.explanation_json),
        "report": (report.snapshot_json, report.content, report.sha256),
    }
    assert before == after
    investigation_snapshot = _investigation_snapshot(db_session, db_session.get(Investigation, scene.investigation.id))
    incident_snapshot = _incident_snapshot(db_session, db_session.get(Incident, scene.incident.id))
    assert any(item["id"] == plan["id"] for item in investigation_snapshot["remediation_plans"])
    assert any(item["id"] == plan["id"] for item in incident_snapshot["remediation_plans"])
    assert any(item["id"] == mapped["id"] for item in investigation_snapshot["control_mappings"])
    assert b"remediation_plans" in _json_bytes(incident_snapshot)
    assert _pdf_bytes(incident_snapshot).startswith(b"%PDF")
    assert db_session.query(RemediationAction).filter_by(plan_id=plan["id"]).count() == 1


def test_viewer_role_is_rejected_by_remediation_write_permission():
    viewer = User(username="remediation-viewer", password_hash="unused", role="viewer")
    analyst = User(username="remediation-analyst-role", password_hash="unused", role="analyst")
    write_permission = require_roles("admin", "analyst")
    with pytest.raises(HTTPException) as rejected:
        write_permission(viewer)
    assert rejected.value.status_code == 403
    assert write_permission(analyst) is analyst


def test_remediation_viewer_http_permissions(workspace):
    client, _factory = workspace
    login(client)
    assert client.get("/api/v1/remediation/controls").status_code == 200
    client.post("/api/v1/auth/logout", headers=csrf(client))
    login(client, "viewer", "Test-Viewer-Password-2026!")
    response = client.post("/api/v1/remediation/plans", headers=csrf(client), json={
        "title": "Viewer plan", "description": "Must remain read-only.", "action_type": "patch",
    })
    assert response.status_code == 403


def test_migration_adds_remediation_records_without_rewriting_saved_data(tmp_path, monkeypatch):
    from pathlib import Path
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect, text

    monkeypatch.delenv("DATABASE_URL", raising=False)
    root = Path(__file__).resolve().parents[2]
    config = Config(str(root / "backend" / "alembic.ini"))
    path = tmp_path / "module13.db"
    config.set_main_option("sqlalchemy.url", f"sqlite:///{path.as_posix()}")
    command.upgrade(config, "20261017_0008")
    engine = create_engine(f"sqlite:///{path.as_posix()}")
    with Session(engine) as db:
        scene = records(db)
        finding_id, report_id = scene.finding.id, scene.report.id
        old_report = (deepcopy(scene.report.snapshot_json), scene.report.content, scene.report.sha256)
        old_finding = (scene.finding.title, scene.finding.details_json, scene.finding.evidence_id)
    # Revision 0002 is a metadata-driven bootstrap that includes today's tables.
    # Remove only the empty Module 13 tables to emulate an existing 0008 database.
    with engine.begin() as connection:
        for table in ("finding_control_mappings", "remediation_actions", "remediation_plans"):
            connection.execute(text(f'DROP TABLE "{table}"'))
    command.upgrade(config, "head")
    tables = set(inspect(engine).get_table_names())
    assert {"remediation_plans", "remediation_actions", "finding_control_mappings"} <= tables
    with Session(engine) as db:
        finding = db.get(Finding, finding_id)
        report = db.get(Report, report_id)
        assert (finding.title, finding.details_json, finding.evidence_id) == old_finding
        assert (report.snapshot_json, report.content, report.sha256) == old_report
    command.check(config)
    engine.dispose()
