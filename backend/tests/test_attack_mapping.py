from datetime import datetime, timezone
import re
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.dependencies import require_roles
from app.models import Asset, AttackMapping, EvidenceSnapshot, Finding, Incident, IncidentFinding, Investigation, Report, User
from app.routes import attack
from app.routes.reports import _incident_snapshot
from app.schemas import AttackMappingCreate, AttackMappingDecision, AttackMappingOut
from app.services.attack import attack_catalog, incident_matrix, suggestions_for_finding, suggestions_for_incident
from conftest import csrf, login


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


def scene(db: Session):
    analyst = User(username="attack-analyst", password_hash="unused", role="analyst")
    viewer = User(username="attack-viewer", password_hash="unused", role="viewer")
    db.add_all([analyst, viewer]); db.flush()
    asset = Asset(kind="application", identifier="Public app", normalized_identifier="public-app",
                  exposure_classification="internet_facing", created_by=analyst.id)
    db.add(asset); db.flush()
    investigation = Investigation(asset_id=asset.id, requested_by=analyst.id, mode="demo", status="completed", progress=100)
    db.add(investigation); db.flush()
    evidence = EvidenceSnapshot(investigation_id=investigation.id, source="NVD fixture", observed_at=datetime.now(timezone.utc),
        evidence_json={"cve": "CVE-2024-1000"}, sha256="a" * 64, is_synthetic=True)
    db.add(evidence); db.flush()
    finding = Finding(asset_id=asset.id, investigation_id=investigation.id, evidence_id=evidence.id,
        fingerprint="b" * 64, category="vulnerabilities", severity="high", title="Applicable CVE candidate",
        explanation="Saved evidence context", recommendation="Review the candidate", source="NVD",
        applicability="applies", details_json={"cve_id": "CVE-2024-1000"}, is_synthetic=True)
    db.add(finding); db.flush()
    incident = Incident(title="Confirmed case", summary="Synthetic test case", classification="confirmed_incident",
        asset_id=asset.id, investigation_id=investigation.id, created_by=analyst.id)
    db.add(incident); db.flush()
    db.add(IncidentFinding(incident_id=incident.id, finding_id=finding.id))
    db.commit()
    return SimpleNamespace(analyst=analyst, viewer=viewer, asset=asset, investigation=investigation,
                           evidence=evidence, finding=finding, incident=incident)


def test_local_catalog_is_versioned_and_all_ids_tactics_validate():
    catalog = attack_catalog()
    assert catalog["catalog_version"] == "cyberlens-attack-enterprise-subset-1.0"
    assert len(catalog["techniques"]) == 4
    assert all(re.fullmatch(r"T\d{4}(?:\.\d{3})?", row["id"]) for row in catalog["techniques"])
    assert all(row["tactics"] and row["url"].startswith("https://attack.mitre.org/techniques/") for row in catalog["techniques"])
    assert len({row["id"] for row in catalog["techniques"]}) == len(catalog["techniques"])


def test_suggestions_are_conservative_and_unknown_findings_stay_unmapped(db_session):
    sample = scene(db_session)
    suggestions = suggestions_for_finding(db_session, sample.finding)
    assert [(row["technique_id"], row["evidence_id"]) for row in suggestions] == [("T1190", sample.evidence.id)]
    assert suggestions[0]["evidence_role"] == "contextual"
    assert "does not show" in suggestions[0]["rationale"]
    sample.incident.classification = "security_issue"
    assert suggestions_for_incident(db_session, sample.incident) == []
    matrix = incident_matrix(db_session, sample.incident)
    assert matrix["suggestions"] == []
    assert matrix["unmapped"][0]["finding_id"] == sample.finding.id


def test_breach_exposure_candidate_requires_a_confirmed_incident_context(db_session):
    sample = scene(db_session)
    breach = Finding(asset_id=sample.asset.id, investigation_id=sample.investigation.id, evidence_id=sample.evidence.id,
        fingerprint="c" * 64, category="breach_exposure", severity="medium", title="Historical email exposure",
        explanation="Synthetic historical exposure context", recommendation="Review account protections", source="HIBP fixture",
        details_json={"breach_count": 1}, is_synthetic=True)
    db_session.add(breach); db_session.flush()
    db_session.add(IncidentFinding(incident_id=sample.incident.id, finding_id=breach.id)); db_session.flush()
    candidates = suggestions_for_finding(db_session, breach)
    assert len(candidates) == 1 and candidates[0]["technique_id"] == "T1589.002"
    assert candidates[0]["evidence_role"] == "contextual"
    assert "does not show" in candidates[0]["rationale"]
    sample.incident.classification = "security_issue"
    assert suggestions_for_incident(db_session, sample.incident) == []
    sample.incident.classification = "confirmed_incident"
    incident_candidates = suggestions_for_incident(db_session, sample.incident)
    assert {item["technique_id"] for item in incident_candidates} == {"T1190", "T1589.002"}
    breach.category = "tls_web"
    assert suggestions_for_finding(db_session, breach) == []


def test_mapping_validates_technique_tactic_evidence_and_review_lifecycle(db_session):
    sample = scene(db_session)
    invalid_id = AttackMappingCreate(finding_id=sample.finding.id, technique_id="T9999", tactic="Initial Access",
        evidence_id=sample.evidence.id, rationale="Analyst reviewed a candidate mapping.", confidence=.4)
    with pytest.raises(HTTPException) as unknown:
        attack.create_mapping(invalid_id, sample.analyst, db_session)
    assert unknown.value.status_code == 422
    invalid_tactic = AttackMappingCreate(finding_id=sample.finding.id, technique_id="T1190", tactic="Reconnaissance",
        evidence_id=sample.evidence.id, rationale="Analyst reviewed a candidate mapping.", confidence=.4)
    with pytest.raises(HTTPException) as tactic_error:
        attack.create_mapping(invalid_tactic, sample.analyst, db_session)
    assert tactic_error.value.status_code == 422
    wrong_evidence = AttackMappingCreate(finding_id=sample.finding.id, technique_id="T1190", tactic="Initial Access",
        evidence_id="missing-evidence", rationale="Analyst reviewed a candidate mapping.", confidence=.4)
    with pytest.raises(HTTPException) as evidence_error:
        attack.create_mapping(wrong_evidence, sample.analyst, db_session)
    assert evidence_error.value.status_code == 422

    created = attack.create_mapping(AttackMappingCreate(finding_id=sample.finding.id, technique_id="T1190",
        tactic="Initial Access", evidence_id=sample.evidence.id, rationale="Internet-facing vulnerability candidate.",
        confidence=.35, evidence_role="contextual"), sample.analyst, db_session)
    AttackMappingOut.model_validate(created)
    assert created["decision"] == "proposed" and created["analyst_confirmed"] is False
    assert created["source"] == "cyberlens-rule:vulnerability_internet_facing_app"
    assert created["catalog_version"] == "cyberlens-attack-enterprise-subset-1.0"
    assert "Terms of Use" in created["catalog_attribution"]
    approved = attack.decide_mapping(created["id"], AttackMappingDecision(decision="approved"), sample.analyst, db_session)
    assert approved["analyst_confirmed"] is True and approved["reviewed_at"] is not None
    rejected = attack.decide_mapping(created["id"], AttackMappingDecision(decision="rejected"), sample.analyst, db_session)
    assert rejected["analyst_confirmed"] is False and rejected["decision"] == "rejected"
    overridden = attack.decide_mapping(created["id"], AttackMappingDecision(decision="overridden", technique_id="T1078",
        tactic="Initial Access", rationale="Evidence supports a valid-account hypothesis after analyst review."), sample.analyst, db_session)
    assert overridden["technique_id"] == "T1078" and overridden["source"] == "analyst-override"
    assert overridden["analyst_confirmed"] is True
    assert db_session.query(AttackMapping).count() == 1


def test_incident_mapping_matrix_and_report_trace_preserve_prior_snapshot(db_session):
    sample = scene(db_session)
    report = Report(incident_id=sample.incident.id, format="json", created_by=sample.analyst.id, is_demo=True,
        snapshot_json={"saved": "before"}, content=b"previous report bytes", sha256="c" * 64)
    db_session.add(report); db_session.commit()
    sample.incident.classification = "confirmed_incident"
    suggestions = suggestions_for_incident(db_session, sample.incident)
    assert suggestions and suggestions[0]["incident_id"] == sample.incident.id
    created = attack.create_mapping(AttackMappingCreate(incident_id=sample.incident.id,
        technique_id=suggestions[0]["technique_id"], tactic=suggestions[0]["tactic"], evidence_id=sample.evidence.id,
        rationale=suggestions[0]["rationale"], confidence=suggestions[0]["confidence"]), sample.analyst, db_session)
    matrix = incident_matrix(db_session, sample.incident)
    assert matrix["mappings"][0]["evidence_id"] == sample.evidence.id
    assert matrix["tactics"][0]["mappings"][0]["technique_id"] == "T1190"
    snapshot = _incident_snapshot(db_session, sample.incident)
    assert snapshot["attack_mappings"][0]["id"] == created["id"]
    assert snapshot["attack_mappings"][0]["evidence_source"] == "NVD fixture"
    assert snapshot["attack_mappings"][0]["catalog_version"] == "cyberlens-attack-enterprise-subset-1.0"
    assert "MITRE ATT&CK" in snapshot["attack_mappings"][0]["catalog_source"]
    db_session.refresh(report)
    assert report.snapshot_json == {"saved": "before"} and report.content == b"previous report bytes"


def test_viewers_are_denied_mapping_writes():
    checker = require_roles("admin", "analyst")
    with pytest.raises(HTTPException) as denied:
        checker(User(username="viewer", password_hash="unused", role="viewer"))
    assert denied.value.status_code == 403


def test_attack_api_requires_analyst_and_csrf(workspace):
    client, factory = workspace
    with factory() as db:
        admin = db.query(User).filter_by(username="admin").one()
        asset = Asset(kind="application", identifier="API asset", normalized_identifier="api-asset",
                      exposure_classification="internet_facing", created_by=admin.id)
        db.add(asset); db.flush()
        investigation = Investigation(asset_id=asset.id, requested_by=admin.id, mode="demo", status="completed")
        db.add(investigation); db.flush()
        evidence = EvidenceSnapshot(investigation_id=investigation.id, source="API fixture", evidence_json={}, sha256="d" * 64)
        db.add(evidence); db.flush()
        finding = Finding(asset_id=asset.id, investigation_id=investigation.id, evidence_id=evidence.id, fingerprint="e" * 64,
            category="vulnerabilities", severity="high", title="API finding", explanation="x", recommendation="y", source="fixture",
            applicability="applies", details_json={})
        db.add(finding); db.commit(); finding_id = finding.id
    login(client, "viewer", "Test-Viewer-Password-2026!")
    denied = client.post("/api/v1/attack/mappings", headers=csrf(client), json={"finding_id": finding_id,
        "technique_id": "T1190", "tactic": "Initial Access", "evidence_id": evidence.id,
        "rationale": "Reviewed evidence supports this candidate.", "confidence": .4})
    assert denied.status_code == 403
    login(client, "admin", "Test-Admin-Password-2026!")
    missing_csrf = client.post("/api/v1/attack/mappings", json={"finding_id": finding_id,
        "technique_id": "T1190", "tactic": "Initial Access", "evidence_id": evidence.id,
        "rationale": "Reviewed evidence supports this candidate.", "confidence": .4})
    assert missing_csrf.status_code == 403
    catalog = client.get("/api/v1/attack/catalog")
    assert catalog.status_code == 200 and catalog.json()["catalog_version"] == "cyberlens-attack-enterprise-subset-1.0"
