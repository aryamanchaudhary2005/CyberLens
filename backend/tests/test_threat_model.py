
import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.models import Asset, AuditEvent, Finding, Incident, Investigation, Report, RiskAssessment, ThreatScenario, User
from app.routes import threat_model
from app.routes.reports import _investigation_snapshot
from app.schemas import AssetThreatProfileOut, ThreatProfileUpdate, ThreatScenarioCreate, ThreatScenarioOut, ThreatScenarioUpdate
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


@pytest.fixture
def scene(db_session):
    analyst = User(username="threat-analyst", password_hash="unused", role="analyst")
    viewer = User(username="threat-viewer", password_hash="unused", role="viewer")
    db_session.add_all([analyst, viewer]); db_session.flush()
    asset = Asset(kind="application", identifier="Payroll application", normalized_identifier="payroll-app", created_by=analyst.id)
    db_session.add(asset); db_session.flush()
    investigation = Investigation(asset_id=asset.id, requested_by=analyst.id, mode="demo", status="completed")
    db_session.add(investigation); db_session.flush()
    finding = Finding(asset_id=asset.id, investigation_id=investigation.id, fingerprint="a" * 64,
        category="vulnerabilities", severity="critical", title="Technical vulnerability", explanation="Finding details",
        recommendation="Patch", source="NVD", details_json={})
    db_session.add(finding); db_session.flush()
    incident = Incident(title="Case", asset_id=asset.id, investigation_id=investigation.id, created_by=analyst.id)
    db_session.add(incident)
    other_asset = Asset(kind="domain", identifier="other.example.test", normalized_identifier="other.example.test", created_by=analyst.id)
    db_session.add(other_asset); db_session.commit()
    return analyst, viewer, asset, investigation, finding, incident, other_asset


def test_score_explanation_is_deterministic_and_separate_from_severity():
    first = threat_model.calculate_scenario_score(4, 5)
    assert first == (20, "Likelihood (4/5) × business impact (5/5) = 20/25. Confidence is recorded separately and does not change this score.")
    assert threat_model.calculate_scenario_score(4, 5) == first
    with pytest.raises(ValueError):
        threat_model.calculate_scenario_score(6, 5)


def test_owner_directory_exposes_only_active_assignable_fields(db_session, scene):
    analyst, viewer, *_ = scene
    viewer.is_active = False
    db_session.commit()
    owners = threat_model.list_threat_model_owners(analyst, db_session)
    assert owners == [{"id": analyst.id, "username": analyst.username, "role": "analyst"}]


def test_scenario_links_audit_and_preserves_analyst_uncertainty(db_session, scene):
    analyst, _viewer, asset, investigation, finding, incident, _other_asset = scene
    risk = RiskAssessment(investigation_id=investigation.id, version="cyberlens-academic-1.0", score=87.0, band="critical",
        weights_json={"vulnerabilities": 35}, assessed_categories=["vulnerabilities"], excluded_categories=[],
        category_scores={"vulnerabilities": 95}, contributing_finding_ids=[finding.id], explanation_json={"business_score": "absent"})
    db_session.add(risk); db_session.flush()
    created = threat_model.create_scenario(ThreatScenarioCreate(asset_id=asset.id, finding_id=finding.id,
        investigation_id=investigation.id, incident_id=incident.id, stride_category="information_disclosure",
        title="Sensitive payroll records exposed", likelihood=3, business_impact=5, confidence=2,
        assumptions=["The service is used for payroll processing."], unconfirmed_information=["Encryption at rest is unverified."],
        review_status="needs_review"), analyst, db_session)
    ThreatScenarioOut.model_validate(created)
    assert created["business_impact_score"] == 15
    assert "15/25" in created["calculation_explanation"]
    assert created["score_notice"] == threat_model.SCORE_NOTICE
    assert created["unconfirmed_information"] == ["Encryption at rest is unverified."]
    assert created["assumptions"] == ["The service is used for payroll processing."]
    assert created["stride_category"] == "information_disclosure"
    assert db_session.query(AuditEvent).filter_by(entity_type="threat_scenario", entity_id=created["id"]).one().action == "threat_model.scenario_created"
    updated = threat_model.update_scenario(created["id"], ThreatScenarioUpdate(review_status="draft", likelihood=4), analyst, db_session)
    assert updated["business_impact_score"] == 20
    assert db_session.query(Finding).filter_by(id=finding.id).one().severity == "critical"
    assert db_session.query(RiskAssessment).filter_by(investigation_id=investigation.id).one().score == 87.0
    assert db_session.query(ThreatScenario).filter_by(id=created["id"]).one().review_status == "draft"


def test_related_records_must_belong_to_same_asset_and_confirmed_requires_resolving_unknowns(db_session, scene):
    analyst, _viewer, asset, _investigation, finding, _incident, other_asset = scene
    with pytest.raises(HTTPException, match="selected asset") as mismatch:
        threat_model.create_scenario(ThreatScenarioCreate(asset_id=other_asset.id, finding_id=finding.id,
            stride_category="spoofing", title="Invalid cross-asset link", likelihood=2, business_impact=3, confidence=2), analyst, db_session)
    assert mismatch.value.status_code == 422
    with pytest.raises(HTTPException, match="unconfirmed") as uncertain:
        threat_model.create_scenario(ThreatScenarioCreate(asset_id=asset.id, stride_category="tampering",
            title="Unverified assertion", likelihood=2, business_impact=3, confidence=2,
            review_status="confirmed", unconfirmed_information=["The access path is not verified."]), analyst, db_session)
    assert uncertain.value.status_code == 422


def test_asset_threat_profile_is_audited_and_keeps_unknown_explicit(db_session, scene):
    analyst, _viewer, asset, *_ = scene
    result = threat_model.update_asset_profile(asset.id, ThreatProfileUpdate(criticality="high", data_classification="restricted",
        trust_zone="internal", exposure_classification="internet_facing", business_owner="Finance IT",
        protection_requirements=["MFA", "Encryption at rest"]), analyst, db_session)
    AssetThreatProfileOut.model_validate(result)
    assert result["criticality"] == "high" and result["business_owner"] == "Finance IT"
    assert result["protection_requirements"] == ["MFA", "Encryption at rest"]
    reset = threat_model.update_asset_profile(asset.id, ThreatProfileUpdate(criticality="unknown", data_classification="unknown",
        trust_zone="unknown", exposure_classification="unknown", business_owner=None, protection_requirements=[]), analyst, db_session)
    assert reset["criticality"] == "unknown" and reset["data_classification"] == "unknown"
    assert db_session.query(AuditEvent).filter_by(action="threat_model.asset_profile_updated").count() == 2


def test_investigation_report_adds_current_threat_context_without_rewriting_saved_report(db_session, scene):
    analyst, *_rest = scene
    asset, investigation = scene[2], scene[3]
    saved = Report(investigation_id=investigation.id, format="json", created_by=analyst.id, is_demo=True,
        snapshot_json={"previous": "immutable"}, content=b"previous report bytes", sha256="f" * 64)
    db_session.add(saved); db_session.commit()
    threat_model.update_asset_profile(asset.id, ThreatProfileUpdate(criticality="high", data_classification="restricted",
        trust_zone="internal", exposure_classification="internet_facing", protection_requirements=["MFA"]), analyst, db_session)
    threat_model.create_scenario(ThreatScenarioCreate(asset_id=asset.id, stride_category="denial_of_service",
        title="Availability loss during payroll close", likelihood=2, business_impact=5, confidence=3,
        assumptions=["Payroll close is time-sensitive."], unconfirmed_information=["Recovery time is unknown."]), analyst, db_session)
    snapshot = _investigation_snapshot(db_session, investigation)
    assert snapshot["threat_scenarios"][0]["business_impact_score"] == 10
    assert snapshot["threat_scenarios"][0]["unconfirmed_information"] == ["Recovery time is unknown."]
    assert snapshot["scope"]["threat_context"]["criticality"] == "high"
    assert snapshot["scope"]["threat_context"]["protection_requirements"] == ["MFA"]
    db_session.refresh(saved)
    assert saved.snapshot_json == {"previous": "immutable"} and saved.content == b"previous report bytes"


def test_viewer_can_read_but_cannot_write_threat_model(workspace):
    client, factory = workspace
    with factory() as db:
        admin = db.query(User).filter_by(username="admin").one()
        asset = Asset(kind="domain", identifier="viewer.example.test", normalized_identifier="viewer.example.test", created_by=admin.id)
        db.add(asset); db.commit(); asset_id = asset.id
    login(client, "viewer", "Test-Viewer-Password-2026!")
    response = client.post("/api/v1/threat-model/scenarios", headers=csrf(client), json={
        "asset_id": asset_id, "stride_category": "spoofing", "title": "Unauthorized impersonation",
        "likelihood": 2, "business_impact": 4, "confidence": 2,
    })
    assert response.status_code == 403
    profile = client.patch(f"/api/v1/threat-model/assets/{asset_id}", headers=csrf(client), json={})
    assert profile.status_code == 403
    assert client.get("/api/v1/threat-model/scenarios").status_code == 200
