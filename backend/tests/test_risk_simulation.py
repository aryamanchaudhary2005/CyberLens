from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from pydantic import ValidationError

from app.database import Base
from app.collectors.demo import demo_result
from app.models import (
    Asset,
    AuditEvent,
    CollectorRun,
    EvidenceSnapshot,
    Finding,
    Incident,
    Investigation,
    PlaybookTask,
    Report,
    RiskAssessment,
    RiskAssessmentRevision,
    User,
    new_id,
)
from app.routes.investigations import risk_simulation, risk_simulation_options
from app.schemas import RiskSimulationInput, RiskSimulationOptionOut, RiskSimulationOut
from app.services.risk_simulation import SimulationError, _header_control, _spf_dmarc_target, simulate_remediation, simulation_options


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


ACTION_CASES = [
    ("patch_applicable_cve", "vulnerabilities", "critical", "CVE-2024-1000 applicability candidate", "nvd_kev",
     {"cve_id": "CVE-2024-1000", "kev": True}, {"candidates": [{"cve_id": "CVE-2024-1000"}]}),
    ("fix_security_headers", "tls_web", "low", "Content Security Policy not observed", "web_tls",
     {}, {"security_headers": {"strict-transport-security": "max-age=31536000"}}),
    ("replace_expired_or_mismatched_certificate", "tls_web", "high", "TLS certificate requires review", "web_tls",
     {"expired": True, "hostname_match": True}, {"certificate": {"expired": True, "hostname_match": True}}),
    ("fix_spf_or_dmarc", "dns_email", "low", "DMARC policy is monitor only", "dns_rdap",
     {}, {"email_configuration": {"mx_present": True, "spf_present": True, "dmarc_present": True},
          "records": {"DMARC": {"status": "success", "values": ["v=DMARC1; p=none"]}}}),
    ("resolve_validated_reputation_finding", "reputation", "high", "Existing reputation report has adverse verdicts", "reputation",
     {"malicious": 3, "suspicious": 0, "asset_context": "direct"},
     {"asset_context": "direct", "analysis_stats": {"malicious": 3, "suspicious": 0}}),
    ("resolve_verified_breach_issue", "breach_exposure", "medium", "Historical email breach exposure found", "hibp",
     {"breach_count": 1}, {"breach_count": 1, "breaches": [{"name": "ExampleBreach"}]}),
]


def make_records(db: Session, *, case_index: int = 4, with_evidence: bool = True, with_snapshots: bool = False):
    action, category, severity, title, collector, details, evidence_data = ACTION_CASES[case_index]
    asset_identifier = f"simulation-{new_id()[:8]}.example.test"
    user = User(username=f"sim-user-{new_id()[:8]}", password_hash="unused", role="analyst")
    db.add(user)
    db.flush()
    asset = Asset(kind="domain", identifier=asset_identifier, normalized_identifier=asset_identifier,
                  created_by=user.id)
    db.add(asset)
    db.flush()
    investigation = Investigation(asset_id=asset.id, requested_by=user.id, mode="demo", scenario="suspicious_website",
                                  status="completed", progress=100)
    db.add(investigation)
    db.flush()
    run = CollectorRun(investigation_id=investigation.id, collector=collector, status="success", source=collector,
                       record_count=1)
    db.add(run)
    db.flush()
    evidence = EvidenceSnapshot(investigation_id=investigation.id, collector_run_id=run.id, source=f"Fixture {collector}",
                                evidence_json={**evidence_data, "provenance": {"status": "success"}},
                                sha256="a" * 64, is_synthetic=True)
    if with_evidence:
        db.add(evidence)
        db.flush()
    finding = Finding(
        asset_id=asset.id, investigation_id=investigation.id, evidence_id=evidence.id if with_evidence else None,
        fingerprint=(f"{case_index}" * 64)[:64], category=category, severity=severity, title=title,
        explanation="Saved synthetic finding used by a deterministic simulation test.", recommendation="Apply and verify the stated remediation.",
        source=f"Fixture {collector}", applicability="applies", details_json=details, is_synthetic=True,
    )
    db.add(finding)
    if with_snapshots:
        risk = RiskAssessment(investigation_id=investigation.id, version="cyberlens-academic-1.0", score=70,
                              band="high", weights_json={"reputation": 30}, assessed_categories=["reputation"],
                              excluded_categories=[], category_scores={"reputation": 70},
                              contributing_finding_ids=[finding.id], explanation_json={"rule_version": "cyberlens-academic-1.0"})
        db.add(risk)
        db.add(RiskAssessmentRevision(investigation_id=investigation.id, revision_number=1, input_fingerprint="b" * 64,
            version="cyberlens-academic-1.0", score=70, band="high", weights_json={"reputation": 30},
            assessed_categories=["reputation"], excluded_categories=[], category_scores={"reputation": 70},
            contributing_finding_ids=[finding.id], explanation_json={"rule_version": "cyberlens-academic-1.0"}))
        db.add(Report(investigation_id=investigation.id, format="json", created_by=user.id, is_demo=True,
                      snapshot_json={"finding": finding.id, "risk_score": 70}, content=b"saved report bytes", sha256="c" * 64))
        incident = Incident(title="Saved incident", summary="unchanged", asset_id=asset.id,
                            investigation_id=investigation.id, created_by=user.id)
        db.add(incident)
        db.flush()
        db.add(PlaybookTask(incident_id=incident.id, playbook_id="website", playbook_version="1", title="Remediation task",
                            description="Track an analyst action", stage="remediation", sort_order=0))
    db.flush()
    return investigation, finding


@pytest.mark.parametrize("case_index,case", enumerate(ACTION_CASES))
def test_all_explicit_remediation_actions_are_evidence_backed_and_deterministic(db_session, case_index, case):
    action = case[0]
    investigation, finding = make_records(db_session, case_index=case_index)
    first = simulate_remediation(db_session, investigation, action, finding.id)
    second = simulate_remediation(db_session, investigation, action, finding.id)
    assert first == second
    assert first["action"] == action
    assert first["affected"]["finding_id"] == finding.id
    assert first["affected"]["evidence_id"] == finding.evidence_id
    assert first["risk_policy_version"] == "cyberlens-academic-1.0"
    assert first["baseline"]["score"] is not None
    assert first["projected"]["score"] <= first["baseline"]["score"]
    assert len(first["assumptions"]) == 5
    assert any("hypothetical" in item for item in first["assumptions"])


def test_xposedornot_simulation_requires_explicitly_verified_source_evidence(db_session):
    investigation, finding = make_records(db_session, case_index=5)
    run = db_session.query(CollectorRun).filter_by(investigation_id=investigation.id).one()
    evidence = db_session.get(EvidenceSnapshot, finding.evidence_id)
    investigation.email_breach_provider = "xposedornot"
    run.collector = "xposedornot"
    run.source = "XposedOrNot community API"
    finding.source = "XposedOrNot community API"
    evidence.source = "XposedOrNot community API"
    evidence.evidence_json = {"records": [{"record_id": "synthetic-1", "verified": True}],
                              "verified_record_count": 1, "provenance": {"status": "success"}}
    finding.details_json = {"breach_count": 1}
    verified = simulate_remediation(db_session, investigation, "resolve_verified_breach_issue", finding.id)
    assert verified["affected"]["evidence_id"] == evidence.id

    evidence.evidence_json = {"records": [{"record_id": "synthetic-1", "verified": None}],
                              "verified_record_count": 0, "provenance": {"status": "success"}}
    with pytest.raises(SimulationError, match="evidence"):
        simulate_remediation(db_session, investigation, "resolve_verified_breach_issue", finding.id)


def test_simulation_route_returns_typed_projection_and_does_not_mutate_saved_records(db_session):
    investigation, finding = make_records(db_session, with_snapshots=True)
    evidence = db_session.get(EvidenceSnapshot, finding.evidence_id)
    report = db_session.query(Report).filter_by(investigation_id=investigation.id).one()
    risk = db_session.query(RiskAssessment).filter_by(investigation_id=investigation.id).one()
    revision = db_session.query(RiskAssessmentRevision).filter_by(investigation_id=investigation.id).one()
    incident = db_session.query(Incident).filter_by(investigation_id=investigation.id).one()
    task = db_session.query(PlaybookTask).filter_by(incident_id=incident.id).one()
    before = {
        "investigation": (investigation.status, investigation.progress, investigation.error_summary, investigation.finished_at),
        "finding": (finding.applicability, deepcopy(finding.details_json), finding.evidence_id),
        "evidence": (deepcopy(evidence.evidence_json), evidence.sha256),
        "report": (deepcopy(report.snapshot_json), report.content, report.sha256),
        "risk": (risk.score, deepcopy(risk.explanation_json)),
        "revision": (revision.revision_number, revision.score, deepcopy(revision.explanation_json)),
        "incident": (incident.status, incident.summary),
        "task": (task.status, task.notes),
    }
    tables = (Finding, EvidenceSnapshot, RiskAssessment, RiskAssessmentRevision, Report, Incident, PlaybookTask, AuditEvent)
    row_counts = {model: db_session.query(model).count() for model in tables}
    payload = RiskSimulationInput(action="resolve_validated_reputation_finding", finding_id=finding.id)
    result = risk_simulation(investigation.id, payload, db_session.get(User, investigation.requested_by), db_session)
    RiskSimulationOut.model_validate(result)
    assert result["baseline"]["score"] == risk.score
    options = risk_simulation_options(investigation.id, db_session.get(User, investigation.requested_by), db_session)
    assert options[0]["finding_id"] == finding.id
    RiskSimulationOptionOut.model_validate(options[0])
    db_session.expire_all()
    finding = db_session.get(Finding, finding.id)
    evidence = db_session.get(EvidenceSnapshot, evidence.id)
    report = db_session.get(Report, report.id)
    risk = db_session.get(RiskAssessment, risk.id)
    revision = db_session.get(RiskAssessmentRevision, revision.id)
    incident = db_session.get(Incident, incident.id)
    task = db_session.get(PlaybookTask, task.id)
    after = {
        "investigation": (db_session.get(Investigation, investigation.id).status,
                          db_session.get(Investigation, investigation.id).progress,
                          db_session.get(Investigation, investigation.id).error_summary,
                          db_session.get(Investigation, investigation.id).finished_at),
        "finding": (finding.applicability, finding.details_json, finding.evidence_id),
        "evidence": (evidence.evidence_json, evidence.sha256),
        "report": (report.snapshot_json, report.content, report.sha256),
        "risk": (risk.score, risk.explanation_json),
        "revision": (revision.revision_number, revision.score, revision.explanation_json),
        "incident": (incident.status, incident.summary),
        "task": (task.status, task.notes),
    }
    assert before == after
    assert row_counts == {model: db_session.query(model).count() for model in tables}
    assert not db_session.new
    assert not db_session.dirty
    assert not db_session.deleted


def test_invalid_action_and_missing_evidence_are_rejected(db_session):
    investigation, finding = make_records(db_session)
    with pytest.raises(SimulationError, match="Unsupported"):
        simulate_remediation(db_session, investigation, "delete_database", finding.id)
    with pytest.raises(ValidationError):
        RiskSimulationInput(action="delete_database", finding_id=finding.id)
    no_evidence_investigation, no_evidence_finding = make_records(db_session, with_evidence=False)
    with pytest.raises(SimulationError, match="evidence snapshot"):
        simulate_remediation(db_session, no_evidence_investigation, "resolve_validated_reputation_finding", no_evidence_finding.id)


def test_action_category_and_evidence_must_match(db_session):
    investigation, finding = make_records(db_session, case_index=1)
    with pytest.raises(SimulationError, match="not supported"):
        simulate_remediation(db_session, investigation, "replace_expired_or_mismatched_certificate", finding.id)


def test_applicability_review_is_required_before_cve_patch_simulation(db_session):
    investigation, finding = make_records(db_session, case_index=0)
    finding.applicability = "needs_review"
    with pytest.raises(SimulationError, match="Only applicable"):
        simulate_remediation(db_session, investigation, "patch_applicable_cve", finding.id)


def test_demo_header_and_dmarc_findings_match_their_saved_evidence():
    asset = SimpleNamespace(kind="domain", identifier="routine.example.test")
    website = demo_result(asset, "routine_website", "web_tls")
    header_finding = next(item for item in website.findings if "Content Security Policy" in item["title"])
    assert _header_control(header_finding["title"], website.evidence["security_headers"]) == "content-security-policy"
    dns = demo_result(asset, "routine_website", "dns_rdap")
    dmarc_finding = next(item for item in dns.findings if "DMARC" in item["title"])
    assert _spf_dmarc_target(dmarc_finding["title"], dns.evidence) == "DMARC"
