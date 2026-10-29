from app import jobs
from app.models import RiskAssessmentRevision
from app.services.risk import RiskFindingRecord, score_records, sensitivity_analysis
from conftest import csrf, login


ALL_SUCCESS = {"nvd_kev": "success", "reputation": "success", "web_tls": "success", "hibp": "success", "dns_rdap": "success"}


def finding(identifier: str, category: str, severity: str, *, applicability: str = "applies", kev: bool = False) -> RiskFindingRecord:
    return RiskFindingRecord(id=identifier, fingerprint=identifier, category=category, severity=severity,
                             applicability=applicability, details={"kev": kev}, source=f"fixture:{category}")


def test_golden_policy_v1_score_and_explanation():
    result = score_records([
        finding("v", "vulnerabilities", "high"), finding("r", "reputation", "medium"),
        finding("w", "tls_web", "low"), finding("b", "breach_exposure", "informational"),
    ], ALL_SUCCESS)
    # (35*70 + 30*45 + 15*20 + 10*0 + 10*0) / 100 = 35.5; the high floor is 50.
    assert result["score"] == 50
    assert result["band"] == "high"
    assert result["version"] == "cyberlens-academic-1.0"
    assert result["contributing_finding_ids"] == ["b", "r", "v", "w"]
    assert result["explanation"]["rule_version"] == result["version"]
    assert "No calibration claim" in result["explanation"]["calibration_notice"]


def test_score_is_deterministic_and_duplicate_findings_do_not_inflate_it():
    records = [finding("a", "reputation", "medium"), RiskFindingRecord(id="duplicate", fingerprint="a", category="reputation", severity="medium", source="fixture:reputation")]
    first = score_records(records, {"reputation": "success"})
    second = score_records(list(reversed(records)), {"reputation": "success"})
    assert first == second
    assert first["score"] == 45
    assert len(first["contributing_finding_ids"]) == 1


def test_higher_severity_is_monotonic_and_unknown_severity_is_ignored():
    scores = [score_records([finding("x", "reputation", severity)], {"reputation": "success"})["score"]
              for severity in ("low", "medium", "high", "critical")]
    assert scores == sorted(scores)
    unknown = score_records([finding("x", "reputation", "not-a-severity")], {"reputation": "success"})
    assert unknown["score"] == 0
    assert unknown["contributing_finding_ids"] == []


def test_category_coverage_and_missing_data_are_explicit_not_safe():
    result = score_records([finding("x", "reputation", "high")], {"reputation": "unavailable"})
    assert result["score"] is None
    assert result["band"] == "insufficient_data"
    assert "reputation" in result["excluded_categories"]
    assert result["explanation"]["coverage"]["reputation"]["covered"] is False


def test_only_confirmed_applicable_kev_vulnerability_affects_vulnerability_category():
    candidate = score_records([finding("candidate", "vulnerabilities", "critical", applicability="needs_review", kev=True)], {"nvd_kev": "success"})
    confirmed = score_records([finding("confirmed", "vulnerabilities", "critical", kev=True)], {"nvd_kev": "success"})
    assert candidate["score"] == 0
    assert candidate["contributing_finding_ids"] == []
    assert confirmed["score"] >= 90
    assert confirmed["contributing_finding_ids"] == ["confirmed"]


def test_sensitivity_analysis_returns_explicit_category_variants():
    result = sensitivity_analysis([finding("x", "reputation", "high"), finding("y", "dns_email", "low")],
                                  {"reputation": "success", "dns_rdap": "success"})
    assert result["baseline_score"] is not None
    assert {item["category"] for item in result["variants"]} == {"vulnerabilities", "reputation", "tls_web", "breach_exposure", "dns_email"}


def test_assessment_revisions_are_immutable_and_reports_keep_snapshot(workspace, monkeypatch):
    client, factory = workspace
    login(client)
    monkeypatch.setattr(jobs, "SessionLocal", factory)
    asset = client.post("/api/v1/assets", headers=csrf(client), json={"kind": "application", "identifier": "Revision app"}).json()
    started = client.post("/api/v1/investigations", headers=csrf(client), json={"asset_id": asset["id"], "scenario": "vulnerable_application"})
    assert started.status_code == 202, started.text
    investigation_id = started.json()["id"]
    jobs.run_investigation(investigation_id)
    detail = client.get(f"/api/v1/investigations/{investigation_id}").json()
    report = client.post("/api/v1/reports", headers=csrf(client), json={"format": "json", "investigation_id": investigation_id})
    assert report.status_code == 201, report.text
    saved_report = client.get(f"/api/v1/reports/{report.json()['id']}").json()
    before = saved_report["snapshot"]
    before_hash = saved_report["sha256"]
    with factory() as db:
        assert db.query(RiskAssessmentRevision).filter_by(investigation_id=investigation_id).count() == 1
        first_revision = db.query(RiskAssessmentRevision).filter_by(investigation_id=investigation_id).one()
        first_score = first_revision.score
    kev = next(item for item in detail["findings"] if item["details_json"].get("kev"))
    decision = client.patch(f"/api/v1/findings/{kev['id']}/applicability", headers=csrf(client),
                            json={"applicability": "applies", "reason": "Confirmed against selected inventory."})
    assert decision.status_code == 200, decision.text
    with factory() as db:
        revisions = db.query(RiskAssessmentRevision).filter_by(investigation_id=investigation_id).order_by(RiskAssessmentRevision.revision_number).all()
        assert len(revisions) == 2
        assert revisions[0].score == first_score
        assert revisions[0].explanation_json["rule_version"] == "cyberlens-academic-1.0"
        revision_ids = [item.id for item in revisions]
    assert client.get(f"/api/v1/investigations/{investigation_id}/risk/revisions").status_code == 200
    assert client.get(f"/api/v1/investigations/{investigation_id}/risk/sensitivity").status_code == 200
    after_report = client.get(f"/api/v1/reports/{report.json()['id']}").json()
    after = after_report["snapshot"]
    assert before == after
    assert after_report["sha256"] == before_hash
    with factory() as db:
        assert [item.id for item in db.query(RiskAssessmentRevision).filter_by(investigation_id=investigation_id).order_by(RiskAssessmentRevision.revision_number).all()] == revision_ids
