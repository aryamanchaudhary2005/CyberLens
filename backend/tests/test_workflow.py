import hashlib
import json

from app import jobs
from app.collectors.demo import demo_result
from app.models import Asset, CollectorRun, Finding, Investigation, User
from conftest import csrf, login


def test_complete_application_investigation_case_and_report(workspace, monkeypatch):
    client, factory = workspace
    login(client)
    monkeypatch.setattr(jobs, "SessionLocal", factory)

    created = client.post("/api/v1/assets", headers=csrf(client), json={"kind": "application", "identifier": "Demo portal", "notes": "Synthetic inventory"})
    assert created.status_code == 201, created.text
    asset_id = created.json()["id"]
    component = client.post(f"/api/v1/assets/{asset_id}/components", headers=csrf(client),
        json={"vendor": "Apache", "product": "HTTP Server", "version": "2.4.49"})
    assert component.status_code == 201, component.text

    started = client.post("/api/v1/investigations", headers=csrf(client),
        json={"asset_id": asset_id, "scenario": "vulnerable_application"})
    assert started.status_code == 202, started.text
    investigation_id = started.json()["id"]
    jobs.run_investigation(investigation_id)
    detail = client.get(f"/api/v1/investigations/{investigation_id}").json()
    assert detail["status"] == "completed"
    assert detail["demo_data"] is True
    assert len(detail["findings"]) == 4
    kev = next(item for item in detail["findings"] if item["details_json"].get("kev"))
    assert kev["applicability"] == "needs_review"
    assert detail["risk"]["score"] == 0

    decision = client.patch(f"/api/v1/findings/{kev['id']}/applicability", headers=csrf(client),
        json={"applicability": "applies", "reason": "Confirmed the version matches the affected range."})
    assert decision.status_code == 200, decision.text
    detail = client.get(f"/api/v1/investigations/{investigation_id}").json()
    assert detail["risk"]["score"] >= 90
    assert detail["risk"]["band"] == "critical"

    case = client.post("/api/v1/incidents", headers=csrf(client), json={"title": kev["title"], "summary": "Review confirmed candidate",
        "asset_id": asset_id, "investigation_id": investigation_id, "finding_ids": [kev["id"]], "priority": "critical", "classification": "security_issue"})
    assert case.status_code == 201, case.text
    case_id = case.json()["id"]
    assert len(case.json()["tasks"]) == 5
    first_task = case.json()["tasks"][0]
    completed = client.patch(f"/api/v1/incidents/{case_id}/tasks/{first_task['id']}", headers=csrf(client),
        json={"status": "completed", "notes": "Validated the installed inventory."})
    assert completed.status_code == 200, completed.text
    assert completed.json()["completed_by"] == "admin"

    for status in ("triaged", "responding", "resolved"):
        response = client.patch(f"/api/v1/incidents/{case_id}", headers=csrf(client), json={"status": status,
            **({"resolution_summary": "Updated to a fixed release and verified the inventory."} if status == "resolved" else {})})
        assert response.status_code == 200, response.text
    closed = client.patch(f"/api/v1/incidents/{case_id}", headers=csrf(client), json={"status": "closed"})
    assert closed.status_code == 200, closed.text
    reopened = client.patch(f"/api/v1/incidents/{case_id}", headers=csrf(client), json={"status": "triaged", "reason": "A new vendor advisory requires revalidation."})
    assert reopened.status_code == 200, reopened.text
    assert any(event["event_type"] == "reopened" for event in reopened.json()["events"])

    exported = client.post("/api/v1/reports", headers=csrf(client), json={"format": "json", "investigation_id": investigation_id})
    assert exported.status_code == 201, exported.text
    report = exported.json()
    assert report["is_demo"] is True
    downloaded = client.get(f"/api/v1/reports/{report['id']}/download")
    assert downloaded.status_code == 200
    assert downloaded.headers["x-content-sha256"] == hashlib.sha256(downloaded.content).hexdigest()
    snapshot = json.loads(downloaded.content)
    assert snapshot["report_label"].startswith("DEMO DATA")
    assert len(snapshot["findings"]) == 4
    incident_export = client.post("/api/v1/reports", headers=csrf(client), json={"format": "pdf", "incident_id": case_id})
    assert incident_export.status_code == 201, incident_export.text
    pdf = client.get(f"/api/v1/reports/{incident_export.json()['id']}/download")
    assert pdf.status_code == 200
    assert pdf.content.startswith(b"%PDF-")


def test_provider_outage_produces_partial_without_inventing_provider_verdict(workspace, monkeypatch):
    client, factory = workspace
    login(client)
    monkeypatch.setattr(jobs, "SessionLocal", factory)
    asset = client.post("/api/v1/assets", headers=csrf(client), json={"kind": "domain", "identifier": "outage.example.test"}).json()
    started = client.post("/api/v1/investigations", headers=csrf(client), json={"asset_id": asset["id"], "scenario": "provider_outage"})
    assert started.status_code == 202, started.text
    jobs.run_investigation(started.json()["id"])
    detail = client.get(f"/api/v1/investigations/{started.json()['id']}").json()
    assert detail["status"] == "partial"
    reputation = next(row for row in detail["collector_runs"] if row["collector"] == "reputation")
    assert reputation["status"] == "unavailable"
    assert "Synthetic provider outage" in reputation["error_explanation"]
    assert all(row["source"] != "VirusTotal" for row in detail["findings"])
    before_count = len(detail["findings"])
    retry = client.post(f"/api/v1/investigations/{started.json()['id']}/retry", headers=csrf(client))
    assert retry.status_code == 202, retry.text
    jobs.run_investigation(started.json()["id"])
    retried = client.get(f"/api/v1/investigations/{started.json()['id']}").json()
    assert retried["status"] == "partial"
    assert len(retried["findings"]) == before_count
    assert any(row["details_json"].get("additional_evidence_ids") for row in retried["findings"])


def test_viewer_cannot_change_applicability(workspace, monkeypatch):
    client, factory = workspace
    login(client)
    db = factory()
    admin = db.query(User).filter_by(username="admin").one()
    asset = Asset(kind="application", identifier="Reader test", normalized_identifier="reader test", created_by=admin.id)
    db.add(asset); db.flush()
    investigation = Investigation(asset_id=asset.id, requested_by=admin.id, mode="demo", scenario="vulnerable_application", status="completed")
    db.add(investigation); db.flush()
    run = CollectorRun(investigation_id=investigation.id, collector="nvd_kev", status="success", source="fixture")
    db.add(run); db.flush()
    finding = Finding(asset_id=asset.id, investigation_id=investigation.id, fingerprint="a" * 64, category="vulnerabilities",
        severity="high", title="Candidate", explanation="Review this candidate.", recommendation="Confirm inventory.", source="fixture", applicability="needs_review")
    db.add(finding); db.commit(); finding_id = finding.id; db.close()
    client.post("/api/v1/auth/logout", headers=csrf(client))
    login(client, "viewer", "Test-Viewer-Password-2026!")
    response = client.patch(f"/api/v1/findings/{finding_id}/applicability", headers=csrf(client),
        json={"applicability": "applies", "reason": "Confirmed manually"})
    assert response.status_code == 403


def test_reports_require_authentication(workspace):
    client, _factory = workspace
    response = client.get("/api/v1/reports")
    assert response.status_code == 401


def test_demo_reset_preserves_live_records_and_refuses_live_mode(workspace, monkeypatch):
    from types import SimpleNamespace
    from app import cli

    _client, factory = workspace
    db = factory()
    admin = db.query(User).filter_by(username="admin").one()
    asset = Asset(kind="domain", identifier="live.example.test", normalized_identifier="live.example.test",
        is_synthetic=True, created_by=admin.id)
    db.add(asset); db.flush()
    investigation = Investigation(asset_id=asset.id, requested_by=admin.id, mode="live", status="completed")
    db.add(investigation); db.commit()
    monkeypatch.setattr(cli, "get_settings", lambda: SimpleNamespace(app_mode="live"))
    try:
        cli.reset_demo(db)
    except RuntimeError as exc:
        assert "APP_MODE=demo" in str(exc)
    else:
        raise AssertionError("Live-mode reset should be refused")
    monkeypatch.setattr(cli, "get_settings", lambda: SimpleNamespace(app_mode="demo"))
    cli.reset_demo(db)
    assert db.get(Asset, asset.id) is not None
    assert db.get(Investigation, investigation.id) is not None
    db.close()


def test_bootstrap_keeps_existing_live_admin_without_secret(workspace, monkeypatch):
    from types import SimpleNamespace
    from app import bootstrap

    _client, factory = workspace
    monkeypatch.setattr(bootstrap, "get_settings", lambda: SimpleNamespace(app_mode="live", bootstrap_admin_password=None, bootstrap_admin_username="admin"))
    monkeypatch.setattr(bootstrap, "SessionLocal", factory)
    bootstrap.main()
    db = factory()
    assert db.query(User).filter_by(username="admin").count() == 1
    db.query(User).delete(); db.commit(); db.close()
    try:
        bootstrap.main()
    except RuntimeError as exc:
        assert "first startup in live mode" in str(exc)
    else:
        raise AssertionError("Fresh live workspace should require a bootstrap password")


def test_demo_fixtures_never_use_external_network(monkeypatch):
    from app import network
    monkeypatch.setattr(network, "safe_get", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("network access")))
    asset = type("AssetFixture", (), {"kind": "application", "identifier": "Example app"})()
    result = demo_result(asset, "vulnerable_application", "nvd_kev")
    assert result.status == "success"
    assert result.evidence["demo_data"] is True
    assert {item["details"]["fixture_case"] for item in result.findings} == {
        "affected_version", "unaffected_installed_version", "ambiguous_configuration", "unknown_severity"}
