import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import jobs
from app.collectors import nvd, osv
from app.collectors.types import CollectorResult
from app.database import Base
from app.models import Asset, Finding, Investigation, Report, RiskAssessment, SoftwareComponent, User, new_id
from app.network import OutboundTimeout, SafeResponse
from app.osv import osv_finding_payload
from app.package_names import normalize_package_name
from app.routes.reports import _finding as report_finding, _pdf_bytes
from app.schemas import ComponentCreate, OsvFindingOut
from app.services.risk import RiskFindingRecord, score_records

FIXTURE = Path(__file__).parent / "fixtures" / "providers" / "osv_query.json"


class FakeRedis:
    def __init__(self):
        self.values = {}
        self.limit = 0
        self.closed = False

    def get(self, key):
        return self.values.get(key)

    def setex(self, key, _ttl, value):
        self.values[key] = value

    def delete(self, key):
        return int(self.values.pop(key, None) is not None)

    def eval(self, _script, _count, _key, _window):
        self.limit += 1
        return self.limit

    def close(self):
        self.closed = True


def settings(mode="live"):
    return SimpleNamespace(app_mode=mode, redis_url="redis://unused", collector_timeout_seconds=3)


def response(payload, status=200):
    return SafeResponse(status, {}, json.dumps(payload).encode("utf-8"), osv.OSV_ENDPOINT, [])


def test_ecosystem_package_names_are_canonical_and_invalid_names_are_rejected():
    assert normalize_package_name("npm", "@Scope/Widget") == "@scope/widget"
    assert normalize_package_name("PyPI", "My_Package.Name") == "my-package-name"
    with pytest.raises(ValueError):
        normalize_package_name("npm", "scope/widget")
    with pytest.raises(ValueError):
        normalize_package_name("PyPI", "invalid package")
    with pytest.raises(ValueError):
        ComponentCreate(vendor="Vendor", product="Product", version="1.2.3", package_ecosystem="npm")
    component = ComponentCreate(vendor="Vendor", product="Product", version="1.2.3",
                                package_ecosystem="PyPI", package_name="My_Package")
    assert component.package_name == "my-package"


def test_osv_api_and_report_projection_keep_advisory_provenance():
    details = {"advisory_id": "OSV-DEMO-1", "aliases": ["CVE-2026-10001"],
        "package": {"ecosystem": "npm", "name": "widget", "version": "1.2.3"},
        "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}]}]}],
        "fixed_versions": ["1.2.4"], "references": [{"type": "ADVISORY", "url": "https://example.test/advisory"}],
        "severity_metadata": [], "published": None, "modified": None, "withdrawn": None,
        "observed_at": "2026-10-19T00:00:00+00:00", "provider_status": "success",
        "freshness": "observed", "provider_version": osv.OSV_VERSION, "advisory_status": "active"}
    projection = osv_finding_payload(details, "saved-evidence-id")
    assert OsvFindingOut.model_validate(projection).evidence_id == "saved-evidence-id"
    projected = report_finding(SimpleNamespace(
        id="finding-id", category="vulnerabilities", severity="unknown", title="OSV candidate",
        explanation="Review", recommendation="Review applicability", source="OSV.dev",
        observed_at=None, applicability="needs_review", applicability_reason=None, is_synthetic=False,
        details_json=details, evidence_id="saved-evidence-id", epss_score=None, epss_percentile=None,
        epss_observed_at=None, epss_provider_status=None, epss_freshness=None))
    assert projected["osv"]["advisory_id"] == "OSV-DEMO-1"
    assert projected["osv"]["fixed_versions"] == ["1.2.4"]
    assert projected["osv"]["evidence_id"] == "saved-evidence-id"
    pdf = _pdf_bytes({"report_type": "investigation", "created_at": "2026-10-19T00:00:00+00:00",
                      "findings": [projected]})
    assert pdf.startswith(b"%PDF-")


def test_lookup_sends_only_normalized_package_and_explicit_version_and_parses_advisories(monkeypatch):
    redis = FakeRedis()
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    calls = []
    monkeypatch.setattr(osv, "get_settings", settings)
    monkeypatch.setattr(osv, "_redis_client", lambda: redis)
    monkeypatch.setattr(osv, "safe_post_json", lambda url, body, **kwargs:
        (calls.append((url, body, kwargs)) or response(payload)))

    result = osv.lookup_package("npm", "@Scope/Widget", "1.0.2")
    assert result["provider_status"] == "success"
    assert result["freshness"] == "observed"
    assert len(result["advisories"]) == 2
    assert result["advisories"][0]["severity"] == "high"
    assert result["advisories"][0]["fixed_versions"] == ["1.0.4"]
    assert result["advisories"][0]["aliases"] == ["CVE-2025-12345"]
    assert result["advisories"][1]["advisory_status"] == "withdrawn"
    assert calls[0][0] == "https://api.osv.dev/v1/query"
    assert calls[0][1] == {"package": {"ecosystem": "npm", "name": "@scope/widget"}, "version": "1.0.2"}
    assert "vendor" not in calls[0][1] and "product" not in calls[0][1]
    assert calls[0][2]["max_redirects"] == 0
    assert redis.closed


def test_unaffected_version_is_an_explicit_no_match(monkeypatch):
    redis = FakeRedis()
    calls = []
    monkeypatch.setattr(osv, "get_settings", settings)
    monkeypatch.setattr(osv, "_redis_client", lambda: redis)
    monkeypatch.setattr(osv, "safe_post_json", lambda _url, body, **_kwargs:
        (calls.append(body) or response({"vulns": []})))
    result = osv.lookup_package("PyPI", "demo_package", "9.9.9")
    assert result["provider_status"] == "no_match"
    assert result["advisories"] == []
    assert calls[0]["package"] == {"ecosystem": "PyPI", "name": "demo-package"}
    assert calls[0]["version"] == "9.9.9"


def test_missing_or_unsupported_severity_remains_unknown(monkeypatch):
    redis = FakeRedis()
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    payload["vulns"][0]["affected"][0].pop("database_specific")
    monkeypatch.setattr(osv, "get_settings", settings)
    monkeypatch.setattr(osv, "_redis_client", lambda: redis)
    monkeypatch.setattr(osv, "safe_post_json", lambda *_args, **_kwargs: response(payload))
    result = osv.lookup_package("npm", "@scope/widget", "1.0.2")
    assert result["advisories"][0]["severity"] == "unknown"
    assert result["advisories"][0]["severity_metadata"] == [{
        "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]


def test_withdrawn_advisories_are_kept_in_evidence_but_not_created_as_findings(monkeypatch):
    redis = FakeRedis()
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    monkeypatch.setattr(osv, "get_settings", settings)
    monkeypatch.setattr(osv, "_redis_client", lambda: redis)
    monkeypatch.setattr(osv, "safe_post_json", lambda *_args, **_kwargs: response(payload))
    component = SimpleNamespace(id="component-1", package_ecosystem="npm", package_name="@scope/widget", version="1.0.2")
    result = osv.collect_osv(SimpleNamespace(kind="application"), [component])
    assert result.status == "success"
    assert len(result.findings) == 1
    assert result.findings[0]["applicability"] == "needs_review"
    assert len(result.evidence["advisories"]) == 2
    assert result.evidence["advisories"][1]["advisory_status"] == "withdrawn"


def test_provider_cache_is_scoped_and_reuses_only_complete_results(monkeypatch):
    redis = FakeRedis()
    calls = []
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    monkeypatch.setattr(osv, "get_settings", settings)
    monkeypatch.setattr(osv, "_redis_client", lambda: redis)
    monkeypatch.setattr(osv, "safe_post_json", lambda *_args, **_kwargs:
        (calls.append(True) or response(payload)))
    first = osv.lookup_package("npm", "@scope/widget", "1.0.2")
    second = osv.lookup_package("npm", "@scope/widget", "1.0.2")
    assert len(calls) == 1
    assert first["cache_state"] == "miss"
    assert second["cache_state"] == "hit"
    assert second["freshness"] == "cached"
    assert next(iter(redis.values)).startswith("cyberlens:provider:osv:package:")


def test_pagination_is_bounded_and_limit_produces_partial_coverage(monkeypatch):
    redis = FakeRedis()
    calls = []
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    monkeypatch.setattr(osv, "get_settings", settings)
    monkeypatch.setattr(osv, "_redis_client", lambda: redis)
    monkeypatch.setattr(osv, "OSV_MAX_PAGES_PER_PACKAGE", 2)
    monkeypatch.setattr(osv, "safe_post_json", lambda _url, body, **_kwargs:
        (calls.append(body) or response({"vulns": payload["vulns"][:1], "next_page_token": f"page-{len(calls)}"})))
    result = osv.lookup_package("npm", "@scope/widget", "1.0.2")
    assert len(calls) == 2
    assert calls[0].get("page_token") is None
    assert calls[1]["page_token"] == "page-1"
    assert result["provider_status"] == "partial"
    assert result["partial_result"] is True
    assert result["pages"] == 2
    assert redis.values == {}

    monkeypatch.setattr(osv, "OSV_MAX_ADVISORIES", 1)
    monkeypatch.setattr(osv, "safe_post_json", lambda *_args, **_kwargs: response(payload))
    limited = osv.lookup_package("npm", "@scope/widget", "1.0.2")
    assert len(limited["advisories"]) == 1
    assert limited["provider_status"] == "partial"
    assert limited["partial_result"] is True


def test_malformed_response_is_failed_and_not_cached(monkeypatch):
    redis = FakeRedis()
    monkeypatch.setattr(osv, "get_settings", settings)
    monkeypatch.setattr(osv, "_redis_client", lambda: redis)
    monkeypatch.setattr(osv, "safe_post_json", lambda *_args, **_kwargs: response({"vulns": "invalid"}))
    result = osv.lookup_package("npm", "@scope/widget", "1.0.2")
    assert result["provider_status"] == "failed"
    assert result["error"] == "malformed_vulns_list"
    assert redis.values == {}


def test_timeout_retries_are_bounded_and_cancellation_status_is_visible(monkeypatch):
    redis = FakeRedis()
    calls = []

    def timeout(*_args, **_kwargs):
        calls.append(True)
        raise OutboundTimeout("fixture deadline exceeded")

    monkeypatch.setattr(osv, "get_settings", settings)
    monkeypatch.setattr(osv, "_redis_client", lambda: redis)
    monkeypatch.setattr(osv, "safe_post_json", timeout)
    monkeypatch.setattr(osv.time, "sleep", lambda _delay: None)
    result = osv.lookup_package("npm", "@scope/widget", "1.0.2")
    assert len(calls) == osv.OSV_TRANSIENT_RETRIES + 1
    assert result["provider_status"] == "unavailable"
    assert result["error"] == "timeout"


def test_transient_server_error_retries_but_quota_does_not(monkeypatch):
    redis = FakeRedis()
    calls = []
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    monkeypatch.setattr(osv, "get_settings", settings)
    monkeypatch.setattr(osv, "_redis_client", lambda: redis)
    monkeypatch.setattr(osv.time, "sleep", lambda _delay: None)

    def transient(_url, _body, **_kwargs):
        calls.append(True)
        return response({}, 503) if len(calls) == 1 else response(payload)

    monkeypatch.setattr(osv, "safe_post_json", transient)
    result = osv.lookup_package("npm", "@scope/widget", "1.0.2")
    assert result["provider_status"] == "success"
    assert len(calls) == 2

    redis = FakeRedis()
    calls.clear()
    monkeypatch.setattr(osv, "_redis_client", lambda: redis)
    monkeypatch.setattr(osv, "safe_post_json", lambda *_args, **_kwargs:
        (calls.append(True) or response({}, 429)))
    result = osv.lookup_package("npm", "@scope/widget", "1.0.2")
    assert result["provider_status"] == "quota_limited"
    assert len(calls) == 1

    monkeypatch.setattr(osv, "lookup_package", lambda *_args, **_kwargs: {
        "provider_status": "quota_limited", "advisories": [], "observed_at": "2026-10-19T00:00:00+00:00",
        "cache_state": "miss", "error": "local_rate_limit"})
    package = SimpleNamespace(id="component-id", package_ecosystem="npm", package_name="widget", version="1.0.2")
    collected = osv.collect_osv(SimpleNamespace(kind="application"), [package])
    assert collected.status == "quota_limited"
    assert collected.evidence["components"][0]["status"] == "quota_limited"


def test_shared_rate_limit_blocks_requests_and_invalid_input_never_touches_provider(monkeypatch):
    redis = FakeRedis()
    redis.limit = 1
    calls = []
    monkeypatch.setattr(osv, "get_settings", settings)
    monkeypatch.setattr(osv, "_redis_client", lambda: redis)
    monkeypatch.setattr(osv, "OSV_MAX_REQUESTS_PER_WINDOW", 1)
    monkeypatch.setattr(osv, "safe_post_json", lambda *_args, **_kwargs: calls.append(True))
    limited = osv.lookup_package("npm", "@scope/widget", "1.0.2")
    assert limited["provider_status"] == "quota_limited"
    assert not calls
    with pytest.raises(ValueError):
        osv.lookup_package("npm", "not a package", "1.0.2")
    assert not calls


def test_demo_mode_uses_fixture_without_redis_or_network(monkeypatch):
    monkeypatch.setattr(osv, "get_settings", lambda: settings("demo"))
    monkeypatch.setattr(osv, "_redis_client", lambda: pytest.fail("Redis touched by Demo OSV path"))
    monkeypatch.setattr(osv, "safe_post_json", lambda *_args, **_kwargs: pytest.fail("OSV network request in Demo"))
    component = SimpleNamespace(id="demo-component", package_ecosystem="npm",
                                package_name="cyberlens-demo-widget", version="1.0.0")
    result = jobs._run_collector("osv", SimpleNamespace(kind="application", identifier="Demo"),
                                 [component], "demo", "vulnerable_application", False)
    assert result.status == "success"
    assert result.findings[0]["applicability"] == "needs_review"
    assert result.findings[0]["details"]["provider_status"] == "synthetic"
    assert result.evidence["demo_data"] is True


def test_live_failure_never_substitutes_demo_osv_results(monkeypatch):
    monkeypatch.setattr(jobs, "collect_osv", lambda *_args: CollectorResult(
        status="failed", source="OSV.dev", evidence={"provider_status": "failed"}))
    monkeypatch.setattr(jobs, "demo_result", lambda *_args, **_kwargs: pytest.fail("Live OSV failure replaced by Demo"))
    result = jobs._run_collector("osv", SimpleNamespace(kind="application"), [], "live", None, False)
    assert result.status == "failed"


def test_cpe_only_software_inventory_still_runs_nvd_without_osv(monkeypatch):
    component = SimpleNamespace(id="cpe-only", vendor="Apache", product="HTTP Server", version="2.4.49",
                                cpe_name="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
                                package_ecosystem=None, package_name=None)
    monkeypatch.setattr(nvd, "cpe_inventory_mismatch", lambda *_args: None)
    monkeypatch.setattr(nvd, "search_cve_page", lambda *_args, **_kwargs: {
        "kev_status": "success", "epss": {"results": []}, "total_results": 0,
        "start_index": 0, "results_per_page": 100, "results": []})
    monkeypatch.setattr(nvd, "get_settings", lambda: settings("live"))
    nvd_result = nvd.collect_nvd(SimpleNamespace(kind="application"), [component])
    osv_result = osv.collect_osv(SimpleNamespace(kind="application"), [component])
    assert nvd_result.status == "success"
    assert osv_result.status == "not_applicable"
    assert "no package was inferred" in osv_result.evidence["message"]


def test_duplicate_delivery_keeps_nvd_and_osv_records_but_scores_alias_once(monkeypatch):
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    monkeypatch.setattr(jobs, "SessionLocal", factory)
    monkeypatch.setattr(jobs, "get_settings", settings)
    calls = []
    monkeypatch.setattr(jobs, "_run_collector", lambda name, asset, components, mode, scenario, authorized:
        (calls.append(name) or _collector_result(name, components[0].id)))
    with factory() as db:
        user = User(username="osv-worker", password_hash="unused", role="admin")
        db.add(user)
        db.flush()
        asset = Asset(kind="application", identifier="OSV test application", normalized_identifier="osv-test-app",
                      created_by=user.id)
        db.add(asset)
        db.flush()
        component = SoftwareComponent(asset_id=asset.id, vendor="Test", product="Package", version="1.0.2",
            package_ecosystem="npm", package_name="@scope/widget")
        db.add(component)
        db.flush()
        investigation = Investigation(asset_id=asset.id, requested_by=user.id, mode="live", status="queued")
        db.add(investigation)
        db.commit()
        attempt_id = jobs.create_attempt(db, investigation, "initial").id
        db.commit()
        investigation_id, component_id = investigation.id, component.id

    jobs.run_investigation_attempt(investigation_id, attempt_id)
    jobs.run_investigation_attempt(investigation_id, attempt_id)
    with factory() as db:
        findings = db.query(Finding).filter_by(investigation_id=investigation_id).all()
        risk = db.query(RiskAssessment).filter_by(investigation_id=investigation_id).one()
        assert calls == ["nvd_kev", "osv"]
        assert len(findings) == 2
        assert {item.source for item in findings} == {"NVD CVE API", "OSV.dev package query API"}
        assert all(item.applicability == "needs_review" for item in findings)
        assert risk.score == 0
        assert len(risk.contributing_finding_ids) == 0

        for item in findings:
            item.applicability = "applies"
        from app.services.risk import assess_investigation
        assessment = assess_investigation(db, db.get(Investigation, investigation_id))
        assert assessment.score == 70
        assert len(assessment.contributing_finding_ids) == 1
        assert len(assessment.explanation_json["vulnerability_intelligence"]) == 2
        assert sum(item["finding_id"] in assessment.contributing_finding_ids
                   for item in assessment.explanation_json["contributors"]) == 1
        saved_report = Report(id=new_id(), investigation_id=investigation_id, format="json", created_by=db.query(User).one().id,
            is_demo=False, snapshot_json={"findings": [{"id": item.id, "source": item.source} for item in findings]},
            content=b"OSV report snapshot", sha256=hashlib.sha256(b"OSV report snapshot").hexdigest())
        db.add(saved_report)
        db.commit()
        report_bytes = saved_report.content
        report_snapshot = copy.deepcopy(saved_report.snapshot_json)
        assert component_id in [item.details_json.get("component_id") for item in findings if item.source.startswith("OSV")]
        assert len(findings) == 2  # both source records remain available after scoring
        assert saved_report.content == report_bytes and saved_report.snapshot_json == report_snapshot
    Base.metadata.drop_all(engine)
    engine.dispose()


def _collector_result(name, component_id):
    if name == "nvd_kev":
        return CollectorResult(status="success", source="NVD CVE API", evidence={"observed_at": "2026-10-19T00:00:00+00:00"},
            findings=[{"category": "vulnerabilities", "severity": "high", "title": "CVE-2025-12345 applicability candidate",
                "explanation": "NVD candidate", "recommendation": "Review", "source": "NVD CVE API",
                "details": {"cve_id": "CVE-2025-12345", "component_id": component_id, "cvss_score": 8.0},
                "applicability": "needs_review"}])
    return CollectorResult(status="success", source="OSV.dev package query API", evidence={"observed_at": "2026-10-19T00:00:00+00:00",
        "provider": "OSV.dev", "provider_version": osv.OSV_VERSION, "provider_status": "success", "advisories": []},
        findings=[{"category": "vulnerabilities", "severity": "unknown", "title": "CYBERLENS-TEST-OSV-1 applicability candidate",
            "explanation": "OSV candidate", "recommendation": "Review", "source": "OSV.dev package query API",
            "details": {"advisory_id": "CYBERLENS-TEST-OSV-1", "aliases": ["CVE-2025-12345"],
                "cve_id": "CVE-2025-12345", "component_id": component_id,
                "package": {"ecosystem": "npm", "name": "@scope/widget", "version": "1.0.2"},
                "provider_status": "success", "freshness": "observed", "provider_version": osv.OSV_VERSION,
                "affected": [], "fixed_versions": [], "references": [], "severity_metadata": [],
                "observed_at": "2026-10-19T00:00:00+00:00", "advisory_status": "active"},
            "applicability": "needs_review"}])
