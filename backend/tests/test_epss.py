import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from datetime import timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import jobs
from app.collectors import epss
from app.database import Base
from app.models import Asset, Investigation, Report, User, new_id
from app.routes.investigations import get_investigation
from app.routes.reports import _investigation_snapshot, _json_bytes, _pdf_bytes
from app.schemas import FindingOut
from app.services.risk import RiskFindingRecord, score_records

FIXTURE = Path(__file__).parent / "fixtures" / "providers" / "epss.json"


class FakeRedis:
    def __init__(self):
        self.values = {}
        self.limit = 0
        self.closed = False

    def get(self, key):
        return self.values.get(key)

    def setex(self, key, _ttl, value):
        self.values[key] = value

    def eval(self, _script, _count, _key, _window):
        self.limit += 1
        return self.limit

    def close(self):
        self.closed = True


def settings(mode="live"):
    return SimpleNamespace(app_mode=mode, redis_url="redis://unused", collector_timeout_seconds=3)


def test_epss_fixture_has_a_score_and_explicit_no_match(monkeypatch):
    redis = FakeRedis()
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    monkeypatch.setattr(epss, "get_settings", settings)
    monkeypatch.setattr(epss, "_redis_client", lambda: redis)
    monkeypatch.setattr(epss, "safe_get", lambda *_args, **_kwargs: SimpleNamespace(
        status=200, body=json.dumps(payload).encode()))

    result = epss.lookup_epss(["CVE-2021-41773", "CVE-2024-0002"])
    assert result["CVE-2021-41773"]["epss_score"] == 0.97123
    assert result["CVE-2021-41773"]["epss_percentile"] == 0.99912
    assert result["CVE-2021-41773"]["epss_provider_status"] == "success"
    assert result["CVE-2024-0002"]["epss_provider_status"] == "no_match"
    assert result["CVE-2024-0002"]["epss_score"] is None
    assert redis.closed


@pytest.mark.parametrize(("http_status", "expected"), [(429, "quota_limited"), (503, "unavailable"), (403, "failed")])
def test_epss_provider_errors_are_explicit_and_not_cached(monkeypatch, http_status, expected):
    redis = FakeRedis()
    monkeypatch.setattr(epss, "get_settings", settings)
    monkeypatch.setattr(epss, "_redis_client", lambda: redis)
    monkeypatch.setattr(epss, "safe_get", lambda *_args, **_kwargs: SimpleNamespace(status=http_status, body=b"{}"))

    result = epss.lookup_epss(["CVE-2021-41773"])["CVE-2021-41773"]
    assert result["epss_provider_status"] == expected
    assert result["epss_score"] is None
    assert result["epss_freshness"] == "unavailable"
    assert redis.values == {}


def test_epss_cache_is_provider_scoped_and_avoids_repeat_requests(monkeypatch):
    redis = FakeRedis()
    calls = []
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    monkeypatch.setattr(epss, "get_settings", settings)
    monkeypatch.setattr(epss, "_redis_client", lambda: redis)
    monkeypatch.setattr(epss, "safe_get", lambda url, **_kwargs: (calls.append(url) or SimpleNamespace(
        status=200, body=json.dumps(payload).encode())))

    first = epss.lookup_epss(["cve-2021-41773"])["CVE-2021-41773"]
    second = epss.lookup_epss(["CVE-2021-41773"])["CVE-2021-41773"]
    assert len(calls) == 1
    assert first["epss_cache_state"] == "miss"
    assert second["epss_cache_state"] == "hit"
    assert second["epss_provider_status"] == "success"
    assert next(iter(redis.values)).startswith("cyberlens:provider:epss:")


def test_epss_shared_rate_limit_blocks_excess_provider_requests(monkeypatch):
    redis = FakeRedis()
    calls = []
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    monkeypatch.setattr(epss, "get_settings", settings)
    monkeypatch.setattr(epss, "_redis_client", lambda: redis)
    monkeypatch.setattr(epss, "EPSS_MAX_REQUESTS_PER_WINDOW", 1)
    monkeypatch.setattr(epss, "safe_get", lambda *_args, **_kwargs: (calls.append(True) or SimpleNamespace(
        status=200, body=json.dumps(payload).encode())))

    first = epss.lookup_epss(["CVE-2021-41773"])["CVE-2021-41773"]
    second = epss.lookup_epss(["CVE-2021-41774"])["CVE-2021-41774"]
    assert first["epss_provider_status"] == "success"
    assert second["epss_provider_status"] == "quota_limited"
    assert len(calls) == 1


def test_epss_malformed_payload_is_failed_not_a_zero_score(monkeypatch):
    redis = FakeRedis()
    payload = {"data": [{"cve": "CVE-2021-41773", "epss": "NaN", "percentile": "0.5", "date": "2026-10-17"}]}
    monkeypatch.setattr(epss, "get_settings", settings)
    monkeypatch.setattr(epss, "_redis_client", lambda: redis)
    monkeypatch.setattr(epss, "safe_get", lambda *_args, **_kwargs: SimpleNamespace(
        status=200, body=json.dumps(payload).encode()))
    result = epss.lookup_epss(["CVE-2021-41773"])["CVE-2021-41773"]
    assert result["epss_provider_status"] == "failed"
    assert result["epss_score"] is None
    assert redis.values == {}


def test_demo_mode_never_calls_epss_provider_or_redis(monkeypatch):
    monkeypatch.setattr(epss, "get_settings", lambda: settings("demo"))
    monkeypatch.setattr(epss, "_redis_client", lambda: pytest.fail("Redis touched in Demo adapter path"))
    monkeypatch.setattr(epss, "safe_get", lambda *_args, **_kwargs: pytest.fail("network call in Demo"))
    result = epss.lookup_epss(["CVE-2021-41773"])["CVE-2021-41773"]
    assert result["epss_provider_status"] == "not_assessed"


def test_unknown_cvss_keV_still_gets_priority_without_epss_affecting_score():
    record = RiskFindingRecord(id="kev-unknown", fingerprint="kev-unknown", category="vulnerabilities",
        severity="unknown", applicability="applies", details={"cve_id": "CVE-2024-0001", "kev": True,
        "cvss_score": None, "epss_score": 0.99}, source="fixture", evidence_id="evidence-1",
        epss_score=0.99, epss_percentile=0.999, epss_provider_status="success", epss_freshness="fresh")
    result = score_records([record], {"nvd_kev": "success"})
    assert result["score"] == 90
    assert result["category_scores"]["vulnerabilities"] == 0
    assert result["contributing_finding_ids"] == ["kev-unknown"]
    trace = result["explanation"]["vulnerability_intelligence"][0]
    assert trace["cvss"]["score"] is None
    assert trace["epss"]["score"] == 0.99
    assert trace["kev"] is True
    assert "not evidence" in result["explanation"]["epss_notice"]


def test_epss_values_do_not_change_risk_score():
    low = RiskFindingRecord(id="finding", fingerprint="finding", category="vulnerabilities", severity="high",
        applicability="applies", details={"kev": False, "epss_score": 0.01}, epss_score=0.01)
    high = RiskFindingRecord(id="finding", fingerprint="finding", category="vulnerabilities", severity="high",
        applicability="applies", details={"kev": False, "epss_score": 0.99}, epss_score=0.99)
    assert score_records([low], {"nvd_kev": "success"})["score"] == score_records([high], {"nvd_kev": "success"})["score"]


def test_epss_and_demo_values_are_exposed_in_api_risk_trace_and_report(monkeypatch):
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    monkeypatch.setattr(jobs, "SessionLocal", factory)
    with factory() as db:
        user = User(username="epss-api-admin", password_hash="not-used", role="admin")
        db.add(user)
        db.flush()
        asset = Asset(kind="application", identifier="EPSS Demo application", normalized_identifier="epss-demo-application",
                      created_by=user.id)
        db.add(asset)
        db.flush()
        investigation = Investigation(id=new_id(), asset_id=asset.id, requested_by=user.id, mode="demo",
                                      scenario="vulnerable_application")
        db.add(investigation)
        db.commit()
        investigation_id = investigation.id
        user_id = user.id

    jobs.run_investigation(investigation_id)
    with factory() as db:
        user = db.get(User, user_id)
        investigation = db.get(Investigation, investigation_id)
        detail = get_investigation(investigation_id, user, db)
        kev = next(item for item in detail["findings"] if item["details_json"].get("kev"))
        typed_finding = FindingOut.model_validate(kev)
        assert kev["cvss_version"] == "3.1" and kev["cvss_score"] == 9.8
        assert kev["kev"] is True and kev["applicability"] == "needs_review"
        assert kev["evidence_id"] is not None
        assert kev["epss_score"] == 0.96
        assert kev["epss_percentile"] == 0.995
        assert kev["epss_provider_status"] == "success"
        assert kev["epss_freshness"] == "synthetic"
        assert typed_finding.epss_score == 0.96 and typed_finding.kev is True
        trace = detail["risk"]["explanation"]["vulnerability_intelligence"]
        assert any(item["finding_id"] == kev["id"] and item["epss"]["score"] == 0.96 for item in trace)

        snapshot = _investigation_snapshot(db, investigation)
        report_id = new_id()
        content = _json_bytes(snapshot)
        report = Report(id=report_id, investigation_id=investigation_id, format="json", created_by=user_id,
                        is_demo=True, snapshot_json=snapshot, content=content,
                        sha256=hashlib.sha256(content).hexdigest())
        db.add(report)
        db.commit()
        saved_report = db.query(Report).filter_by(id=report_id).one()
        saved_finding = next(item for item in saved_report.snapshot_json["findings"] if item["id"] == kev["id"])
        assert saved_finding["epss"] == {
            "score": 0.96, "percentile": 0.995, "observed_at": kev["epss_observed_at"].replace(tzinfo=timezone.utc).isoformat(),
            "provider_status": "success", "freshness": "synthetic", "provider": "Synthetic EPSS fixture",
            "provider_version": "CyberLens Demo fixture schema 1", "source_date": None,
        }
        assert saved_report.snapshot_json["risk"]["explanation"]["epss_notice"]
        assert _pdf_bytes(snapshot).startswith(b"%PDF")
    Base.metadata.drop_all(engine)
    engine.dispose()
