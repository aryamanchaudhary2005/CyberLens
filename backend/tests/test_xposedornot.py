"""Offline tests for the opt-in, privacy-conscious XposedOrNot adapter."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import threading
import time
from types import SimpleNamespace

from cryptography.fernet import Fernet
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
import pytest

from app.authorization import active_email_breach_authorization
from app.config import Settings
from app.collectors import xposedornot
from app.collectors.types import CollectorResult
from app.models import (Asset, AuditEvent, CollectorRun, EmailBreachAuthorization, EvidenceSnapshot,
                        Investigation, User, now_utc)
from app.database import Base
from app.dependencies import require_roles
from app.routes import investigations as investigation_routes
from app.routes import assets as assets_routes
from app.routes import integrations as integration_routes
from app.routes.reports import _investigation_snapshot, _pdf_bytes
from app.schemas import InvestigationCreate
from app.services.risk import RiskEvidenceRecord, RiskFindingRecord, score_records
from app.jobs import _collectors, _run_collector


FIXTURES = Path(__file__).parent / "fixtures" / "providers"
KEY = Fernet.generate_key().decode("ascii")


@pytest.fixture
def xon_db():
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = Session(engine, autoflush=False, expire_on_commit=False)
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(engine)
        engine.dispose()


class SharedMemoryRedis:
    """Small locked Redis stand-in shared by test worker threads."""

    def __init__(self):
        self.values: dict[str, bytes] = {}
        self.events: dict[str, list[int]] = {}
        self.lock = threading.Lock()
        self.closed = False
        self.now_ms = int(time.time() * 1000)

    def eval(self, _script, _keys, key, member):
        now_ms = self.now_ms
        with self.lock:
            recent = [score for score in self.events.get(key, []) if score >= now_ms - 86_400_000]
            if sum(score >= now_ms - 1_000 for score in recent) >= 2:
                self.events[key] = recent
                return 0
            if sum(score >= now_ms - 3_600_000 for score in recent) >= 25:
                self.events[key] = recent
                return 0
            if len(recent) >= 100:
                self.events[key] = recent
                return 0
            recent.append(now_ms)
            self.events[key] = recent
            return 1

    def get(self, key):
        return self.values.get(key)

    def setex(self, key, _ttl, value):
        self.values[key] = bytes(value)

    def delete(self, key):
        return int(self.values.pop(key, None) is not None)

    def close(self):
        self.closed = True


def _settings(**overrides):
    values = {"app_mode": "live", "virustotal_api_key": None, "hibp_api_key": None,
              "xposedornot_enabled": True, "xposedornot_community_use_ack": True,
              "xposedornot_cache_key": KEY, "xposedornot_cache_ttl_seconds": 900,
              "collector_timeout_seconds": 2, "redis_url": "redis://unused"}
    values.update(overrides)
    return SimpleNamespace(**values)


def _response(status=200, payload=None, body=None):
    if body is None:
        body = json.dumps(payload).encode("utf-8")
    return SimpleNamespace(status=status, body=body)


def _asset(email="synthetic-person@example.test"):
    return SimpleNamespace(kind="email", identifier=email, normalized_identifier=email)


def test_live_provider_configuration_requires_explicit_ack_and_usable_private_cache_key():
    base = {"_env_file": None, "app_mode": "live", "cookie_secure": True,
            "database_url": "postgresql://operator:private@localhost/cyberlens",
            "redis_url": "redis://:private@localhost/0", "xposedornot_enabled": True,
            "xposedornot_community_use_ack": True, "xposedornot_cache_key": KEY}
    configured = Settings(**base)
    assert configured.xposedornot_enabled and configured.xposedornot_community_use_ack
    with pytest.raises(ValidationError, match="COMMUNITY_USE_ACK"):
        Settings(**{**base, "xposedornot_community_use_ack": False})
    with pytest.raises(ValidationError, match="valid Fernet key"):
        Settings(**{**base, "xposedornot_cache_key": "not-a-fernet-key"})


@pytest.fixture
def provider_fixtures():
    return {name: json.loads((FIXTURES / f"xposedornot_{name}.json").read_text(encoding="utf-8"))
            for name in ("found", "no_match", "unverified")}


def test_documented_match_details_are_normalized_and_lookup_is_single_encoded_get(provider_fixtures, monkeypatch):
    monkeypatch.setattr(xposedornot, "get_settings", lambda: _settings())
    calls = []
    monkeypatch.setattr(xposedornot, "safe_get", lambda url, **kwargs: (
        calls.append((url, kwargs)) or _response(payload=provider_fixtures["found"])))
    redis = SharedMemoryRedis()
    result = xposedornot.collect_xposedornot(_asset(), authorized=True, redis_client=redis)

    assert result.status == "success"
    assert calls[0][0] == "https://api.xposedornot.com/v1/check-email/synthetic-person%40example.test?details=true"
    assert calls[0][1]["max_redirects"] == 0
    assert calls[0][1]["max_bytes"] == xposedornot.XON_RESPONSE_MAX_BYTES
    assert calls[0][1]["send_range_header"] is False
    assert len(calls) == 1
    assert result.evidence["records"] == [{
        "record_id": "ExampleForum-2024", "name": "ExampleForum",
        "breach_date": "2024-03-01T00:00:00+00:00", "exposed_data": ["Email addresses", "Names"],
        "verified": True, "verification_value": "true", "source": "XposedOrNot",
    }]
    assert result.findings[0]["category"] == "breach_exposure"
    serialized = json.dumps({"evidence": result.evidence, "findings": result.findings})
    assert "synthetic-person@example.test" not in serialized
    assert "Synthetic fixture text that must not be persisted" not in serialized
    assert "passwordRisk" not in serialized


def test_basic_documented_response_preserves_verified_marker_without_claiming_record_verified(monkeypatch):
    monkeypatch.setattr(xposedornot, "get_settings", lambda: _settings())
    monkeypatch.setattr(xposedornot, "safe_get", lambda *_args, **_kwargs: _response(payload={
        "status": "success", "email": "synthetic-person@example.test", "breaches": [["ExampleForum", "Verified"]]}))
    result = xposedornot.collect_xposedornot(_asset(), authorized=True, redis_client=SharedMemoryRedis())
    assert result.status == "success"
    assert result.evidence["records"][0]["name"] == "ExampleForum"
    assert result.evidence["records"][0]["verified"] is None
    assert result.evidence["verification_flags"] == ["Verified"]
    assert result.findings == []


def test_empty_optional_details_do_not_turn_documented_breach_names_into_no_match():
    parsed, records, markers = xposedornot.parse_response({
        "status": "success", "breaches": [["ExampleForum", "Verified"]],
        "exposedBreaches": {"breaches_details": []},
    })
    assert parsed == "found"
    assert [item["name"] for item in records] == ["ExampleForum"]
    assert records[0]["verified"] is None
    assert markers == ["Verified"]


def test_unverified_and_missing_verification_stay_evidence_only(provider_fixtures, monkeypatch):
    monkeypatch.setattr(xposedornot, "get_settings", lambda: _settings())
    monkeypatch.setattr(xposedornot, "safe_get", lambda *_args, **_kwargs: _response(payload=provider_fixtures["unverified"]))
    result = xposedornot.collect_xposedornot(_asset(), authorized=True, redis_client=SharedMemoryRedis())
    assert result.evidence["records"][0]["verified"] is False
    assert result.findings == []


def test_exact_no_match_message_and_unexpected_missing_fields_are_distinguished(provider_fixtures):
    assert xposedornot.parse_response(provider_fixtures["no_match"])[0] == "no_match"
    assert xposedornot.parse_response({"status": "success", "breaches": []})[0] == "no_match"
    assert xposedornot.parse_response({"status": "success"})[0] == "malformed"
    assert xposedornot.parse_response({"breaches": [None]})[0] == "malformed"


@pytest.mark.parametrize("body", [b"not-json", b"{\"breaches\":[\n]"]) 
def test_malformed_json_is_failed_without_body_or_email(provider_fixtures, monkeypatch, body):
    monkeypatch.setattr(xposedornot, "get_settings", lambda: _settings())
    monkeypatch.setattr(xposedornot, "safe_get", lambda *_args, **_kwargs: _response(body=body))
    result = xposedornot.collect_xposedornot(_asset(), authorized=True, redis_client=SharedMemoryRedis())
    assert result.status == "failed"
    serialized = json.dumps(result.evidence) + (result.error_explanation or "")
    assert "synthetic-person@example.test" not in serialized
    assert "not-json" not in serialized


def test_no_authorization_disabled_provider_and_demo_path_make_no_request(monkeypatch):
    monkeypatch.setattr(xposedornot, "get_settings", lambda: _settings())
    monkeypatch.setattr(xposedornot, "safe_get", lambda *_args, **_kwargs: pytest.fail("provider request without authorization"))
    unauthorized = xposedornot.collect_xposedornot(_asset(), authorized=False, redis_client=SharedMemoryRedis())
    assert unauthorized.status == "not_applicable"
    assert unauthorized.evidence["provider_status"] == "authorization_required"
    monkeypatch.setattr(xposedornot, "get_settings", lambda: _settings(xposedornot_enabled=False))
    disabled = xposedornot.collect_xposedornot(_asset(), authorized=True, redis_client=SharedMemoryRedis())
    assert disabled.status == "unavailable"

    from app.collectors import demo
    monkeypatch.setattr(demo, "now_iso", lambda: "2026-10-19T00:00:00+00:00")
    result = _run_collector("xposedornot", _asset(), [], "demo", "exposed_email", False)
    assert result.status == "success" and result.findings
    assert result.evidence["demo_data"] is True
    assert _collectors(_asset(), "xposedornot") == ["xposedornot"]
    assert _collectors(_asset()) == ["hibp"]


def test_integration_status_exposes_opt_in_state_without_replacing_hibp(monkeypatch):
    settings = Settings(app_mode="live", cookie_secure=True,
                        database_url="postgresql+psycopg://cyberlens:private-test@localhost:5432/cyberlens",
                        redis_url="redis://:private-test@localhost:6379/0", xposedornot_enabled=True,
                        xposedornot_community_use_ack=True, xposedornot_cache_key=KEY, _env_file=None)
    monkeypatch.setattr(integration_routes, "get_settings", lambda: settings)
    result = integration_routes.integration_status(SimpleNamespace(role="analyst"))
    providers = {item["id"]: item for item in result["integrations"]}
    assert providers["xposedornot"]["configured"] is True
    assert "coverage differs from HIBP" in providers["xposedornot"]["behavior"]
    assert providers["hibp"]["id"] == "hibp"

    settings.xposedornot_enabled = False
    result = integration_routes.integration_status(SimpleNamespace(role="analyst"))
    providers = {item["id"]: item for item in result["integrations"]}
    assert providers["xposedornot"]["configured"] is False
    assert "HIBP remains unchanged" in providers["xposedornot"]["behavior"]


def test_timeout_quota_and_transport_errors_do_not_retain_urls_or_response_bodies(monkeypatch, caplog):
    monkeypatch.setattr(xposedornot, "get_settings", lambda: _settings())
    monkeypatch.setattr(xposedornot, "safe_get", lambda *_args, **_kwargs: (_ for _ in ()).throw(
        xposedornot.OutboundTimeout("synthetic-person@example.test in url")))
    timeout = xposedornot.collect_xposedornot(_asset(), authorized=True, redis_client=SharedMemoryRedis())
    assert timeout.status == "unavailable" and timeout.evidence["provider_status"] == "timeout"
    assert "synthetic-person@example.test" not in json.dumps(timeout.evidence) + str(timeout.error_explanation)

    monkeypatch.setattr(xposedornot, "safe_get", lambda *_args, **_kwargs: _response(status=429, body=b"provider body with synthetic-person@example.test"))
    quota = xposedornot.collect_xposedornot(_asset("another@example.test"), authorized=True, redis_client=SharedMemoryRedis())
    assert quota.status == "quota_limited"
    from app.orchestration import _is_transient_evidence
    assert not _is_transient_evidence(quota.evidence)
    assert "provider body" not in json.dumps(quota.evidence)

    def fail_with_url(url, **_kwargs):
        raise RuntimeError(f"transport error {url}")
    monkeypatch.setattr(xposedornot, "safe_get", fail_with_url)
    failure = xposedornot.collect_xposedornot(_asset("person-two@example.test"), authorized=True, redis_client=SharedMemoryRedis())
    assert failure.status == "failed"
    assert "person-two@example.test" not in json.dumps(failure.evidence) + str(failure.error_explanation)
    assert "synthetic-person@example.test" not in caplog.text
    assert "person-two@example.test" not in caplog.text
    assert "provider body" not in caplog.text


@pytest.mark.parametrize("status,expected,provider_status", [
    (401, "failed", "request_rejected"), (403, "failed", "request_rejected"),
    (503, "unavailable", "provider_unavailable"), (400, "failed", "failed_request"),
])
def test_http_failures_are_distinguished_without_retaining_provider_bodies(monkeypatch, status, expected, provider_status):
    monkeypatch.setattr(xposedornot, "get_settings", lambda: _settings())
    monkeypatch.setattr(xposedornot, "safe_get", lambda *_args, **_kwargs: _response(
        status=status, body=b"synthetic response body with subject@example.test"))
    result = xposedornot.collect_xposedornot(_asset(), authorized=True, redis_client=SharedMemoryRedis())
    assert result.status == expected
    assert result.evidence["provider_status"] == provider_status
    assert "subject@example.test" not in json.dumps(result.evidence) + str(result.error_explanation)
    assert "synthetic response body" not in json.dumps(result.evidence) + str(result.error_explanation)


def test_shared_rolling_quota_is_enforced_under_concurrent_workers():
    redis = SharedMemoryRedis()
    with ThreadPoolExecutor(max_workers=20) as pool:
        results = list(pool.map(lambda _index: xposedornot._reserve(redis), range(20)))
    assert sum(results) == 2

    # Hourly and daily shared counters are also hard-capped even when the
    # per-second window is clear.
    now_ms = redis.now_ms
    key = "cyberlens:provider:xon:check-email:shared-quota"
    redis.events[key] = [now_ms - (index + 1) * 2000 for index in range(25)]
    assert not xposedornot._reserve(redis)
    redis.events[key] = [now_ms - 3_600_001 - index * 800_000 for index in range(100)]
    assert not xposedornot._reserve(redis)


def test_cache_key_is_keyed_digest_and_cached_sensitive_content_is_encrypted(monkeypatch, provider_fixtures):
    monkeypatch.setattr(xposedornot, "get_settings", lambda: _settings())
    calls = []
    monkeypatch.setattr(xposedornot, "safe_get", lambda *_args, **_kwargs: (
        calls.append(1) or _response(payload=provider_fixtures["found"])))
    redis = SharedMemoryRedis()
    first = xposedornot.collect_xposedornot(_asset(), authorized=True, redis_client=redis)
    second = xposedornot.collect_xposedornot(_asset(), authorized=True, redis_client=redis)
    assert first.evidence == second.evidence
    assert len(calls) == 1
    assert all("synthetic-person@example.test" not in key for key in redis.values)
    encrypted = b"".join(redis.values.values())
    assert b"ExampleForum" not in encrypted and b"synthetic-person@example.test" not in encrypted
    assert all(len(key.rsplit(":", 1)[-1]) == 64 for key in redis.values)


def test_duplicate_hibp_and_xon_breach_findings_do_not_raise_risk_and_sources_remain_traced():
    finding_hibp = RiskFindingRecord(id="hibp", fingerprint="hibp-fp", category="breach_exposure",
        severity="medium", source="Have I Been Pwned", evidence_id="e-hibp")
    finding_xon = RiskFindingRecord(id="xon", fingerprint="xon-fp", category="breach_exposure",
        severity="medium", source="XposedOrNot community API", evidence_id="e-xon")
    statuses = {"hibp": "success", "xposedornot": "success"}
    evidence = [RiskEvidenceRecord(id="e-hibp", source="Have I Been Pwned", observed_at=None),
                RiskEvidenceRecord(id="e-xon", source="XposedOrNot community API", observed_at=None)]
    baseline = score_records([finding_hibp], statuses, evidence)
    both = score_records([finding_hibp, finding_xon], statuses, evidence)
    assert both["score"] == baseline["score"]
    assert both["explanation"]["source_coverage"].keys() == {"Have I Been Pwned", "XposedOrNot community API"}
    assert {item["finding_id"] for item in both["explanation"]["contributors"]} == {"hibp", "xon"}


def test_provider_outage_is_unknown_breach_coverage_not_a_safe_result():
    evidence = RiskEvidenceRecord(id="xon-outage-evidence", source="XposedOrNot community API",
                                  observed_at=None, provenance={"status": "unavailable"})
    result = score_records([], {"xposedornot": "unavailable"}, [evidence])
    assert "breach_exposure" in result["excluded_categories"]
    assert result["explanation"]["source_coverage"]["XposedOrNot community API"]["status"] == "unavailable"


def test_investigation_authorization_is_explicit_scoped_and_viewer_is_rejected(xon_db, monkeypatch):
    db = xon_db
    admin = User(username="xon-admin", password_hash="unused", role="admin", must_change_password=False)
    viewer = User(username="xon-viewer", password_hash="unused", role="viewer", must_change_password=False)
    db.add_all([admin, viewer])
    db.flush()
    asset = Asset(kind="email", identifier="synthetic-person@example.test",
                  normalized_identifier="synthetic-person@example.test", created_by=admin.id)
    db.add(asset)
    db.flush()
    monkeypatch.setattr(investigation_routes, "get_settings", lambda: SimpleNamespace(
        app_mode="live", xposedornot_enabled=True, xposedornot_community_use_ack=True))

    with pytest.raises(HTTPException) as omitted:
        investigation_routes.start_investigation(
            InvestigationCreate(asset_id=asset.id, email_breach_provider="xposedornot"), admin, db)
    assert omitted.value.status_code == 422
    assert db.query(EmailBreachAuthorization).count() == 0

    queued = investigation_routes.start_investigation(InvestigationCreate(
        asset_id=asset.id, email_breach_provider="xposedornot", xposedornot_authorization_confirmed=True), admin, db)
    investigation = db.get(Investigation, queued["id"])
    authorization = db.get(EmailBreachAuthorization, investigation.email_breach_authorization_id)
    assert investigation.email_breach_provider == "xposedornot"
    assert authorization.asset_id == asset.id and authorization.provider == "xposedornot"
    assert authorization.consent_version == "xon-email-lookup-v1"
    assert authorization.expires_at is not None
    assert active_email_breach_authorization(db, asset.id, authorization.id) is authorization
    event = db.query(AuditEvent).filter_by(action="email_breach.authorization_granted").one()
    serialized = json.dumps(event.details_json)
    assert "synthetic-person@example.test" not in serialized
    assert "outcome" in event.details_json and "reason" in event.details_json
    revoked = assets_routes.revoke_email_breach_authorization(asset.id, admin, db)
    assert revoked["email_breach_authorization_id"] is None
    assert authorization.revoked_at is not None
    assert active_email_breach_authorization(db, asset.id, authorization.id) is None
    assert "synthetic-person@example.test" not in json.dumps([row.details_json for row in db.query(AuditEvent).all()])
    with pytest.raises(HTTPException) as role_denied:
        require_roles("admin", "analyst")(viewer)
    assert role_denied.value.status_code == 403


def test_xon_expired_or_revoked_authorization_never_authorizes_lookup(xon_db):
    db = xon_db
    user = User(username="xon-expiry-test", password_hash="unused", role="analyst", must_change_password=False)
    db.add(user)
    db.flush()
    asset = Asset(kind="email", identifier="subject@example.test", normalized_identifier="subject@example.test",
                  created_by=user.id)
    db.add(asset)
    db.flush()
    auth = EmailBreachAuthorization(asset_id=asset.id, provider="xposedornot", authorized_by=user.id,
        consent_version="xon-email-lookup-v1", created_at=now_utc(), expires_at=now_utc() - timedelta(seconds=1))
    db.add(auth)
    db.flush()
    assert active_email_breach_authorization(db, asset.id, auth.id) is None
    auth.expires_at = now_utc() + timedelta(days=1)
    auth.revoked_at = now_utc()
    assert active_email_breach_authorization(db, asset.id, auth.id) is None


def test_xon_selected_investigation_uses_no_demo_external_request(monkeypatch):
    monkeypatch.setattr(xposedornot, "safe_get", lambda *_args, **_kwargs: pytest.fail("Demo performed a provider request"))
    result = _run_collector("xposedornot", _asset(), [], "demo", "exposed_email", authorized=False)
    assert result.status == "success"
    assert result.evidence["demo_data"] is True


def test_provider_attribution_and_exact_no_match_survive_new_report_export(xon_db):
    db = xon_db
    user = User(username="xon-report", password_hash="unused", role="analyst", must_change_password=False)
    db.add(user)
    db.flush()
    asset = Asset(kind="email", identifier="report-subject@example.test",
                  normalized_identifier="report-subject@example.test", created_by=user.id)
    db.add(asset)
    db.flush()
    investigation = Investigation(asset_id=asset.id, requested_by=user.id, mode="live", status="partial",
                                  progress=100, email_breach_provider="xposedornot")
    db.add(investigation)
    db.flush()
    run = CollectorRun(investigation_id=investigation.id, collector="xposedornot", status="no_match",
                       source="XposedOrNot community API", record_count=0)
    db.add(run)
    db.flush()
    db.add(EvidenceSnapshot(investigation_id=investigation.id, collector_run_id=run.id,
        source="XposedOrNot community API", observed_at=now_utc(),
        evidence_json={"provider_status": "no_match", "records": [], "breach_count": 0,
                       "no_match_message": "No record found in this provider's dataset.",
                       "provenance": {"provider": "xposedornot", "status": "no_match"}},
        sha256="d" * 64, is_synthetic=False))
    db.flush()

    snapshot = _investigation_snapshot(db, investigation)
    lookup = snapshot["email_breach_lookup"]
    assert lookup["provider"] == "xposedornot"
    assert lookup["source"] == "XposedOrNot community API"
    assert lookup["status"] == "no_match"
    assert lookup["evidence_id"] is not None
    assert lookup["no_match_message"] == "No record found in this provider's dataset."
    assert "does not have identical coverage" in lookup["coverage_note"]
    assert "current account compromise" in lookup["notice"]
    pdf = _pdf_bytes(snapshot)
    assert pdf.startswith(b"%PDF")

