import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from rq.exceptions import DuplicateJobError

from app import jobs
from app.collectors import spamhaus_drop as collector
from app.collectors.common import finding
from app.collectors.demo import demo_result
from app.collectors.types import CollectorResult
from app.config import Settings
from app.models import (
    Asset,
    CollectorRun,
    EvidenceSnapshot,
    Finding,
    Investigation,
    InvestigationAttempt,
    ThreatFeedNetwork,
    ThreatFeedRefreshAttempt,
    ThreatFeedSnapshot,
    ThreatFeedSource,
    User,
)
from app.network import SafeResponse
from app.services import threat_feeds
from app.services.risk import RiskFindingRecord, score_records
from conftest import csrf, login


def live_settings(**overrides):
    values = {
        "app_mode": "live", "cookie_secure": True,
        "database_url": "postgresql+psycopg://cyberlens:strong-pass@localhost:5432/cyberlens",
        "redis_url": "redis://:strong-pass@localhost:6379/0",
        "spamhaus_drop_enabled": True, "collector_timeout_seconds": 3.0,
        "spamhaus_drop_refresh_interval_hours": 24,
    }
    values.update(overrides)
    return Settings(**values)


def body(family: int, network: str, sbl_id: str) -> bytes:
    timestamp = 1_760_900_000 + family
    return (
        json.dumps({"cidr": network, "sblid": sbl_id}) + "\n" +
        json.dumps({"type": "meta", "timestamp": timestamp, "records": 1,
                    "copyright": "Copyright (c) 2026 Spamhaus Project"}) + "\n"
    ).encode()


class FakeQueue:
    def __init__(self, duplicate=False):
        self.jobs = []
        self.duplicate = duplicate

    def enqueue(self, *args, **kwargs):
        self.jobs.append((args, kwargs))
        if self.duplicate:
            raise DuplicateJobError()


def response(family: int) -> SafeResponse:
    return SafeResponse(
        status=200, headers={"content-type": "text/json", "etag": f'"drop-v{family}-1"',
                             "last-modified": "Tue, 20 Oct 2026 00:00:00 GMT"},
        body=body(family, "8.8.8.0/24" if family == 4 else "2606:4700:4700::/48", f"SBL{family}24001"),
        final_url=threat_feeds.FEED_URLS[family], redirects=[],
    )


def test_official_json_lines_parse_metadata_and_preserve_provider_attribution():
    parsed = threat_feeds.parse_drop_feed(body(4, "8.8.8.0/24", "SBL123"), 4, max_bytes=2048)
    assert parsed.networks == ({"address_family": 4, "network": "8.8.8.0/24", "sbl_id": "SBL123"},)
    assert parsed.metadata["copyright"] == "Copyright (c) 2026 Spamhaus Project"
    assert parsed.metadata["timestamp"] == 1_760_900_004
    assert parsed.published_at.tzinfo == timezone.utc


@pytest.mark.parametrize("payload", [
    b"", b"<html>blocked</html>", b"{\"cidr\":\"8.8.8.0/24\"}\n",
    b"{broken json}\n", b"[]\n", b"{\"cidr\":\"8.8.8.1/24\",\"sblid\":\"SBL1\"}\n{\"type\":\"meta\",\"timestamp\":1,\"copyright\":\"x\"}\n",
    b"{\"cidr\":\"2001:db8::/32\",\"sblid\":\"SBL1\"}\n{\"type\":\"meta\",\"timestamp\":1,\"copyright\":\"x\"}\n",
])
def test_malformed_truncated_html_and_invalid_family_payloads_fail_closed(payload):
    with pytest.raises(threat_feeds.ThreatFeedError):
        threat_feeds.parse_drop_feed(payload, 4, max_bytes=2048)


def test_network_matching_uses_ipv4_ipv6_boundaries_and_overlaps_without_expansion():
    records = [
        {"network": "8.8.8.0/24", "sbl_id": "SBL-BROAD"},
        {"network": "8.8.8.8/32", "sbl_id": "SBL-HOST"},
        {"network": "2606:4700:4700::/48", "sbl_id": "SBL-V6"},
    ]
    assert threat_feeds.match_public_ip("8.8.8.0", records) == [{"network": "8.8.8.0/24", "sbl_id": "SBL-BROAD"}]
    assert [item["sbl_id"] for item in threat_feeds.match_public_ip("8.8.8.8", records)] == ["SBL-HOST", "SBL-BROAD"]
    assert threat_feeds.match_public_ip("8.8.9.0", records) == []
    assert threat_feeds.match_public_ip("2606:4700:4700::ffff", records) == [{"network": "2606:4700:4700::/48", "sbl_id": "SBL-V6"}]
    assert threat_feeds.match_public_ip("2606:4700:4701::1", records) == []
    assert threat_feeds.match_public_ip("192.168.1.5", records) == []


@pytest.mark.parametrize("address", ["10.0.0.1", "192.168.1.2", "2001:db8::1", "invalid-ip"])
def test_collector_rejects_non_public_or_invalid_direct_ip(address, monkeypatch):
    monkeypatch.setattr(collector, "get_settings", lambda: live_settings())
    result = collector.collect_spamhaus_drop(SimpleNamespace(kind="ip", identifier=address), {
        "integrity_valid": True, "fresh": True, "networks": [{"network": "0.0.0.0/0", "sbl_id": "SBL1"}],
    })
    assert result.status == "not_applicable"
    assert result.findings == []
    assert result.evidence["provider_status"] in {"non_public_ip", "invalid_ip_asset"}


def test_live_refresh_interval_cannot_be_configured_below_provider_daily_limit():
    with pytest.raises(ValueError, match="between 24 and 720"):
        live_settings(spamhaus_drop_refresh_interval_hours=23)


def test_collector_match_is_medium_needs_review_and_only_analyst_applies_changes_risk(monkeypatch):
    monkeypatch.setattr(collector, "get_settings", lambda: live_settings())
    asset = SimpleNamespace(kind="ip", identifier="8.8.8.8")
    snapshot = {
        "snapshot_id": "snapshot-current", "content_sha256": "f" * 64,
        "parser_version": threat_feeds.PARSER_VERSION, "record_count": 1,
        "retrieved_at": datetime.now(timezone.utc), "published_at": datetime.now(timezone.utc),
        "last_successful_revalidation_at": datetime.now(timezone.utc), "snapshot_age_seconds": 5,
        "fresh": True, "integrity_valid": True, "metadata": {"feeds": {}},
        "networks": [{"network": "8.8.8.0/24", "address_family": 4, "sbl_id": "SBL123"}],
    }
    result = collector.collect_spamhaus_drop(asset, snapshot)
    assert result.status == "success"
    assert result.findings[0]["severity"] == "medium"
    assert result.findings[0]["applicability"] == "needs_review"
    assert result.findings[0]["details"]["severity_policy"] == "CyberLens medium-priority review rule v1"
    candidate = RiskFindingRecord(id="drop-1", fingerprint="drop-1", category="reputation", severity="medium",
                                  applicability="needs_review", source="Spamhaus Project DROP")
    unreviewed = score_records([candidate], {"spamhaus_drop": "success"})
    applied = score_records([RiskFindingRecord(**{**candidate.__dict__, "applicability": "applies"})],
                            {"spamhaus_drop": "success"})
    assert unreviewed["score"] == 0
    assert not unreviewed["explanation"]["contributors"]
    assert applied["score"] == 45
    assert applied["explanation"]["contributors"][0]["source"] == "Spamhaus Project DROP"


def test_stale_matches_and_no_matches_are_unavailable_not_safe_or_scored(monkeypatch):
    monkeypatch.setattr(collector, "get_settings", lambda: live_settings())
    asset = SimpleNamespace(kind="ip", identifier="8.8.8.8")
    snapshot = {"snapshot_id": "old", "integrity_valid": True, "fresh": False, "snapshot_age_seconds": 999999,
                "networks": [{"network": "8.8.8.0/24", "address_family": 4, "sbl_id": "SBL123"}]}
    stale_match = collector.collect_spamhaus_drop(asset, snapshot)
    assert stale_match.status == "unavailable"
    assert stale_match.findings[0]["applicability"] == "needs_review"
    assert stale_match.evidence["freshness"] == "stale"
    risk = score_records([RiskFindingRecord(id="old", fingerprint="old", category="reputation", severity="medium",
                                             applicability="needs_review")], {"spamhaus_drop": "unavailable"})
    assert risk["score"] is None
    assert "reputation" in risk["excluded_categories"]
    fresh_no_match = collector.collect_spamhaus_drop(asset, {**snapshot, "fresh": True, "snapshot_age_seconds": 30,
        "networks": [{"network": "1.1.1.0/24", "address_family": 4, "sbl_id": "SBL_OTHER"}]})
    assert fresh_no_match.status == "no_match"
    assert fresh_no_match.evidence["message"] == "Not listed in this snapshot."
    assert "safe" not in fresh_no_match.evidence["message"].casefold()


def test_snapshot_refresh_persists_immutable_payload_and_duplicate_delivery_is_idempotent(workspace, monkeypatch):
    _client, factory = workspace
    settings = live_settings()
    at = datetime(2026, 10, 20, 12, tzinfo=timezone.utc)
    with factory() as db:
        attempt = threat_feeds.queue_refresh(db, trigger_kind="admin", now=at, settings=settings)
        first_id = attempt.id
        db.commit()
    captured = []

    def fetcher(url, **kwargs):
        captured.append((url, kwargs))
        family = 4 if url.endswith("drop_v4.json") else 6
        return response(family)

    with factory() as db:
        threat_feeds.process_refresh_attempt(first_id, session_factory=factory, settings=settings, fetcher=fetcher)
    with factory() as db:
        attempt = db.get(ThreatFeedRefreshAttempt, first_id)
        source = db.get(ThreatFeedSource, threat_feeds.SOURCE_ID)
        snapshot = db.get(ThreatFeedSnapshot, source.active_snapshot_id)
        records = db.query(ThreatFeedNetwork).filter_by(snapshot_id=snapshot.id).all()
        old_retrieved = snapshot.retrieved_at
        assert attempt.status == "succeeded"
        assert source.last_successful_revalidation_at is not None
        assert snapshot.record_count == 2
        assert len(records) == 2
        assert {item.address_family for item in records} == {4, 6}
        assert snapshot.metadata_json["attribution"].startswith("Spamhaus Project")
        snapshot_id = snapshot.id
        content_hash = snapshot.content_sha256
    assert [url for url, _kwargs in captured] == list(threat_feeds.FEED_URLS.values())
    assert all(kwargs["max_redirects"] == 0 and kwargs["max_bytes"] <= settings.spamhaus_drop_max_download_bytes
               and kwargs["verify_tls"] for _url, kwargs in captured)

    # A duplicate RQ delivery for the terminal attempt performs no additional HTTP request.
    threat_feeds.process_refresh_attempt(first_id, session_factory=factory, settings=settings, fetcher=fetcher)
    assert len(captured) == 2

    # A later scheduled request sends conditional validators.  A 304 revalidates the same immutable snapshot.
    with factory() as db:
        later = threat_feeds.queue_refresh(db, trigger_kind="scheduled", now=at + timedelta(hours=24), settings=settings)
        later_id = later.id
        db.commit()
    conditional_calls = []

    def unchanged(url, **kwargs):
        conditional_calls.append((url, kwargs))
        return SafeResponse(304, {"etag": kwargs["headers"].get("if-none-match", "")}, b"", url, [])

    threat_feeds.process_refresh_attempt(later_id, session_factory=factory, settings=settings, fetcher=unchanged)
    with factory() as db:
        later = db.get(ThreatFeedRefreshAttempt, later_id)
        source = db.get(ThreatFeedSource, threat_feeds.SOURCE_ID)
        snapshot = db.get(ThreatFeedSnapshot, snapshot_id)
        assert later.status == "unchanged"
        assert later.snapshot_id == snapshot_id
        assert source.active_snapshot_id == snapshot_id
        assert snapshot.content_sha256 == content_hash
        assert snapshot.retrieved_at.replace(tzinfo=timezone.utc) == old_retrieved.replace(tzinfo=timezone.utc)
        assert source.last_successful_revalidation_at.replace(tzinfo=timezone.utc) > old_retrieved.replace(tzinfo=timezone.utc)
    assert all("if-none-match" in kwargs["headers"] and "if-modified-since" in kwargs["headers"]
               for _url, kwargs in conditional_calls)


def test_refresh_failure_keeps_last_snapshot_and_cooldown_rejects_manual_retry(workspace):
    _client, factory = workspace
    settings = live_settings()
    at = datetime(2026, 10, 20, 12, tzinfo=timezone.utc)
    with factory() as db:
        first = threat_feeds.queue_refresh(db, trigger_kind="admin", now=at, settings=settings)
        first_id = first.id
        db.commit()
    threat_feeds.process_refresh_attempt(first_id, session_factory=factory, settings=settings,
        fetcher=lambda url, **_kwargs: response(4 if url.endswith("drop_v4.json") else 6))
    with factory() as db:
        source = db.get(ThreatFeedSource, threat_feeds.SOURCE_ID)
        snapshot_id = source.active_snapshot_id
        checked_at = source.last_successful_revalidation_at
    with factory() as db:
        with pytest.raises(threat_feeds.ThreatFeedCooldown):
            threat_feeds.queue_refresh(db, trigger_kind="admin", now=at + timedelta(hours=1), settings=settings)
    with factory() as db:
        failed = threat_feeds.queue_refresh(db, trigger_kind="scheduled", now=at + timedelta(hours=24), settings=settings)
        failed_id = failed.id
        db.commit()
    calls = 0

    def partial_failure(url, **_kwargs):
        nonlocal calls
        calls += 1
        if url.endswith("drop_v6.json"):
            return SafeResponse(503, {"content-type": "text/html"}, b"unavailable", url, [])
        return response(4)

    threat_feeds.process_refresh_attempt(failed_id, session_factory=factory, settings=settings, fetcher=partial_failure)
    with factory() as db:
        source = db.get(ThreatFeedSource, threat_feeds.SOURCE_ID)
        attempt = db.get(ThreatFeedRefreshAttempt, failed_id)
        assert attempt.status == "failed"
        assert attempt.error_code == "invalid_or_unavailable_feed"
        assert source.active_snapshot_id == snapshot_id
        assert source.last_successful_revalidation_at.replace(tzinfo=timezone.utc) == checked_at.replace(tzinfo=timezone.utc)
    assert calls == 2


def test_daily_scheduler_and_dispatcher_reuse_one_stable_job_id(workspace):
    _client, factory = workspace
    settings = live_settings()
    at = datetime(2026, 10, 20, 12, tzinfo=timezone.utc)
    with factory() as db:
        assert threat_feeds.enqueue_due_refresh(db, now=at, settings=settings)
        assert not threat_feeds.enqueue_due_refresh(db, now=at + timedelta(minutes=5), settings=settings)
        queue = FakeQueue(duplicate=True)
        assert threat_feeds.dispatch_pending_refreshes(db, queue=queue, now=at, settings=settings) == 2
        attempts = db.query(ThreatFeedRefreshAttempt).all()
        assert {item.source_id for item in attempts} == {"spamhaus_drop", "cins_army"}
        assert all(item.status == "dispatched" for item in attempts)
        assert {item[1]["job_id"] for item in queue.jobs} == {
            f"threat-feed-refresh-{attempt.id}" for attempt in attempts
        }


def test_stale_dispatched_refresh_is_reconciled_with_the_same_job_identity(workspace):
    _client, factory = workspace
    settings = live_settings()
    now = datetime(2026, 10, 20, 12, tzinfo=timezone.utc)
    with factory() as db:
        attempt = threat_feeds.queue_refresh(db, trigger_kind="admin", now=now, settings=settings)
        attempt.status = "dispatched"
        attempt.updated_at = now - timedelta(minutes=20)
        attempt_id = attempt.id
        db.commit()
        assert threat_feeds.reconcile_stale_refreshes(db, now=now, stale_after_seconds=60) == 1
        attempt = db.get(ThreatFeedRefreshAttempt, attempt_id)
        assert attempt.status == "queued"
        assert attempt.error_code == "stale_delivery_reconciled"
        queue = FakeQueue()
        assert threat_feeds.dispatch_pending_refreshes(db, queue=queue, now=now, settings=settings) == 1
        assert queue.jobs[0][1]["job_id"] == f"threat-feed-refresh-{attempt_id}"


def test_demo_uses_only_synthetic_fixture_and_has_no_outbound_request(monkeypatch):
    monkeypatch.setattr(threat_feeds, "safe_get", lambda *_args, **_kwargs: pytest.fail("Demo must not use outbound HTTP"))
    asset = SimpleNamespace(kind="ip", identifier="203.0.113.42")
    result = demo_result(asset, "routine_website", "spamhaus_drop")
    assert result.status == "success"
    assert result.evidence["demo_data"] is True
    assert result.evidence["snapshot_id"] == "synthetic-spamhaus-drop-demo-v1"
    assert result.findings[0]["applicability"] == "needs_review"


def test_admin_refresh_permissions_and_demo_refresh_is_disabled(workspace):
    client, _factory = workspace
    login(client, "viewer", "Test-Viewer-Password-2026!")
    response_viewer = client.post("/api/v1/integrations/spamhaus-drop/refresh", headers=csrf(client))
    assert response_viewer.status_code == 403
    client.post("/api/v1/auth/logout", headers=csrf(client))
    login(client)
    response_admin = client.post("/api/v1/integrations/spamhaus-drop/refresh", headers=csrf(client))
    assert response_admin.status_code == 409
    assert "synthetic fixture" in response_admin.json()["detail"].casefold()
    status = client.get("/api/v1/integrations/spamhaus-drop/status")
    assert status.status_code == 200
    assert status.json()["mode"] == "demo"
    assert status.json()["freshness"] == "synthetic"


def test_investigation_pins_snapshot_and_retry_does_not_duplicate_finding_or_mutate_old_report(workspace, monkeypatch):
    client, factory = workspace
    login(client)
    asset = client.post("/api/v1/assets", headers=csrf(client), json={"kind": "ip", "identifier": "8.8.8.8"}).json()
    started = client.post("/api/v1/investigations", headers=csrf(client), json={"asset_id": asset["id"]}).json()
    from app.config import get_settings
    monkeypatch.setenv("APP_MODE", "live")
    monkeypatch.setenv("COOKIE_SECURE", "true")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://test-user:test-password@localhost/cyberlens")
    monkeypatch.setenv("REDIS_PASSWORD", "test-redis-password")
    monkeypatch.setenv("REDIS_URL", "redis://:test-redis-password@localhost:6379/0")
    get_settings.cache_clear()
    monkeypatch.setattr(jobs, "SessionLocal", factory)
    with factory() as db:
        investigation = db.get(Investigation, started["id"])
        investigation.mode = "live"
        investigation.scenario = None
        db.get(Asset, asset["id"]).is_synthetic = False
        db.commit()
    monkeypatch.setattr(collector, "get_settings", lambda: SimpleNamespace(
        app_mode="live", spamhaus_drop_enabled=True, spamhaus_drop_freshness_hours=48,
    ))
    snapshot_id = "snapshot-pinned-v1"
    snapshot = {"snapshot_id": snapshot_id, "content_sha256": "a" * 64,
                "parser_version": threat_feeds.PARSER_VERSION, "record_count": 1,
                "retrieved_at": datetime.now(timezone.utc), "published_at": datetime.now(timezone.utc),
                "last_successful_revalidation_at": datetime.now(timezone.utc), "snapshot_age_seconds": 1,
                "fresh": True, "integrity_valid": True, "metadata": {"feeds": {}},
                "networks": [{"network": "8.8.8.0/24", "address_family": 4, "sbl_id": "SBL1"}]}
    monkeypatch.setattr(threat_feeds, "load_active_snapshot_for_collection",
                        lambda _db, source_id="spamhaus_drop": snapshot if source_id == "spamhaus_drop" else None)

    def collect(name, asset_row, _components, _mode, _scenario, _authorized, feed_snapshot=None):
        if name == "spamhaus_drop":
            assert feed_snapshot["snapshot_id"] == snapshot_id
            return collector.collect_spamhaus_drop(asset_row, feed_snapshot)
        if name == "cins_army":
            return CollectorResult(status="unavailable", source="CINS Army",
                                   evidence={"provider_status": "missing_snapshot"})
        return CollectorResult(status="no_match", source="VirusTotal", evidence={"provider_status": "no_match"})

    monkeypatch.setattr(jobs, "_run_collector", collect)
    jobs.run_investigation_attempt(started["id"], started["attempt_id"])
    first_report = client.post("/api/v1/reports", headers=csrf(client),
                               json={"format": "json", "investigation_id": started["id"]})
    assert first_report.status_code == 201, first_report.text
    report_before = client.get(f"/api/v1/reports/{first_report.json()['id']}").json()
    spamhaus_snapshot = next(item for item in report_before["snapshot"]["threat_feed_snapshots"]
                             if item["source"] == "Spamhaus Project DROP")
    assert spamhaus_snapshot["snapshot_id"] == snapshot_id
    retry = client.post(f"/api/v1/investigations/{started['id']}/retry", headers=csrf(client))
    assert retry.status_code == 202, retry.text
    jobs.run_investigation_attempt(started["id"], retry.json()["attempt_id"])

    with factory() as db:
        runs = db.query(CollectorRun).filter_by(investigation_id=started["id"], collector="spamhaus_drop").all()
        findings = db.query(Finding).filter_by(investigation_id=started["id"], source="Spamhaus Project DROP").all()
        assert len(runs) == 2
        assert all(run.feed_snapshot_id == snapshot_id for run in runs)
        assert len(findings) == 1
        evidence_ids = {findings[0].evidence_id, *findings[0].details_json["additional_evidence_ids"]}
        assert len(evidence_ids) == 2
        assert db.query(InvestigationAttempt).filter_by(investigation_id=started["id"]).count() == 2
    report_after = client.get(f"/api/v1/reports/{first_report.json()['id']}").json()
    assert report_after["snapshot"] == report_before["snapshot"]
    assert report_after["sha256"] == report_before["sha256"]
