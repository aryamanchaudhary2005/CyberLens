"""Offline OpenPhish parsing, snapshot, access, collector, and Demo coverage."""

from datetime import datetime, timedelta, timezone
import hashlib
import json
from types import SimpleNamespace

import pytest

from app import jobs, main
from app.collectors import openphish as collector
from app.collectors.demo import demo_result
from app.config import Settings
from app.models import (
    AuditEvent,
    Asset,
    CollectorRun,
    EvidenceSnapshot,
    Investigation,
    Report,
    ThreatFeedRefreshAttempt,
    ThreatFeedSnapshot,
    ThreatFeedSource,
    ThreatFeedUrl,
    User,
    UserSession,
)
from app.network import SafeResponse
from app.openphish_access import openphish_configuration, personal_data_owner
from app.routes import auth, integrations
from app.services import threat_feeds
from app.services.risk import RiskFindingRecord, score_records
from app.security import token_digest
from app.url_normalization import canonicalize_http_url
from conftest import csrf, login


FEED_URL = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
SYNTHETIC_URL = "https://phishing.example.test/login?campaign=synthetic"


def live_settings(**overrides):
    values = {
        "app_mode": "live", "cookie_secure": True,
        "database_url": "postgresql+psycopg://cyberlens:strong-pass@localhost:5432/cyberlens",
        "redis_url": "redis://:strong-pass@localhost:6379/0",
        "openphish_enabled": True, "openphish_use_ack": True,
        "openphish_personal_owner_username": "admin",
        "openphish_refresh_interval_hours": 12,
        "openphish_freshness_hours": 24,
        "collector_timeout_seconds": 3.0,
    }
    values.update(overrides)
    return Settings(**values)


def feed_response(content: bytes, *, status: int = 200, headers: dict | None = None):
    return SafeResponse(status, {"content-type": "text/plain", **(headers or {})}, content, FEED_URL, [])


def parsed_snapshot(content: bytes = SYNTHETIC_URL.encode(), *, fresh=True, complete=True):
    parsed = threat_feeds.parse_openphish_feed(content, max_bytes=4096)
    return SimpleNamespace(
        kind="url", identifier=parsed.urls[0]["canonical_url"], url_retention_complete=complete,
    ), {
        "snapshot_id": "openphish-snapshot-test",
        "content_sha256": threat_feeds._canonical_openphish_hash(parsed.urls),
        "parser_version": threat_feeds.OPENPHISH_PARSER_VERSION,
        "record_count": len(parsed.urls), "retrieved_at": datetime.now(timezone.utc),
        "last_successful_revalidation_at": datetime.now(timezone.utc),
        "snapshot_age_seconds": 4, "fresh": fresh, "integrity_valid": True,
        "urls": list(parsed.urls),
    }


def test_openphish_parser_normalizes_only_case_insensitive_url_parts_and_deduplicates():
    parsed = threat_feeds.parse_openphish_feed(
        b"# synthetic fixture\n\nHTTPS://Example.TEST/Admin/Case?token=synthetic#Part\n"
        b"https://example.test/Admin/Case?token=synthetic#Part\n"
        b"https://example.test/admin/case?token=synthetic#Part\n",
        max_bytes=4096,
    )
    assert [row["canonical_url"] for row in parsed.urls] == [
        "https://example.test/Admin/Case?token=synthetic#Part",
        "https://example.test/admin/case?token=synthetic#Part",
    ]
    assert {row["hostname"] for row in parsed.urls} == {"example.test"}
    assert len({row["canonical_sha256"] for row in parsed.urls}) == 2
    assert parsed.metadata["record_count"] == 2
    assert all("score" not in row and "first_seen" not in row for row in parsed.urls)


def test_matching_preserves_query_path_fragment_and_encoded_reserved_characters_and_normalizes_idna():
    submitted = "HTTPS://BÜCHER.example/Case%2FPart?token=synthetic&next=%26#Fragment"
    canonical, host = canonicalize_http_url(submitted)
    assert canonical == "https://xn--bcher-kva.example/Case%2FPart?token=synthetic&next=%26#Fragment"
    assert host == "xn--bcher-kva.example"
    asset = SimpleNamespace(kind="url", identifier=submitted, url_retention_complete=True)
    snapshot = {
        "snapshot_id": "openphish-idna-test", "content_sha256": "a" * 64,
        "parser_version": threat_feeds.OPENPHISH_PARSER_VERSION, "record_count": 1,
        "retrieved_at": datetime.now(timezone.utc), "last_successful_revalidation_at": datetime.now(timezone.utc),
        "snapshot_age_seconds": 2, "fresh": True, "integrity_valid": True,
        "urls": [{"canonical_url": canonical, "canonical_sha256": hashlib.sha256(canonical.encode()).hexdigest(),
                   "hostname": host}],
    }
    matched = collector.collect_openphish(asset, snapshot)
    assert matched.findings and matched.evidence["match_scope"] == "exact_url"

    changed_components = [
        submitted.replace("token=synthetic", "token=other"),
        submitted.replace("/Case%2FPart", "/case%2FPart"),
        submitted.replace("/Case%2FPart", "/Case/Part"),
        submitted.replace("#Fragment", "#fragment"),
    ]
    for identifier in changed_components:
        result = collector.collect_openphish(
            SimpleNamespace(kind="url", identifier=identifier, url_retention_complete=True), snapshot,
        )
        assert result.status == "partial"
        assert result.findings == []
        assert result.evidence["match_scope"] == "contextual_hostname"

    credential_url = "https://person:synthetic-secret@xn--bcher-kva.example/Case%2FPart"
    rejected = collector.collect_openphish(
        SimpleNamespace(kind="url", identifier=credential_url, url_retention_complete=True), snapshot,
    )
    assert rejected.status == "not_applicable"
    assert "synthetic-secret" not in json.dumps(rejected.evidence)
    assert "synthetic-secret" not in (rejected.error_explanation or "")


@pytest.mark.parametrize("payload", [
    b"", b"# comment only\n", b"ftp://example.test/file\n", b"https://user:secret@example.test/login\n",
    b"https://example.test\\admin\n", b"https://example.test:bad/path\n", b"<html>blocked</html>",
    b"\xff", b"https://example.test/" * 200,
])
def test_openphish_parser_rejects_empty_invalid_html_and_oversized_entries(payload):
    with pytest.raises(threat_feeds.ThreatFeedError):
        threat_feeds.parse_openphish_feed(payload, max_bytes=1024)


def test_collector_direct_match_is_medium_needs_review_and_context_is_not_a_finding(monkeypatch):
    monkeypatch.setattr(threat_feeds, "safe_get", lambda *_args, **_kwargs: pytest.fail("collector must not visit URL assets"))
    asset, snapshot = parsed_snapshot()
    direct = collector.collect_openphish(asset, snapshot)
    assert direct.status == "success"
    assert len(direct.findings) == 1
    assert direct.findings[0]["severity"] == "medium"
    assert direct.findings[0]["applicability"] == "needs_review"
    assert direct.findings[0]["details"]["snapshot_id"] == snapshot["snapshot_id"]
    assert "exactly matches" in direct.findings[0]["explanation"]
    assert "compromised" in direct.findings[0]["explanation"]
    assert "listed_url" not in json.dumps(direct.evidence)

    contextual_asset = SimpleNamespace(kind="url", identifier="https://phishing.example.test/other?campaign=synthetic",
                                       url_retention_complete=True)
    contextual = collector.collect_openphish(contextual_asset, snapshot)
    assert contextual.status == "partial"
    assert contextual.findings == []
    assert contextual.evidence["match_scope"] == "contextual_hostname"

    legacy_asset, _ = parsed_snapshot(complete=False)
    legacy = collector.collect_openphish(legacy_asset, snapshot)
    assert legacy.status == "partial" and legacy.findings == []
    assert legacy.evidence["url_retention_limitation"]


def test_stale_unknown_integrity_and_no_match_never_create_findings_or_safe_claims():
    asset, snapshot = parsed_snapshot()
    stale = collector.collect_openphish(asset, {**snapshot, "fresh": False})
    assert stale.status == "unavailable" and stale.findings == []
    assert stale.evidence["result"] == "unknown"
    assert "coverage is unknown" in stale.error_explanation
    failed = collector.collect_openphish(asset, {**snapshot, "integrity_valid": False})
    assert failed.status == "unavailable" and failed.findings == []
    no_match_asset = SimpleNamespace(kind="url", identifier="https://other.example.test/login?campaign=synthetic",
                                     url_retention_complete=True)
    no_match = collector.collect_openphish(no_match_asset, snapshot)
    assert no_match.status == "no_match" and no_match.findings == []
    assert no_match.evidence["message"] == "No exact URL match in this snapshot."
    assert "safe" not in no_match.evidence["message"].casefold()
    missing = collector.collect_openphish(asset, None)
    assert missing.status == "unavailable" and missing.evidence["result"] == "unknown"


def test_openphish_candidate_only_affects_risk_after_analyst_applicability():
    candidate = RiskFindingRecord(id="openphish-1", fingerprint="openphish-1", category="reputation",
                                  severity="medium", applicability="needs_review", source="OpenPhish Community Feed")
    pending = score_records([candidate], {"openphish": "success"})
    confirmed = score_records([RiskFindingRecord(**{**candidate.__dict__, "applicability": "applies"})],
                              {"openphish": "success"})
    assert pending["score"] == 0 and not pending["explanation"]["contributors"]
    assert confirmed["score"] == 45


def test_openphish_refresh_uses_fixed_url_stores_exact_snapshot_and_retains_last_good_on_failure(workspace, monkeypatch):
    _client, factory = workspace
    settings = live_settings()
    monkeypatch.setattr(threat_feeds, "get_settings", lambda: settings)
    at = datetime.now(timezone.utc).replace(microsecond=0)
    with factory() as db:
        admin = db.query(User).filter_by(username="admin").one()
        first = threat_feeds.queue_refresh(db, requested_by=admin, source_id="openphish", now=at, settings=settings)
        duplicate = threat_feeds.queue_refresh(db, requested_by=admin, source_id="openphish", now=at, settings=settings)
        assert duplicate.id == first.id
        assert db.query(ThreatFeedRefreshAttempt).filter_by(source_id="openphish").count() == 1
        first_id = first.id
        db.commit()

    requests = []

    def fetcher(url, **kwargs):
        requests.append((url, kwargs))
        assert url == FEED_URL
        return feed_response((SYNTHETIC_URL + "\n").encode(), headers={"etag": '"synthetic-1"'})

    threat_feeds.process_refresh_attempt(first_id, session_factory=factory, settings=settings, fetcher=fetcher)
    with factory() as db:
        source = db.get(ThreatFeedSource, "openphish")
        attempt = db.get(ThreatFeedRefreshAttempt, first_id)
        snapshot = db.get(ThreatFeedSnapshot, source.active_snapshot_id)
        rows = db.query(ThreatFeedUrl).filter_by(snapshot_id=snapshot.id).all()
        assert attempt.status == "succeeded"
        assert source.personal_owner_user_id == db.query(User).filter_by(username="admin").one().id
        assert snapshot.record_count == 1 and snapshot.parser_version == threat_feeds.OPENPHISH_PARSER_VERSION
        assert rows[0].canonical_url == SYNTHETIC_URL
        snapshot_id = snapshot.id
        good_revalidation = source.last_successful_revalidation_at
        next_at = at + timedelta(hours=12)
    options = requests[0][1]
    assert options["verify_tls"] is True and options["max_redirects"] == 0
    assert options["max_bytes"] == settings.openphish_max_download_bytes
    assert options["timeout"] <= settings.collector_timeout_seconds
    assert "https://phishing.example.test" not in requests[0][0]

    with factory() as db:
        later = threat_feeds.queue_refresh(db, source_id="openphish", trigger_kind="scheduled", now=next_at,
                                           settings=settings)
        later_id = later.id
        db.commit()
    threat_feeds.process_refresh_attempt(later_id, session_factory=factory, settings=settings,
        fetcher=lambda url, **kwargs: (
            requests.append((url, kwargs)) or SafeResponse(304, {"etag": '"synthetic-1"'}, b"", url, [])
        ))
    with factory() as db:
        unchanged = db.get(ThreatFeedRefreshAttempt, later_id)
        assert unchanged.status == "unchanged" and unchanged.snapshot_id == snapshot_id
        refreshed_at = db.get(ThreatFeedSource, "openphish").last_successful_revalidation_at
        assert refreshed_at.replace(tzinfo=timezone.utc) >= good_revalidation.replace(tzinfo=timezone.utc)
        failed_attempt = threat_feeds.queue_refresh(db, source_id="openphish", trigger_kind="scheduled",
                                                    now=at + timedelta(hours=24), settings=settings)
        failed_id = failed_attempt.id
        db.commit()
    threat_feeds.process_refresh_attempt(failed_id, session_factory=factory, settings=settings,
        fetcher=lambda url, **kwargs: SafeResponse(503, {"content-type": "text/plain"}, b"unavailable", url, []))
    with factory() as db:
        source = db.get(ThreatFeedSource, "openphish")
        assert db.get(ThreatFeedRefreshAttempt, failed_id).status == "failed"
        assert source.active_snapshot_id == snapshot_id
        assert source.last_successful_revalidation_at.replace(tzinfo=timezone.utc) == refreshed_at.replace(tzinfo=timezone.utc)
        status = threat_feeds.openphish_status_payload(db, settings=settings)
        assert "urls" not in status
        assert SYNTHETIC_URL not in json.dumps(status, default=str)


def test_openphish_is_disabled_by_default_requires_terms_ack_and_separates_shared_permission(workspace):
    _client, factory = workspace
    disabled = live_settings(openphish_enabled=False, openphish_use_ack=False,
                             openphish_personal_owner_username=None)
    assert openphish_configuration(disabled)["ready"] is False
    with factory() as db:
        with pytest.raises(threat_feeds.ThreatFeedError, match="disabled"):
            threat_feeds.queue_refresh(db, source_id="openphish", settings=disabled)
        no_ack = live_settings(openphish_use_ack=False)
        with pytest.raises(threat_feeds.ThreatFeedError, match="terms"):
            threat_feeds.queue_refresh(db, source_id="openphish", settings=no_ack)
        shared = live_settings(openphish_personal_owner_username=None,
                               openphish_provider_sharing_permission_ack=True)
        assert openphish_configuration(shared)["access_scope"] == "provider_authorized_shared"
        attempt = threat_feeds.queue_refresh(db, source_id="openphish", settings=shared)
        assert attempt.requested_by is None


def test_personal_owner_gate_survives_feature_disable_and_only_shares_with_separate_permission(workspace):
    _client, factory = workspace
    with factory() as db:
        owner = db.query(User).filter_by(username="admin").one()
        db.add(ThreatFeedSource(id="openphish", display_name="OpenPhish Community Feed",
            source_urls_json=[FEED_URL], personal_owner_user_id=owner.id, validators_json={}))
        db.flush()
        disabled = live_settings(openphish_enabled=False, openphish_use_ack=False,
                                 openphish_personal_owner_username=None)
        restricted, owner_id = personal_data_owner(db, disabled)
        assert restricted and owner_id == owner.id
        permission_without_enable = live_settings(openphish_enabled=False,
            openphish_provider_sharing_permission_ack=True)
        restricted, owner_id = personal_data_owner(db, permission_without_enable)
        assert restricted and owner_id == owner.id
        authorized_shared = live_settings(openphish_enabled=True, openphish_use_ack=True,
            openphish_personal_owner_username=None, openphish_provider_sharing_permission_ack=True)
        assert personal_data_owner(db, authorized_shared) == (False, None)


def test_demo_openphish_scenarios_are_offline_synthetic_and_keep_sources_separate(monkeypatch):
    monkeypatch.setattr(threat_feeds, "safe_get", lambda *_args, **_kwargs: pytest.fail("Demo must not request a feed"))
    monkeypatch.setattr(jobs, "get_settings", lambda: Settings(app_mode="demo"))
    assert "openphish" in jobs._collectors(SimpleNamespace(kind="url", identifier=SYNTHETIC_URL), mode="demo")
    asset = SimpleNamespace(kind="url", identifier=SYNTHETIC_URL, url_retention_complete=True)
    one_source = demo_result(asset, "openphish_match", "openphish")
    overlap_openphish = demo_result(asset, "openphish_overlap", "openphish")
    overlap_vt = demo_result(asset, "openphish_overlap", "reputation")
    no_match = demo_result(asset, "openphish_no_match", "openphish")
    outage = demo_result(asset, "openphish_outage", "openphish")
    assert one_source.findings[0]["applicability"] == "needs_review"
    assert overlap_openphish.findings and overlap_vt.findings
    assert overlap_openphish.findings[0]["source"] != overlap_vt.findings[0]["source"]
    assert no_match.status == "no_match" and no_match.findings == []
    assert outage.status == "unavailable" and outage.findings == []
    assert all(result.evidence.get("demo_data") is True for result in
               (one_source, overlap_openphish, no_match, outage))


def test_live_private_workspace_hides_openphish_report_from_other_users(workspace, monkeypatch):
    client, factory = workspace
    login(client)
    viewer_token = "synthetic-existing-viewer-session-token"
    viewer_csrf = "synthetic-existing-viewer-csrf-token"
    with factory() as db:
        admin = db.query(User).filter_by(username="admin").one()
        viewer = db.query(User).filter_by(username="viewer").one()
        asset = Asset(kind="url", identifier=SYNTHETIC_URL, normalized_identifier=SYNTHETIC_URL,
                      url_retention_complete=True, created_by=admin.id)
        db.add(asset)
        db.flush()
        investigation = Investigation(asset_id=asset.id, requested_by=admin.id, mode="live", status="completed")
        db.add(investigation)
        db.flush()
        run = CollectorRun(investigation_id=investigation.id, collector="openphish", status="success",
                           source="OpenPhish Community Feed", record_count=1)
        db.add(run)
        db.flush()
        evidence = EvidenceSnapshot(investigation_id=investigation.id, collector_run_id=run.id,
            source="OpenPhish Community Feed", evidence_json={"result": "listed", "snapshot_id": "test-snapshot"},
            sha256="d" * 64, is_synthetic=False)
        db.add(evidence)
        # This session was valid before the operator enables the personal-only
        # Live data restriction. The API must re-check scope on every request.
        db.add(UserSession(user_id=viewer.id, token_hash=token_digest(viewer_token),
                           csrf_token_hash=token_digest(viewer_csrf),
                           expires_at=datetime.now(timezone.utc) + timedelta(hours=1)))
        db.commit()
        investigation_id = investigation.id
    restricted = live_settings()
    monkeypatch.setattr(auth, "get_settings", lambda: restricted)
    monkeypatch.setattr(integrations, "get_settings", lambda: restricted)
    monkeypatch.setattr(main, "settings", restricted)
    from app import dependencies
    monkeypatch.setattr(dependencies, "get_settings", lambda: restricted)
    from app.services import threat_feeds as feed_service
    monkeypatch.setattr(feed_service, "get_settings", lambda: restricted)

    report = client.post("/api/v1/reports", headers=csrf(client),
                         json={"format": "json", "investigation_id": investigation_id})
    assert report.status_code == 201, report.text
    report_detail = client.get(f"/api/v1/reports/{report.json()['id']}")
    assert report_detail.status_code == 200
    body = report_detail.json()["snapshot"]
    assert "openphish_use_notice" in body
    assert body["threat_feed_snapshots"][0]["source"] == "OpenPhish Community Feed"
    assert SYNTHETIC_URL in json.dumps(body)
    assert client.post("/api/v1/auth/logout", headers=csrf(client)).status_code == 200

    # Existing sessions and new sign-ins for other users are both denied in personal-only mode.
    client.cookies.clear()
    client.cookies.set("cyberlens_session", viewer_token, path="/")
    client.cookies.set("cyberlens_csrf", viewer_csrf, path="/")
    assert client.get("/api/v1/auth/me").status_code == 403
    assert client.get(f"/api/v1/reports/{report.json()['id']}").status_code == 403
    assert client.get(f"/api/v1/reports/{report.json()['id']}/download").status_code == 403
    assert client.get(f"/api/v1/investigations/{investigation_id}").status_code == 403
    assert client.get("/api/v1/findings").status_code == 403
    assert client.get("/api/v1/integrations/openphish/status").status_code == 403
    assert client.post("/api/v1/auth/logout", headers=csrf(client)).status_code == 200
    csrf_response = client.get("/api/v1/auth/csrf")
    assert csrf_response.status_code == 200
    login_attempt = client.post("/api/v1/auth/login",
        json={"username": "viewer", "password": "Test-Viewer-Password-2026!"}, headers=csrf(client))
    assert login_attempt.status_code == 403


def test_legacy_url_confirmation_is_explicit_and_audit_does_not_store_the_url(workspace):
    client, factory = workspace
    login(client)
    with factory() as db:
        admin = db.query(User).filter_by(username="admin").one()
        asset = Asset(kind="url", identifier="https://example.test/Admin/Case",
                      normalized_identifier="https://example.test/Admin/Case",
                      url_retention_complete=False, created_by=admin.id)
        db.add(asset)
        db.commit()
        asset_id = asset.id
    mismatch = client.post(f"/api/v1/assets/{asset_id}/url-retention-confirmation", headers=csrf(client),
                           json={"identifier": "https://example.test/Admin/Case?token=synthetic"})
    assert mismatch.status_code == 409
    confirmed = client.post(f"/api/v1/assets/{asset_id}/url-retention-confirmation", headers=csrf(client),
                            json={"identifier": "https://example.test/Admin/Case"})
    assert confirmed.status_code == 200, confirmed.text
    assert confirmed.json()["url_retention_complete"] is True
    with factory() as db:
        event = db.query(AuditEvent).filter_by(action="asset.url_retention_confirmed", entity_id=asset_id).one()
        assert event.details_json == {"confirmation": "exact_url_components_reviewed"}
        assert "example.test" not in json.dumps(event.details_json)

