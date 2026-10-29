"""CINS Army adapter, shared snapshot lifecycle, and IP-source comparison tests."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from rq.exceptions import DuplicateJobError

from app import jobs
from app.collectors import cins_army, spamhaus_drop
from app.collectors.demo import demo_result
from app.config import Settings
from app.ip_intelligence import build_ip_intelligence_history
from app.models import (Asset, AuditEvent, CollectorRun, EvidenceSnapshot, Investigation, ThreatFeedNetwork,
                        ThreatFeedRefreshAttempt, ThreatFeedSnapshot, ThreatFeedSource, User, new_id)
from app.network import SafeResponse
from app.routes import integrations
from app.services import threat_feeds
from app.services.risk import RiskFindingRecord, score_records
from conftest import csrf, login


def live_settings(**overrides):
    values = {
        "app_mode": "live", "cookie_secure": True,
        "database_url": "postgresql+psycopg://cyberlens:strong-pass@localhost:5432/cyberlens",
        "redis_url": "redis://:strong-pass@localhost:6379/0",
        "cins_army_enabled": True, "cins_army_refresh_interval_hours": 24,
        "collector_timeout_seconds": 4.0,
    }
    values.update(overrides)
    return Settings(**values)


def text_response(body=b"8.8.8.8\n", *, status=200, headers=None):
    return SafeResponse(status, {"content-type": "text/plain", **(headers or {})}, body,
                        threat_feeds.CINS_FEED_URL, [])


class FakeQueue:
    def __init__(self, duplicate=False):
        self.jobs = []
        self.duplicate = duplicate

    def enqueue(self, *args, **kwargs):
        self.jobs.append((args, kwargs))
        if self.duplicate:
            raise DuplicateJobError()


def test_parser_handles_comments_blanks_duplicates_ipv4_and_ipv6_without_prefix_inference():
    parsed = threat_feeds.parse_cins_army_feed(
        b"# official list\n\n8.8.8.8\n8.8.8.8\n; comment\n2001:4860:4860:0000:0000:0000:0000:8888\n// another comment\n",
        max_bytes=2048,
    )
    assert [item["network"] for item in parsed.addresses] == ["8.8.8.8", "2001:4860:4860::8888"]
    assert all(item["indicator_type"] == "ip" and "/" not in item["network"] for item in parsed.addresses)
    assert parsed.addresses[0]["sbl_id"] == ""
    assert "provider_publication_time" not in parsed.metadata
    digest = threat_feeds._canonical_cins_hash(parsed.addresses)
    assert threat_feeds._canonical_cins_hash((*parsed.addresses, parsed.addresses[0])) != digest
    with pytest.raises(ValueError, match="non-canonical IP"):
        threat_feeds._canonical_cins_hash(({**parsed.addresses[0], "address_family": 6},))


@pytest.mark.parametrize("payload", [
    b"", b"# no entries\n", b"8.8.8.8/32\n", b"not-an-ip\n", b"<html>blocked</html>", b"\xff\xfe",
])
def test_parser_rejects_empty_invalid_html_and_non_ip_entries(payload):
    with pytest.raises(threat_feeds.ThreatFeedError):
        threat_feeds.parse_cins_army_feed(payload, max_bytes=2048)


def test_exact_matching_normalizes_addresses_and_never_matches_neighbor_or_private_ip():
    records = [{"indicator_type": "ip", "network": "8.8.8.8"},
               {"indicator_type": "ip", "network": "2606:4700:4700::1111"}]
    assert threat_feeds.match_cins_ip("8.8.8.8", records) == "8.8.8.8"
    assert threat_feeds.match_cins_ip("8.8.8.9", records) is None
    assert threat_feeds.match_cins_ip("2606:4700:4700:0000:0000:0000:0000:1111", records) == "2606:4700:4700::1111"
    assert threat_feeds.match_cins_ip("10.0.0.1", [{"indicator_type": "ip", "network": "10.0.0.1"}]) is None
    assert threat_feeds.match_cins_ip("8.8.8.8", frozenset({"8.8.8.8"})) == "8.8.8.8"


def test_settings_enforce_conservative_daily_cins_interval():
    with pytest.raises(ValueError, match="between 24 and 720"):
        live_settings(cins_army_refresh_interval_hours=23)


def test_live_collector_returns_medium_needs_review_exact_match_and_no_invented_attributes(monkeypatch):
    monkeypatch.setattr(cins_army, "get_settings", lambda: live_settings())
    asset = SimpleNamespace(kind="ip", identifier="8.8.8.8")
    snapshot = {
        "snapshot_id": "cins-snapshot-a", "content_sha256": "a" * 64,
        "parser_version": threat_feeds.CINS_PARSER_VERSION, "record_count": 1,
        "retrieved_at": datetime.now(timezone.utc), "published_at": None,
        "last_successful_revalidation_at": datetime.now(timezone.utc), "snapshot_age_seconds": 5,
        "fresh": True, "integrity_valid": True, "metadata": {},
        "addresses": frozenset({"8.8.8.8"}), "networks": [{"indicator_type": "ip", "network": "8.8.8.8"}],
    }
    result = cins_army.collect_cins_army(asset, snapshot)
    assert result.status == "success"
    assert result.findings[0]["severity"] == "medium"
    assert result.findings[0]["applicability"] == "needs_review"
    assert result.findings[0]["details"]["snapshot_id"] == "cins-snapshot-a"
    assert "score" not in result.evidence and "attack_category" not in result.evidence
    assert result.evidence["provider_published_at"] is None


def test_stale_match_is_unknown_to_risk_and_absence_is_not_called_safe(monkeypatch):
    monkeypatch.setattr(cins_army, "get_settings", lambda: live_settings())
    asset = SimpleNamespace(kind="ip", identifier="8.8.8.8")
    snapshot = {"snapshot_id": "old", "integrity_valid": True, "fresh": False, "snapshot_age_seconds": 999999,
                "addresses": frozenset({"8.8.8.8"}), "record_count": 1, "content_sha256": "b" * 64}
    matched = cins_army.collect_cins_army(asset, snapshot)
    assert matched.status == "unavailable" and matched.findings[0]["applicability"] == "needs_review"
    assert matched.evidence["result"] == "stale_match"
    absent = cins_army.collect_cins_army(asset, {**snapshot, "fresh": True, "addresses": frozenset(), "record_count": 0})
    assert absent.status == "no_match"
    assert absent.evidence["message"] == "Not listed in this snapshot."
    assert "safe" not in absent.evidence["message"].casefold()


def test_two_reputation_sources_do_not_raise_category_score_or_merge_evidence():
    cins = RiskFindingRecord(id="cins-1", fingerprint="cins-1", category="reputation", severity="medium",
                             applicability="applies", source="CINS Army", evidence_id="e-cins")
    drop = RiskFindingRecord(id="drop-1", fingerprint="drop-1", category="reputation", severity="medium",
                             applicability="applies", source="Spamhaus Project DROP", evidence_id="e-drop")
    one = score_records([cins], {"cins_army": "success"})
    both = score_records([cins, drop], {"cins_army": "success", "spamhaus_drop": "success"})
    assert one["score"] == both["score"] == 45
    assert {item["source"] for item in both["explanation"]["contributors"]} == {"CINS Army", "Spamhaus Project DROP"}
    assert {item["evidence_id"] for item in both["explanation"]["contributors"]} == {"e-cins", "e-drop"}


def test_cins_refresh_reuses_shared_snapshot_lifecycle_and_retains_last_good_on_failure(workspace):
    _client, factory = workspace
    settings = live_settings()
    at = datetime(2026, 10, 20, 12, tzinfo=timezone.utc)
    with factory() as db:
        first = threat_feeds.queue_refresh(db, source_id=threat_feeds.CINS_SOURCE_ID, trigger_kind="admin", now=at, settings=settings)
        first_id = first.id
        db.commit()
    requests = []

    def fetcher(url, **kwargs):
        requests.append((url, kwargs))
        return text_response(b"8.8.8.8\n2001:4860:4860::8888\n8.8.8.8\n",
                             headers={"etag": '"cins-v1"', "last-modified": "Tue, 20 Oct 2026 00:00:00 GMT"})

    threat_feeds.process_refresh_attempt(first_id, session_factory=factory, settings=settings, fetcher=fetcher)
    with factory() as db:
        attempt = db.get(ThreatFeedRefreshAttempt, first_id)
        source = db.get(ThreatFeedSource, threat_feeds.CINS_SOURCE_ID)
        snapshot = db.get(ThreatFeedSnapshot, source.active_snapshot_id)
        rows = db.query(ThreatFeedNetwork).filter_by(snapshot_id=snapshot.id).all()
        assert attempt.status == "succeeded" and snapshot.record_count == 2
        assert {row.indicator_type for row in rows} == {"ip"}
        assert {row.network for row in rows} == {"8.8.8.8", "2001:4860:4860::8888"}
        assert all("/" not in row.network and row.sbl_id == "" for row in rows)
        assert snapshot.published_at is None
        snapshot_id = snapshot.id
        retrieved_at = snapshot.retrieved_at
    assert len(requests) == 1 and requests[0][0] == threat_feeds.CINS_FEED_URL
    options = requests[0][1]
    assert options["max_redirects"] == 0 and options["verify_tls"] is True
    assert options["max_bytes"] == settings.cins_army_max_download_bytes
    assert options["timeout"] <= settings.collector_timeout_seconds

    # The same terminal delivery cannot fetch again.
    threat_feeds.process_refresh_attempt(first_id, session_factory=factory, settings=settings, fetcher=fetcher)
    assert len(requests) == 1

    with factory() as db:
        with pytest.raises(threat_feeds.ThreatFeedCooldown):
            threat_feeds.queue_refresh(db, source_id=threat_feeds.CINS_SOURCE_ID, trigger_kind="admin",
                                       now=at + timedelta(hours=1), settings=settings)
        later = threat_feeds.queue_refresh(db, source_id=threat_feeds.CINS_SOURCE_ID, trigger_kind="scheduled",
                                           now=at + timedelta(hours=24), settings=settings)
        later_id = later.id
        db.commit()

    def unchanged(url, **kwargs):
        requests.append((url, kwargs))
        assert kwargs["headers"].get("if-none-match") == '"cins-v1"'
        assert "if-modified-since" in kwargs["headers"]
        return SafeResponse(304, {"etag": '"cins-v1"'}, b"", url, [])

    threat_feeds.process_refresh_attempt(later_id, session_factory=factory, settings=settings, fetcher=unchanged)
    with factory() as db:
        source = db.get(ThreatFeedSource, threat_feeds.CINS_SOURCE_ID)
        snapshot = db.get(ThreatFeedSnapshot, snapshot_id)
        later = db.get(ThreatFeedRefreshAttempt, later_id)
        assert later.status == "unchanged" and later.snapshot_id == snapshot_id
        assert snapshot.retrieved_at.replace(tzinfo=timezone.utc) == retrieved_at.replace(tzinfo=timezone.utc)
        current_snapshot_id = source.active_snapshot_id
        failed = threat_feeds.queue_refresh(db, source_id=threat_feeds.CINS_SOURCE_ID, trigger_kind="scheduled",
                                            now=at + timedelta(hours=48), settings=settings)
        failed_id = failed.id
        db.commit()
    threat_feeds.process_refresh_attempt(failed_id, session_factory=factory, settings=settings,
        fetcher=lambda url, **_kwargs: text_response(status=503))
    with factory() as db:
        source = db.get(ThreatFeedSource, threat_feeds.CINS_SOURCE_ID)
        retained_snapshot = db.get(ThreatFeedSnapshot, current_snapshot_id)
        retained_records = db.query(ThreatFeedNetwork).filter_by(snapshot_id=current_snapshot_id).all()
        assert source.active_snapshot_id == current_snapshot_id
        assert retained_snapshot is not None and retained_snapshot.record_count == 2
        assert {row.network for row in retained_records} == {"8.8.8.8", "2001:4860:4860::8888"}
        assert db.get(ThreatFeedRefreshAttempt, failed_id).status == "failed"


def test_shared_dispatcher_uses_source_qualified_durable_job_id(workspace):
    _client, factory = workspace
    settings = live_settings()
    now = datetime(2026, 10, 20, 12, tzinfo=timezone.utc)
    with factory() as db:
        attempt = threat_feeds.queue_refresh(db, source_id=threat_feeds.CINS_SOURCE_ID,
                                            trigger_kind="admin", now=now, settings=settings)
        attempt_id = attempt.id
        db.commit()
        queue = FakeQueue(duplicate=True)
        assert threat_feeds.dispatch_pending_refreshes(db, queue=queue, now=now, settings=settings) == 1
        assert queue.jobs[0][0][0] == "app.jobs.refresh_threat_feed"
        assert queue.jobs[0][1]["job_id"] == f"threat-feed-refresh-{attempt_id}"
        assert db.get(ThreatFeedRefreshAttempt, attempt_id).status == "dispatched"


def _add_ip_run(db, asset, at, *, collector, status, evidence, source, investigation=None):
    if investigation is None:
        investigation = Investigation(asset_id=asset.id, requested_by=asset.created_by, mode="live", status="completed",
                                      created_at=at, started_at=at, finished_at=at + timedelta(seconds=1))
        db.add(investigation)
        db.flush()
    run = CollectorRun(investigation_id=investigation.id, collector=collector, status=status, source=source,
                       started_at=at, finished_at=at + timedelta(seconds=1), record_count=0)
    db.add(run)
    db.flush()
    row = EvidenceSnapshot(investigation_id=investigation.id, collector_run_id=run.id, source=source,
                           observed_at=at + timedelta(seconds=1), evidence_json=evidence,
                           sha256="c" * 64, is_synthetic=False)
    db.add(row)
    db.flush()
    return investigation, run, row


def test_source_grouping_preserves_evidence_and_valid_refresh_absence_is_not_remediation(workspace):
    _client, factory = workspace
    at = datetime(2026, 10, 20, tzinfo=timezone.utc)
    with factory() as db:
        user = db.query(User).filter_by(username="admin").one()
        asset = Asset(kind="ip", identifier="8.8.8.8", normalized_identifier="8.8.8.8", created_by=user.id)
        db.add(asset)
        db.flush()
        previous, _cins_run, cins_evidence = _add_ip_run(db, asset, at, collector="cins_army", status="success",
            source="CINS Army", evidence={"result": "listed", "freshness": "fresh", "snapshot_id": "cins-1",
            "matched_ip": "8.8.8.8"})
        _add_ip_run(db, asset, at, collector="spamhaus_drop", status="success", source="Spamhaus Project DROP",
            investigation=previous,
            evidence={"result": "listed", "freshness": "fresh", "snapshot_id": "drop-1", "matched_networks": ["8.8.8.0/24"]})
        current, _cins_run, current_cins = _add_ip_run(db, asset, at + timedelta(days=1), collector="cins_army", status="no_match",
            source="CINS Army", evidence={"result": "not_listed_in_snapshot", "freshness": "fresh", "snapshot_id": "cins-2"})
        _drop_investigation, _drop_run, current_drop_evidence = _add_ip_run(db, asset, at + timedelta(days=1), collector="spamhaus_drop", status="success", source="Spamhaus Project DROP",
            investigation=current,
            evidence={"result": "listed", "freshness": "fresh", "snapshot_id": "drop-1", "matched_networks": ["8.8.8.0/24"]})
        summary = build_ip_intelligence_history(db, current)
        assert summary["corroboration_label"] == "Listed by one source"
        source_evidence = {item["collector"]: item["evidence_id"] for item in summary["sources"]}
        assert source_evidence["cins_army"] == current_cins.id
        assert source_evidence["spamhaus_drop"] == current_drop_evidence.id
        assert source_evidence["cins_army"] != source_evidence["spamhaus_drop"]
        assert all(item["observed_at"] is not None for item in summary["sources"][:2])
        cins_history = [event for event in summary["history"] if event["collector"] == "cins_army"]
        assert cins_history[-1]["classification"] == "no_longer_listed"
        spamhaus_history = [event for event in summary["history"] if event["collector"] == "spamhaus_drop"]
        assert spamhaus_history[-1]["classification"] == "continuing_listing"
        assert "not prove remediation" in cins_history[-1]["reason"].casefold()
        assert cins_history[0]["evidence_id"] == cins_evidence.id
        assert cins_history[-1]["evidence_id"] == current_cins.id
        assert {event["evidence_id"] for event in summary["sources"] if event["collector"] in {"cins_army", "spamhaus_drop"}} <= {
            row.id for row in db.query(EvidenceSnapshot).filter(EvidenceSnapshot.investigation_id == current.id).all()
        }
        corroborated, _run, _evidence = _add_ip_run(db, asset, at + timedelta(days=2), collector="cins_army",
            status="success", source="CINS Army",
            evidence={"result": "listed", "freshness": "fresh", "snapshot_id": "cins-3", "matched_ip": "8.8.8.8"})
        _add_ip_run(db, asset, at + timedelta(days=2), collector="spamhaus_drop", status="success",
            source="Spamhaus Project DROP", investigation=corroborated,
            evidence={"result": "listed", "freshness": "fresh", "snapshot_id": "drop-2", "matched_networks": ["8.8.8.0/24"]})
        corroborated_summary = build_ip_intelligence_history(db, corroborated)
        assert corroborated_summary["corroboration_label"] == "Listed by two sources"
        assert set(corroborated_summary["listed_sources"]) == {"CINS Army", "Spamhaus DROP"}
        assert all(item["evidence_id"] for item in corroborated_summary["sources"][:2])


def test_failed_or_stale_observation_is_unknown_not_a_removal(workspace):
    _client, factory = workspace
    at = datetime(2026, 10, 20, tzinfo=timezone.utc)
    with factory() as db:
        user = db.query(User).filter_by(username="admin").one()
        asset = Asset(kind="ip", identifier="8.8.4.4", normalized_identifier="8.8.4.4", created_by=user.id)
        db.add(asset)
        db.flush()
        _add_ip_run(db, asset, at, collector="cins_army", status="success", source="CINS Army",
            evidence={"result": "listed", "freshness": "fresh", "snapshot_id": "snapshot-1"})
        current, _run, _evidence = _add_ip_run(db, asset, at + timedelta(days=1), collector="cins_army", status="unavailable",
            source="CINS Army", evidence={"result": "stale_no_match", "freshness": "stale", "snapshot_id": "snapshot-1"})
        summary = build_ip_intelligence_history(db, current)
        latest = next(event for event in summary["history"] if event["investigation_id"] == current.id)
        assert latest["classification"] == "unknown"
        assert "no listing change was inferred" in latest["reason"].casefold()


def test_new_listing_requires_a_different_successful_snapshot(workspace):
    _client, factory = workspace
    at = datetime(2026, 10, 20, tzinfo=timezone.utc)
    with factory() as db:
        user = db.query(User).filter_by(username="admin").one()
        asset = Asset(kind="ip", identifier="8.8.4.8", normalized_identifier="8.8.4.8", created_by=user.id)
        db.add(asset)
        db.flush()
        _add_ip_run(db, asset, at, collector="cins_army", status="no_match", source="CINS Army",
            evidence={"result": "not_listed_in_snapshot", "freshness": "fresh", "snapshot_id": "cins-old"})
        current, _run, _evidence = _add_ip_run(db, asset, at + timedelta(days=1), collector="cins_army",
            status="success", source="CINS Army",
            evidence={"result": "listed", "freshness": "fresh", "snapshot_id": "cins-new"})
        summary = build_ip_intelligence_history(db, current)
        events = [item for item in summary["history"] if item["collector"] == "cins_army"]
        assert [item["classification"] for item in events] == ["baseline_not_listed", "newly_observed_listing"]


def test_demo_scenarios_cover_cins_only_overlap_no_match_and_outage_without_network(monkeypatch):
    monkeypatch.setattr(threat_feeds, "safe_get", lambda *_args, **_kwargs: pytest.fail("Demo must not request feeds"))
    cins_only_ip = SimpleNamespace(kind="ip", identifier="198.51.100.23")
    overlap_ip = SimpleNamespace(kind="ip", identifier="203.0.113.42")
    no_match_ip = SimpleNamespace(kind="ip", identifier="192.0.2.44")
    outage_ip = SimpleNamespace(kind="ip", identifier="203.0.113.43")
    cins_only = demo_result(cins_only_ip, "ip_cins_only", "cins_army")
    cins_only_drop = demo_result(cins_only_ip, "ip_cins_only", "spamhaus_drop")
    assert cins_only.status == "success" and cins_only.findings
    assert cins_only_drop.status == "no_match" and not cins_only_drop.findings
    assert demo_result(overlap_ip, "ip_overlap", "cins_army").findings
    assert demo_result(overlap_ip, "ip_overlap", "spamhaus_drop").findings
    assert demo_result(no_match_ip, "ip_no_match", "cins_army").status == "no_match"
    assert demo_result(no_match_ip, "ip_no_match", "spamhaus_drop").status == "no_match"
    outage = demo_result(outage_ip, "ip_provider_outage", "cins_army")
    assert outage.status == "unavailable" and not outage.findings


def test_demo_ip_investigation_finishes_partial_during_feed_outage_and_report_snapshot_is_immutable(workspace, monkeypatch):
    client, factory = workspace
    login(client)
    asset = client.post("/api/v1/assets", headers=csrf(client), json={"kind": "ip", "identifier": "203.0.113.43"}).json()
    queued = client.post("/api/v1/investigations", headers=csrf(client),
                         json={"asset_id": asset["id"], "scenario": "ip_provider_outage"}).json()
    monkeypatch.setattr(jobs, "SessionLocal", factory)
    monkeypatch.setattr(threat_feeds, "safe_get", lambda *_args, **_kwargs: pytest.fail("Demo must not refresh feeds"))
    jobs.run_investigation_attempt(queued["id"], queued["attempt_id"])
    detail = client.get(f"/api/v1/investigations/{queued['id']}").json()
    assert detail["status"] == "partial"
    runs = {row["collector"]: row for row in detail["collector_runs"]}
    assert runs["cins_army"]["status"] == "unavailable"
    assert detail["ip_intelligence"]["corroboration_label"] != "Listed by two sources"

    report = client.post("/api/v1/reports", headers=csrf(client),
                         json={"format": "json", "investigation_id": queued["id"]})
    assert report.status_code == 201, report.text
    report_before = client.get(f"/api/v1/reports/{report.json()['id']}").json()
    assert "ip_intelligence" in report_before["snapshot"]
    feed_snapshots = {item["source"]: item for item in report_before["snapshot"]["threat_feed_snapshots"]}
    assert set(feed_snapshots) == {
        "Synthetic Spamhaus DROP fixture", "Synthetic CINS Army fixture",
    }
    for item in feed_snapshots.values():
        assert item["evidence_id"] and item["evidence"]["observed_at"]
    assert feed_snapshots["Synthetic Spamhaus DROP fixture"]["snapshot_id"]
    assert feed_snapshots["Synthetic CINS Army fixture"]["snapshot_id"] is None
    pdf_report = client.post("/api/v1/reports", headers=csrf(client),
                             json={"format": "pdf", "investigation_id": queued["id"]})
    assert pdf_report.status_code == 201, pdf_report.text
    pdf_download = client.get(pdf_report.json()["download_url"])
    assert pdf_download.content.startswith(b"%PDF-")
    retry = client.post(f"/api/v1/investigations/{queued['id']}/retry", headers=csrf(client))
    assert retry.status_code == 202
    jobs.run_investigation_attempt(queued["id"], retry.json()["attempt_id"])
    report_after = client.get(f"/api/v1/reports/{report.json()['id']}").json()
    assert report_after["snapshot"] == report_before["snapshot"]
    assert report_after["sha256"] == report_before["sha256"]


def test_status_and_admin_refresh_permissions_preserve_demo_offline_mode(workspace, monkeypatch):
    client, _factory = workspace
    monkeypatch.setattr(threat_feeds, "safe_get", lambda *_args, **_kwargs: pytest.fail("Demo refresh must not use HTTP"))
    login(client, "viewer", "Test-Viewer-Password-2026!")
    status = client.get("/api/v1/integrations/cins-army/status")
    assert status.status_code == 200
    assert status.json()["mode"] == "demo" and status.json()["freshness"] == "synthetic"
    assert status.json()["integrity_valid"] is True
    denied = client.post("/api/v1/integrations/cins-army/refresh", headers=csrf(client))
    assert denied.status_code == 403
    client.post("/api/v1/auth/logout", headers=csrf(client))
    login(client)
    disabled = client.post("/api/v1/integrations/cins-army/refresh", headers=csrf(client))
    assert disabled.status_code == 409
    assert "synthetic fixture" in disabled.json()["detail"].casefold()


def test_admin_live_refresh_uses_shared_queue_and_audit_event(workspace, monkeypatch):
    client, factory = workspace
    login(client)
    monkeypatch.setattr(integrations, "get_settings", lambda: live_settings())
    response = client.post("/api/v1/integrations/cins-army/refresh", headers=csrf(client))
    assert response.status_code == 202, response.text
    payload = response.json()
    assert payload["status"] == "queued" and payload["trigger_kind"] == "admin"
    with factory() as db:
        attempt = db.query(ThreatFeedRefreshAttempt).filter_by(source_id="cins_army").one()
        event = db.query(AuditEvent).filter_by(action="threat_feed.refresh_requested", entity_id="cins_army").one()
        assert event.details_json["attempt_id"] == attempt.id == payload["id"]
