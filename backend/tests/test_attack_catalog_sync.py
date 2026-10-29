from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
from pathlib import Path
import threading

import pytest
from fastapi import HTTPException
from redis import Redis
from rq.exceptions import DuplicateJobError
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import Settings
from app.database import Base
from app.dependencies import require_roles
from app.models import AttackCatalogVersion, AttackMapping, Investigation, Report, User, new_id, now_utc
from app.routes import attack
from app.services import attack_catalog_sync as sync
from app.services.attack import attack_catalog, mapping_payload, technique
from conftest import csrf, login

FIXTURE = Path(__file__).parent / "fixtures" / "attack_enterprise_stix_small.json"


def live_settings() -> Settings:
    return Settings(app_mode="live", database_url="postgresql+psycopg://cyberlens:private@localhost:5432/cyberlens",
                    redis_url="redis://:private@localhost:6379/0", cookie_secure=True)


@pytest.fixture
def catalog_workspace(tmp_path):
    engine = create_engine(
        f"sqlite:///{(tmp_path / 'attack-catalog.db').as_posix()}",
        connect_args={"check_same_thread": False, "timeout": 10},
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    try:
        yield engine, factory
    finally:
        engine.dispose()


def load_fixture() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def normalized(*, version="20.0", checksum="a" * 64, bundle=None):
    retrieved = datetime(2026, 10, 18, tzinfo=timezone.utc)
    version_key = f"mitre-attack-enterprise-{version}-{checksum}"
    catalog = sync.normalize_enterprise_bundle(
        bundle or load_fixture(), release_version=version,
        source_reference=f"https://github.com/mitre-attack/attack-stix-data/blob/{'1' * 40}/enterprise-attack/enterprise-attack-{version}.json",
        retrieved_at=retrieved, checksum=checksum,
    )
    catalog["catalog_version"] = version_key
    return {
        "catalog_version": version_key, "release_version": version,
        "source_reference": catalog["source_reference"], "retrieved_at": retrieved,
        "checksum": checksum, "catalog_json": catalog,
        "result_json": {"technique_count": len(catalog["techniques"]), "tactic_count": len(catalog["tactics"]),
                        "subtechnique_count": sum(row["is_subtechnique"] for row in catalog["techniques"]),
                        "revoked_count": sum(row["revoked"] for row in catalog["techniques"]),
                        "deprecated_count": sum(row["deprecated"] for row in catalog["techniques"])},
    }


def seed_legacy(db: Session) -> AttackCatalogVersion:
    legacy = json.loads((Path(__file__).parents[1] / "app" / "data" / "attack_enterprise_subset.json").read_text(encoding="utf-8"))
    row = AttackCatalogVersion(
        id="legacy-version-row", catalog_version=legacy["catalog_version"],
        source="MITRE ATT&CK Enterprise curated bundled subset", release_version="legacy-subset-1.0",
        source_reference="bundled:attack_enterprise_subset.json", retrieved_at=datetime(2026, 10, 17, tzinfo=timezone.utc),
        checksum="b" * 64, import_status="active", active=True, catalog_json=legacy,
        result_json={"technique_count": len(legacy["techniques"]), "tactic_count": 4}, created_at=now_utc(), updated_at=now_utc(),
    )
    db.add(row)
    db.commit()
    return row


def queued(db: Session, key: str | None = None) -> AttackCatalogVersion:
    now = now_utc()
    row = AttackCatalogVersion(
        id=new_id(), catalog_version=key or f"sync-{new_id()}", source=sync.OFFICIAL_SOURCE,
        import_status="queued", active=False, available_at=now, dispatch_attempts=0,
        created_at=now, updated_at=now,
    )
    db.add(row)
    db.commit()
    return row


def test_valid_stix_import_preserves_subtechnique_and_lifecycle_metadata():
    result = normalized()
    techniques = {row["id"]: row for row in result["catalog_json"]["techniques"]}
    assert set(techniques) == {"T9990", "T9990.001", "T9991", "T9992"}
    assert techniques["T9990.001"]["parent_id"] == "T9990"
    assert techniques["T9990.001"]["stix_id"].startswith("attack-pattern--")
    assert techniques["T9991"]["revoked"] is True and techniques["T9991"]["selectable"] is False
    assert techniques["T9992"]["deprecated"] is True and techniques["T9992"]["selectable"] is False
    assert result["catalog_json"]["relationships"][0]["relationship_type"] == "subtechnique-of"
    assert techniques["T9990"]["references"][0]["source_name"] == "mitre-attack"


@pytest.mark.parametrize("mutate, message", [
    (lambda data: data.update(spec_version="2.0"), "STIX 2.1"),
    (lambda data: data["objects"].pop(0), "missing Enterprise tactic"),
    (lambda data: data["objects"][2]["external_references"].clear(), "missing or ambiguous ATT&CK references"),
    (lambda data: data["objects"].pop(), "no valid parent relationship"),
])
def test_malformed_or_incomplete_bundle_is_rejected(mutate, message):
    data = load_fixture()
    mutate(data)
    with pytest.raises(sync.AttackCatalogImportError, match=message):
        sync.normalize_enterprise_bundle(data, release_version="20.0", source_reference="fixture",
                                         retrieved_at=now_utc(), checksum="a" * 64)


def test_duplicate_external_technique_id_is_rejected():
    data = load_fixture()
    data["objects"][2]["external_references"][0]["external_id"] = "T9990"
    with pytest.raises(sync.AttackCatalogImportError, match="duplicate Enterprise technique IDs"):
        sync.normalize_enterprise_bundle(data, release_version="20.0", source_reference="fixture",
                                         retrieved_at=now_utc(), checksum="a" * 64)


class FakeQueue:
    def __init__(self, duplicate=False):
        self.jobs = []
        self.duplicate = duplicate

    def enqueue(self, *args, **kwargs):
        self.jobs.append((args, kwargs))
        if self.duplicate:
            raise DuplicateJobError("already enqueued")


def test_catalog_worker_entry_point_runs_only_the_catalog_import(monkeypatch):
    from app import jobs

    imported = []
    monkeypatch.setattr(sync, "process_catalog_sync", imported.append)
    monkeypatch.setattr(jobs, "run_investigation_attempt", lambda *_args: pytest.fail("Unrelated investigation execution"))

    jobs.sync_attack_catalog("catalog-request")

    assert imported == ["catalog-request"]


def test_database_dispatch_uses_stable_job_ids_and_handles_duplicate_delivery(catalog_workspace):
    _engine, factory = catalog_workspace
    with factory() as db:
        request = queued(db)
        queue = FakeQueue()
        assert sync.dispatch_pending_catalog_syncs(db, queue=queue) == 1
        assert queue.jobs[0][1]["job_id"] == f"attack-catalog-sync-{request.id}"
        assert db.get(AttackCatalogVersion, request.id).import_status == "dispatched"
        request = queued(db)
        queue = FakeQueue(duplicate=True)
        assert sync.dispatch_pending_catalog_syncs(db, queue=queue) == 1
        assert db.get(AttackCatalogVersion, request.id).import_status == "dispatched"


def test_repeat_import_is_idempotent_and_retains_all_versions(catalog_workspace):
    _engine, factory = catalog_workspace
    with factory() as db:
        legacy = seed_legacy(db)
        first = queued(db)
        sync.process_catalog_sync(first.id, session_factory=factory, settings=live_settings(),
                                  fetcher=normalized)
        db.refresh(legacy)
        db.refresh(first)
        assert first.import_status == "active" and first.active is True
        assert legacy.import_status == "available" and legacy.active is False
        second = queued(db)
        sync.process_catalog_sync(second.id, session_factory=factory, settings=live_settings(),
                                  fetcher=normalized)
        db.refresh(second)
        assert second.import_status == "duplicate" and second.active is False
        assert second.duplicate_of == first.catalog_version
        assert db.query(AttackCatalogVersion).filter_by(active=True).count() == 1


def test_failed_download_keeps_active_catalog_investigation_and_report_unchanged(catalog_workspace):
    _engine, factory = catalog_workspace
    with factory() as db:
        legacy = seed_legacy(db)
        user = User(username="catalog-admin", password_hash="unused", role="admin")
        db.add(user)
        investigation = Investigation(asset_id="existing-asset", requested_by="existing-user", mode="demo", status="completed")
        report = Report(format="json", created_by="existing-user", is_demo=True,
                        snapshot_json={"attack_mappings": [{"catalog_version": legacy.catalog_version,
                                                            "technique_name": "Valid Accounts"}]},
                        content=b"saved report bytes", sha256="c" * 64)
        db.add_all([user, investigation, report])
        request = queued(db)
        db.commit()

        def broken_download():
            raise sync.AttackCatalogImportError("The official Enterprise STIX bundle endpoint returned HTTP 503.")

        sync.process_catalog_sync(request.id, session_factory=factory, settings=live_settings(), fetcher=broken_download)
        db.refresh(legacy); db.refresh(request); db.refresh(investigation); db.refresh(report)
        assert legacy.active is True and legacy.catalog_json["catalog_version"] == "cyberlens-attack-enterprise-subset-1.0"
        assert request.import_status == "failed" and "HTTP 503" in request.error_summary
        assert investigation.status == "completed"
        assert report.snapshot_json["attack_mappings"][0]["technique_name"] == "Valid Accounts"
        assert report.content == b"saved report bytes"


def test_demo_worker_never_calls_fetcher(catalog_workspace):
    _engine, factory = catalog_workspace
    with factory() as db:
        seed_legacy(db)
        request = queued(db)
    called = False

    def should_not_fetch():
        nonlocal called
        called = True
        raise AssertionError("network fetch must not run in Demo")

    sync.process_catalog_sync(request.id, session_factory=factory, settings=Settings(app_mode="demo"), fetcher=should_not_fetch)
    with factory() as db:
        assert db.get(AttackCatalogVersion, request.id).import_status == "failed"
    assert called is False


def test_same_catalog_version_mapping_remains_resolvable_after_activation(catalog_workspace):
    _engine, factory = catalog_workspace
    with factory() as db:
        legacy = seed_legacy(db)
        row = AttackMapping(
            id="historical-map", incident_id="historical-incident", technique_id="T1190", technique_name="Exploit Public-Facing Application",
            tactic="Initial Access", catalog_version=legacy.catalog_version, rationale="Saved mapping text.",
            confidence=.3, source="legacy-test", evidence_role="contextual", evidence_id="evidence-id",
            decision="approved", analyst_confirmed=True, created_by="user-id", created_at=now_utc(), updated_at=now_utc(),
        )
        db.add(row)
        request = queued(db)
        db.commit()
        sync.process_catalog_sync(request.id, session_factory=factory, settings=live_settings(),
                                  fetcher=normalized)
        db.refresh(row)
        assert row.catalog_version == legacy.catalog_version
        assert row.technique_name == "Exploit Public-Facing Application"
        payload = mapping_payload(db, row)
        assert payload["catalog_release_version"] == "legacy-subset-1.0"
        assert "Terms of Use" in payload["catalog_attribution"]
        assert attack_catalog(db)["catalog_version"] == f"mitre-attack-enterprise-20.0-{'a' * 64}"
        assert attack_catalog(db, legacy.catalog_version)["catalog_version"] == legacy.catalog_version
        assert technique("T1190", db=db, version=row.catalog_version)["name"] == row.technique_name


def test_sync_permission_is_administrator_only_and_demo_route_is_disabled(catalog_workspace, monkeypatch):
    _engine, factory = catalog_workspace
    viewer_gate = require_roles("admin")
    with pytest.raises(HTTPException) as denied:
        viewer_gate(User(username="viewer", password_hash="unused", role="viewer"))
    assert denied.value.status_code == 403
    analyst_gate = require_roles("admin")
    with pytest.raises(HTTPException) as analyst_denied:
        analyst_gate(User(username="analyst", password_hash="unused", role="analyst"))
    assert analyst_denied.value.status_code == 403
    monkeypatch.setattr(attack, "get_settings", lambda: Settings(app_mode="demo"))
    with factory() as db:
        with pytest.raises(HTTPException) as demo_denied:
            attack.start_catalog_sync(User(username="admin", password_hash="unused", role="admin", id="admin-id"), db)
        assert demo_denied.value.status_code == 409
        assert db.query(AttackCatalogVersion).count() == 0


def test_catalog_sync_api_requires_admin_and_csrf(workspace, monkeypatch):
    client, _factory = workspace
    monkeypatch.setattr(attack, "get_settings", live_settings)
    login(client, "viewer", "Test-Viewer-Password-2026!")
    viewer_denied = client.post("/api/v1/attack/catalog/sync", headers=csrf(client), json={})
    assert viewer_denied.status_code == 403
    login(client, "admin", "Test-Admin-Password-2026!")
    missing_csrf = client.post("/api/v1/attack/catalog/sync", json={})
    assert missing_csrf.status_code == 403
    queued_response = client.post("/api/v1/attack/catalog/sync", headers=csrf(client), json={})
    assert queued_response.status_code == 202
    assert queued_response.json()["import_status"] == "queued"
    versions = client.get("/api/v1/attack/catalog/versions")
    assert versions.status_code == 200 and versions.json()["versions"][0]["import_status"] == "queued"


def test_official_fetch_uses_pinned_approved_urls_and_reports_quota(monkeypatch):
    from app import network

    sha = "1" * 40
    version = "20.0"
    index = {"collections": [{"id": sync.ENTERPRISE_COLLECTION_ID, "name": "Enterprise ATT&CK",
                               "versions": [{"version": version, "modified": "2026-10-13T17:53:10.145Z",
                                             "url": f"{sync.RAW_ROOT}/master/enterprise-attack/enterprise-attack-{version}.json"}]}]}
    payloads = {
        sync.GITHUB_COMMIT_API: {"sha": sha},
        f"{sync.RAW_ROOT}/{sha}/index.json": index,
        f"{sync.RAW_ROOT}/{sha}/enterprise-attack/enterprise-attack-{version}.json": load_fixture(),
    }
    calls = []

    class Response:
        def __init__(self, url, value, status=200):
            self.status, self.final_url = status, url
            self.body = json.dumps(value).encode()

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        return Response(url, payloads[url])

    monkeypatch.setattr(network, "safe_get", fake_get)
    imported = sync.fetch_current_enterprise_catalog(clock=lambda: datetime(2026, 10, 18, tzinfo=timezone.utc))
    assert imported["release_version"] == "20.0"
    assert imported["source_reference"].endswith(f"{sha}/enterprise-attack/enterprise-attack-20.0.json")
    assert len(calls) == 3 and all(call[1]["max_redirects"] == 0 for call in calls)
    assert calls[-1][0] == f"{sync.RAW_ROOT}/{sha}/enterprise-attack/enterprise-attack-20.0.json"

    def quota_get(url, **kwargs):
        return Response(url, {"message": "rate limit"}, status=403)

    monkeypatch.setattr(network, "safe_get", quota_get)
    with pytest.raises(sync.AttackCatalogImportError, match="HTTP 403"):
        sync.fetch_current_enterprise_catalog()


def test_oversized_official_download_keeps_active_catalog_usable(catalog_workspace, monkeypatch):
    from app import network

    _engine, factory = catalog_workspace
    with factory() as db:
        legacy = seed_legacy(db)
        request = queued(db)
        class OversizedResponse:
            status = 200
            final_url = sync.GITHUB_COMMIT_API
            body = b"x" * (sync.MAX_INDEX_BYTES + 1)

        monkeypatch.setattr(network, "safe_get", lambda *_args, **_kwargs: OversizedResponse())
        sync.process_catalog_sync(request.id, session_factory=factory, settings=live_settings(),
                                  fetcher=sync.fetch_current_enterprise_catalog)
        db.refresh(legacy)
        db.refresh(request)
        assert request.import_status == "failed"
        assert legacy.active is True and legacy.import_status == "active"


def test_incomplete_staged_import_keeps_active_catalog_usable(catalog_workspace):
    _engine, factory = catalog_workspace
    with factory() as db:
        legacy = seed_legacy(db)
        request = queued(db)
        sync.process_catalog_sync(request.id, session_factory=factory, settings=live_settings(),
                                  fetcher=lambda: {"catalog_version": "incomplete"})
        db.refresh(legacy)
        db.refresh(request)
        assert request.import_status == "failed"
        assert legacy.active is True and legacy.import_status == "active"


def test_concurrent_activations_never_leave_two_active_catalogs(catalog_workspace):
    engine, factory = catalog_workspace
    with factory() as db:
        seed_legacy(db)
        first, second = queued(db), queued(db)
    barrier = threading.Barrier(2)

    def fetch_for(version: str, checksum: str):
        result = normalized(version=version, checksum=checksum)
        def wait_fetch():
            barrier.wait(timeout=4)
            return result
        return wait_fetch

    def run(row, version, checksum):
        sync.process_catalog_sync(row.id, session_factory=factory, settings=live_settings(),
                                  fetcher=fetch_for(version, checksum))

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(run, first, "20.0", "a" * 64), executor.submit(run, second, "20.1", "d" * 64)]
        for future in futures:
            future.result(timeout=20)
    with factory() as db:
        assert db.query(AttackCatalogVersion).filter_by(active=True).count() == 1
        rows = db.query(AttackCatalogVersion).filter(AttackCatalogVersion.id.in_([first.id, second.id])).all()
        assert sum(row.import_status == "active" for row in rows) == 1

