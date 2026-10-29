import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.graph import ensure_relationships
from app.schemas import EvidenceGraphChangesOut, EvidenceGraphOut
from app.models import (
    Asset,
    CollectorRun,
    EvidenceSnapshot,
    EvidenceRelationship,
    Finding,
    Investigation,
    InvestigationAttempt,
    SoftwareComponent,
    User,
)
from app.routes.investigations import compare_evidence_graphs, get_evidence_graph
from conftest import login

GRAPH_FIXTURE = Path(__file__).parent / "fixtures" / "graph" / "domain_observations.json"
OBSERVED_AT = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def graph_workspace():
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    with factory() as db:
        admin = User(username="graph-admin", password_hash="not-used", role="admin")
        db.add(admin)
        db.flush()
        asset = Asset(kind="domain", identifier="portal.example.test", normalized_identifier="portal.example.test",
                      created_by=admin.id, is_synthetic=True)
        db.add(asset)
        db.commit()
        asset_id, admin_id = asset.id, admin.id
    yield factory, asset_id, admin_id
    Base.metadata.drop_all(engine)
    engine.dispose()


def _create_investigation(factory, *, asset_id: str, admin_id: str, status: str,
                          dns_status: str = "success", dns_empty: bool = False,
                          include_software_finding: bool = False,
                          certificate_trust_valid: bool | None = None) -> str:
    with factory() as db:
        investigation = Investigation(asset_id=asset_id, requested_by=admin_id, mode="demo",
                                      scenario="routine_website", status=status, progress=100,
                                      created_at=OBSERVED_AT, started_at=OBSERVED_AT,
                                      finished_at=OBSERVED_AT)
        db.add(investigation)
        db.flush()
        attempt = InvestigationAttempt(investigation_id=investigation.id, attempt_number=1,
                                       retry_kind="initial", status=status, progress=100,
                                       created_at=OBSERVED_AT, started_at=OBSERVED_AT,
                                       finished_at=OBSERVED_AT)
        db.add(attempt)
        db.flush()
        dns_run = CollectorRun(investigation_id=investigation.id, attempt_id=attempt.id,
                               collector="dns_rdap", status=dns_status, source="Synthetic DNS fixture",
                               record_count=1 if dns_status == "success" else 0,
                               started_at=OBSERVED_AT, finished_at=OBSERVED_AT)
        db.add(dns_run)
        db.flush()
        fixture = json.loads(GRAPH_FIXTURE.read_text(encoding="utf-8"))
        dns_payload = fixture["dns"] if dns_status == "success" and not dns_empty else {
            "submitted_host": "portal.example.test",
            "records": ({"A": {"status": "no_match", "values": []}, "AAAA": {"status": "no_match", "values": []}}
                        if dns_empty else
                        {"A": {"status": "failed", "values": [], "error": "ProviderUnavailable"},
                         "AAAA": {"status": "failed", "values": [], "error": "ProviderUnavailable"}}),
        }
        dns_evidence = EvidenceSnapshot(investigation_id=investigation.id, collector_run_id=dns_run.id,
                                        source="Synthetic DNS fixture", observed_at=OBSERVED_AT,
                                        evidence_json=dns_payload, sha256="a" * 64, is_synthetic=True)
        db.add(dns_evidence)
        db.flush()
        if dns_status == "success":
            for collector, key, source in (("web_tls", "website", "Synthetic website fixture"),):
                run = CollectorRun(investigation_id=investigation.id, attempt_id=attempt.id,
                                   collector=collector, status="success", source=source, record_count=0,
                                   started_at=OBSERVED_AT, finished_at=OBSERVED_AT)
                db.add(run)
                db.flush()
                observation = fixture[key]
                if key == "website" and certificate_trust_valid is not None:
                    observation["certificate"]["trust_valid"] = certificate_trust_valid
                db.add(EvidenceSnapshot(investigation_id=investigation.id, collector_run_id=run.id,
                    source=source, observed_at=OBSERVED_AT, evidence_json=observation,
                    sha256="b" * 64, is_synthetic=True))
        if include_software_finding:
            software = SoftwareComponent(asset_id=asset_id, vendor="Acme", product="Widget", version="1.2.3")
            db.add(software)
            db.flush()
            nvd_run = CollectorRun(investigation_id=investigation.id, attempt_id=attempt.id,
                                   collector="nvd_kev", status="success", source="Synthetic NVD fixture",
                                   record_count=1, started_at=OBSERVED_AT, finished_at=OBSERVED_AT)
            db.add(nvd_run)
            db.flush()
            nvd_evidence = EvidenceSnapshot(investigation_id=investigation.id, collector_run_id=nvd_run.id,
                source="Synthetic NVD fixture", observed_at=OBSERVED_AT,
                evidence_json={"components": [{"component_id": software.id, "status": "success"}]},
                sha256="c" * 64, is_synthetic=True)
            db.add(nvd_evidence)
            db.flush()
            db.add(Finding(asset_id=asset_id, investigation_id=investigation.id, evidence_id=nvd_evidence.id,
                fingerprint="f" * 64, category="vulnerabilities", severity="high", title="CVE-2026-1000 candidate",
                explanation="Synthetic candidate.", recommendation="Review candidate.", source="Synthetic NVD fixture",
                observed_at=OBSERVED_AT, applicability="needs_review", is_synthetic=True,
                details_json={"cve_id": "CVE-2026-1000", "component_id": software.id}))
        db.flush()
        ensure_relationships(db, investigation)
        db.commit()
        return investigation.id


def _append_dns_outage_retry(factory, investigation_id: str) -> None:
    with factory() as db:
        investigation = db.get(Investigation, investigation_id)
        retry_at = OBSERVED_AT + timedelta(minutes=1)
        attempt = InvestigationAttempt(investigation_id=investigation.id, attempt_number=2,
            retry_kind="manual", status="partial", progress=100, created_at=retry_at,
            started_at=retry_at, finished_at=retry_at)
        db.add(attempt)
        db.flush()
        run = CollectorRun(investigation_id=investigation.id, attempt_id=attempt.id,
            collector="dns_rdap", status="unavailable", source="Synthetic DNS fixture",
            record_count=0, started_at=retry_at, finished_at=retry_at)
        db.add(run)
        db.flush()
        db.add(EvidenceSnapshot(investigation_id=investigation.id, collector_run_id=run.id,
            source="Synthetic DNS fixture", observed_at=retry_at,
            evidence_json={"submitted_host": "portal.example.test", "records": {
                "A": {"status": "failed", "values": [], "error": "ProviderUnavailable"},
                "AAAA": {"status": "failed", "values": [], "error": "ProviderUnavailable"}}},
            sha256="e" * 64, is_synthetic=True))
        investigation.status = "partial"
        investigation.finished_at = retry_at
        db.flush()
        ensure_relationships(db, investigation)
        db.commit()


def test_graph_projection_is_typed_temporal_and_every_edge_traces_to_evidence(graph_workspace):
    factory, asset_id, admin_id = graph_workspace
    investigation_id = _create_investigation(factory, asset_id=asset_id, admin_id=admin_id,
                                               status="completed", include_software_finding=True)

    with factory() as db:
        count_before = db.query(EvidenceRelationship).filter_by(investigation_id=investigation_id).count()
        graph = get_evidence_graph(investigation_id, db.get(User, admin_id), db)
        count_after = db.query(EvidenceRelationship).filter_by(investigation_id=investigation_id).count()
        assert count_after == count_before
    EvidenceGraphOut.model_validate(graph)
    assert {node["type"] for node in graph["nodes"]} >= {
        "asset", "domain", "ip", "certificate", "software", "cve", "finding", "investigation"
    }
    assert {edge["relationship_type"] for edge in graph["edges"]} >= {
        "resolves_to", "redirects_to", "presents_certificate", "references_cve", "potentially_affected_by"
    }
    assert {edge["evidence_role"] for edge in graph["edges"]} == {"direct", "contextual"}
    assert all(edge["observed_at"] and edge["source"] and edge["evidence_id"] for edge in graph["edges"])
    assert all(edge["data_mode"] == "demo" for edge in graph["edges"])
    with factory() as db:
        snapshots = {row.id: row for row in db.query(EvidenceSnapshot).filter_by(investigation_id=investigation_id).all()}
        stored_edges = db.query(EvidenceRelationship).filter_by(investigation_id=investigation_id).all()
        assert stored_edges
        for edge in graph["edges"]:
            assert edge["evidence_id"] in snapshots
            assert edge["source"] == snapshots[edge["evidence_id"]].source
        assert all(edge.evidence_id in snapshots for edge in stored_edges)
        assert all(edge.investigation_id == investigation_id for edge in stored_edges)


def test_provider_outage_marks_prior_relationship_unknown_never_removed(graph_workspace):
    factory, asset_id, admin_id = graph_workspace
    previous_id = _create_investigation(factory, asset_id=asset_id, admin_id=admin_id, status="completed")
    current_id = _create_investigation(factory, asset_id=asset_id, admin_id=admin_id,
                                       status="partial", dns_status="success")
    _append_dns_outage_retry(factory, current_id)

    with factory() as db:
        payload = compare_evidence_graphs(current_id, previous_id, db.get(User, admin_id), db)
        EvidenceGraphChangesOut.model_validate(payload)
        changes = payload["changes"]
    lost_dns_edge = next(item for item in changes if item["edge"]["relationship_type"] == "resolves_to")
    assert lost_dns_edge["status"] == "unknown"
    assert "absence is not evidence of removal" in lost_dns_edge["reason"]
    assert not any(item["status"] == "no_longer_observed" and
                   item["edge"]["relationship_type"] == "resolves_to" for item in changes)


def test_successful_collector_absence_is_classified_no_longer_observed(graph_workspace):
    factory, asset_id, admin_id = graph_workspace
    previous_id = _create_investigation(factory, asset_id=asset_id, admin_id=admin_id, status="completed")
    current_id = _create_investigation(factory, asset_id=asset_id, admin_id=admin_id,
                                       status="completed", dns_empty=True)
    with factory() as db:
        payload = compare_evidence_graphs(current_id, previous_id, db.get(User, admin_id), db)
        EvidenceGraphChangesOut.model_validate(payload)
        changes = payload["changes"]
    lost_dns_edge = next(item for item in changes if item["edge"]["relationship_type"] == "resolves_to")
    assert lost_dns_edge["status"] == "no_longer_observed"


def test_changed_certificate_context_is_classified_changed(graph_workspace):
    factory, asset_id, admin_id = graph_workspace
    previous_id = _create_investigation(factory, asset_id=asset_id, admin_id=admin_id,
        status="completed", certificate_trust_valid=True)
    current_id = _create_investigation(factory, asset_id=asset_id, admin_id=admin_id,
        status="completed", certificate_trust_valid=False)
    with factory() as db:
        changes = compare_evidence_graphs(current_id, previous_id, db.get(User, admin_id), db)["changes"]
    certificate_change = next(item for item in changes if item["edge"]["relationship_type"] == "presents_certificate")
    assert certificate_change["status"] == "changed"
    assert certificate_change["edge"]["details"]["trust_valid"] is False


def test_viewer_graph_api_is_read_only_and_returns_evidence_links(workspace):
    client, factory = workspace
    with factory() as db:
        admin = db.query(User).filter_by(username="admin").one()
        asset = Asset(kind="domain", identifier="viewer.example.test", normalized_identifier="viewer.example.test",
                      created_by=admin.id)
        db.add(asset)
        db.commit()
        asset_id, admin_id = asset.id, admin.id
    investigation_id = _create_investigation(factory, asset_id=asset_id, admin_id=admin_id, status="completed")
    with factory() as db:
        before = db.query(EvidenceRelationship).filter_by(investigation_id=investigation_id).count()

    login(client, "viewer", "Test-Viewer-Password-2026!")
    response = client.get(f"/api/v1/investigations/{investigation_id}/graph")
    assert response.status_code == 200, response.text
    graph = response.json()
    assert graph["edges"]
    assert all(edge["evidence_id"] for edge in graph["edges"])
    with factory() as db:
        after = db.query(EvidenceRelationship).filter_by(investigation_id=investigation_id).count()
    assert after == before
