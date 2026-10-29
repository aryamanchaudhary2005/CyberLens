from concurrent.futures import ThreadPoolExecutor
import hashlib
import json

import pytest
from fastapi import HTTPException, Response
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.audit_chain import hash_payload
from app.database import Base
from app.integrity import combine_states, integrity_summary, verify_audit_chain, verify_evidence
from app.models import Asset, AuditChainHead, AuditEvent, EvidenceSnapshot, Investigation, User
from app.pagination import Page
from app.routes.audit import list_audit_events
from app.routes.integrity import (export_audit_chain, get_audit_chain_integrity, get_evidence_integrity,
                                   get_integrity_summary, list_evidence_integrity)
from app.routes.reports import _investigation_snapshot, _pdf_bytes
from app.dependencies import require_roles


@pytest.fixture
def db_session():
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = Session(engine, autoflush=False, expire_on_commit=False)
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(engine)
        engine.dispose()


def append(db: Session, action: str, entity_id: str) -> None:
    db.add(AuditEvent(action=action, entity_type="integrity_test", entity_id=entity_id,
                      details_json={"message": "ordinary event metadata"}))


def test_audit_chain_appends_sequences_and_verifies_every_event(db_session):
    append(db_session, "test.first", "one")
    append(db_session, "test.second", "two")
    db_session.commit()
    rows = db_session.query(AuditEvent).order_by(AuditEvent.event_sequence).all()
    head = db_session.get(AuditChainHead, 1)
    assert [row.event_sequence for row in rows] == [1, 2]
    assert rows[0].previous_hash == "0" * 64
    assert rows[1].previous_hash == rows[0].current_hash
    assert head.event_sequence == 2 and head.current_hash == rows[1].current_hash
    assert verify_audit_chain(db_session)["state"] == "verified"


def test_audit_chain_detects_metadata_tampering(db_session):
    append(db_session, "test.append", "one")
    db_session.commit()
    row_id = db_session.query(AuditEvent.id).scalar()
    db_session.execute(text("UPDATE audit_events SET details_json=:value WHERE id=:id"),
                       {"value": json.dumps({"message": "changed"}), "id": row_id})
    db_session.commit()
    result = verify_audit_chain(db_session)
    assert result["state"] == "failed"
    assert result["failed_sequence"] == 1


def test_audit_events_reject_orm_updates_and_deletes(db_session):
    append(db_session, "test.append", "one")
    db_session.commit()
    row = db_session.query(AuditEvent).first()
    row.action = "changed"
    with pytest.raises(ValueError, match="append-only"):
        db_session.flush()
    db_session.rollback()
    row = db_session.query(AuditEvent).first()
    db_session.delete(row)
    with pytest.raises(ValueError, match="append-only"):
        db_session.flush()
    db_session.rollback()


def test_evidence_checksum_verification_detects_mismatch(db_session):
    row = EvidenceSnapshot(investigation_id="investigation-fixture", source="Fixture provider",
        evidence_json={"observed": "value"}, sha256=hash_payload({"observed": "value"}), is_synthetic=True)
    db_session.add(row)
    db_session.commit()
    assert verify_evidence(row)["state"] == "verified"
    row.evidence_json = {"observed": "modified"}
    db_session.commit()
    assert verify_evidence(row)["state"] == "failed"


def test_concurrent_audit_appends_keep_a_contiguous_chain(tmp_path):
    database = tmp_path / "audit-concurrency.db"
    engine = create_engine(f"sqlite+pysqlite:///{database.as_posix()}", connect_args={"timeout": 15})
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def add_event(index: int) -> None:
        with factory() as db:
            append(db, "test.concurrent", str(index))
            db.commit()

    try:
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(add_event, range(24)))
        with factory() as db:
            rows = db.query(AuditEvent).order_by(AuditEvent.event_sequence).all()
            assert [row.event_sequence for row in rows] == list(range(1, 25))
            assert verify_audit_chain(db)["state"] == "verified"
    finally:
        engine.dispose()


def test_new_reports_snapshot_audit_and_evidence_integrity(db_session):
    user = User(username="integrity-reporter", password_hash="unused", role="analyst")
    db_session.add(user)
    db_session.flush()
    asset = Asset(kind="domain", identifier="integrity.example", normalized_identifier="integrity.example",
                  created_by=user.id)
    db_session.add(asset)
    db_session.flush()
    investigation = Investigation(asset_id=asset.id, requested_by=user.id, mode="demo", status="completed", progress=100)
    db_session.add(investigation)
    db_session.flush()
    evidence_json = {"status": "fixture"}
    evidence = EvidenceSnapshot(investigation_id=investigation.id, source="Fixture provider",
        evidence_json=evidence_json, sha256=hashlib.sha256(json.dumps(evidence_json, sort_keys=True,
            separators=(",", ":"), ensure_ascii=False).encode()).hexdigest(), is_synthetic=True)
    db_session.add(evidence)
    append(db_session, "test.report_context", investigation.id)
    db_session.commit()

    snapshot = _investigation_snapshot(db_session, db_session.get(Investigation, investigation.id))
    assert snapshot["integrity"]["state"] == "verified"
    assert snapshot["integrity"]["evidence"]["items"][0]["evidence_id"] == evidence.id
    assert "do not prove forensic authenticity" in snapshot["integrity"]["limitation"]
    assert _pdf_bytes(snapshot).startswith(b"%PDF")


def test_audit_collection_exposes_chain_fields_and_viewer_role_is_read_only(db_session):
    append(db_session, "test.list", "one")
    db_session.commit()
    result = list_audit_events(_user=User(username="viewer", password_hash="unused", role="viewer"),
        db=db_session, response=Response(), action=None, entity_type=None, actor_id=None, q=None,
        sort="created_at", order="desc", page=Page(1, 20))
    assert result[0]["event_sequence"] == 1
    assert len(result[0]["current_hash"]) == 64
    assert result[0]["metadata"] == result[0]["details"]
    check_export = require_roles("admin", "analyst")
    check_export(User(username="analyst", password_hash="unused", role="analyst"))
    with pytest.raises(HTTPException) as denied:
        check_export(User(username="viewer", password_hash="unused", role="viewer"))
    assert denied.value.status_code == 403


def test_integrity_api_handlers_verify_evidence_and_export_chain(db_session):
    evidence_json = {"provider": "offline fixture"}
    evidence = EvidenceSnapshot(investigation_id="api-fixture", source="Fixture", evidence_json=evidence_json,
        sha256=hash_payload(evidence_json), is_synthetic=True)
    db_session.add(evidence)
    append(db_session, "test.api", "integrity")
    db_session.commit()
    viewer = User(username="integrity-viewer", password_hash="unused", role="viewer")
    analyst = User(username="integrity-analyst", password_hash="unused", role="analyst")

    assert get_integrity_summary(_user=viewer, db=db_session)["state"] == "verified"
    assert get_audit_chain_integrity(_user=viewer, db=db_session)["state"] == "verified"
    assert list_evidence_integrity(_user=viewer, db=db_session, response=Response(), page=Page(1, 20))[0]["state"] == "verified"
    assert get_evidence_integrity(evidence.id, _user=viewer, db=db_session)["state"] == "verified"
    exported = export_audit_chain(_user=analyst, db=db_session)
    assert exported.media_type == "application/x-ndjson"
    assert exported.headers["X-Audit-Chain-State"] == "verified"
    assert json.loads(exported.body)["event_sequence"] == 1


def test_empty_workspace_integrity_is_incomplete(db_session):
    # An absent evidence set is not reported as a successful evidence check.
    assert integrity_summary(db_session)["evidence"]["state"] == "incomplete"
    assert integrity_summary(db_session)["audit_chain"]["state"] == "incomplete"
    assert combine_states(["verified", "unavailable"]) == "unavailable"
    assert combine_states(["verified", "failed", "unavailable"]) == "failed"
