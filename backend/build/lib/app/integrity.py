"""Verification helpers for the audit hash chain and evidence snapshots."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit_chain import GENESIS_HASH, audit_chain_read_lock, event_payload, hash_payload
from app.models import AuditChainHead, AuditEvent, EvidenceSnapshot

IntegrityState = str  # verified | failed | unavailable | incomplete


def checked_at() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def verify_audit_chain(db: Session) -> dict:
    with audit_chain_read_lock():
        return _verify_audit_chain_locked(db)


def _verify_audit_chain_locked(db: Session) -> dict:
    # PostgreSQL's row lock coordinates verification with appends from other
    # processes; SQLite is serialized by the in-process append lock above.
    head = db.execute(select(AuditChainHead).where(AuditChainHead.id == 1).with_for_update()).scalar_one_or_none()
    events = db.query(AuditEvent).order_by(AuditEvent.event_sequence, AuditEvent.id).all()
    if head is None:
        return {"state": "incomplete", "checked_at": checked_at(), "event_count": len(events),
                "verified_count": 0, "last_sequence": None, "last_hash": None,
                "failed_sequence": None, "message": "Audit chain head is not available."}

    expected_sequence = 1
    expected_previous_hash = GENESIS_HASH
    verified_count = 0
    for row in events:
        if row.event_sequence is None or not row.previous_hash or not row.current_hash:
            return {"state": "incomplete", "checked_at": checked_at(), "event_count": len(events),
                    "verified_count": verified_count, "last_sequence": row.event_sequence,
                    "last_hash": None, "failed_sequence": row.event_sequence,
                    "message": "An audit event is missing chain fields."}
        if row.event_sequence != expected_sequence or row.previous_hash != expected_previous_hash:
            return {"state": "failed", "checked_at": checked_at(), "event_count": len(events),
                    "verified_count": verified_count, "last_sequence": row.event_sequence,
                    "last_hash": row.current_hash, "failed_sequence": row.event_sequence,
                    "message": "Audit event sequence or previous hash does not match the chain."}
        expected_hash = hash_payload(event_payload(row))
        if row.current_hash != expected_hash:
            return {"state": "failed", "checked_at": checked_at(), "event_count": len(events),
                    "verified_count": verified_count, "last_sequence": row.event_sequence,
                    "last_hash": row.current_hash, "failed_sequence": row.event_sequence,
                    "message": "Audit event contents do not match its stored hash."}
        expected_sequence += 1
        expected_previous_hash = row.current_hash
        verified_count += 1

    actual_sequence = expected_sequence - 1
    if head.event_sequence != actual_sequence or head.current_hash != expected_previous_hash:
        return {"state": "failed", "checked_at": checked_at(), "event_count": len(events),
                "verified_count": verified_count, "last_sequence": actual_sequence,
                "last_hash": expected_previous_hash, "failed_sequence": actual_sequence or 1,
                "message": "Audit chain head does not match the verified event sequence."}
    return {"state": "verified", "checked_at": checked_at(), "event_count": len(events),
            "verified_count": verified_count, "last_sequence": actual_sequence,
            "last_hash": expected_previous_hash, "failed_sequence": None,
            "message": "Every audit event and the chain head verified."}


def verify_evidence(row: EvidenceSnapshot) -> dict:
    calculated = hash_payload(row.evidence_json or {})
    stored = row.sha256 or ""
    valid_stored_hash = len(stored) == 64 and all(char in "0123456789abcdef" for char in stored.lower())
    state = "incomplete" if not stored else "verified" if valid_stored_hash and calculated == stored.lower() else "failed"
    return {"evidence_id": row.id, "state": state, "source": row.source,
            "observed_at": row.observed_at, "stored_sha256": stored,
            "calculated_sha256": calculated, "is_synthetic": row.is_synthetic}


def combine_states(states: Iterable[str]) -> str:
    values = list(states)
    if "failed" in values:
        return "failed"
    if "unavailable" in values:
        return "unavailable"
    if "incomplete" in values or not values:
        return "incomplete"
    return "verified"


def verify_evidence_collection(db: Session, *, offset: int = 0, limit: int | None = None) -> dict:
    query = db.query(EvidenceSnapshot).order_by(EvidenceSnapshot.observed_at, EvidenceSnapshot.id)
    total = query.count()
    if limit is not None:
        rows = query.offset(offset).limit(limit).all()
    else:
        rows = query.all()
    records = [verify_evidence(row) for row in rows]
    counts = {state: sum(record["state"] == state for record in records)
              for state in ("verified", "failed", "unavailable", "incomplete")}
    state = combine_states([record["state"] for record in records]) if total else "incomplete"
    return {"state": state, "total": total, "checked": len(records), "counts": counts,
            "items": records}


def integrity_summary(db: Session) -> dict:
    audit = verify_audit_chain(db)
    evidence = verify_evidence_collection(db)
    return {"state": combine_states([audit["state"], evidence["state"]]),
            "checked_at": checked_at(), "audit_chain": audit,
            "evidence": {key: value for key, value in evidence.items() if key != "items"}}


def report_integrity(db: Session, evidence_rows: Iterable[EvidenceSnapshot]) -> dict:
    audit = verify_audit_chain(db)
    evidence = [verify_evidence(row) for row in evidence_rows]
    evidence_state = combine_states([item["state"] for item in evidence])
    return {"state": combine_states([audit["state"], evidence_state]), "checked_at": checked_at(),
            "audit_chain": audit, "evidence": {"state": evidence_state, "total": len(evidence),
                "counts": {state: sum(item["state"] == state for item in evidence)
                           for state in ("verified", "failed", "unavailable", "incomplete")},
                "items": evidence},
            "limitation": "Checksums detect changes to stored bytes; they do not prove forensic authenticity or chain of custody."}
