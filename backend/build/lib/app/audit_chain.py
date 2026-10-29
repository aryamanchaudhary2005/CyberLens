"""Transactional, append-only hash chaining for workspace audit events."""

from __future__ import annotations

import hashlib
import json
from contextlib import contextmanager
from datetime import datetime, timezone
from threading import RLock

from sqlalchemy import event, select
from sqlalchemy.orm import Session

from app.models import AuditChainHead, AuditEvent, new_id, now_utc

GENESIS_HASH = "0" * 64
_APPEND_LOCK = RLock()
_INSTALLED = False


@contextmanager
def audit_chain_read_lock():
    """Keep in-process appenders from racing a chain verification pass."""
    _APPEND_LOCK.acquire()
    try:
        yield
    finally:
        _APPEND_LOCK.release()


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def event_payload(row: AuditEvent) -> dict:
    """Return the stable, versioned fields covered by an event's SHA-256."""
    return {
        "chain_version": 1,
        "sequence": row.event_sequence,
        "previous_hash": row.previous_hash,
        "id": row.id,
        "actor_id": row.actor_id,
        "action": row.action,
        "entity_type": row.entity_type,
        "entity_id": row.entity_id,
        "created_at": _utc_text(row.created_at),
        "metadata": row.details_json or {},
    }


def hash_payload(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _release_append_lock(session: Session, _previous_transaction=None) -> None:
    if session.info.pop("_audit_chain_append_lock", False):
        _APPEND_LOCK.release()


def _before_flush(session: Session, _flush_context, _instances) -> None:
    for row in session.dirty:
        if isinstance(row, AuditEvent) and session.is_modified(row, include_collections=False):
            raise ValueError("Audit events are append-only")
    if any(isinstance(row, AuditEvent) for row in session.deleted):
        raise ValueError("Audit events are append-only")

    pending = [row for row in session.new if isinstance(row, AuditEvent)]
    if not pending:
        return

    if not session.info.get("_audit_chain_append_lock"):
        _APPEND_LOCK.acquire()
        session.info["_audit_chain_append_lock"] = True

    try:
        head = next((row for row in session.new if isinstance(row, AuditChainHead) and row.id == 1), None)
        if head is None:
            head = session.execute(
                select(AuditChainHead).where(AuditChainHead.id == 1).with_for_update()
            ).scalar_one_or_none()
        if head is None:
            head = AuditChainHead(id=1, event_sequence=0, current_hash=GENESIS_HASH, updated_at=now_utc())
            session.add(head)

        sequence = head.event_sequence
        previous_hash = head.current_hash or GENESIS_HASH
        for row in pending:
            sequence += 1
            row.id = row.id or new_id()
            row.created_at = row.created_at or now_utc()
            row.details_json = row.details_json or {}
            row.event_sequence = sequence
            row.previous_hash = previous_hash
            row.current_hash = hash_payload(event_payload(row))
            previous_hash = row.current_hash

        head.event_sequence = sequence
        head.current_hash = previous_hash
        head.updated_at = now_utc()
    except Exception:
        _release_append_lock(session)
        raise


def install_audit_event_hooks() -> None:
    global _INSTALLED
    if _INSTALLED:
        return
    event.listen(Session, "before_flush", _before_flush)
    event.listen(Session, "after_commit", _release_append_lock)
    event.listen(Session, "after_rollback", _release_append_lock)
    event.listen(Session, "after_soft_rollback", _release_append_lock)
    _INSTALLED = True
