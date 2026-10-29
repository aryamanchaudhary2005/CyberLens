import json

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user, require_roles
from app.integrity import checked_at, integrity_summary, verify_audit_chain, verify_evidence
from app.models import AuditEvent, EvidenceSnapshot, User
from app.pagination import Page, apply_page, page_params
from app.schemas import AuditChainIntegrityOut, EvidenceIntegrityOut, IntegritySummaryOut

router = APIRouter(prefix="/integrity", tags=["integrity"])


def _unavailable_chain() -> dict:
    return {"state": "unavailable", "checked_at": checked_at(), "event_count": 0,
            "verified_count": 0, "last_sequence": None, "last_hash": None,
            "failed_sequence": None, "message": "The audit chain could not be read."}


@router.get("", response_model=IntegritySummaryOut)
def get_integrity_summary(_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    """Verify the audit chain and all saved evidence checksums."""
    try:
        return integrity_summary(db)
    except Exception:
        db.rollback()
        chain = _unavailable_chain()
        return {"state": "unavailable", "checked_at": checked_at(), "audit_chain": chain,
                "evidence": {"state": "unavailable", "total": 0, "checked": 0,
                    "counts": {"verified": 0, "failed": 0, "unavailable": 0, "incomplete": 0}}}


@router.get("/audit-chain", response_model=AuditChainIntegrityOut)
def get_audit_chain_integrity(_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    try:
        return verify_audit_chain(db)
    except Exception:
        db.rollback()
        return _unavailable_chain()


@router.get("/evidence", response_model=list[EvidenceIntegrityOut])
def list_evidence_integrity(
    _user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    response: Response = None,
    page: Page = Depends(page_params),
) -> list[dict]:
    query = db.query(EvidenceSnapshot).order_by(EvidenceSnapshot.observed_at.desc(), EvidenceSnapshot.id.asc())
    rows = apply_page(query, page, response)
    return [verify_evidence(row) for row in rows]


@router.get("/evidence/{evidence_id}", response_model=EvidenceIntegrityOut)
def get_evidence_integrity(evidence_id: str, _user: User = Depends(get_current_user),
                           db: Session = Depends(get_db)) -> dict:
    try:
        row = db.get(EvidenceSnapshot, evidence_id)
    except Exception:
        db.rollback()
        return {"evidence_id": evidence_id, "state": "unavailable", "source": None,
                "observed_at": None, "stored_sha256": None, "calculated_sha256": None,
                "is_synthetic": None, "message": "The evidence record could not be read."}
    if row is None:
        return {"evidence_id": evidence_id, "state": "incomplete", "source": None,
                "observed_at": None, "stored_sha256": None, "calculated_sha256": None,
                "is_synthetic": None, "message": "The referenced evidence record is missing."}
    return verify_evidence(row)


@router.get("/audit-export")
def export_audit_chain(_user: User = Depends(require_roles("admin", "analyst")),
                       db: Session = Depends(get_db)) -> Response:
    """Download audit events as JSON Lines; chain state is included in response headers."""
    try:
        verification = verify_audit_chain(db)
        rows = db.query(AuditEvent).order_by(AuditEvent.event_sequence, AuditEvent.id).all()
        lines = [json.dumps({
            "event_sequence": item.event_sequence,
            "previous_hash": item.previous_hash,
            "current_hash": item.current_hash,
            "id": item.id,
            "actor_id": item.actor_id,
            "action": item.action,
            "entity_type": item.entity_type,
            "entity_id": item.entity_id,
            "created_at": item.created_at.isoformat(),
            "metadata": item.details_json or {},
        }, ensure_ascii=False, sort_keys=True, separators=(",", ":")) for item in rows]
    except Exception:
        db.rollback()
        raise HTTPException(503, "Audit export is unavailable")
    return Response("\n".join(lines) + ("\n" if lines else ""), media_type="application/x-ndjson",
                    headers={"Content-Disposition": "attachment; filename=cyberlens-audit.jsonl",
                             "X-Audit-Chain-State": verification["state"],
                             "X-Audit-Chain-Last-Sequence": str(verification.get("last_sequence") or 0)})
