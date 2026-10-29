"""Create the first local workspace administrator, if one is not present."""

import logging

from app.config import get_settings
from app.database import SessionLocal
from app.models import AuditEvent, User, UserSession, now_utc
from app.security import hash_password, verify_password
from app.services.password_screening import PasswordScreeningError, require_password_not_compromised, screening_audit_event

SHARED_DEMO_PASSWORD = "CyberLens-Demo-Only-2026!"


def require_live_admin_rotation(db) -> int:
    """Lock administrators who still use the shared Demo credential."""
    changed = 0
    rotated_at = now_utc()
    for user in db.query(User).filter_by(role="admin").all():
        if not verify_password(user.password_hash, SHARED_DEMO_PASSWORD):
            continue
        revoked = (db.query(UserSession).filter_by(user_id=user.id, revoked_at=None).update(
            {UserSession.revoked_at: rotated_at}, synchronize_session=False,
        ))
        if not user.must_change_password or revoked:
            user.must_change_password = True
            db.add(AuditEvent(
                actor_id=None,
                action="user.shared_demo_password_rotation_required",
                entity_type="user",
                entity_id=user.id,
                details_json={"reason": "shared_demo_password_detected", "sessions_revoked": revoked},
            ))
            changed += 1
    if changed:
        db.commit()
    return changed


def main() -> None:
    settings = get_settings()
    db = SessionLocal()
    try:
        if settings.app_mode == "live":
            require_live_admin_rotation(db)
        existing = db.query(User).filter_by(username=settings.bootstrap_admin_username).first()
        if existing is not None:
            logging.getLogger("cyberlens.bootstrap").info("Initial workspace administrator already exists")
            return
        password = settings.bootstrap_admin_password
        if not password and settings.app_mode == "demo":
            password = "CyberLens-Demo-Only-2026!"
        if not password:
            raise RuntimeError("Set BOOTSTRAP_ADMIN_PASSWORD before first startup in live mode")
        if settings.app_mode != "demo":
            if len(password) < 12:
                raise RuntimeError("BOOTSTRAP_ADMIN_PASSWORD must contain at least 12 characters in live mode")
        if settings.app_mode != "demo" and password == SHARED_DEMO_PASSWORD:
            raise RuntimeError("The shared demo password cannot be used to bootstrap a live administrator")
        try:
            screening = require_password_not_compromised(password, app_mode=settings.app_mode)
        except PasswordScreeningError as exc:
            raise RuntimeError(exc.public_message) from None
        user = User(
            username=settings.bootstrap_admin_username,
            password_hash=hash_password(password),
            role="admin",
            must_change_password=True,
        )
        db.add(user)
        db.flush()
        db.add(AuditEvent(actor_id=None, action="user.bootstrap_created", entity_type="user", entity_id=user.id))
        db.add(screening_audit_event(actor_id=None, user_id=user.id, result=screening))
        db.commit()
        logging.getLogger("cyberlens.bootstrap").info("Created initial workspace administrator")
    finally:
        db.close()


if __name__ == "__main__":
    main()
