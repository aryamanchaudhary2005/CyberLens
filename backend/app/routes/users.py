from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.dependencies import require_roles, require_roles_csrf
from app.models import AuditEvent, User, UserSession, now_utc
from app.schemas import AdminPasswordReset, UserCreate, UserOut, UserRoleUpdate
from app.security import hash_password
from app.services.password_screening import PasswordScreeningError, require_password_not_compromised, screening_audit_event

router = APIRouter(prefix="/users", tags=["users"])


@router.get("", response_model=list[UserOut])
def list_users(_admin: User = Depends(require_roles("admin")), db: Session = Depends(get_db)) -> list[User]:
    return db.query(User).order_by(User.username).all()


@router.post("", response_model=UserOut, status_code=201)
def create_user(
    payload: UserCreate,
    admin: User = Depends(require_roles_csrf("admin")),
    db: Session = Depends(get_db),
) -> User:
    username = payload.username.strip().lower()
    if db.query(User).filter_by(username=username).first():
        raise HTTPException(409, "Username already exists")
    normalized_email = payload.email.lower() if payload.email else None
    if normalized_email and db.query(User).filter_by(email=normalized_email).first():
        raise HTTPException(409, "Email address already belongs to a workspace user")
    try:
        screening = require_password_not_compromised(payload.password, app_mode=get_settings().app_mode)
    except PasswordScreeningError as exc:
        raise HTTPException(exc.status_code, exc.public_message, headers=exc.headers) from None
    user = User(username=username, email=normalized_email,
                password_hash=hash_password(payload.password), role=payload.role, must_change_password=True)
    db.add(user)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "Username or email already belongs to a workspace user") from exc
    db.add(AuditEvent(actor_id=admin.id, action="user.created", entity_type="user", entity_id=user.id,
                      details_json={"role": user.role}))
    db.add(screening_audit_event(actor_id=admin.id, user_id=user.id, result=screening))
    db.commit()
    db.refresh(user)
    return user


@router.patch("/{user_id}/active", response_model=UserOut)
def set_user_active(
    user_id: str,
    active: bool,
    admin: User = Depends(require_roles_csrf("admin")),
    db: Session = Depends(get_db),
) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(404, "User not found")
    if user.is_active and user.role == "admin" and not active:
        active_admins = _lock_active_admins(db)
        if len(active_admins) <= 1:
            raise HTTPException(409, "The last active administrator cannot be deactivated")
    if user.id == admin.id and not active:
        raise HTTPException(400, "You cannot deactivate your own account")
    if user.is_active == active:
        return user
    user.is_active = active
    if not active:
        _revoke_user_sessions(db, user.id)
    db.add(AuditEvent(actor_id=admin.id, action="user.active_changed", entity_type="user", entity_id=user.id,
                      details_json={"active": active}))
    db.commit()
    return user


@router.patch("/{user_id}/role", response_model=UserOut)
def set_user_role(
    user_id: str,
    payload: UserRoleUpdate,
    admin: User = Depends(require_roles_csrf("admin")),
    db: Session = Depends(get_db),
) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(404, "User not found")
    previous_role = user.role
    if user.is_active and previous_role == "admin" and payload.role != "admin":
        active_admins = _lock_active_admins(db)
        if len(active_admins) <= 1:
            raise HTTPException(409, "The last active administrator cannot be demoted")
    if previous_role == payload.role:
        return user
    user.role = payload.role
    db.add(AuditEvent(actor_id=admin.id, action="user.role_changed", entity_type="user", entity_id=user.id,
                      details_json={"from": previous_role, "to": payload.role}))
    db.commit()
    return user


@router.post("/{user_id}/password-reset", response_model=UserOut)
def reset_user_password(
    user_id: str,
    payload: AdminPasswordReset,
    admin: User = Depends(require_roles_csrf("admin")),
    db: Session = Depends(get_db),
) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(404, "User not found")
    if user.id == admin.id:
        raise HTTPException(400, "Use the password change flow to update your own password")
    try:
        screening = require_password_not_compromised(payload.new_password, app_mode=get_settings().app_mode)
    except PasswordScreeningError as exc:
        raise HTTPException(exc.status_code, exc.public_message, headers=exc.headers) from None
    user.password_hash = hash_password(payload.new_password)
    user.must_change_password = True
    revoked_count = _revoke_user_sessions(db, user.id)
    db.add(AuditEvent(actor_id=admin.id, action="user.password_reset", entity_type="user", entity_id=user.id,
                      details_json={"sessions_revoked": revoked_count}))
    db.add(screening_audit_event(actor_id=admin.id, user_id=user.id, result=screening))
    db.commit()
    return user


def _lock_active_admins(db: Session) -> list[User]:
    return (
        db.query(User)
        .filter(User.role == "admin", User.is_active.is_(True))
        .with_for_update()
        .all()
    )


def _revoke_user_sessions(db: Session, user_id: str) -> int:
    now = now_utc()
    sessions = db.query(UserSession).filter_by(user_id=user_id, revoked_at=None).all()
    for session in sessions:
        session.revoked_at = now
    return len(sessions)
