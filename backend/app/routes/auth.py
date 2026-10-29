import logging

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from redis import Redis
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.dependencies import CSRF_COOKIE, SESSION_COOKIE, get_current_user, require_csrf
from app.models import AuditEvent, User, UserSession, new_id, now_utc
from app.openphish_access import personal_data_owner
from app.rate_limit import check_login_rate_limit, clear_login_attempts, get_login_rate_limit_redis
from app.schemas import LoginInput, PasswordChange, UserOut
from app.security import hash_password, new_token, session_expiry, token_digest, verify_password
from app.services.password_screening import PasswordScreeningError, require_password_not_compromised, screening_audit_event

router = APIRouter(prefix="/auth", tags=["auth"])
settings = get_settings()
logger = logging.getLogger("cyberlens.auth")


def _set_cookie(response: Response, name: str, value: str, *, http_only: bool) -> None:
    response.set_cookie(
        name,
        value,
        httponly=http_only,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
        max_age=60 * 60 * 12,
    )


@router.get("/csrf")
def csrf_token(response: Response) -> dict[str, str]:
    token = new_token()
    _set_cookie(response, CSRF_COOKIE, token, http_only=False)
    return {"csrf_token": token}


@router.post("/login")
def login(
    payload: LoginInput,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    redis: Redis = Depends(get_login_rate_limit_redis),
) -> dict:
    cookie_token = request.cookies.get(CSRF_COOKIE, "")
    if not cookie_token or cookie_token != request.headers.get("x-csrf-token", ""):
        raise HTTPException(403, "Fetch a CSRF token before signing in")
    client_key = request.client.host if request.client else "unknown"
    check_login_rate_limit(redis, client_key)
    user = db.query(User).filter_by(username=payload.username).first()
    if user is None or not verify_password(user.password_hash, payload.password) or not user.is_active:
        logger.info("Rejected login for account identifier")
        raise HTTPException(401, "Invalid username or password")
    restricted, owner_id = personal_data_owner(db, get_settings())
    if restricted and user.id != owner_id and not user.must_change_password:
        raise HTTPException(
            403,
            "This Live workspace is restricted to its configured personal OpenPhish owner. "
            "Shared or business use requires prior written provider permission.",
        )
    clear_login_attempts(redis, client_key)
    session_token = new_token()
    csrf = new_token()
    session = UserSession(
        id=new_id(),
        user_id=user.id,
        token_hash=token_digest(session_token),
        csrf_token_hash=token_digest(csrf),
        expires_at=session_expiry(),
    )
    db.add(session)
    db.add(AuditEvent(actor_id=user.id, action="auth.login", entity_type="user", entity_id=user.id))
    db.commit()
    _set_cookie(response, SESSION_COOKIE, session_token, http_only=True)
    _set_cookie(response, CSRF_COOKIE, csrf, http_only=False)
    return {"user": UserOut.model_validate(user).model_dump(), "csrf_token": csrf}


@router.post("/logout")
def logout(request: Request, response: Response, _user: User = Depends(require_csrf), db: Session = Depends(get_db)) -> dict[str, str]:
    session: UserSession = request.state.user_session
    session.revoked_at = now_utc()
    db.add(AuditEvent(actor_id=_user.id, action="auth.logout", entity_type="user", entity_id=_user.id))
    db.commit()
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
    return {"status": "signed_out"}


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)) -> User:
    return user


@router.post("/change-password", response_model=UserOut)
def change_password(
    payload: PasswordChange,
    response: Response,
    user: User = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> User:
    if not verify_password(user.password_hash, payload.current_password):
        raise HTTPException(400, "Current password is incorrect")
    try:
        screening = require_password_not_compromised(payload.new_password, app_mode=settings.app_mode)
    except PasswordScreeningError as exc:
        raise HTTPException(exc.status_code, exc.public_message, headers=exc.headers) from None
    user.password_hash = hash_password(payload.new_password)
    user.must_change_password = False
    rotated_at = now_utc()
    for session in db.query(UserSession).filter_by(user_id=user.id, revoked_at=None).all():
        session.revoked_at = rotated_at
    session_token = new_token()
    csrf = new_token()
    db.add(UserSession(
        id=new_id(),
        user_id=user.id,
        token_hash=token_digest(session_token),
        csrf_token_hash=token_digest(csrf),
        created_at=rotated_at,
        expires_at=session_expiry(),
    ))
    db.add(AuditEvent(actor_id=user.id, action="auth.password_changed", entity_type="user", entity_id=user.id))
    db.add(screening_audit_event(actor_id=user.id, user_id=user.id, result=screening))
    db.commit()
    _set_cookie(response, SESSION_COOKIE, session_token, http_only=True)
    _set_cookie(response, CSRF_COOKIE, csrf, http_only=False)
    return user
