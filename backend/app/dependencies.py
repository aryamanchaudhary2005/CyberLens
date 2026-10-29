from collections.abc import Callable

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.models import User, UserSession
from app.openphish_access import personal_data_owner
from app.security import is_expired, token_digest

SESSION_COOKIE = "cyberlens_session"
CSRF_COOKIE = "cyberlens_csrf"


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sign in required")
    session = db.query(UserSession).filter_by(token_hash=token_digest(token), revoked_at=None).first()
    if session is None or is_expired(session.expires_at):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired")
    user = db.get(User, session.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Account unavailable")
    restricted, owner_id = personal_data_owner(db, get_settings())
    is_logout = request.url.path.rstrip("/").endswith("/auth/logout")
    if restricted and user.id != owner_id and not is_logout and not user.must_change_password:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=("This Live workspace is restricted to its configured personal OpenPhish owner. "
                    "Shared or business use requires prior written provider permission."),
        )
    if user.must_change_password:
        allowed_paths = {"/api/v1/auth/me", "/api/v1/auth/change-password", "/api/v1/auth/logout"}
        if request.url.path.rstrip("/") not in allowed_paths:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="Change your password before using the workspace")
    request.state.user_session = session
    return user


def require_csrf(request: Request, user: User = Depends(get_current_user)) -> User:
    session: UserSession = request.state.user_session
    token = request.cookies.get(CSRF_COOKIE, "")
    header = request.headers.get("x-csrf-token", "")
    if not token or not header or token != header or token_digest(token) != session.csrf_token_hash:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token missing or invalid")
    return user


def require_roles(*roles: str) -> Callable:
    def dependency(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return user

    return dependency


def require_roles_csrf(*roles: str) -> Callable:
    def dependency(
        user: User = Depends(require_roles(*roles)),
        _session: UserSession = Depends(require_csrf),
    ) -> User:
        return user

    return dependency
