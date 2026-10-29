"""Website authorization checks shared by API and worker code."""

from datetime import datetime

from sqlalchemy.orm import Session

from app.models import EmailBreachAuthorization, WebsiteAuthorization, now_utc


def active_website_authorization(db: Session, asset_id: str, at: datetime | None = None) -> WebsiteAuthorization | None:
    current_time = at or now_utc()
    return (
        db.query(WebsiteAuthorization)
        .filter(
            WebsiteAuthorization.asset_id == asset_id,
            WebsiteAuthorization.revoked_at.is_(None),
            WebsiteAuthorization.expires_at > current_time,
        )
        .order_by(WebsiteAuthorization.created_at.desc())
        .first()
    )


def active_email_breach_authorization(
    db: Session, asset_id: str, authorization_id: str | None = None, at: datetime | None = None,
) -> EmailBreachAuthorization | None:
    current_time = at or now_utc()
    query = db.query(EmailBreachAuthorization).filter(
        EmailBreachAuthorization.asset_id == asset_id,
        EmailBreachAuthorization.provider == "xposedornot",
        EmailBreachAuthorization.revoked_at.is_(None),
        EmailBreachAuthorization.expires_at > current_time,
    )
    if authorization_id is not None:
        query = query.filter(EmailBreachAuthorization.id == authorization_id)
    return query.order_by(EmailBreachAuthorization.created_at.desc()).first()
