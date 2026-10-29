"""Operator configuration and access scope for OpenPhish Community Feed data."""

from typing import Any

from sqlalchemy.orm import Session

from app.config import Settings
from app.models import ThreatFeedSource, User

SOURCE_ID = "openphish"


def openphish_configuration(settings: Settings) -> dict[str, Any]:
    if settings.app_mode == "demo":
        return {"ready": False, "state": "synthetic_demo", "access_scope": "synthetic_demo",
                "reason": "Demo uses a bundled synthetic fixture and never contacts OpenPhish."}
    if not settings.openphish_enabled:
        return {"ready": False, "state": "disabled", "access_scope": "disabled",
                "reason": "Live OpenPhish ingestion is disabled by the operator."}
    if not settings.openphish_use_ack:
        return {"ready": False, "state": "acknowledgement_required", "access_scope": "disabled",
                "reason": "Review the current provider terms and configure OPENPHISH_USE_ACK for an applicable permitted use."}
    if settings.openphish_provider_sharing_permission_ack:
        return {"ready": True, "state": "enabled", "access_scope": "provider_authorized_shared",
                "reason": "The operator records that prior written provider permission covers shared or business use. This setting does not grant permission."}
    owner = (settings.openphish_personal_owner_username or "").strip().lower()
    if not owner:
        return {"ready": False, "state": "personal_owner_required", "access_scope": "disabled",
                "reason": "Personal-use mode requires OPENPHISH_PERSONAL_OWNER_USERNAME. Acknowledgement does not grant provider rights."}
    return {"ready": True, "state": "enabled", "access_scope": "personal_only",
            "reason": "Personal-use data is available only to the configured owner; other accounts cannot access this Live workspace while the restriction applies."}


def _configured_owner(db: Session, settings: Settings) -> User | None:
    owner_name = (settings.openphish_personal_owner_username or "").strip().lower()
    if not owner_name:
        return None
    return db.query(User).filter(User.username == owner_name, User.is_active.is_(True)).one_or_none()


def personal_data_owner(db: Session, settings: Settings) -> tuple[bool, str | None]:
    """Return whether private-scope restrictions apply and the permitted user ID.

    The owner ID is persisted on the shared feed source when ingestion is
    queued. The configured username is used before the first refresh and when
    a former shared deployment is deliberately placed back into personal mode.
    If source data exists but no owner can be resolved, access fails closed.
    """
    shared_use_enabled = bool(
        settings.openphish_enabled
        and settings.openphish_use_ack
        and settings.openphish_provider_sharing_permission_ack
    )
    if shared_use_enabled:
        return False, None
    source = db.get(ThreatFeedSource, SOURCE_ID)
    config = openphish_configuration(settings)
    if config["access_scope"] == "personal_only":
        owner = _configured_owner(db, settings)
        return True, owner.id if owner else None
    if source and (source.personal_owner_user_id or source.active_snapshot_id):
        owner_id = source.personal_owner_user_id
        if owner_id is None:
            owner = _configured_owner(db, settings)
            owner_id = owner.id if owner else None
        return True, owner_id
    return False, None


def assert_personal_owner(db: Session, settings: Settings, user: User) -> User:
    """Pin and return the configured active personal owner, or raise ValueError."""
    config = openphish_configuration(settings)
    if not config["ready"]:
        raise ValueError(config["reason"])
    if config["access_scope"] != "personal_only":
        raise ValueError("No personal owner is required in provider-authorized shared mode.")
    owner = _configured_owner(db, settings)
    if owner is None:
        raise ValueError("The configured OpenPhish personal owner is not an active account.")
    if owner.id != user.id:
        raise ValueError("Only the configured personal owner may request OpenPhish refreshes.")
    source = db.get(ThreatFeedSource, SOURCE_ID)
    if source is None:
        raise ValueError("The OpenPhish shared snapshot source is unavailable.")
    if source.personal_owner_user_id and source.personal_owner_user_id != owner.id:
        raise ValueError("The OpenPhish source is pinned to a different personal owner.")
    source.personal_owner_user_id = owner.id
    return owner


def collection_allowed(db: Session, settings: Settings, requested_by: str) -> bool:
    config = openphish_configuration(settings)
    if not config["ready"]:
        return False
    if config["access_scope"] == "provider_authorized_shared":
        return True
    owner = _configured_owner(db, settings)
    if owner is None or owner.id != requested_by:
        return False
    source = db.get(ThreatFeedSource, SOURCE_ID)
    return source is None or source.personal_owner_user_id in {None, owner.id}
