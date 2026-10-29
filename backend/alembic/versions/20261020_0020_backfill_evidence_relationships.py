"""Backfill evidence-backed graph relationships after the schema upgrades.

Revision ID: 20261020_0020
Revises: 20261020_0019
"""

from alembic import op
from sqlalchemy.orm import Session

revision = "20261020_0020"
down_revision = "20261020_0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()

    # Preserve older investigation/evidence history with a one-time, idempotent
    # projection. At this revision, all columns used by the current ORM models
    # have been created. Later relationships are written transactionally, so
    # graph GET requests remain read-only for Viewers.
    from app.graph import ensure_relationships
    from app.models import Investigation

    with Session(bind=bind, autoflush=False, expire_on_commit=False) as db:
        for investigation in db.query(Investigation).order_by(Investigation.created_at, Investigation.id).all():
            ensure_relationships(db, investigation)
        db.flush()


def downgrade() -> None:
    raise NotImplementedError("Evidence graph history is forward-only to preserve temporal relationship records.")
