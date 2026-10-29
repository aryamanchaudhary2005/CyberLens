"""Preserve case-sensitive URL paths in asset deduplication keys.

Revision ID: 20261017_0005
Revises: 20261016_0004
"""

from alembic import op
import sqlalchemy as sa

revision = "20261017_0005"
down_revision = "20261016_0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # `identifier` already stores the canonical scheme/host with its original
    # path case. Older rows used a lowercased copy as the uniqueness key.
    bind = op.get_bind()
    bind.execute(sa.text(
        "UPDATE assets SET normalized_identifier = identifier WHERE kind = 'url'"
    ))


def downgrade() -> None:
    raise NotImplementedError("URL path canonicalization is forward-only to avoid merging distinct assets.")
