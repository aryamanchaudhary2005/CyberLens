"""Add first-class EPSS fields to vulnerability findings.

Revision ID: 20261017_0008
Revises: 20261017_0007
"""

from alembic import op
import sqlalchemy as sa

revision = "20261017_0008"
down_revision = "20261017_0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    existing = {column["name"] for column in inspector.get_columns("findings")}
    additions = (
        sa.Column("epss_score", sa.Float(), nullable=True),
        sa.Column("epss_percentile", sa.Float(), nullable=True),
        sa.Column("epss_observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("epss_provider_status", sa.String(length=32), nullable=True),
        sa.Column("epss_freshness", sa.String(length=24), nullable=True),
    )
    for column in additions:
        if column.name not in existing:
            op.add_column("findings", column)


def downgrade() -> None:
    raise NotImplementedError("EPSS enrichment is forward-only to preserve vulnerability evidence history.")
