"""Create shared workspace metadata table."""

from alembic import op
import sqlalchemy as sa

revision = "20261011_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "workspace_metadata",
        sa.Column("key", sa.String(length=100), primary_key=True),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.bulk_insert(
        sa.table(
            "workspace_metadata",
            sa.column("key", sa.String(length=100)),
            sa.column("value", sa.Text()),
        ),
        [{"key": "schema_generation", "value": "1"}],
    )


def downgrade() -> None:
    op.drop_table("workspace_metadata")
