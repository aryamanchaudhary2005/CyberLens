"""Create shared CyberLens records for auth, investigations, cases and reports."""

from alembic import op

from app.models import Base

revision = "20261011_0002"
down_revision = "20261011_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    tables = [table for table in Base.metadata.sorted_tables if table.name != "workspace_metadata"]
    Base.metadata.create_all(bind=op.get_bind(), tables=tables)


def downgrade() -> None:
    tables = [table for table in Base.metadata.sorted_tables if table.name != "workspace_metadata"]
    Base.metadata.drop_all(bind=op.get_bind(), tables=list(reversed(tables)))
