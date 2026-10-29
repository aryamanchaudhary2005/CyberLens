"""Add optional explicit package identity to software inventory.

Revision ID: 20261019_0014
Revises: 20261017_0013
"""

from alembic import op
import sqlalchemy as sa

revision = "20261019_0014"
down_revision = "20261017_0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    columns = {item["name"] for item in inspector.get_columns("software_components")}
    if "package_ecosystem" not in columns:
        op.add_column("software_components", sa.Column("package_ecosystem", sa.String(length=12), nullable=True))
    if "package_name" not in columns:
        op.add_column("software_components", sa.Column("package_name", sa.String(length=214), nullable=True))
    constraints = {item["name"] for item in sa.inspect(op.get_bind()).get_check_constraints("software_components")}
    if "ck_software_component_package_identity" not in constraints:
        with op.batch_alter_table("software_components") as batch:
            batch.create_check_constraint(
                "ck_software_component_package_identity",
                "(package_ecosystem IS NULL AND package_name IS NULL) OR "
                "(package_ecosystem IN ('npm', 'PyPI') AND package_name IS NOT NULL)",
            )


def downgrade() -> None:
    # Forward-only: package inventory is analyst-entered evidence context.
    pass
