"""Add asset threat context and analyst-owned STRIDE scenarios.

Revision ID: 20261017_0010
Revises: 20261017_0009
"""

from alembic import op
import sqlalchemy as sa

revision = "20261017_0010"
down_revision = "20261017_0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("assets")}
    additions = [
        sa.Column("criticality", sa.String(length=20), nullable=False, server_default="unknown"),
        sa.Column("data_classification", sa.String(length=20), nullable=False, server_default="unknown"),
        sa.Column("trust_zone", sa.String(length=30), nullable=False, server_default="unknown"),
        sa.Column("exposure_classification", sa.String(length=30), nullable=False, server_default="unknown"),
        sa.Column("business_owner", sa.String(length=200), nullable=True),
        sa.Column("protection_requirements", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
    ]
    for column in additions:
        if column.name not in columns:
            op.add_column("assets", column)

    if "threat_scenarios" not in set(inspector.get_table_names()):
        op.create_table(
            "threat_scenarios",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("asset_id", sa.String(length=36), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
            sa.Column("finding_id", sa.String(length=36), sa.ForeignKey("findings.id", ondelete="SET NULL"), nullable=True),
            sa.Column("investigation_id", sa.String(length=36), sa.ForeignKey("investigations.id", ondelete="SET NULL"), nullable=True),
            sa.Column("incident_id", sa.String(length=36), sa.ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True),
            sa.Column("stride_category", sa.String(length=32), nullable=False),
            sa.Column("title", sa.String(length=300), nullable=False),
            sa.Column("description", sa.Text(), nullable=False),
            sa.Column("likelihood", sa.Integer(), nullable=False),
            sa.Column("business_impact", sa.Integer(), nullable=False),
            sa.Column("confidence", sa.Integer(), nullable=False),
            sa.Column("assumptions_json", sa.JSON(), nullable=False),
            sa.Column("unconfirmed_information_json", sa.JSON(), nullable=False),
            sa.Column("owner_id", sa.String(length=36), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
            sa.Column("review_status", sa.String(length=24), nullable=False),
            sa.Column("created_by", sa.String(length=36), sa.ForeignKey("users.id"), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
    indexes = {index["name"] for index in sa.inspect(bind).get_indexes("threat_scenarios")}
    for name, columns in (
        ("ix_threat_scenarios_asset_id", ["asset_id"]),
        ("ix_threat_scenarios_review_status", ["review_status"]),
        ("ix_threat_scenarios_owner_id", ["owner_id"]),
        ("ix_threat_scenarios_asset_review", ["asset_id", "review_status"]),
        ("ix_threat_scenarios_finding", ["finding_id"]),
        ("ix_threat_scenarios_investigation", ["investigation_id"]),
        ("ix_threat_scenarios_incident", ["incident_id"]),
    ):
        if name not in indexes:
            op.create_index(name, "threat_scenarios", columns)


def downgrade() -> None:
    # Forward-only: threat scenarios and analyst-authored asset context are retained.
    pass
