"""Add evidence-backed temporal graph relationships.

Revision ID: 20261017_0006
Revises: 20261017_0005
"""

from alembic import op
import sqlalchemy as sa

revision = "20261017_0006"
down_revision = "20261017_0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if "evidence_relationships" not in sa.inspect(bind).get_table_names():
        op.create_table(
            "evidence_relationships",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("investigation_id", sa.String(length=36), nullable=False),
            sa.Column("from_node_type", sa.String(length=32), nullable=False),
            sa.Column("from_node_id", sa.String(length=300), nullable=False),
            sa.Column("to_node_type", sa.String(length=32), nullable=False),
            sa.Column("to_node_id", sa.String(length=300), nullable=False),
            sa.Column("relationship_type", sa.String(length=48), nullable=False),
            sa.Column("evidence_role", sa.String(length=16), nullable=False),
            sa.Column("collector", sa.String(length=80), nullable=False),
            sa.Column("source", sa.String(length=200), nullable=False),
            sa.Column("evidence_id", sa.String(length=36), nullable=False),
            sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("data_mode", sa.String(length=10), nullable=False),
            sa.Column("details_json", sa.JSON(), nullable=False),
            sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["evidence_id"], ["evidence_snapshots.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint(
                "evidence_id", "from_node_id", "to_node_id", "relationship_type",
                name="uq_evidence_relationship_observation",
            ),
        )
        op.create_index("ix_evidence_relationships_investigation_id", "evidence_relationships", ["investigation_id"])
        op.create_index("ix_evidence_relationships_evidence_id", "evidence_relationships", ["evidence_id"])
        op.create_index(
            "ix_evidence_relationships_investigation_observed", "evidence_relationships",
            ["investigation_id", "observed_at"],
        )

    # The legacy evidence backfill runs in a later migration, after the full
    # schema is present. Using current ORM models here would select columns
    # introduced by migrations after this revision.


def downgrade() -> None:
    raise NotImplementedError("Evidence graph history is forward-only to preserve temporal relationship records.")
