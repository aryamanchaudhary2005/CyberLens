"""Add evidence-linked, analyst-reviewed ATT&CK mappings.

Revision ID: 20261017_0011
Revises: 20261017_0010
"""

from alembic import op
import sqlalchemy as sa

revision = "20261017_0011"
down_revision = "20261017_0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if "attack_mappings" not in set(sa.inspect(op.get_bind()).get_table_names()):
        op.create_table(
            "attack_mappings",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("finding_id", sa.String(length=36), sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=True),
            sa.Column("incident_id", sa.String(length=36), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True),
            sa.Column("technique_id", sa.String(length=20), nullable=False),
            sa.Column("technique_name", sa.String(length=200), nullable=False),
            sa.Column("tactic", sa.String(length=80), nullable=False),
            sa.Column("catalog_version", sa.String(length=60), nullable=False),
            sa.Column("rationale", sa.Text(), nullable=False),
            sa.Column("confidence", sa.Float(), nullable=False),
            sa.Column("source", sa.String(length=80), nullable=False),
            sa.Column("evidence_role", sa.String(length=16), nullable=False, server_default="contextual"),
            sa.Column("evidence_id", sa.String(length=36), sa.ForeignKey("evidence_snapshots.id", ondelete="CASCADE"), nullable=False),
            sa.Column("decision", sa.String(length=20), nullable=False, server_default="proposed"),
            sa.Column("analyst_confirmed", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("created_by", sa.String(length=36), sa.ForeignKey("users.id"), nullable=False),
            sa.Column("reviewed_by", sa.String(length=36), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
            sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.CheckConstraint(
                "(finding_id IS NOT NULL AND incident_id IS NULL) OR (finding_id IS NULL AND incident_id IS NOT NULL)",
                name="ck_attack_mapping_target",
            ),
            sa.CheckConstraint("confidence >= 0 AND confidence <= 1", name="ck_attack_mapping_confidence"),
            sa.CheckConstraint("decision IN ('proposed', 'approved', 'rejected', 'overridden')", name="ck_attack_mapping_decision"),
            sa.CheckConstraint("evidence_role IN ('direct', 'contextual')", name="ck_attack_mapping_evidence_role"),
        )
    indexes = {index["name"] for index in sa.inspect(op.get_bind()).get_indexes("attack_mappings")}
    for name, columns in (
        ("ix_attack_mappings_finding", ["finding_id"]),
        ("ix_attack_mappings_incident", ["incident_id"]),
        ("ix_attack_mappings_technique", ["technique_id"]),
        ("ix_attack_mappings_decision", ["decision"]),
    ):
        if name not in indexes:
            op.create_index(name, "attack_mappings", columns)


def downgrade() -> None:
    # Forward-only: analyst decisions and evidence references must be retained.
    pass
