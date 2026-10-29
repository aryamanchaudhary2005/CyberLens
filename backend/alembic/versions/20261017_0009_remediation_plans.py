"""Add analyst remediation plans, actions, and control mappings.

Revision ID: 20261017_0009
Revises: 20261017_0008
"""

from alembic import op
import sqlalchemy as sa

revision = "20261017_0009"
down_revision = "20261017_0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    existing = set(inspector.get_table_names())

    if "remediation_plans" not in existing:
        op.create_table(
            "remediation_plans",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("title", sa.String(length=300), nullable=False),
            sa.Column("description", sa.Text(), nullable=False),
            sa.Column("action_type", sa.String(length=80), nullable=False),
            sa.Column("finding_id", sa.String(length=36), sa.ForeignKey("findings.id", ondelete="SET NULL"), nullable=True),
            sa.Column("incident_id", sa.String(length=36), sa.ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True),
            sa.Column("playbook_task_id", sa.String(length=36), sa.ForeignKey("playbook_tasks.id", ondelete="SET NULL"), nullable=True),
            sa.Column("owner_id", sa.String(length=36), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
            sa.Column("priority", sa.String(length=20), nullable=False),
            sa.Column("due_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("status", sa.String(length=24), nullable=False),
            sa.Column("assumptions_json", sa.JSON(), nullable=False),
            sa.Column("notes", sa.Text(), nullable=True),
            sa.Column("created_by", sa.String(length=36), sa.ForeignKey("users.id"), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_remediation_plans_finding", "remediation_plans", ["finding_id"])
        op.create_index("ix_remediation_plans_incident", "remediation_plans", ["incident_id"])
        op.create_index("ix_remediation_plans_playbook_task_id", "remediation_plans", ["playbook_task_id"])
        op.create_index("ix_remediation_plans_status", "remediation_plans", ["status"])
        op.create_index("ix_remediation_plans_owner_id", "remediation_plans", ["owner_id"])
        op.create_index("ix_remediation_plans_status_due", "remediation_plans", ["status", "due_at"])

    if "remediation_actions" not in existing:
        op.create_table(
            "remediation_actions",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("plan_id", sa.String(length=36), sa.ForeignKey("remediation_plans.id", ondelete="CASCADE"), nullable=False),
            sa.Column("title", sa.String(length=300), nullable=False),
            sa.Column("description", sa.Text(), nullable=False),
            sa.Column("action_type", sa.String(length=80), nullable=False),
            sa.Column("owner_id", sa.String(length=36), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
            sa.Column("priority", sa.String(length=20), nullable=False),
            sa.Column("due_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("status", sa.String(length=24), nullable=False),
            sa.Column("assumptions_json", sa.JSON(), nullable=False),
            sa.Column("verification_instructions", sa.Text(), nullable=False),
            sa.Column("notes", sa.Text(), nullable=True),
            sa.Column("verification_evidence_id", sa.String(length=36), sa.ForeignKey("evidence_snapshots.id", ondelete="SET NULL"), nullable=True),
            sa.Column("validated_by", sa.String(length=36), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
            sa.Column("validated_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_by", sa.String(length=36), sa.ForeignKey("users.id"), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_remediation_actions_plan_id", "remediation_actions", ["plan_id"])
        op.create_index("ix_remediation_actions_owner_id", "remediation_actions", ["owner_id"])
        op.create_index("ix_remediation_actions_status", "remediation_actions", ["status"])
        op.create_index("ix_remediation_actions_plan_status", "remediation_actions", ["plan_id", "status"])
        op.create_index("ix_remediation_actions_due", "remediation_actions", ["due_at"])

    if "finding_control_mappings" not in existing:
        op.create_table(
            "finding_control_mappings",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("finding_id", sa.String(length=36), sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False),
            sa.Column("control_id", sa.String(length=80), nullable=False),
            sa.Column("catalog_version", sa.String(length=40), nullable=False),
            sa.Column("rationale", sa.Text(), nullable=False),
            sa.Column("confidence", sa.Float(), nullable=False),
            sa.Column("status", sa.String(length=24), nullable=False),
            sa.Column("verification_evidence_id", sa.String(length=36), sa.ForeignKey("evidence_snapshots.id", ondelete="SET NULL"), nullable=True),
            sa.Column("validated_by", sa.String(length=36), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
            sa.Column("validated_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_by", sa.String(length=36), sa.ForeignKey("users.id"), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("finding_id", "control_id", "catalog_version", name="uq_finding_control_catalog"),
        )
        op.create_index("ix_finding_control_mappings_finding_id", "finding_control_mappings", ["finding_id"])
        op.create_index("ix_finding_control_mappings_status", "finding_control_mappings", ["status"])
        op.create_index("ix_finding_control_mappings_finding", "finding_control_mappings", ["finding_id"])


def downgrade() -> None:
    raise NotImplementedError("Remediation plans and validation history are forward-only.")
