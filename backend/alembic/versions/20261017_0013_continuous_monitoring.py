"""Add analyst-controlled, authorization-bound monitoring schedules.

Revision ID: 20261017_0013
Revises: 20261017_0012
"""

from alembic import op
import sqlalchemy as sa

revision = "20261017_0013"
down_revision = "20261017_0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if "monitoring_schedules" not in tables:
        op.create_table(
            "monitoring_schedules",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("asset_id", sa.String(length=36), sa.ForeignKey("assets.id", ondelete="RESTRICT"), nullable=False),
            sa.Column("authorization_id", sa.String(length=36), sa.ForeignKey("website_authorizations.id", ondelete="RESTRICT"), nullable=False),
            sa.Column("owner_id", sa.String(length=36), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False),
            sa.Column("cadence", sa.String(length=12), nullable=False),
            sa.Column("status", sa.String(length=16), nullable=False, server_default="active"),
            sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("failure_code", sa.String(length=60), nullable=True),
            sa.Column("failure_detail", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.CheckConstraint("cadence IN ('daily', 'weekly')", name="ck_monitoring_schedule_cadence"),
            sa.CheckConstraint("status IN ('active', 'paused', 'failed', 'completed')", name="ck_monitoring_schedule_status"),
        )
    schedule_indexes = {item["name"] for item in sa.inspect(op.get_bind()).get_indexes("monitoring_schedules")}
    for name, columns in (
        ("ix_monitoring_schedule_due", ["status", "next_run_at"]),
        ("ix_monitoring_schedule_asset", ["asset_id"]),
        ("ix_monitoring_schedule_owner", ["owner_id"]),
    ):
        if name not in schedule_indexes:
            op.create_index(name, "monitoring_schedules", columns)

    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if "monitoring_runs" not in tables:
        op.create_table(
            "monitoring_runs",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("schedule_id", sa.String(length=36), sa.ForeignKey("monitoring_schedules.id", ondelete="CASCADE"), nullable=False),
            sa.Column("investigation_id", sa.String(length=36), sa.ForeignKey("investigations.id", ondelete="RESTRICT"), nullable=False),
            sa.Column("previous_investigation_id", sa.String(length=36), sa.ForeignKey("investigations.id", ondelete="SET NULL"), nullable=True),
            sa.Column("scheduled_for", sa.DateTime(timezone=True), nullable=False),
            sa.Column("status", sa.String(length=16), nullable=False, server_default="queued"),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("failure_detail", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("schedule_id", "scheduled_for", name="uq_monitoring_run_schedule_slot"),
            sa.UniqueConstraint("investigation_id", name="uq_monitoring_run_investigation"),
            sa.CheckConstraint("status IN ('queued', 'running', 'completed', 'partial', 'failed')", name="ck_monitoring_run_status"),
        )
    run_indexes = {item["name"] for item in sa.inspect(op.get_bind()).get_indexes("monitoring_runs")}
    for name, columns in (
        ("ix_monitoring_run_schedule_time", ["schedule_id", "scheduled_for"]),
        ("ix_monitoring_run_status", ["status"]),
    ):
        if name not in run_indexes:
            op.create_index(name, "monitoring_runs", columns)


def downgrade() -> None:
    # Forward-only: schedule history references saved investigations.
    pass
