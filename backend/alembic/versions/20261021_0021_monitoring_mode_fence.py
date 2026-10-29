"""Keep scheduled investigations bound to their original operating mode.

Revision ID: 20261021_0021
Revises: 20261020_0020
"""

from alembic import op
import sqlalchemy as sa


revision = "20261021_0021"
down_revision = "20261020_0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    columns = {column["name"] for column in inspector.get_columns("monitoring_schedules")}
    constraints = {item.get("name") for item in inspector.get_check_constraints("monitoring_schedules")}
    if "mode" in columns:
        # Some legacy-upgrade test fixtures create their starting schema from
        # current ORM metadata. They already contain the additive column.
        if "ck_monitoring_schedule_mode" not in constraints:
            with op.batch_alter_table("monitoring_schedules") as batch:
                batch.create_check_constraint("ck_monitoring_schedule_mode", "mode IN ('demo', 'live')")
        return

    with op.batch_alter_table("monitoring_schedules") as batch:
        batch.add_column(sa.Column("mode", sa.String(length=8), nullable=True))

    # A schedule with any historical Demo execution remains Demo-bound. A
    # schedule with only Live history remains Live-bound. Unrun legacy
    # schedules default to Demo because the previous normal Compose workflow
    # was Demo; this prevents implicit outbound checks after a mode switch.
    op.execute(sa.text("""
        UPDATE monitoring_schedules
        SET mode = CASE
            WHEN EXISTS (
                SELECT 1
                FROM monitoring_runs AS run
                JOIN investigations AS investigation
                  ON investigation.id = run.investigation_id
                WHERE run.schedule_id = monitoring_schedules.id
                  AND investigation.mode = 'demo'
            ) THEN 'demo'
            WHEN EXISTS (
                SELECT 1
                FROM monitoring_runs AS run
                JOIN investigations AS investigation
                  ON investigation.id = run.investigation_id
                WHERE run.schedule_id = monitoring_schedules.id
                  AND investigation.mode = 'live'
            ) THEN 'live'
            ELSE 'demo'
        END
    """))

    with op.batch_alter_table("monitoring_schedules") as batch:
        batch.alter_column("mode", existing_type=sa.String(length=8), nullable=False,
                            server_default=sa.text("'demo'"))
        batch.create_check_constraint("ck_monitoring_schedule_mode", "mode IN ('demo', 'live')")


def downgrade() -> None:
    raise NotImplementedError("Monitoring mode history is forward-only to prevent cross-mode job delivery.")
