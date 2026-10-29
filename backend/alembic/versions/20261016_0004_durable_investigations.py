"""Add transactional investigation delivery and attempt history.

Revision ID: 20261016_0004
Revises: 20261016_0003
"""

from datetime import datetime, timezone
import uuid

from alembic import op
import sqlalchemy as sa

revision = "20261016_0004"
down_revision = "20261016_0003"
branch_labels = None
depends_on = None


def _tables(bind) -> set[str]:
    return set(sa.inspect(bind).get_table_names())


def _ensure_attempt_tables(bind) -> None:
    tables = _tables(bind)
    if "investigation_attempts" not in tables:
        op.create_table(
            "investigation_attempts",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("investigation_id", sa.String(length=36), nullable=False),
            sa.Column("attempt_number", sa.Integer(), nullable=False),
            sa.Column("retry_kind", sa.String(length=20), nullable=False),
            sa.Column("status", sa.String(length=20), nullable=False),
            sa.Column("progress", sa.Integer(), nullable=False),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("error_summary", sa.Text(), nullable=True),
            sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("lease_token", sa.String(length=36), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("investigation_id", "attempt_number", name="uq_investigation_attempt_number"),
        )
        op.create_index("ix_investigation_attempts_investigation_id", "investigation_attempts", ["investigation_id"])
        op.create_index("ix_investigation_attempts_status", "investigation_attempts", ["status"])
        op.create_index("ix_investigation_attempts_status_heartbeat", "investigation_attempts", ["status", "heartbeat_at"])

    if "investigation_outbox" not in _tables(bind):
        op.create_table(
            "investigation_outbox",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("attempt_id", sa.String(length=36), nullable=False),
            sa.Column("status", sa.String(length=20), nullable=False),
            sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("dispatch_attempts", sa.Integer(), nullable=False),
            sa.Column("last_error", sa.Text(), nullable=True),
            sa.Column("dispatched_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["attempt_id"], ["investigation_attempts.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("attempt_id", name="uq_investigation_outbox_attempt"),
        )
        op.create_index("ix_investigation_outbox_status", "investigation_outbox", ["status"])
        op.create_index("ix_investigation_outbox_status_available", "investigation_outbox", ["status", "available_at"])


def _alter_collector_runs(bind) -> None:
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("collector_runs")}
    unique_names = {item.get("name") for item in inspector.get_unique_constraints("collector_runs")}
    has_new_unique = "uq_collector_run_attempt" in unique_names
    has_old_unique = "uq_collector_run_investigation" in unique_names
    has_attempt_column = "attempt_id" in columns
    if has_attempt_column and has_new_unique and not has_old_unique:
        return

    if bind.dialect.name == "sqlite":
        with op.batch_alter_table("collector_runs") as batch:
            if not has_attempt_column:
                batch.add_column(sa.Column("attempt_id", sa.String(length=36), nullable=True))
                batch.create_foreign_key("fk_collector_runs_attempt_id", "investigation_attempts", ["attempt_id"], ["id"], ondelete="SET NULL")
            if has_old_unique:
                batch.drop_constraint("uq_collector_run_investigation", type_="unique")
            if not has_new_unique:
                batch.create_unique_constraint("uq_collector_run_attempt", ["attempt_id", "collector"])
    else:
        if not has_attempt_column:
            op.add_column("collector_runs", sa.Column("attempt_id", sa.String(length=36), nullable=True))
            op.create_foreign_key("fk_collector_runs_attempt_id", "collector_runs", "investigation_attempts",
                                  ["attempt_id"], ["id"], ondelete="SET NULL")
        if has_old_unique:
            op.drop_constraint("uq_collector_run_investigation", "collector_runs", type_="unique")
        if not has_new_unique:
            op.create_unique_constraint("uq_collector_run_attempt", "collector_runs", ["attempt_id", "collector"])
    if "ix_collector_runs_attempt_id" not in {item["name"] for item in sa.inspect(bind).get_indexes("collector_runs")}:
        op.create_index("ix_collector_runs_attempt_id", "collector_runs", ["attempt_id"])


def _backfill_attempts(bind) -> None:
    now = datetime.now(timezone.utc)
    investigations = bind.execute(sa.text(
        "SELECT id, status, progress, started_at, finished_at, error_summary, created_at "
        "FROM investigations ORDER BY created_at, id"
    )).mappings().all()
    for item in investigations:
        existing = bind.execute(sa.text(
            "SELECT id FROM investigation_attempts WHERE investigation_id = :investigation_id "
            "ORDER BY attempt_number LIMIT 1"
        ), {"investigation_id": item["id"]}).first()
        if existing:
            attempt_id = existing[0]
        else:
            attempt_id = str(uuid.uuid4())
            heartbeat = item["started_at"] or item["created_at"] or now
            bind.execute(sa.text(
                "INSERT INTO investigation_attempts "
                "(id, investigation_id, attempt_number, retry_kind, status, progress, started_at, finished_at, "
                "error_summary, heartbeat_at, lease_token, created_at) "
                "VALUES (:id, :investigation_id, 1, 'initial', :status, :progress, :started_at, :finished_at, "
                ":error_summary, :heartbeat_at, NULL, :created_at)"
            ), {
                "id": attempt_id, "investigation_id": item["id"], "status": item["status"],
                "progress": item["progress"], "started_at": item["started_at"],
                "finished_at": item["finished_at"], "error_summary": item["error_summary"],
                "heartbeat_at": heartbeat, "created_at": item["created_at"] or now,
            })
        bind.execute(sa.text(
            "UPDATE collector_runs SET attempt_id = :attempt_id "
            "WHERE investigation_id = :investigation_id AND attempt_id IS NULL"
        ), {"attempt_id": attempt_id, "investigation_id": item["id"]})

        if item["status"] in {"queued", "running"}:
            outbox = bind.execute(sa.text(
                "SELECT id FROM investigation_outbox WHERE attempt_id = :attempt_id"
            ), {"attempt_id": attempt_id}).first()
            if outbox is None:
                active_status = "pending" if item["status"] == "queued" else "dispatched"
                dispatched_at = None if active_status == "pending" else (item["started_at"] or now)
                bind.execute(sa.text(
                    "INSERT INTO investigation_outbox "
                    "(id, attempt_id, status, available_at, dispatch_attempts, last_error, dispatched_at, created_at, updated_at) "
                    "VALUES (:id, :attempt_id, :status, :available_at, 0, NULL, :dispatched_at, :created_at, :updated_at)"
                ), {"id": str(uuid.uuid4()), "attempt_id": attempt_id, "status": active_status,
                    "available_at": item["created_at"] or now, "dispatched_at": dispatched_at,
                    "created_at": item["created_at"] or now, "updated_at": now})


def upgrade() -> None:
    bind = op.get_bind()
    _ensure_attempt_tables(bind)
    _alter_collector_runs(bind)
    _backfill_attempts(bind)


def downgrade() -> None:
    raise NotImplementedError("Investigation attempts and outbox history are forward-only.")
