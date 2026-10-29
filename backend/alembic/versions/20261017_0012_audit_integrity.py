"""Add a tamper-evident append-only audit chain.

Revision ID: 20261017_0012
Revises: 20261017_0011
"""

from datetime import datetime, timezone
import hashlib
import json

from alembic import op
import sqlalchemy as sa

revision = "20261017_0012"
down_revision = "20261017_0011"
branch_labels = None
depends_on = None

GENESIS_HASH = "0" * 64


def _utc_text(value) -> str:
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _event_hash(row: dict, sequence: int, previous_hash: str) -> str:
    payload = {
        "chain_version": 1,
        "sequence": sequence,
        "previous_hash": previous_hash,
        "id": row["id"],
        "actor_id": row["actor_id"],
        "action": row["action"],
        "entity_type": row["entity_type"],
        "entity_id": row["entity_id"],
        "created_at": _utc_text(row["created_at"]),
        "metadata": row["details_json"] or {},
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    if "audit_events" not in tables:
        return

    columns = {column["name"] for column in inspector.get_columns("audit_events")}
    for name, type_ in (("event_sequence", sa.Integer()), ("previous_hash", sa.String(64)), ("current_hash", sa.String(64))):
        if name not in columns:
            op.add_column("audit_events", sa.Column(name, type_, nullable=True))

    if "audit_chain_heads" not in tables:
        op.create_table(
            "audit_chain_heads",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("event_sequence", sa.Integer(), nullable=False),
            sa.Column("current_hash", sa.String(64), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )

    events = sa.table(
        "audit_events",
        sa.column("id", sa.String(36)), sa.column("actor_id", sa.String(36)),
        sa.column("action", sa.String(80)), sa.column("entity_type", sa.String(80)),
        sa.column("entity_id", sa.String(36)), sa.column("details_json", sa.JSON()),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("event_sequence", sa.Integer()), sa.column("previous_hash", sa.String(64)),
        sa.column("current_hash", sa.String(64)),
    )
    rows = list(bind.execute(sa.select(events).order_by(events.c.created_at, events.c.id)).mappings())
    sequence = 0
    previous_hash = GENESIS_HASH
    for row in rows:
        sequence += 1
        current_hash = _event_hash(dict(row), sequence, previous_hash)
        bind.execute(events.update().where(events.c.id == row["id"]).values(
            event_sequence=sequence, previous_hash=previous_hash, current_hash=current_hash,
        ))
        previous_hash = current_hash

    heads = sa.table("audit_chain_heads", sa.column("id", sa.Integer()),
                     sa.column("event_sequence", sa.Integer()), sa.column("current_hash", sa.String(64)),
                     sa.column("updated_at", sa.DateTime(timezone=True)))
    if bind.execute(sa.select(heads.c.id).where(heads.c.id == 1)).first() is None:
        bind.execute(heads.insert().values(id=1, event_sequence=sequence, current_hash=previous_hash,
                                           updated_at=datetime.now(timezone.utc)))
    else:
        bind.execute(heads.update().where(heads.c.id == 1).values(
            event_sequence=sequence, current_hash=previous_hash, updated_at=datetime.now(timezone.utc)))

    inspector = sa.inspect(bind)
    column_info = {column["name"]: column for column in inspector.get_columns("audit_events")}
    check_names = {item.get("name") for item in inspector.get_check_constraints("audit_events")}
    needs_batch = any(column_info[name]["nullable"] for name in ("event_sequence", "previous_hash", "current_hash")) or \
        "ck_audit_events_sequence_positive" not in check_names
    if needs_batch:
        with op.batch_alter_table("audit_events") as batch:
            for name, type_ in (("event_sequence", sa.Integer()), ("previous_hash", sa.String(64)), ("current_hash", sa.String(64))):
                if column_info[name]["nullable"]:
                    batch.alter_column(name, existing_type=type_, nullable=False)
            if "ck_audit_events_sequence_positive" not in check_names:
                batch.create_check_constraint("ck_audit_events_sequence_positive", "event_sequence > 0")

    indexes = {item["name"] for item in sa.inspect(bind).get_indexes("audit_events")}
    if "uq_audit_events_sequence" not in indexes:
        op.create_index("uq_audit_events_sequence", "audit_events", ["event_sequence"], unique=True)

    if bind.dialect.name == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS trg_audit_events_no_update")
        op.execute("DROP TRIGGER IF EXISTS trg_audit_events_no_delete")
        op.execute("""CREATE TRIGGER trg_audit_events_no_update BEFORE UPDATE ON audit_events
            BEGIN SELECT RAISE(ABORT, 'audit_events are append-only'); END""")
        op.execute("""CREATE TRIGGER trg_audit_events_no_delete BEFORE DELETE ON audit_events
            BEGIN SELECT RAISE(ABORT, 'audit_events are append-only'); END""")
    elif bind.dialect.name == "postgresql":
        op.execute("""CREATE OR REPLACE FUNCTION cyberlens_deny_audit_mutation() RETURNS trigger AS $$
            BEGIN RAISE EXCEPTION 'audit_events are append-only'; END; $$ LANGUAGE plpgsql""")
        op.execute("DROP TRIGGER IF EXISTS trg_audit_events_append_only ON audit_events")
        op.execute("""CREATE TRIGGER trg_audit_events_append_only BEFORE UPDATE OR DELETE ON audit_events
            FOR EACH ROW EXECUTE FUNCTION cyberlens_deny_audit_mutation()""")


def downgrade() -> None:
    # Forward-only: dropping a chain would erase verification history.
    pass
