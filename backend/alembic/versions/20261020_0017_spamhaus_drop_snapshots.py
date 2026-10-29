"""Add durable threat-feed snapshots and Spamhaus DROP refresh history.

Revision ID: 20261020_0017
Revises: 20261019_0016
"""

from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa

revision = "20261020_0017"
down_revision = "20261019_0016"
branch_labels = None
depends_on = None


SOURCE_URLS = [
    "https://www.spamhaus.org/drop/drop_v4.json",
    "https://www.spamhaus.org/drop/drop_v6.json",
]


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    if "threat_feed_sources" not in tables:
        op.create_table(
            "threat_feed_sources",
            sa.Column("id", sa.String(80), primary_key=True),
            sa.Column("display_name", sa.String(160), nullable=False),
            sa.Column("source_urls_json", sa.JSON(), nullable=False),
            sa.Column("active_snapshot_id", sa.String(36), nullable=True),
            sa.Column("validators_json", sa.JSON(), nullable=False, server_default="{}"),
            sa.Column("last_successful_revalidation_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("next_refresh_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("dispatch_attempts", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )

    tables = set(sa.inspect(bind).get_table_names())
    if "threat_feed_snapshots" not in tables:
        op.create_table(
            "threat_feed_snapshots",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("source_id", sa.String(80), sa.ForeignKey("threat_feed_sources.id", ondelete="RESTRICT"), nullable=False),
            sa.Column("content_sha256", sa.String(64), nullable=False),
            sa.Column("parser_version", sa.String(40), nullable=False),
            sa.Column("record_count", sa.Integer(), nullable=False),
            sa.Column("retrieved_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("metadata_json", sa.JSON(), nullable=False),
            sa.UniqueConstraint("source_id", "content_sha256", name="uq_threat_feed_snapshot_content"),
        )
        op.create_index("ix_threat_feed_snapshots_source_retrieved", "threat_feed_snapshots", ["source_id", "retrieved_at"])

    if bind.dialect.name == "postgresql":
        existing_fks = {item["name"] for item in sa.inspect(bind).get_foreign_keys("threat_feed_sources")}
        if "fk_threat_feed_source_active_snapshot" not in existing_fks:
            op.create_foreign_key(
                "fk_threat_feed_source_active_snapshot", "threat_feed_sources", "threat_feed_snapshots",
                ["active_snapshot_id"], ["id"], ondelete="SET NULL",
            )

    tables = set(sa.inspect(bind).get_table_names())
    if "threat_feed_networks" not in tables:
        op.create_table(
            "threat_feed_networks",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("snapshot_id", sa.String(36), sa.ForeignKey("threat_feed_snapshots.id", ondelete="RESTRICT"), nullable=False),
            sa.Column("address_family", sa.Integer(), nullable=False),
            sa.Column("network", sa.String(64), nullable=False),
            sa.Column("sbl_id", sa.String(40), nullable=False),
            sa.UniqueConstraint("snapshot_id", "address_family", "network", "sbl_id", name="uq_threat_feed_network_record"),
        )
        op.create_index("ix_threat_feed_networks_snapshot_family", "threat_feed_networks", ["snapshot_id", "address_family"])

    tables = set(sa.inspect(bind).get_table_names())
    if "threat_feed_refresh_attempts" not in tables:
        op.create_table(
            "threat_feed_refresh_attempts",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("source_id", sa.String(80), sa.ForeignKey("threat_feed_sources.id", ondelete="RESTRICT"), nullable=False),
            sa.Column("trigger_kind", sa.String(16), nullable=False),
            sa.Column("requested_by", sa.String(36), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
            sa.Column("status", sa.String(20), nullable=False, server_default="queued"),
            sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("dispatch_attempts", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("error_code", sa.String(80), nullable=True),
            sa.Column("http_status_v4", sa.Integer(), nullable=True),
            sa.Column("http_status_v6", sa.Integer(), nullable=True),
            sa.Column("snapshot_id", sa.String(36), sa.ForeignKey("threat_feed_snapshots.id", ondelete="SET NULL"), nullable=True),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.CheckConstraint("status IN ('queued', 'dispatched', 'running', 'succeeded', 'unchanged', 'failed')", name="ck_threat_feed_refresh_status"),
            sa.CheckConstraint("trigger_kind IN ('scheduled', 'admin')", name="ck_threat_feed_refresh_trigger"),
        )
        op.create_index("ix_threat_feed_refresh_source_created", "threat_feed_refresh_attempts", ["source_id", "created_at"])
        op.create_index("ix_threat_feed_refresh_pending", "threat_feed_refresh_attempts", ["status", "available_at"])
        op.create_index(
            "uq_threat_feed_refresh_single_open", "threat_feed_refresh_attempts", ["source_id"], unique=True,
            sqlite_where=sa.text("status IN ('queued', 'dispatched', 'running')"),
            postgresql_where=sa.text("status IN ('queued', 'dispatched', 'running')"),
        )

    if "collector_runs" in set(sa.inspect(bind).get_table_names()):
        columns = {item["name"] for item in sa.inspect(bind).get_columns("collector_runs")}
        if "feed_snapshot_id" not in columns:
            op.add_column("collector_runs", sa.Column(
                "feed_snapshot_id", sa.String(36),
                sa.ForeignKey("threat_feed_snapshots.id", ondelete="RESTRICT"), nullable=True,
            ))
            op.create_index("ix_collector_runs_feed_snapshot_id", "collector_runs", ["feed_snapshot_id"])

    source = bind.execute(sa.text("SELECT id FROM threat_feed_sources WHERE id = 'spamhaus_drop'")).first()
    if source is None:
        now = datetime.now(timezone.utc)
        source_table = sa.table(
            "threat_feed_sources", sa.column("id", sa.String()), sa.column("display_name", sa.String()),
            sa.column("source_urls_json", sa.JSON()), sa.column("active_snapshot_id", sa.String()),
            sa.column("validators_json", sa.JSON()), sa.column("last_successful_revalidation_at", sa.DateTime(timezone=True)),
            sa.column("next_refresh_at", sa.DateTime(timezone=True)), sa.column("dispatch_attempts", sa.Integer()),
            sa.column("created_at", sa.DateTime(timezone=True)), sa.column("updated_at", sa.DateTime(timezone=True)),
        )
        bind.execute(source_table.insert().values(
            id="spamhaus_drop", display_name="Spamhaus DROP IPv4 and IPv6", source_urls_json=SOURCE_URLS,
            active_snapshot_id=None, validators_json={}, last_successful_revalidation_at=None,
            next_refresh_at=None, dispatch_attempts=0, created_at=now, updated_at=now,
        ))


def downgrade() -> None:
    # Forward-only: investigations and reports may refer to retained snapshots.
    pass
