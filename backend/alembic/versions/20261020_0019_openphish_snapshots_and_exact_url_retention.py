"""Add OpenPhish URL snapshots and mark legacy URLs as incomplete for exact matching.

Revision ID: 20261020_0019
Revises: 20261020_0018
"""

from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa

revision = "20261020_0019"
down_revision = "20261020_0018"
branch_labels = None
depends_on = None

OPENPHISH_URL = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"


def upgrade() -> None:
    bind = op.get_bind()
    asset_columns = {item["name"] for item in sa.inspect(bind).get_columns("assets")}
    if "url_retention_complete" not in asset_columns:
        op.add_column("assets", sa.Column(
            "url_retention_complete", sa.Boolean(), nullable=False, server_default=sa.false(),
        ))

    source_columns = {item["name"] for item in sa.inspect(bind).get_columns("threat_feed_sources")}
    if "personal_owner_user_id" not in source_columns:
        op.add_column("threat_feed_sources", sa.Column(
            "personal_owner_user_id", sa.String(36),
            sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True,
        ))
        op.create_index("ix_threat_feed_sources_personal_owner_user_id", "threat_feed_sources",
                        ["personal_owner_user_id"])

    tables = set(sa.inspect(bind).get_table_names())
    if "threat_feed_urls" not in tables:
        op.create_table(
            "threat_feed_urls",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("snapshot_id", sa.String(36),
                      sa.ForeignKey("threat_feed_snapshots.id", ondelete="RESTRICT"), nullable=False),
            sa.Column("canonical_url", sa.String(2048), nullable=False),
            sa.Column("canonical_sha256", sa.String(64), nullable=False),
            sa.Column("hostname", sa.String(253), nullable=False),
            sa.UniqueConstraint("snapshot_id", "canonical_sha256", name="uq_threat_feed_url_digest"),
        )
        op.create_index("ix_threat_feed_urls_snapshot_id", "threat_feed_urls", ["snapshot_id"])
        op.create_index("ix_threat_feed_urls_snapshot_hostname", "threat_feed_urls", ["snapshot_id", "hostname"])

    now = datetime.now(timezone.utc)
    exists = bind.execute(sa.text("SELECT id FROM threat_feed_sources WHERE id = 'openphish' ")).first()
    if exists is None:
        source_table = sa.table(
            "threat_feed_sources", sa.column("id", sa.String()),
            sa.column("display_name", sa.String()), sa.column("source_urls_json", sa.JSON()),
            sa.column("active_snapshot_id", sa.String()), sa.column("validators_json", sa.JSON()),
            sa.column("last_successful_revalidation_at", sa.DateTime(timezone=True)),
            sa.column("next_refresh_at", sa.DateTime(timezone=True)),
            sa.column("dispatch_attempts", sa.Integer()), sa.column("created_at", sa.DateTime(timezone=True)),
            sa.column("updated_at", sa.DateTime(timezone=True)),
        )
        bind.execute(source_table.insert().values(
            id="openphish", display_name="OpenPhish Community Feed", source_urls_json=[OPENPHISH_URL],
            active_snapshot_id=None, validators_json={}, last_successful_revalidation_at=None,
            next_refresh_at=None, dispatch_attempts=0, created_at=now, updated_at=now,
        ))


def downgrade() -> None:
    # Forward-only: retained snapshots, reports, and the legacy URL limitation state are durable.
    pass
