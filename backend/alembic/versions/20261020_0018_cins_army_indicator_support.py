"""Support exact IP indicators and add the CINS Army source.

Revision ID: 20261020_0018
Revises: 20261020_0017
"""

from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa

revision = "20261020_0018"
down_revision = "20261020_0017"
branch_labels = None
depends_on = None

CINS_URL = "https://cinsscore.com/list/ci-badguys.txt"


def upgrade() -> None:
    bind = op.get_bind()
    columns = {item["name"] for item in sa.inspect(bind).get_columns("threat_feed_networks")}
    if "indicator_type" not in columns:
        op.add_column("threat_feed_networks", sa.Column(
            "indicator_type", sa.String(16), nullable=False, server_default="network",
        ))
    indexes = {item["name"] for item in sa.inspect(bind).get_indexes("threat_feed_networks")}
    if "ix_threat_feed_networks_snapshot_indicator" not in indexes:
        op.create_index(
            "ix_threat_feed_networks_snapshot_indicator", "threat_feed_networks",
            ["snapshot_id", "indicator_type", "network"], unique=False,
        )

    now = datetime.now(timezone.utc)
    exists = bind.execute(sa.text(
        "SELECT id FROM threat_feed_sources WHERE id = 'cins_army'"
    )).first()
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
            id="cins_army", display_name="CINS Army IP list", source_urls_json=[CINS_URL],
            active_snapshot_id=None, validators_json={}, last_successful_revalidation_at=None,
            next_refresh_at=None, dispatch_attempts=0, created_at=now, updated_at=now,
        ))


def downgrade() -> None:
    # Forward-only: snapshot rows and investigation references must remain durable.
    pass
