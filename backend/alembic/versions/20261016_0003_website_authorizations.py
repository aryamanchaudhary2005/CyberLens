"""Add expiring and revocable website authorization records.

Revision ID: 20261016_0003
Revises: 20261011_0002
"""

from datetime import datetime, timedelta, timezone
import uuid

from alembic import op
import sqlalchemy as sa

revision = "20261016_0003"
down_revision = "20261011_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if "website_authorizations" not in sa.inspect(bind).get_table_names():
        op.create_table(
            "website_authorizations",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("asset_id", sa.String(length=36), nullable=False),
            sa.Column("authorized_by", sa.String(length=36), nullable=True),
            sa.Column("note", sa.Text(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("revoked_by", sa.String(length=36), nullable=True),
            sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["authorized_by"], ["users.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["revoked_by"], ["users.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_website_authorizations_asset_id", "website_authorizations", ["asset_id"])
        op.create_index(
            "ix_website_authorizations_asset_active",
            "website_authorizations",
            ["asset_id", "revoked_at", "expires_at"],
        )

    # Preserve legacy notes/timestamps while granting a finite transition
    # window for operators to review and renew authorization explicitly.
    rows = bind.execute(
        sa.text(
            "SELECT id, authorized_at, authorization_note FROM assets "
            "WHERE authorized_at IS NOT NULL"
        )
    ).mappings().all()
    legacy_expiry = datetime.now(timezone.utc) + timedelta(days=30)
    for row in rows:
        already_migrated = bind.execute(
            sa.text("SELECT 1 FROM website_authorizations WHERE asset_id = :asset_id LIMIT 1"),
            {"asset_id": row["id"]},
        ).first()
        if already_migrated:
            continue
        created_at = row["authorized_at"]
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at)
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        bind.execute(
            sa.text(
                "INSERT INTO website_authorizations "
                "(id, asset_id, authorized_by, note, created_at, expires_at, revoked_at, revoked_by) "
                "VALUES (:id, :asset_id, NULL, :note, :created_at, :expires_at, NULL, NULL)"
            ),
            {
                "id": str(uuid.uuid4()),
                "asset_id": row["id"],
                "note": row["authorization_note"] or "Migrated legacy website authorization",
                "created_at": created_at,
                "expires_at": legacy_expiry,
            },
        )


def downgrade() -> None:
    raise NotImplementedError("Website authorization records are forward-only to preserve authorization history.")
