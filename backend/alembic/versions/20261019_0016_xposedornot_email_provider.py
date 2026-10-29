"""Add opt-in, revocable XposedOrNot email lookup authorization.

Revision ID: 20261019_0016
Revises: 20261019_0015
"""

from alembic import op
import sqlalchemy as sa

revision = "20261019_0016"
down_revision = "20261019_0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if "email_breach_authorizations" not in inspector.get_table_names():
        op.create_table(
            "email_breach_authorizations",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("asset_id", sa.String(length=36), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
            sa.Column("provider", sa.String(length=32), nullable=False),
            sa.Column("authorized_by", sa.String(length=36), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
            sa.Column("consent_version", sa.String(length=40), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("revoked_by", sa.String(length=36), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
            sa.CheckConstraint("provider = 'xposedornot'", name="ck_email_breach_authorization_provider"),
        )
    indexes = {item["name"] for item in sa.inspect(op.get_bind()).get_indexes("email_breach_authorizations")}
    if "ix_email_breach_authorizations_asset_id" not in indexes:
        op.create_index("ix_email_breach_authorizations_asset_id", "email_breach_authorizations", ["asset_id"])
    if "ix_email_breach_authorizations_asset_active" not in indexes:
        op.create_index("ix_email_breach_authorizations_asset_active", "email_breach_authorizations",
                        ["asset_id", "revoked_at", "expires_at"])

    columns = {item["name"] for item in sa.inspect(op.get_bind()).get_columns("investigations")}
    if "email_breach_provider" not in columns:
        op.add_column("investigations", sa.Column("email_breach_provider", sa.String(length=32), nullable=True))
    if "email_breach_authorization_id" not in columns:
        op.add_column("investigations", sa.Column(
            "email_breach_authorization_id", sa.String(length=36),
            sa.ForeignKey("email_breach_authorizations.id", ondelete="SET NULL"), nullable=True,
        ))


def downgrade() -> None:
    # Forward-only: authorization decisions and saved investigation evidence are retained.
    pass
