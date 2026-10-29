"""Add versioned local Enterprise ATT&CK catalog storage and seed legacy subset.

Revision ID: 20261019_0015
Revises: 20261019_0014
"""

from datetime import datetime, timezone
import hashlib
import json

from alembic import op
import sqlalchemy as sa

revision = "20261019_0015"
down_revision = "20261019_0014"
branch_labels = None
depends_on = None


LEGACY_CATALOG = {
    "catalog_version": "cyberlens-attack-enterprise-subset-1.0",
    "framework": "MITRE ATT&CK Enterprise",
    "snapshot_date": "2026-10-17",
    "source_url": "https://attack.mitre.org/",
    "techniques": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactics": ["Initial Access"],
         "url": "https://attack.mitre.org/techniques/T1190/"},
        {"id": "T1589.002", "name": "Gather Victim Identity Information: Email Addresses",
         "tactics": ["Reconnaissance"], "url": "https://attack.mitre.org/techniques/T1589/002/"},
        {"id": "T1595.002", "name": "Active Scanning: Vulnerability Scanning", "tactics": ["Reconnaissance"],
         "url": "https://attack.mitre.org/techniques/T1595/002/"},
        {"id": "T1078", "name": "Valid Accounts",
         "tactics": ["Stealth", "Persistence", "Privilege Escalation", "Initial Access"],
         "url": "https://attack.mitre.org/techniques/T1078/"},
    ],
}


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    if "attack_catalog_versions" not in tables:
        op.create_table(
            "attack_catalog_versions",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("catalog_version", sa.String(length=128), nullable=False, unique=True),
            sa.Column("source", sa.String(length=160), nullable=False),
            sa.Column("release_version", sa.String(length=40), nullable=True),
            sa.Column("source_reference", sa.Text(), nullable=True),
            sa.Column("retrieved_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("checksum", sa.String(length=64), nullable=True),
            sa.Column("import_status", sa.String(length=20), nullable=False, server_default="queued"),
            sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("available_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("dispatch_attempts", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("catalog_json", sa.JSON(), nullable=True),
            sa.Column("result_json", sa.JSON(), nullable=True),
            sa.Column("error_summary", sa.Text(), nullable=True),
            sa.Column("duplicate_of", sa.String(length=128), nullable=True),
            sa.Column("requested_by", sa.String(length=36), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.CheckConstraint(
                "import_status IN ('queued', 'dispatched', 'downloading', 'validating', 'active', 'available', 'failed', 'duplicate')",
                name="ck_attack_catalog_import_status",
            ),
        )

    indexes = {item["name"] for item in sa.inspect(bind).get_indexes("attack_catalog_versions")}
    if "uq_attack_catalog_single_active" not in indexes:
        op.create_index(
            "uq_attack_catalog_single_active", "attack_catalog_versions", ["active"], unique=True,
            sqlite_where=sa.text("active = 1"), postgresql_where=sa.text("active = true"),
        )
    if "ix_attack_catalog_created" not in indexes:
        op.create_index("ix_attack_catalog_created", "attack_catalog_versions", ["created_at"])

    existing = bind.execute(sa.text(
        "SELECT id FROM attack_catalog_versions WHERE catalog_version = :version"
    ), {"version": LEGACY_CATALOG["catalog_version"]}).first()
    if existing is None:
        canonical = json.dumps(LEGACY_CATALOG, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        checksum = hashlib.sha256(canonical).hexdigest()
        retrieved_at = datetime(2026, 10, 17, tzinfo=timezone.utc)
        tactics = sorted({tactic for item in LEGACY_CATALOG["techniques"] for tactic in item["tactics"]})
        op.bulk_insert(
            sa.table(
                "attack_catalog_versions",
                sa.column("id", sa.String()), sa.column("catalog_version", sa.String()),
                sa.column("source", sa.String()), sa.column("release_version", sa.String()),
                sa.column("source_reference", sa.Text()), sa.column("retrieved_at", sa.DateTime(timezone=True)),
                sa.column("checksum", sa.String()), sa.column("import_status", sa.String()),
                sa.column("active", sa.Boolean()), sa.column("catalog_json", sa.JSON()),
                sa.column("result_json", sa.JSON()), sa.column("created_at", sa.DateTime(timezone=True)),
                sa.column("available_at", sa.DateTime(timezone=True)), sa.column("dispatch_attempts", sa.Integer()),
                sa.column("updated_at", sa.DateTime(timezone=True)),
                sa.column("completed_at", sa.DateTime(timezone=True)),
            ),
            [{
                "id": "00000000-0000-4000-8000-000000000015",
                "catalog_version": LEGACY_CATALOG["catalog_version"],
                "source": "MITRE ATT&CK Enterprise curated bundled subset",
                "release_version": "legacy-subset-1.0",
                "source_reference": f"bundled:backend/app/data/attack_enterprise_subset.json#sha256={checksum}",
                "retrieved_at": retrieved_at, "checksum": checksum,
                "import_status": "active", "active": True,
                "catalog_json": LEGACY_CATALOG,
                "result_json": {"technique_count": len(LEGACY_CATALOG["techniques"]),
                                "tactic_count": len(tactics), "legacy": True},
                "created_at": retrieved_at, "available_at": None, "dispatch_attempts": 0,
                "updated_at": retrieved_at, "completed_at": retrieved_at,
            }],
        )


def downgrade() -> None:
    # Forward-only: mappings and report snapshots retain their catalog version.
    pass
