from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


def test_attack_mapping_revision_upgrades_existing_schema(tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    root = Path(__file__).resolve().parents[2]
    database = tmp_path / "attack-upgrade.db"
    config = Config(str(root / "backend" / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database.as_posix()}")
    command.upgrade(config, "20261017_0010")
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    try:
        # Revision 0002 captured historical metadata; remove a table that a legacy
        # bootstrap may have created early so this specifically exercises 0011.
        with engine.begin() as connection:
            if "attack_mappings" in inspect(connection).get_table_names():
                connection.exec_driver_sql("DROP TABLE attack_mappings")
        command.upgrade(config, "20261017_0011")
        inspector = inspect(engine)
        assert "attack_mappings" in inspector.get_table_names()
        columns = {column["name"] for column in inspector.get_columns("attack_mappings")}
        assert {"finding_id", "incident_id", "technique_id", "technique_name", "tactic", "catalog_version",
                "rationale", "confidence", "source", "evidence_role", "evidence_id", "decision",
                "analyst_confirmed", "created_by", "reviewed_by", "reviewed_at"} <= columns
        foreign_keys = {tuple(item["constrained_columns"]) for item in inspector.get_foreign_keys("attack_mappings")}
        assert {("finding_id",), ("incident_id",), ("evidence_id",), ("created_by",), ("reviewed_by",)} <= foreign_keys
        command.upgrade(config, "head")
        audit_columns = {column["name"] for column in inspect(engine).get_columns("audit_events")}
        assert {"event_sequence", "previous_hash", "current_hash"} <= audit_columns
        catalog_columns = {column["name"] for column in inspect(engine).get_columns("attack_catalog_versions")}
        assert {"catalog_version", "source", "release_version", "source_reference", "retrieved_at", "checksum",
                "import_status", "active", "catalog_json", "result_json", "error_summary"} <= catalog_columns
        with engine.connect() as connection:
            legacy = connection.execute(text(
                "SELECT catalog_version, import_status, active, checksum FROM attack_catalog_versions "
                "WHERE catalog_version = 'cyberlens-attack-enterprise-subset-1.0'"
            )).one()
        assert legacy.import_status == "active" and bool(legacy.active) and len(legacy.checksum) == 64
        command.check(config)
    finally:
        engine.dispose()
