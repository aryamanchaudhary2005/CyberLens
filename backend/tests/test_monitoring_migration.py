from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


def test_monitoring_migration_is_additive_and_installs_idempotency_constraints(tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    root = Path(__file__).resolve().parents[2]
    database = tmp_path / "monitoring-migration.db"
    url = f"sqlite:///{database.as_posix()}"
    config = Config(str(root / "backend" / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "20261017_0012")
    engine = create_engine(url)
    try:
        with engine.begin() as connection:
            before = set(inspect(connection).get_table_names())
            connection.execute(text("INSERT INTO users (id, username, email, password_hash, role, is_active, must_change_password, created_at) VALUES ('monitor-user', 'monitor-user', NULL, 'hash', 'admin', 1, 0, CURRENT_TIMESTAMP)"))
            connection.execute(text("INSERT INTO assets (id, kind, identifier, normalized_identifier, notes, is_synthetic, created_by, created_at, updated_at) VALUES ('monitor-asset', 'domain', 'monitor.example.test', 'monitor.example.test', '', 0, 'monitor-user', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"))

        command.upgrade(config, "head")
        command.check(config)
        inspector = inspect(engine)
        after = set(inspector.get_table_names())
        assert after == before | {"monitoring_schedules", "monitoring_runs"}
        assert {column["name"] for column in inspector.get_columns("monitoring_schedules")} >= {
            "asset_id", "authorization_id", "owner_id", "cadence", "status", "next_run_at",
            "last_run_at", "failure_code", "failure_detail",
        }
        schedule_constraints = {item.get("name") for item in inspector.get_check_constraints("monitoring_schedules")}
        assert {"ck_monitoring_schedule_cadence", "ck_monitoring_schedule_status"} <= schedule_constraints
        run_constraints = {item.get("name") for item in inspector.get_unique_constraints("monitoring_runs")}
        assert {"uq_monitoring_run_schedule_slot", "uq_monitoring_run_investigation"} <= run_constraints
        with engine.connect() as connection:
            assert connection.execute(text("SELECT COUNT(*) FROM assets WHERE id='monitor-asset'")).scalar_one() == 1
    finally:
        engine.dispose()
