param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-z0-9][a-z0-9_-]{0,62}$')]
    [string]$ProjectName,

    [ValidatePattern('^[A-Za-z0-9_]+$')]
    [string]$FromRevision = '20261020_0019'
)

$ErrorActionPreference = 'Stop'
$databaseName = 'cyberlens_upgrade_' + [guid]::NewGuid().ToString('N')

$python = @'
import json, os
from datetime import datetime, timezone
from uuid import uuid4
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

base_url = make_url(os.environ['DATABASE_URL'])
test_name = '__DATABASE_NAME__'
from_revision = '__FROM_REVISION__'
admin_engine = create_engine(base_url.set(database='postgres'))
created = False
test_engine = None
original_database_url = os.environ['DATABASE_URL']
try:
    with admin_engine.connect().execution_options(isolation_level='AUTOCOMMIT') as conn:
        exists = conn.execute(text('SELECT 1 FROM pg_database WHERE datname=:name'), {'name': test_name}).scalar()
        if exists:
            raise RuntimeError('Disposable migration database already exists; refusing to overwrite it')
        conn.exec_driver_sql('CREATE DATABASE "' + test_name + '"')
        created = True

    test_url = base_url.set(database=test_name)
    os.environ['DATABASE_URL'] = test_url.render_as_string(hide_password=False).replace('%', '%%')
    config = Config('alembic.ini')
    command.upgrade(config, from_revision)

    from app.models import Asset, EvidenceSnapshot, Investigation, User
    user_id, asset_id, investigation_id, evidence_id = [str(uuid4()) for _ in range(4)]
    observed = datetime.now(timezone.utc)
    test_engine = create_engine(test_url)
    with Session(test_engine) as db:
        db.add(User(id=user_id, username='migration-upgrade-fixture', password_hash='disposable-not-a-login',
                    role='analyst', is_active=True, must_change_password=False, created_at=observed))
        db.flush()
        db.add(Asset(id=asset_id, kind='domain', identifier='upgrade.example.test',
                     normalized_identifier='upgrade.example.test', created_by=user_id, is_synthetic=True,
                     demo_scenario='routine_website', created_at=observed, updated_at=observed))
        db.flush()
        db.add(Investigation(id=investigation_id, asset_id=asset_id, requested_by=user_id, mode='demo',
                             status='completed', progress=100, created_at=observed, finished_at=observed))
        db.flush()
        db.add(EvidenceSnapshot(id=evidence_id, investigation_id=investigation_id,
                                source='Synthetic migration-upgrade fixture', observed_at=observed,
                                evidence_json={'submitted_url':'https://upgrade.example.test/path'},
                                sha256='a' * 64, is_synthetic=True))
        db.commit()

    command.upgrade(config, 'head')
    with test_engine.connect() as conn:
        revision = conn.execute(text('SELECT version_num FROM alembic_version')).scalar_one()
        tables = ('users', 'assets', 'investigations', 'evidence_snapshots', 'evidence_relationships')
        counts = {table: conn.execute(text('SELECT count(*) FROM ' + table)).scalar_one() for table in tables}
    if (counts['users'], counts['assets'], counts['investigations'], counts['evidence_snapshots']) != (1, 1, 1, 1):
        raise RuntimeError('Representative records did not survive the migration: ' + repr(counts))
    if counts['evidence_relationships'] < 1:
        raise RuntimeError('Evidence relationship backfill did not create an edge: ' + repr(counts))
    print(json.dumps({'from_revision': from_revision, 'to_revision': revision,
                      'preserved_counts': counts, 'result': 'passed'}))
finally:
    if test_engine is not None:
        test_engine.dispose()
    os.environ['DATABASE_URL'] = original_database_url
    if created:
        with admin_engine.connect().execution_options(isolation_level='AUTOCOMMIT') as conn:
            conn.exec_driver_sql('DROP DATABASE "' + test_name + '" WITH (FORCE)')
    admin_engine.dispose()
'@

$python = $python.Replace('__DATABASE_NAME__', $databaseName).Replace('__FROM_REVISION__', $FromRevision)
$python | docker compose --project-name $ProjectName -f docker-compose.yml -f docker-compose.demo.yml -f docker-compose.verify.yml exec -T api python -
if ($LASTEXITCODE -ne 0) {
    throw "Disposable migration upgrade check failed with exit code $LASTEXITCODE"
}
