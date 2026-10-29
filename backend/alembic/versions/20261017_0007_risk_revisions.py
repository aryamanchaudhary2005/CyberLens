"""Add immutable, input-addressed risk assessment revisions.

Revision ID: 20261017_0007
Revises: 20261017_0006
"""

from __future__ import annotations

import hashlib
import json

from alembic import op
import sqlalchemy as sa
from sqlalchemy.orm import Session

from app.models import RiskAssessment, RiskAssessmentRevision

revision = "20261017_0007"
down_revision = "20261017_0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "risk_assessments" in inspector.get_table_names() and "weights_json" not in {column["name"] for column in inspector.get_columns("risk_assessments")}:
        op.add_column("risk_assessments", sa.Column("weights_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")))
    RiskAssessmentRevision.__table__.create(bind=bind, checkfirst=True)
    inspector = sa.inspect(bind)
    if "weights_json" not in {column["name"] for column in inspector.get_columns("risk_assessment_revisions")}:
        op.add_column("risk_assessment_revisions", sa.Column("weights_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")))
    with Session(bind=bind, autoflush=False, expire_on_commit=False) as db:
        for assessment in db.query(RiskAssessment).all():
            assessment.weights_json = (assessment.explanation_json or {}).get("weights_percent", {})
            if db.query(RiskAssessmentRevision).filter_by(investigation_id=assessment.investigation_id).first():
                continue
            payload = {
                "version": assessment.version,
                "score": assessment.score,
                "band": assessment.band,
                "assessed_categories": assessment.assessed_categories,
                "excluded_categories": assessment.excluded_categories,
                "category_scores": assessment.category_scores,
                "contributing_finding_ids": assessment.contributing_finding_ids,
                "explanation": assessment.explanation_json,
            }
            fingerprint = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str, separators=(",", ":")).encode()).hexdigest()
            db.add(RiskAssessmentRevision(
                investigation_id=assessment.investigation_id,
                revision_number=1,
                input_fingerprint=fingerprint,
                version=assessment.version,
                score=assessment.score,
                band=assessment.band,
                weights_json=assessment.weights_json,
                assessed_categories=assessment.assessed_categories,
                excluded_categories=assessment.excluded_categories,
                category_scores=assessment.category_scores,
                contributing_finding_ids=assessment.contributing_finding_ids,
                explanation_json=assessment.explanation_json,
                created_at=assessment.created_at,
            ))
        db.commit()


def downgrade() -> None:
    raise NotImplementedError("Risk assessment history is forward-only to preserve immutable revisions.")
