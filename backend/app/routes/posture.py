from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BeforeValidator
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user
from app.models import User
from app.schemas import PostureScorecardOut
from app.services.posture import build_scorecard

router = APIRouter(prefix="/posture", tags=["posture"])


def _coerce_range_query(value: object) -> object:
    # HTTP query values arrive as strings. Literal[int] alone does not coerce
    # them, even though the OpenAPI parameter is an integer enum.
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return value
    return value


PostureRange = Annotated[Literal[7, 30, 90, 365], BeforeValidator(_coerce_range_query), Query()]


@router.get("/scorecard", response_model=PostureScorecardOut)
def get_posture_scorecard(
    range_days: PostureRange = 30,
    _user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Return a read-only, explicitly scoped workspace posture aggregation."""
    return build_scorecard(db, range_days)
