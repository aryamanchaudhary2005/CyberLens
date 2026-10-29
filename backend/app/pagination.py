"""Shared, backwards-compatible pagination helpers for collection routes."""

from dataclasses import dataclass
from typing import Any

from fastapi import Query, Response


@dataclass(frozen=True)
class Page:
    number: int = 1
    size: int = 100

    @property
    def offset(self) -> int:
        return (self.number - 1) * self.size


def page_params(
    page: int = Query(1, ge=1, description="One-based page number."),
    page_size: int = Query(100, ge=1, le=250, description="Maximum records per page."),
) -> Page:
    return Page(page, page_size)


def apply_page(query: Any, page: Page, response: Response | None) -> list[Any]:
    """Apply offset/limit and expose metadata without changing list bodies."""
    total = query.order_by(None).count()
    rows = query.offset(page.offset).limit(page.size).all()
    if response is not None:
        response.headers["X-Total-Count"] = str(total)
        response.headers["X-Page"] = str(page.number)
        response.headers["X-Page-Size"] = str(page.size)
        response.headers["X-Has-Next"] = "true" if page.offset + len(rows) < total else "false"
    return rows
