from dataclasses import dataclass, field
from typing import Any


@dataclass
class CollectorResult:
    status: str = "success"
    source: str = "unknown"
    evidence: dict[str, Any] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    error_explanation: str | None = None
