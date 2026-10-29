"""Canonical names for explicitly inventoried package identities."""

import re


def normalize_package_name(ecosystem: str, name: str) -> str:
    """Normalize only the two package ecosystems CyberLens currently supports."""
    value = name.strip()
    if not value:
        raise ValueError("Package name cannot be blank")
    if ecosystem == "npm":
        normalized = value.lower()
        if len(normalized) > 214 or normalized in {".", ".."}:
            raise ValueError("Enter a valid npm package name")
        unscoped = re.fullmatch(r"[a-z0-9][a-z0-9._-]*", normalized)
        scoped = re.fullmatch(r"@[a-z0-9][a-z0-9._-]{0,99}/[a-z0-9][a-z0-9._-]{0,99}", normalized)
        if not (unscoped or scoped):
            raise ValueError("Enter a valid npm package name, including @scope/name when scoped")
        return normalized
    if ecosystem == "PyPI":
        if len(value) > 200 or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?", value):
            raise ValueError("Enter a valid PyPI package name")
        return re.sub(r"[-_.]+", "-", value).lower()
    raise ValueError("OSV package analysis currently supports npm and PyPI")
