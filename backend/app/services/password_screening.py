"""Privacy-preserving checks for newly submitted account passwords."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import re
from typing import Literal

from app.models import AuditEvent
from app.network import OutboundTimeout, SafeResponse, safe_get

Outcome = Literal["not_found", "found", "unavailable"]
HIBP_RANGE_BASE = "https://api.pwnedpasswords.com/range"
HIBP_RANGE_RESPONSE_BYTES = 128_000
HIBP_LOOKUP_TIMEOUT_SECONDS = 4.0
_SUFFIX_PATTERN = re.compile(r"^[0-9A-F]{35}$")
_COUNT_PATTERN = re.compile(r"^[0-9]+$")


@dataclass(frozen=True)
class PasswordScreeningResult:
    outcome: Outcome
    reason: str


class PasswordScreeningError(Exception):
    """Safe failure that contains no password, hash, prefix, suffix or body."""

    def __init__(self, outcome: Literal["found", "unavailable"], reason: str) -> None:
        self.outcome = outcome
        self.reason = reason
        if outcome == "found":
            self.status_code = 422
            self.public_message = (
                "Choose a different password. This password appears in the Pwned Passwords dataset; "
                "this does not mean your CyberLens account was breached."
            )
            self.headers: dict[str, str] = {}
        else:
            self.status_code = 503
            self.public_message = "Password screening is temporarily unavailable. Please retry; your password was not changed."
            self.headers = {"Retry-After": "15"}
        super().__init__(self.public_message)


def _parse_range_response(response: SafeResponse, *, expected_url: str, target_suffix: str) -> bool:
    """Return whether a positive-count exact suffix exists; reject malformed bodies safely."""
    if response.status != 200 or response.final_url != expected_url or len(response.body) > HIBP_RANGE_RESPONSE_BYTES:
        raise ValueError("invalid range response")
    try:
        text = response.body.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("invalid range response") from exc
    if not text:
        raise ValueError("invalid range response")

    found = False
    for line in text.splitlines():
        if not line or ":" not in line:
            raise ValueError("invalid range response")
        suffix, count_text = line.split(":", 1)
        suffix = suffix.upper()
        if (not _SUFFIX_PATTERN.fullmatch(suffix) or not _COUNT_PATTERN.fullmatch(count_text)
                or len(count_text) > 18):
            raise ValueError("invalid range response")
        count = int(count_text)
        # Padded records have count zero and are not matches.
        if count > 0 and hmac.compare_digest(suffix, target_suffix):
            found = True
    return found


def check_password_candidate(password: str, *, app_mode: str) -> PasswordScreeningResult:
    """Screen one submitted password. Demo is a deterministic offline not-found fixture.

    The full SHA-1 digest exists only in this stack frame for the HIBP range
    protocol. Password storage continues to use the application's Argon2 path.
    """
    if app_mode == "demo":
        return PasswordScreeningResult("not_found", "demo_offline_fixture")
    if app_mode != "live":
        return PasswordScreeningResult("unavailable", "unsupported_application_mode")

    try:
        digest = hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()
    except (UnicodeError, ValueError):
        return PasswordScreeningResult("unavailable", "password_encoding_error")
    prefix, target_suffix = digest[:5], digest[5:]
    url = f"{HIBP_RANGE_BASE}/{prefix}"
    try:
        response = safe_get(
            url,
            timeout=HIBP_LOOKUP_TIMEOUT_SECONDS,
            max_bytes=HIBP_RANGE_RESPONSE_BYTES,
            max_redirects=0,
            send_range_header=False,
            headers={
                "Add-Padding": "true",
                "User-Agent": "CyberLens/0.1",
            },
        )
    except (OutboundTimeout, TimeoutError):
        return PasswordScreeningResult("unavailable", "provider_timeout")
    except Exception:
        # Do not log or expose the exception: HTTP libraries may include URLs
        # and other request context in exception text.
        return PasswordScreeningResult("unavailable", "provider_unreachable")

    if response.status == 429:
        return PasswordScreeningResult("unavailable", "provider_rate_limited")
    try:
        found = _parse_range_response(response, expected_url=url, target_suffix=target_suffix)
    except ValueError:
        return PasswordScreeningResult("unavailable", "provider_response_invalid")
    return PasswordScreeningResult("found", "matching_nonzero_count") if found else PasswordScreeningResult(
        "not_found", "no_matching_suffix",
    )


def require_password_not_compromised(password: str, *, app_mode: str) -> PasswordScreeningResult:
    result = check_password_candidate(password, app_mode=app_mode)
    if result.outcome in {"found", "unavailable"}:
        raise PasswordScreeningError(result.outcome, result.reason)
    return result


def screening_audit_event(*, actor_id: str | None, user_id: str, result: PasswordScreeningResult) -> AuditEvent:
    """Build a safe outcome-only audit row for a successfully set password."""
    return AuditEvent(
        actor_id=actor_id,
        action="auth.password_screened",
        entity_type="user",
        entity_id=user_id,
        details_json={"outcome": result.outcome, "reason": result.reason},
    )
