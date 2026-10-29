import pytest
from pydantic import ValidationError

from app.config import Settings


@pytest.mark.parametrize(
    ("mode", "expected"),
    [("Demo", "demo"), ("LIVE", "live"), (" live ", "live")],
)
def test_app_mode_is_normalized_case_insensitively(mode: str, expected: str) -> None:
    settings = Settings(
        app_mode=mode,
        cookie_secure=True,
        database_url="postgresql+psycopg://cyberlens:private@localhost:5432/cyberlens",
        redis_url="redis://:private@localhost:6379/0",
    )

    assert settings.app_mode == expected


def test_app_mode_rejects_unknown_values() -> None:
    with pytest.raises(ValidationError):
        Settings(app_mode="preview")


def test_cors_origins_accept_comma_separated_environment_value() -> None:
    settings = Settings(api_cors_origins="http://localhost:5173,https://analyst.example")

    assert settings.api_cors_origins == [
        "http://localhost:5173",
        "https://analyst.example",
    ]
