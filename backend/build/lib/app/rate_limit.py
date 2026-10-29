"""Shared Redis-backed login throttling."""

from collections.abc import Generator
from hashlib import sha256

from fastapi import HTTPException
from redis import Redis
from redis.exceptions import RedisError

from app.config import get_settings

LOGIN_LIMIT = 5
LOGIN_WINDOW_SECONDS = 15 * 60
_INCREMENT_WITH_WINDOW = """
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return count
"""


def get_login_rate_limit_redis() -> Generator[Redis, None, None]:
    client = Redis.from_url(
        get_settings().redis_url,
        socket_connect_timeout=2,
        socket_timeout=2,
    )
    try:
        yield client
    finally:
        client.close()


def login_rate_limit_key(client_address: str) -> str:
    digest = sha256(client_address.encode("utf-8")).hexdigest()
    return f"cyberlens:auth:login:{digest}"


def check_login_rate_limit(redis: Redis, client_address: str) -> None:
    key = login_rate_limit_key(client_address)
    try:
        attempts = int(redis.eval(_INCREMENT_WITH_WINDOW, 1, key, LOGIN_WINDOW_SECONDS))
    except (RedisError, OSError, TimeoutError) as exc:
        raise HTTPException(503, "Authentication service temporarily unavailable") from exc
    if attempts > LOGIN_LIMIT:
        raise HTTPException(429, "Too many login attempts. Try again in 15 minutes.")


def clear_login_attempts(redis: Redis, client_address: str) -> None:
    try:
        redis.delete(login_rate_limit_key(client_address))
    except (RedisError, OSError, TimeoutError) as exc:
        raise HTTPException(503, "Authentication service temporarily unavailable") from exc
