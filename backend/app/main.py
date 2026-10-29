import logging
import time
import uuid

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from redis import Redis

from app.config import get_settings
from app.database import check_database, get_db
from app.logging_config import configure_logging
from app.logging_config import request_id_context
from app.metrics import record_request, snapshot as metrics_snapshot
from app.routes import assets, audit, auth, attack, findings, incidents, investigations, reports, users, integrations, remediation, threat_model, integrity, monitoring, posture
from app.orchestration import worker_is_ready
from app.schemas import HealthLiveOut, MetricsOut, PostgresReadyOut, ReadinessOut, RedisReadyOut, WorkerReadyOut
from app.dependencies import get_current_user
from sqlalchemy.orm import Session

settings = get_settings()
configure_logging(settings.log_level)
logger = logging.getLogger("cyberlens.api")

app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description="CyberLens cyber threat analysis platform API.",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.api_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-CSRF-Token", "X-Request-ID"],
    expose_headers=["X-Request-ID"],
)

router = APIRouter(prefix="/api/v1")


@app.middleware("http")
async def request_context(request: Request, call_next):
    supplied = request.headers.get("x-request-id", "")
    if not supplied or len(supplied) > 100 or any(ord(char) < 32 for char in supplied):
        supplied = str(uuid.uuid4())
    token = request_id_context.set(supplied)
    started = time.perf_counter()
    try:
        if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.url.path.startswith("/api/v1/"):
            cookie_token = request.cookies.get("cyberlens_csrf", "")
            header_token = request.headers.get("x-csrf-token", "")
            if not cookie_token or not header_token or cookie_token != header_token:
                response = JSONResponse(status_code=403, content={"detail": "CSRF token missing or invalid"})
                response.headers["X-Request-ID"] = supplied
                record_request((time.perf_counter() - started) * 1000, response.status_code)
                return response
        response = await call_next(request)
        response.headers["X-Request-ID"] = supplied
        duration_ms = round((time.perf_counter() - started) * 1000, 3)
        record_request(duration_ms, response.status_code)
        logger.info("request completed", extra={"event": "request.completed", "method": request.method,
                                                 "path": request.url.path, "status_code": response.status_code,
                                                 "duration_ms": duration_ms})
        return response
    except Exception:
        duration_ms = round((time.perf_counter() - started) * 1000, 3)
        record_request(duration_ms, 500)
        logger.exception("request failed", extra={"event": "request.failed", "method": request.method,
                                                   "path": request.url.path, "status_code": 500,
                                                   "duration_ms": duration_ms})
        raise
    finally:
        request_id_context.reset(token)


@router.get("/health/live", tags=["health"], response_model=HealthLiveOut)
def liveness() -> dict[str, str]:
    return {"status": "alive", "service": "cyberlens-api"}


@router.get("/metrics", tags=["operations"], response_model=MetricsOut)
def metrics(_user=Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    client = Redis.from_url(settings.redis_url, socket_timeout=2)
    try:
        return metrics_snapshot(db, client)
    finally:
        client.close()


def dependency_status() -> dict[str, bool]:
    database_ok = False
    redis_ok = False
    worker_ok = False
    try:
        database_ok = check_database()
    except Exception:
        logger.exception("database readiness check failed")
    try:
        client = Redis.from_url(settings.redis_url, socket_timeout=2)
        try:
            redis_ok = bool(client.ping())
            worker_ok = worker_is_ready(client) if redis_ok else False
        finally:
            client.close()
    except Exception:
        logger.exception("redis readiness check failed")
    return {"database": database_ok, "redis": redis_ok, "worker": worker_ok}


@router.get("/health/postgres", tags=["health"], response_model=PostgresReadyOut)
def postgres_readiness() -> dict[str, object]:
    try:
        ready = check_database()
    except Exception:
        logger.exception("postgres readiness check failed")
        ready = False
    if not ready:
        raise HTTPException(status_code=503, detail={"status": "not_ready", "postgres": False})
    return {"status": "ready", "postgres": True}


@router.get("/health/redis", tags=["health"], response_model=RedisReadyOut)
def redis_readiness() -> dict[str, object]:
    try:
        client = Redis.from_url(settings.redis_url, socket_timeout=2)
        try:
            ready = bool(client.ping())
        finally:
            client.close()
    except Exception:
        logger.exception("redis readiness check failed")
        ready = False
    if not ready:
        raise HTTPException(status_code=503, detail={"status": "not_ready", "redis": False})
    return {"status": "ready", "redis": True}


@router.get("/health/worker", tags=["health"], response_model=WorkerReadyOut)
def worker_readiness() -> dict[str, object]:
    try:
        client = Redis.from_url(settings.redis_url, socket_timeout=2)
        try:
            ready = bool(client.ping()) and worker_is_ready(client)
        finally:
            client.close()
    except Exception:
        logger.exception("worker readiness check failed")
        ready = False
    if not ready:
        raise HTTPException(status_code=503, detail={"status": "not_ready", "worker": False})
    return {"status": "ready", "worker": True}


@router.get("/health/ready", tags=["health"], response_model=ReadinessOut)
def readiness() -> dict[str, object]:
    dependencies = dependency_status()
    if not all(dependencies.values()):
        raise HTTPException(
            status_code=503,
            detail={"status": "not_ready", "dependencies": dependencies},
        )
    return {
        "status": "ready",
        "service": "cyberlens-api",
        "mode": settings.app_mode,
        "demo_data": settings.app_mode == "demo",
        "dependencies": dependencies,
    }


app.include_router(router)
for module in (auth, users, assets, investigations, findings, incidents, reports, integrations, audit, remediation, threat_model, attack, integrity, monitoring, posture):
    app.include_router(module.router, prefix="/api/v1")
