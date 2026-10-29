from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import sessionmaker

from app.config import get_settings


class Base(DeclarativeBase):
    """Base for persistent application records added by later modules."""


engine = create_engine(get_settings().database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def get_db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def check_database() -> bool:
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
    return True
