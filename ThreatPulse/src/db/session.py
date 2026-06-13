"""
session.py — Database session factory for the Threat Intelligence Pipeline.

Provides a reusable SQLAlchemy engine and session maker, with a
context manager for safe transaction handling.
"""

import logging
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from src.config import DATABASE_URL

logger = logging.getLogger(__name__)

# ─── Engine ──────────────────────────────────────────────────────────────────

engine = create_engine(
    DATABASE_URL,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,          # Verify connection health before use
    pool_recycle=3600,           # Recycle connections every hour
    echo=False,                  # Set True for SQL debug logging
)

# ─── Session Factory ─────────────────────────────────────────────────────────

SessionFactory = sessionmaker(bind=engine, expire_on_commit=False)


# ─── Context Manager ────────────────────────────────────────────────────────

@contextmanager
def get_session() -> Session:
    """
    Provide a transactional scope around a series of operations.

    Usage:
        with get_session() as session:
            session.add(indicator)
            # auto-commits on success, auto-rolls-back on exception
    """
    session = SessionFactory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        logger.exception("Database session error — rolled back transaction")
        raise
    finally:
        session.close()


def init_db():
    """Initialize the database — create all tables if they don't exist."""
    from src.db.models import Base
    Base.metadata.create_all(engine)
    logger.info("Database tables created/verified successfully")
