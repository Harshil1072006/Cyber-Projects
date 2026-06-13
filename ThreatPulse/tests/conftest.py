"""
conftest.py — Shared pytest fixtures for the Threat Intelligence Pipeline tests.

Provides an in-memory SQLite database with all tables created, a fresh session
for each test, and mock HTTP responses.
"""

import pytest
import uuid
from datetime import datetime, timezone

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.dialects.postgresql import ARRAY

from src.db.models import Base, Indicator, IOCSource, EnrichmentData

@compiles(ARRAY, "sqlite")
def compile_array_sqlite(type_, compiler, **kw):
    return "TEXT"


# ─── SQLite in-memory engine (mimics PostgreSQL for unit tests) ──────────────

@pytest.fixture(scope="session")
def engine():
    """Create a shared in-memory SQLite engine for all tests."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    # SQLite doesn't have ARRAY type — use TEXT for tags and open_ports
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_conn, connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    # Create all tables (SQLite doesn't support PG-specific types perfectly,
    # so we patch ARRAY and UUID columns via dialect-level adapters)
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)


@pytest.fixture
def session(engine):
    """Provide a transactional session that rolls back after each test."""
    SessionLocal = sessionmaker(bind=engine)
    sess = SessionLocal()
    yield sess
    sess.rollback()
    sess.close()


# ─── Sample data fixtures ────────────────────────────────────────────────────

@pytest.fixture
def sample_ip_indicator(session):
    """Insert and return a sample IP indicator."""
    ind = Indicator(
        id=uuid.uuid4(),
        ioc_value="198.51.100.42",
        ioc_type="ip",
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
        is_active=True,
        confidence_score=0.0,
        risk_score=0.0,
        source_count=1,
        tags=["botnet_c2"],
    )
    session.add(ind)
    session.flush()
    return ind


@pytest.fixture
def sample_domain_indicator(session):
    """Insert and return a sample domain indicator."""
    ind = Indicator(
        id=uuid.uuid4(),
        ioc_value="evil-phishing.example.com",
        ioc_type="domain",
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
        is_active=True,
        confidence_score=0.0,
        risk_score=0.0,
        source_count=2,
        tags=["phishing"],
    )
    session.add(ind)
    session.flush()
    return ind


@pytest.fixture
def sample_hash_indicator(session):
    """Insert and return a sample SHA256 hash indicator."""
    ind = Indicator(
        id=uuid.uuid4(),
        ioc_value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ioc_type="hash_sha256",
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
        is_active=True,
        confidence_score=0.0,
        risk_score=0.0,
        source_count=1,
        tags=["malware", "trojan"],
    )
    session.add(ind)
    session.flush()
    return ind


@pytest.fixture
def sample_source(session, sample_ip_indicator):
    """Insert and return an IOCSource linked to the sample IP indicator."""
    src = IOCSource(
        id=uuid.uuid4(),
        ioc_id=sample_ip_indicator.id,
        source_name="feodo_tracker",
        source_confidence=90.0,
        raw_data={"ip": "198.51.100.42", "status": "online"},
    )
    session.add(src)
    session.flush()
    return src


@pytest.fixture
def sample_enrichment(session, sample_ip_indicator):
    """Insert and return enrichment data for the sample IP indicator."""
    ed = EnrichmentData(
        id=uuid.uuid4(),
        ioc_id=sample_ip_indicator.id,
        country_code="RU",
        asn="AS12345 Evil-Hosting-Corp",
        reputation_score=85.0,
        vt_detections=12,
        abuse_reports=45,
        usage_type="Data Center/Web Hosting/Transit",
        open_ports=[22, 80, 443, 8080],
        enriched_at=datetime.now(timezone.utc),
    )
    session.add(ed)
    session.flush()
    return ed
