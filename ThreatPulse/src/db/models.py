"""
models.py — SQLAlchemy ORM models for the Threat Intelligence Pipeline.

Implements the 3-table schema from Section 7 of the blueprint:
  1. indicators    — Core IOC store (one row per unique IOC value)
  2. ioc_sources   — Which feeds reported each IOC
  3. enrichment_data — OSINT context added after collection
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Index,
    create_engine,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSON, UUID
from sqlalchemy.orm import DeclarativeBase, relationship


# ─── Base ────────────────────────────────────────────────────────────────────

class Base(DeclarativeBase):
    """Declarative base for all ORM models."""
    pass


# ─── IOC Type Enum ───────────────────────────────────────────────────────────

IOC_TYPE_ENUM = Enum(
    "ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256",
    name="ioc_type_enum",
    create_constraint=True,
)


# ─── Table 1: indicators ─────────────────────────────────────────────────────

class Indicator(Base):
    """
    Core IOC store — one row per unique IOC value.

    Columns map directly to Section 7.2, Table 1 of the blueprint.
    """

    __tablename__ = "indicators"

    # Primary key
    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        comment="Unique identifier for this IOC record",
    )

    # The actual indicator value
    ioc_value = Column(
        String(2048),
        nullable=False,
        unique=True,
        index=True,
        comment="The IOC itself: IP, domain, URL, or hash",
    )

    # Type classification
    ioc_type = Column(
        IOC_TYPE_ENUM,
        nullable=False,
        index=True,
        comment="One of: ip, domain, url, hash_md5, hash_sha1, hash_sha256",
    )

    # Temporal tracking
    first_seen = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        comment="When this IOC was first ingested by the pipeline",
    )
    last_seen = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        comment="When this IOC was most recently seen in any feed",
    )

    # Status
    is_active = Column(
        Boolean,
        nullable=False,
        default=True,
        index=True,
        comment="True if still within the active retention window",
    )

    # Scoring
    confidence_score = Column(
        Float,
        nullable=False,
        default=0.0,
        comment="Calculated trust score (0-100) based on sources and enrichment",
    )
    risk_score = Column(
        Float,
        nullable=False,
        default=0.0,
        comment="How dangerous this IOC is (0-100) based on context",
    )

    # Provenance
    source_count = Column(
        Integer,
        nullable=False,
        default=1,
        comment="How many distinct feeds reported this IOC",
    )

    # Classification
    tags = Column(
        ARRAY(Text),
        nullable=True,
        default=list,
        comment="Labels: ['botnet', 'c2', 'emotet', 'phishing'] etc.",
    )

    # Metadata timestamps
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        comment="Database record creation time",
    )
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        comment="Last time this record was modified",
    )

    # ── Relationships ──
    sources = relationship(
        "IOCSource", back_populates="indicator", cascade="all, delete-orphan"
    )
    enrichment = relationship(
        "EnrichmentData", back_populates="indicator", cascade="all, delete-orphan", uselist=False
    )

    # ── Indexes for common queries ──
    __table_args__ = (
        Index("ix_indicators_type_active", "ioc_type", "is_active"),
        Index("ix_indicators_risk", "risk_score"),
        Index("ix_indicators_confidence", "confidence_score"),
        Index("ix_indicators_last_seen", "last_seen"),
    )

    def __repr__(self):
        return (
            f"<Indicator(type={self.ioc_type}, value={self.ioc_value[:40]}..., "
            f"confidence={self.confidence_score}, risk={self.risk_score})>"
        )


# ─── Table 2: ioc_sources ────────────────────────────────────────────────────

class IOCSource(Base):
    """
    Which feeds reported each IOC, with timestamps and raw data.

    Maps to Section 7.2, Table 2 of the blueprint.
    """

    __tablename__ = "ioc_sources"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # Foreign key to indicators
    ioc_id = Column(
        UUID(as_uuid=True),
        ForeignKey("indicators.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Links to the parent indicator",
    )

    # Source identification
    source_name = Column(
        String(100),
        nullable=False,
        index=True,
        comment="Normalized feed name: 'feodo_tracker', 'abuseipdb', etc.",
    )

    # When this source first reported the IOC
    reported_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        comment="When this source first reported this IOC",
    )

    # Raw data preservation
    raw_data = Column(
        JSON,
        nullable=True,
        comment="Original raw record from the feed (JSON blob)",
    )

    # Trust weight for this source
    source_confidence = Column(
        Float,
        nullable=False,
        default=50.0,
        comment="Trust weight for this specific source (0-100)",
    )

    # ── Relationships ──
    indicator = relationship("Indicator", back_populates="sources")

    # Prevent duplicate source entries for the same IOC
    __table_args__ = (
        UniqueConstraint("ioc_id", "source_name", name="uq_ioc_source"),
        Index("ix_ioc_sources_ioc_source", "ioc_id", "source_name"),
    )

    def __repr__(self):
        return f"<IOCSource(source={self.source_name}, ioc_id={self.ioc_id})>"


# ─── Table 3: enrichment_data ────────────────────────────────────────────────

class EnrichmentData(Base):
    """
    OSINT context added after collection — geolocation, WHOIS, reputation, etc.

    Maps to Section 7.2, Table 3 of the blueprint.
    """

    __tablename__ = "enrichment_data"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # Foreign key to indicators (one-to-one)
    ioc_id = Column(
        UUID(as_uuid=True),
        ForeignKey("indicators.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
        comment="Links to the parent indicator",
    )

    # GeoIP
    country_code = Column(
        String(2),
        nullable=True,
        comment="Two-letter country code from GeoIP: 'RU', 'CN', 'US'",
    )

    # Network
    asn = Column(
        String(200),
        nullable=True,
        comment="Autonomous System: 'AS12345 Some-Hosting-Co'",
    )

    # WHOIS
    whois_registrar = Column(
        String(500),
        nullable=True,
        comment="Domain registrar from WHOIS lookup",
    )
    whois_created = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="Domain registration date — new domains are higher risk",
    )

    # DNS
    dns_records = Column(
        JSON,
        nullable=True,
        comment="JSON: A, MX, NS, TXT records from DNS resolution",
    )

    # Reputation
    reputation_score = Column(
        Float,
        nullable=True,
        comment="Score from VirusTotal, AbuseIPDB, or similar (0-100)",
    )
    vt_detections = Column(
        Integer,
        nullable=True,
        comment="How many VirusTotal engines flagged this IOC as malicious",
    )

    # Open ports (Shodan)
    open_ports = Column(
        ARRAY(Integer),
        nullable=True,
        comment="Open ports from Shodan scan",
    )

    # Abuse data
    abuse_reports = Column(
        Integer,
        nullable=True,
        comment="Number of abuse reports from AbuseIPDB",
    )
    usage_type = Column(
        String(100),
        nullable=True,
        comment="Usage type: 'Data Center', 'ISP', 'Tor Exit Node'",
    )

    # Cache management
    enriched_at = Column(
        DateTime(timezone=True),
        nullable=True,
        default=lambda: datetime.now(timezone.utc),
        comment="When enrichment was performed — for cache management",
    )

    # ── Relationships ──
    indicator = relationship("Indicator", back_populates="enrichment")

    def __repr__(self):
        return (
            f"<EnrichmentData(ioc_id={self.ioc_id}, country={self.country_code}, "
            f"vt_detections={self.vt_detections})>"
        )


# ─── Utility: Create all tables ──────────────────────────────────────────────

def create_all_tables(engine):
    """Create all tables in the database. Used for initial setup."""
    Base.metadata.create_all(engine)


def drop_all_tables(engine):
    """Drop all tables. USE WITH CAUTION — for testing only."""
    Base.metadata.drop_all(engine)
