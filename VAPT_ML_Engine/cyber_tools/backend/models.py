import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Text, DateTime, ForeignKey, Integer, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.database import Base

def utcnow():
    return datetime.now(timezone.utc)

class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    target: Mapped[str] = mapped_column(String, nullable=False)
    tool: Mapped[str] = mapped_column(String, nullable=False)
    workflow: Mapped[str] = mapped_column(String, nullable=True)  # e.g. "full_audit"
    status: Mapped[str] = mapped_column(String, default="pending")  # pending | running | done | error
    command: Mapped[str] = mapped_column(Text, nullable=True)
    raw_output: Mapped[str] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)

    findings: Mapped[list["Finding"]] = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id"), nullable=False)
    type: Mapped[str] = mapped_column(String, nullable=False)   # port | subdomain | vuln | directory | credential
    severity: Mapped[str] = mapped_column(String, nullable=True)  # info | low | medium | high | critical
    title: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    host: Mapped[str] = mapped_column(String, nullable=True)
    port: Mapped[int] = mapped_column(Integer, nullable=True)
    service: Mapped[str] = mapped_column(String, nullable=True)
    protocol: Mapped[str] = mapped_column(String, nullable=True)
    extra: Mapped[dict] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")
