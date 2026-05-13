import os
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, DateTime, JSON
from datetime import datetime, timezone

DATABASE_URL = "sqlite+aiosqlite:///./vapt.db"

engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(
    engine, expire_on_commit=False, class_=AsyncSession
)

Base = declarative_base()

class Scan(Base):
    __tablename__ = "scans"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    filename: Mapped[str] = mapped_column(String, index=True)
    status: Mapped[str] = mapped_column(String, default="pending")  # pending, scanning, completed, failed
    scan_mode: Mapped[str] = mapped_column(String, default="offline")  # offline, online
    ai_mode: Mapped[str] = mapped_column(String, default="offline")  # offline, online
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    scan_type: Mapped[str] = mapped_column(String) # SAST, Binary, DAST, Auto

class Finding(Base):
    __tablename__ = "findings"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(Integer, index=True)
    tool_name: Mapped[str] = mapped_column(String)  # nuclei, trivy, bandit, etc
    vulnerability_name: Mapped[str] = mapped_column(String)
    severity: Mapped[str] = mapped_column(String)  # Critical, High, Medium, Low, Info
    description: Mapped[Text] = mapped_column(Text)
    file_path: Mapped[str | None] = mapped_column(String, nullable=True)
    line_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    raw_data: Mapped[dict] = mapped_column(JSON) # Store unstructured JSON from tools

class AIAnalysis(Base):
    __tablename__ = "ai_analysis"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(Integer, index=True)
    finding_id: Mapped[int | None] = mapped_column(Integer, nullable=True) # If null, applies to whole scan
    analysis_text: Mapped[Text] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
