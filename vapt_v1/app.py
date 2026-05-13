import asyncio
import shutil
import json
from contextlib import asynccontextmanager
from fastapi import FastAPI, File, UploadFile, BackgroundTasks, HTTPException, Query, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pathlib import Path
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import traceback
import sys
from datetime import datetime, timezone

from database import init_db, AsyncSessionLocal, Scan, Finding, AIAnalysis
from file_processor import FileProcessor
from scanners.orchestrator import ScannerOrchestrator
from ai_engine import AIEngine
from sqlalchemy import select, delete, func

# ─────────────────────────────────────────────
#  Global AI Engine
# ─────────────────────────────────────────────
ai_engine: Optional[AIEngine] = None

# ─────────────────────────────────────────────
#  Lifespan (replaces deprecated @app.on_event)
# ─────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    global ai_engine
    await init_db()
    try:
        ai_engine = AIEngine()
    except Exception as e:
        with open("engine_debug.log", "a") as log:
            log.write(f"Startup AI Init Error: {e}\n")
    yield
    # Shutdown logic (if needed)

app = FastAPI(title="AI VAPT Engine v1.1.1", version="1.1.1", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────
#  Pydantic Response Models
# ─────────────────────────────────────────────
class ScanResponse(BaseModel):
    id: int
    filename: str
    status: str
    scan_mode: str
    scan_type: str
    ai_mode: str
    created_at: str  # ISO format
    completed_at: Optional[str] = None

    class Config:
        from_attributes = True

class FindingResponse(BaseModel):
    id: int
    scan_id: int
    tool_name: str
    vulnerability_name: str
    severity: str
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    raw_data: Optional[dict] = None

    class Config:
        from_attributes = True

def serialize_scan(scan: Scan) -> dict:
    return {
        "id": scan.id,
        "filename": scan.filename,
        "status": scan.status,
        "scan_mode": scan.scan_mode or "offline",
        "scan_type": scan.scan_type or "Auto",
        "ai_mode": scan.ai_mode or "offline",
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
    }

def serialize_finding(f: Finding) -> dict:
    return {
        "id": f.id,
        "scan_id": f.scan_id,
        "tool_name": f.tool_name,
        "vulnerability_name": f.vulnerability_name,
        "severity": f.severity,
        "description": f.description,
        "file_path": f.file_path,
        "line_number": f.line_number,
        "raw_data": f.raw_data,
    }

# ─────────────────────────────────────────────
#  Root & Health
# ─────────────────────────────────────────────
# ─────────────────────────────────────────────
#  Live Scan Log (in-memory per scan)
# ─────────────────────────────────────────────
from collections import defaultdict
_scan_logs: Dict[int, List[Dict[str, Any]]] = defaultdict(list)

def _log(scan_id: int, message: str, level: str = "info", percent: int = None):
    """Append a timestamped log entry for a scan."""
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "message": message,
    }
    if percent is not None:
        entry["percent"] = percent
    _scan_logs[scan_id].append(entry)

@app.get("/")
def read_root():
    return {"status": "VAPT Engine is running", "version": "1.1.1", "message": "Ready to ingest files for scanning."}

@app.get("/api/health")
def health_check():
    tools = {
        "nuclei": Path("tools/nuclei/nuclei.exe").exists(),
        "trivy": Path("tools/trivy/trivy.exe").exists(),
        "radare2": Path("tools/radare2/r2blob.static.exe").exists(),
        "zap": _find_zap_bat() is not None,
        "ai_model": Path("models/Meta-Llama-3-8B-Instruct-Q4_K_M.gguf").exists(),
        "ai_loaded": ai_engine is not None and ai_engine.is_offline_available(),
        "ai_online": ai_engine is not None and ai_engine.is_online_available(),
    }
    return {"tools": tools}

def _find_zap_bat():
    import os
    zap_dir = Path("tools/zap")
    if zap_dir.exists():
        for root, dirs, files in os.walk(str(zap_dir)):
            if "zap.bat" in files:
                return Path(root) / "zap.bat"
    return None

# ─────────────────────────────────────────────
#  AI Settings
# ─────────────────────────────────────────────
class AISettingsPayload(BaseModel):
    groq_api_key: Optional[str] = None

@app.post("/api/settings/ai")
async def update_ai_settings(payload: AISettingsPayload):
    """Update AI engine settings (e.g., Groq API key for online mode)."""
    if ai_engine and payload.groq_api_key is not None:
        ai_engine.set_groq_key(payload.groq_api_key)
        return {"status": "success", "online_available": ai_engine.is_online_available()}
    return {"status": "error", "message": "AI engine not initialized"}

@app.get("/api/settings/ai")
async def get_ai_settings():
    """Get current AI capabilities."""
    if ai_engine:
        return {
            "offline_available": ai_engine.is_offline_available(),
            "online_available": ai_engine.is_online_available(),
            "has_groq_key": bool(ai_engine.groq_api_key),
        }
    return {"offline_available": False, "online_available": False, "has_groq_key": False}

# ─────────────────────────────────────────────
#  Scan Pipelines (Background Tasks)
# ─────────────────────────────────────────────
ACTIVE_SCAN_STATUSES = {"pending", "processing_files", "scanning", "ai_analysis"}

async def run_scan_pipeline(scan_id: int, file_path: str, scan_mode: str = "offline", ai_mode: str = "offline"):
    try:
        abs_file_path = str(Path(file_path).resolve())
        _log(scan_id, f"🚀 Pipeline started — File: {Path(file_path).name}, Mode: {scan_mode}, AI: {ai_mode}", "info", 0)
        with open("engine_debug.log", "a") as log:
            log.write(f"\n--- Scan {scan_id} Pipeline Started (mode: {scan_mode}, ai: {ai_mode}) ---\n")
            log.write(f"Source Upload Path: {abs_file_path}\n")

        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if not scan:
                return
            scan.status = "processing_files"
            await db.commit()

        _log(scan_id, "📦 Extracting and preparing uploaded file for scanning...", "info", 5)
        rel_target = FileProcessor.prepare_for_scan(abs_file_path, str(scan_id))
        target_path = str(Path(rel_target).resolve())
        _log(scan_id, f"✅ File prepared at: {Path(target_path).name}", "success", 10)

        with open("engine_debug.log", "a") as log:
            log.write(f"Extracted/Target Path: {target_path}\n")

        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if scan:
                scan.status = "scanning"
                await db.commit()

        _log(scan_id, "🔍 Starting security scanner suite...", "info", 12)
        _log(scan_id, "⚡ Running SAST Scanner — analyzing source code for insecure patterns...", "info", 15)
        _log(scan_id, "🔬 Running Binary Scanner — analyzing compiled binaries and executables...", "info", 25)
        _log(scan_id, "🛡️  Running Trivy Scanner — checking for CVEs in dependencies and configs...", "info", 40)
        if scan_mode == "online":
            _log(scan_id, "🌐 Running Nuclei Scanner — probing for known vulnerability templates...", "info", 55)
            _log(scan_id, "🕷️  Running ZAP Scanner — performing DAST web application testing...", "info", 65)

        orchestrator = ScannerOrchestrator()
        raw_findings = await orchestrator.run_all(target_path, scan_id, scan_mode=scan_mode)

        _log(scan_id, f"📊 Scanning complete — {len(raw_findings)} raw findings collected", "success", 75)
        with open("engine_debug.log", "a") as log:
            log.write(f"Findings Count: {len(raw_findings)}\n")

        _log(scan_id, "💾 Persisting findings to database...", "info", 78)
        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            for f in raw_findings:
                finding = Finding(
                    scan_id=scan_id,
                    tool_name=f.get('tool_name', 'System'),
                    vulnerability_name=f.get('vulnerability_name', 'Unknown'),
                    severity=f.get('severity', 'Info'),
                    description=f.get('description', ''),
                    file_path=f.get('file_path'),
                    line_number=f.get('line_number'),
                    raw_data=f.get('raw_data', {})
                )
                db.add(finding)

            if scan:
                scan.status = "ai_analysis"
            await db.commit()

        _log(scan_id, f"🤖 Starting AI analysis in {ai_mode} mode — generating executive summary...", "info", 82)
        if ai_engine:
            with open("engine_debug.log", "a") as log:
                log.write(f"Running AI Analysis (mode: {ai_mode})...\n")
            analysis_text = await ai_engine.analyze_findings(raw_findings, ai_mode=ai_mode)
            async with AsyncSessionLocal() as db:
                ai_doc = AIAnalysis(scan_id=scan_id, analysis_text=analysis_text)
                db.add(ai_doc)
                await db.commit()
            _log(scan_id, "✅ AI analysis complete — executive summary generated", "success", 95)
        else:
            _log(scan_id, "⚠️  AI engine not initialized — skipping AI analysis", "warning", 95)

        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if scan:
                scan.status = "completed"
                scan.completed_at = datetime.now(timezone.utc)
                await db.commit()

        _log(scan_id, "🎉 Scan pipeline completed successfully!", "success", 100)
        with open("engine_debug.log", "a") as log:
            log.write(f"Scan {scan_id} Pipeline Completed.\n")

    except Exception as e:
        _log(scan_id, f"❌ Pipeline error: {str(e)[:200]}", "error")
        with open("engine_debug.log", "a") as log:
            log.write(f"Pipeline Error for Scan {scan_id}: {e}\n{traceback.format_exc()}\n")
        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if scan:
                scan.status = "failed"
                await db.commit()


async def run_url_scan_pipeline(scan_id: int, target_url: str, ai_mode: str = "offline"):
    try:
        _log(scan_id, f"🌐 URL Scan started — Target: {target_url}, AI: {ai_mode}", "info", 0)
        with open("engine_debug.log", "a") as log:
            log.write(f"\n--- URL Scan {scan_id} Started (ai: {ai_mode}) ---\n")
            log.write(f"Target URL: {target_url}\n")

        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if not scan:
                return
            scan.status = "scanning"
            await db.commit()

        _log(scan_id, f"🔍 Resolving target and initiating network scan...", "info", 10)
        _log(scan_id, "⚡ Running Nuclei Scanner — testing for CVEs and misconfigurations...", "info", 20)
        _log(scan_id, "🕷️  Running ZAP Scanner — performing active web vulnerability testing (XSS, SQLi, CSRF)...", "info", 45)

        orchestrator = ScannerOrchestrator()
        raw_findings = await orchestrator.run_all(target_url, scan_id, scan_mode="online")

        _log(scan_id, f"📊 Scanning complete — {len(raw_findings)} findings collected", "success", 75)
        with open("engine_debug.log", "a") as log:
            log.write(f"URL Scan Findings: {len(raw_findings)}\n")

        _log(scan_id, "💾 Persisting findings to database...", "info", 78)
        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            for f in raw_findings:
                finding = Finding(
                    scan_id=scan_id,
                    tool_name=f.get('tool_name', 'System'),
                    vulnerability_name=f.get('vulnerability_name', 'Unknown'),
                    severity=f.get('severity', 'Info'),
                    description=f.get('description', ''),
                    file_path=f.get('file_path'),
                    line_number=f.get('line_number'),
                    raw_data=f.get('raw_data', {})
                )
                db.add(finding)
            if scan:
                scan.status = "ai_analysis"
            await db.commit()

        _log(scan_id, f"🤖 Running AI analysis ({ai_mode}) — generating executive summary...", "info", 82)
        if ai_engine:
            with open("engine_debug.log", "a") as log:
                log.write(f"Running AI Analysis on URL scan (mode: {ai_mode})...\n")
            analysis_text = await ai_engine.analyze_findings(raw_findings, ai_mode=ai_mode)
            async with AsyncSessionLocal() as db:
                ai_doc = AIAnalysis(scan_id=scan_id, analysis_text=analysis_text)
                db.add(ai_doc)
                await db.commit()
            _log(scan_id, "✅ AI analysis complete", "success", 95)
        else:
            _log(scan_id, "⚠️  AI engine not available — skipping AI analysis", "warning", 95)

        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if scan:
                scan.status = "completed"
                scan.completed_at = datetime.now(timezone.utc)
                await db.commit()

        _log(scan_id, "🎉 URL Scan pipeline completed successfully!", "success", 100)
        with open("engine_debug.log", "a") as log:
            log.write(f"URL Scan {scan_id} Completed.\n")

    except Exception as e:
        _log(scan_id, f"❌ URL Scan error: {str(e)[:200]}", "error")
        with open("engine_debug.log", "a") as log:
            log.write(f"URL Scan Error {scan_id}: {e}\n{traceback.format_exc()}\n")
        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if scan:
                scan.status = "failed"
                await db.commit()


# ─────────────────────────────────────────────
#  API Endpoints
# ─────────────────────────────────────────────

@app.post("/api/scan/upload")
async def upload_for_scan(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    ai_mode: str = Query("offline", description="AI analysis mode: 'online' or 'offline'")
):
    try:
        upload_path = Path("uploads") / file.filename
        upload_path.parent.mkdir(exist_ok=True)
        abs_upload_path = str(upload_path.resolve())

        with open(abs_upload_path, "wb") as buffer:
            while content := await file.read(1024 * 1024):
                buffer.write(content)

        async with AsyncSessionLocal() as db:
            scan = Scan(
                filename=file.filename,
                scan_type="Auto",
                scan_mode="offline",
                ai_mode=ai_mode,
                status="pending"
            )
            db.add(scan)
            await db.flush()
            await db.commit()
            await db.refresh(scan)
            scan_id = scan.id

        background_tasks.add_task(run_scan_pipeline, scan_id, abs_upload_path, "offline", ai_mode)
        return {"status": "success", "scan_id": scan_id, "message": f"Scan started (AI: {ai_mode})"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scan/url")
async def scan_url(
    background_tasks: BackgroundTasks,
    target_url: str = Query(..., description="Target URL to scan"),
    ai_mode: str = Query("offline", description="AI analysis mode: 'online' or 'offline'")
):
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        raise HTTPException(status_code=400, detail="URL must start with http:// or https://")

    try:
        async with AsyncSessionLocal() as db:
            scan = Scan(
                filename=target_url,
                scan_type="DAST",
                scan_mode="online",
                ai_mode=ai_mode,
                status="pending"
            )
            db.add(scan)
            await db.flush()
            await db.commit()
            await db.refresh(scan)
            scan_id = scan.id

        background_tasks.add_task(run_url_scan_pipeline, scan_id, target_url, ai_mode)
        return {"status": "success", "scan_id": scan_id, "message": f"URL scan started (AI: {ai_mode})"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/scans")
async def list_scans():
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Scan).order_by(Scan.created_at.desc()))
        scans = result.scalars().all()
        return {"scans": [serialize_scan(s) for s in scans]}


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: int):
    async with AsyncSessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        findings_query = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
        findings = findings_query.scalars().all()

        ai_query = await db.execute(select(AIAnalysis).where(AIAnalysis.scan_id == scan_id))
        ai_analysis = ai_query.scalars().first()

        return {
            "scan": serialize_scan(scan),
            "findings": [serialize_finding(f) for f in findings],
            "ai_analysis": ai_analysis.analysis_text if ai_analysis else None
        }


@app.delete("/api/scan/{scan_id}")
async def delete_scan(scan_id: int, force: bool = Query(False, description="Force delete even if scan is active")):
    """
    Delete a scan and all related data.
    Blocks deletion of active scans unless force=True.
    """
    async with AsyncSessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Guard: prevent deleting active scans
        if scan.status in ACTIVE_SCAN_STATUSES and not force:
            raise HTTPException(
                status_code=409,
                detail=f"Scan is currently '{scan.status}'. Use force=true to delete an active scan."
            )

        filename = scan.filename

        await db.execute(delete(Finding).where(Finding.scan_id == scan_id))
        await db.execute(delete(AIAnalysis).where(AIAnalysis.scan_id == scan_id))
        await db.delete(scan)
        await db.commit()

    # Clean up disk
    upload_file = Path("uploads") / filename
    if upload_file.exists():
        try:
            upload_file.unlink()
        except Exception:
            pass

    work_dir = Path("workdir") / str(scan_id)
    if work_dir.exists():
        try:
            shutil.rmtree(work_dir)
        except Exception:
            pass

    return {"status": "success", "message": f"Scan {scan_id} deleted"}


@app.delete("/api/scans/all")
async def delete_all_scans(force: bool = Query(False, description="Force delete even for active scans")):
    """Bulk delete all scans."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Scan))
        scans = result.scalars().all()
        deleted = 0
        skipped = 0

        for scan in scans:
            if scan.status in ACTIVE_SCAN_STATUSES and not force:
                skipped += 1
                continue

            await db.execute(delete(Finding).where(Finding.scan_id == scan.id))
            await db.execute(delete(AIAnalysis).where(AIAnalysis.scan_id == scan.id))
            await db.delete(scan)

            # Disk cleanup
            upload_file = Path("uploads") / scan.filename
            if upload_file.exists():
                try:
                    upload_file.unlink()
                except Exception:
                    pass
            work_dir = Path("workdir") / str(scan.id)
            if work_dir.exists():
                try:
                    shutil.rmtree(work_dir)
                except Exception:
                    pass
            deleted += 1

        await db.commit()

    return {"status": "success", "deleted": deleted, "skipped": skipped}


@app.get("/api/scan/{scan_id}/logs")
async def get_scan_logs(scan_id: int, since: int = Query(0, description="Return only entries from this index onward")):
    """Return live scan log entries for a given scan, with optional offset to stream incrementally."""
    entries = _scan_logs.get(scan_id, [])
    return {"scan_id": scan_id, "total": len(entries), "logs": entries[since:]}


@app.get("/api/scan/{scan_id}/export")
async def export_scan(scan_id: int, format: str = Query("json", description="Export format: 'json' or 'text'")):
    """Export scan results as JSON or formatted text report."""
    async with AsyncSessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        findings_q = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
        findings = findings_q.scalars().all()

        ai_q = await db.execute(select(AIAnalysis).where(AIAnalysis.scan_id == scan_id))
        ai_analysis = ai_q.scalars().first()

        if format == "text":
            # Generate formatted text report
            report_lines = [
                "=" * 60,
                "  VAPT SECURITY SCAN REPORT",
                "=" * 60,
                f"  Scan ID:      {scan.id}",
                f"  Target:       {scan.filename}",
                f"  Status:       {scan.status}",
                f"  Scan Mode:    {scan.scan_mode or 'offline'}",
                f"  AI Mode:      {scan.ai_mode or 'offline'}",
                f"  Started:      {scan.created_at.isoformat() if scan.created_at else 'N/A'}",
                f"  Completed:    {scan.completed_at.isoformat() if scan.completed_at else 'N/A'}",
                "=" * 60,
                "",
                f"TOTAL VULNERABILITIES: {len(findings)}",
                "-" * 40,
            ]

            severity_counts = {}
            for f in findings:
                severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            for sev, count in sorted(severity_counts.items()):
                report_lines.append(f"  {sev}: {count}")
            report_lines.append("")

            if ai_analysis:
                report_lines.append("=" * 60)
                report_lines.append("  AI EXECUTIVE SUMMARY")
                report_lines.append("=" * 60)
                report_lines.append(ai_analysis.analysis_text)
                report_lines.append("")

            report_lines.append("=" * 60)
            report_lines.append("  DETAILED FINDINGS")
            report_lines.append("=" * 60)

            for i, f in enumerate(findings, 1):
                report_lines.append(f"\n--- Finding #{i} ---")
                report_lines.append(f"  Severity:       {f.severity}")
                report_lines.append(f"  Vulnerability:  {f.vulnerability_name}")
                report_lines.append(f"  Tool:           {f.tool_name}")
                report_lines.append(f"  File:           {f.file_path or 'N/A'}")
                report_lines.append(f"  Line:           {f.line_number or 'N/A'}")
                report_lines.append(f"  Description:    {f.description}")

            report_lines.append("\n" + "=" * 60)
            report_lines.append("  End of Report")
            report_lines.append("=" * 60)

            return JSONResponse(content={"report": "\n".join(report_lines), "format": "text"})

        else:
            # JSON export
            export_data = {
                "scan": serialize_scan(scan),
                "findings": [serialize_finding(f) for f in findings],
                "ai_analysis": ai_analysis.analysis_text if ai_analysis else None,
                "summary": {
                    "total_findings": len(findings),
                    "by_severity": {},
                    "by_tool": {},
                },
            }

            for f in findings:
                export_data["summary"]["by_severity"][f.severity] = export_data["summary"]["by_severity"].get(f.severity, 0) + 1
                export_data["summary"]["by_tool"][f.tool_name] = export_data["summary"]["by_tool"].get(f.tool_name, 0) + 1

            return JSONResponse(content=export_data)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8484, reload=True)
