"""
Scan CRUD endpoints.
"""
import asyncio
import uuid
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from backend.database import get_db
from backend.models import Scan, Finding
from backend.plugins.tools import TOOL_REGISTRY
from backend.engine.runner import run_command_sync
from backend.engine.correlator import correlate

router = APIRouter()


class LaunchScanRequest(BaseModel):
    target: str
    tool: str
    options: dict = {}


class WorkflowRequest(BaseModel):
    target: str
    workflow: str  # "quick_look" | "deep_web" | "full_audit"


WORKFLOWS = {
    "quick_look": [
        {"tool": "nmap",     "options": {"service_detection": True, "timing": 4}},
        {"tool": "httpx",    "options": {"title": True, "tech_detect": True}},
    ],
    "deep_web": [
        {"tool": "nmap",      "options": {"service_detection": True, "default_scripts": True, "timing": 4}},
        {"tool": "httpx",     "options": {"title": True, "tech_detect": True}},
        {"tool": "gobuster",  "options": {"mode": "dir", "threads": 20}},
        {"tool": "nuclei",    "options": {"severities": ["medium", "high", "critical"]}},
    ],
    "full_audit": [
        {"tool": "subfinder", "options": {"silent": True}},
        {"tool": "nmap",      "options": {"service_detection": True, "default_scripts": True, "os_detection": True, "timing": 4}},
        {"tool": "httpx",     "options": {"title": True, "tech_detect": True}},
        {"tool": "gobuster",  "options": {"mode": "dir", "threads": 25}},
        {"tool": "nuclei",    "options": {"severities": ["low", "medium", "high", "critical"]}},
    ],
}


@router.get("/")
async def list_scans(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).order_by(desc(Scan.created_at)).limit(100))
    scans = result.scalars().all()
    return [
        {
            "id": s.id, "target": s.target, "tool": s.tool,
            "status": s.status, "workflow": s.workflow,
            "created_at": s.created_at, "completed_at": s.completed_at,
        }
        for s in scans
    ]


@router.get("/{scan_id}")
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    findings_result = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    findings = findings_result.scalars().all()
    suggestions = correlate([{
        "type": f.type, "severity": f.severity, "title": f.title,
        "host": f.host, "port": f.port, "service": f.service,
    } for f in findings])
    return {
        "id": scan.id, "target": scan.target, "tool": scan.tool,
        "status": scan.status, "workflow": scan.workflow,
        "command": scan.command, "raw_output": scan.raw_output,
        "created_at": scan.created_at, "completed_at": scan.completed_at,
        "findings": [
            {
                "id": f.id, "type": f.type, "severity": f.severity,
                "title": f.title, "description": f.description,
                "host": f.host, "port": f.port, "service": f.service,
                "protocol": f.protocol, "extra": f.extra,
            }
            for f in findings
        ],
        "suggestions": suggestions,
    }


@router.post("/launch")
async def launch_scan(req: LaunchScanRequest, db: AsyncSession = Depends(get_db)):
    plugin = TOOL_REGISTRY.get(req.tool)
    if not plugin:
        raise HTTPException(400, f"Tool '{req.tool}' not found in registry")

    cmd = plugin.build_command(req.target, req.options)
    scan_id = str(uuid.uuid4())
    scan = Scan(
        id=scan_id, target=req.target, tool=req.tool,
        command=" ".join(cmd), status="running",
    )
    db.add(scan)
    await db.commit()

    # Run in a thread so we don't block the async event loop
    try:
        raw_output, returncode = await asyncio.to_thread(run_command_sync, cmd)
        findings_data = plugin.parse_output(raw_output, req.target)
        scan.raw_output = raw_output
        scan.status = "done" if returncode == 0 else "error"
    except FileNotFoundError:
        scan.status = "error"
        scan.raw_output = f"Error: '{req.tool}' is not installed or not in PATH."
        findings_data = []
    except asyncio.TimeoutError:
        scan.status = "error"
        scan.raw_output = f"Error: Scan timed out."
        findings_data = []
    except Exception as e:
        scan.status = "error"
        scan.raw_output = str(e)
        findings_data = []

    scan.completed_at = datetime.now(timezone.utc)
    for fd in findings_data:
        db.add(Finding(
            scan_id=scan_id,
            type=fd.get("type", "info"),
            severity=fd.get("severity", "info"),
            title=fd.get("title", ""),
            description=fd.get("description"),
            host=fd.get("host"),
            port=fd.get("port"),
            service=fd.get("service"),
            protocol=fd.get("protocol"),
            extra=fd.get("extra"),
        ))
    await db.commit()
    return {"scan_id": scan_id, "status": scan.status, "findings_count": len(findings_data)}


@router.post("/workflow")
async def launch_workflow(req: WorkflowRequest, db: AsyncSession = Depends(get_db)):
    steps = WORKFLOWS.get(req.workflow)
    if not steps:
        raise HTTPException(400, f"Workflow '{req.workflow}' not found")

    scan_ids = []
    for step in steps:
        plugin = TOOL_REGISTRY.get(step["tool"])
        if not plugin:
            continue
        cmd = plugin.build_command(req.target, step["options"])
        scan_id = str(uuid.uuid4())
        scan = Scan(
            id=scan_id, target=req.target, tool=step["tool"],
            workflow=req.workflow, command=" ".join(cmd), status="running",
        )
        db.add(scan)
        await db.commit()

        # Run in a thread so we don't block the async event loop
        try:
            raw_output, returncode = await asyncio.to_thread(run_command_sync, cmd)
            findings_data = plugin.parse_output(raw_output, req.target)
            scan.raw_output = raw_output
            scan.status = "done" if returncode == 0 else "error"
        except FileNotFoundError:
            scan.status = "error"
            scan.raw_output = f"Error: '{step['tool']}' is not installed or not in PATH."
            findings_data = []
        except asyncio.TimeoutError:
            scan.status = "error"
            scan.raw_output = f"Error: Scan timed out."
            findings_data = []
        except Exception as e:
            scan.status = "error"
            scan.raw_output = str(e)
            findings_data = []

        scan.completed_at = datetime.now(timezone.utc)
        for fd in findings_data:
            db.add(Finding(
                scan_id=scan_id,
                type=fd.get("type", "info"),
                severity=fd.get("severity", "info"),
                title=fd.get("title", ""),
                description=fd.get("description"),
                host=fd.get("host"),
                port=fd.get("port"),
                service=fd.get("service"),
                protocol=fd.get("protocol"),
                extra=fd.get("extra"),
            ))
        await db.commit()
        scan_ids.append(scan_id)

    return {"workflow": req.workflow, "scan_ids": scan_ids}


@router.delete("/{scan_id}")
async def delete_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    await db.delete(scan)
    await db.commit()
    return {"deleted": scan_id}
