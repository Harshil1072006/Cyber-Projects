import asyncio
import json
import os
from pathlib import Path
from .base_scanner import BaseScanner
from typing import List, Dict, Any

class TrivyScanner(BaseScanner):
    def __init__(self):
        self.trivy_path = Path("tools") / "trivy" / "trivy.exe"
        if not self.trivy_path.exists():
            print(f"Warning: Trivy not found at {self.trivy_path}")

    async def scan(self, target_path: str, scan_id: int, scan_mode: str = "offline") -> List[Dict[str, Any]]:
        if not self.trivy_path.exists():
            return []

        # Trivy is a filesystem scanner; skip if target is a URL
        if target_path.startswith("http"):
            return []

        output_file = Path("workdir") / str(scan_id) / "trivy_out.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        target = os.path.abspath(target_path)
        
        cmd = [
            str(self.trivy_path.absolute()),
            "fs",  # File system scan
            "--format", "json",
            "--output", str(output_file.absolute()),
            "--quiet",
            target
        ]

        # In offline mode, skip DB update to avoid network errors
        if scan_mode == "offline":
            cmd.insert(2, "--skip-db-update")

        print(f"Running Trivy: {' '.join(cmd)}")
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
        except Exception as e:
            print(f"Trivy execution error: {e}")
            return []
        
        findings = []
        if output_file.exists():
            try:
                with open(output_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                results = data.get("Results", [])
                for result in results:
                    target_file = result.get("Target", "")
                    for vuln in result.get("Vulnerabilities", []):
                        findings.append({
                            "vulnerability_name": vuln.get("VulnerabilityID", "Unknown"),
                            "severity": vuln.get("Severity", "Info").capitalize(),
                            "description": vuln.get("Title", "") + " - " + vuln.get("Description", ""),
                            "file_path": target_file,
                            "line_number": None,
                            "raw_data": vuln
                        })
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
                
        return findings
