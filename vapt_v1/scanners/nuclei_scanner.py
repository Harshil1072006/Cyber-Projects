import asyncio
import json
import os
from pathlib import Path
from .base_scanner import BaseScanner
from typing import List, Dict, Any

class NucleiScanner(BaseScanner):
    def __init__(self):
        self.nuclei_path = Path("tools") / "nuclei" / "nuclei.exe"
        if not self.nuclei_path.exists():
            print(f"Warning: Nuclei not found at {self.nuclei_path}")

    async def scan(self, target_path: str, scan_id: int) -> List[Dict[str, Any]]:
        if not self.nuclei_path.exists():
            return []

        output_file = Path("workdir") / str(scan_id) / "nuclei_out.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)

        # Determine target: if it starts with http, scan as URL (online mode)
        # Otherwise, skip Nuclei for local files (Nuclei is a network scanner)
        if target_path.startswith("http"):
            target = target_path
        else:
            # Nuclei is primarily a network/URL scanner.
            # For local file scans, it provides minimal value. Skip gracefully.
            return []

        cmd = [
            str(self.nuclei_path.absolute()),
            "-u", target,
            "-j",  # JSON output
            "-o", str(output_file.absolute()),
            "-silent"  # Clean output
        ]

        print(f"Running Nuclei: {' '.join(cmd)}")
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
        except Exception as e:
            print(f"Nuclei execution error: {e}")
            return []
        
        findings = []
        if output_file.exists():
            with open(output_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        data = json.loads(line)
                        findings.append({
                            "vulnerability_name": data.get("info", {}).get("name", "Unknown Vulnerability"),
                            "severity": data.get("info", {}).get("severity", "Info").capitalize(),
                            "description": data.get("info", {}).get("description", ""),
                            "file_path": data.get("matched-at", ""),
                            "line_number": None,
                            "raw_data": data
                        })
                    except json.JSONDecodeError:
                        pass
        return findings
