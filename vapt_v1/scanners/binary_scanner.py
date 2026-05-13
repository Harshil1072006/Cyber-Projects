import asyncio
import os
from pathlib import Path
from typing import List, Dict, Any
from .base_scanner import BaseScanner

class BinaryScanner(BaseScanner):
    def __init__(self):
        # Use absolute path for tools
        self.r2_path = Path("tools") / "radare2" / "r2blob.static.exe"
        if not self.r2_path.exists():
            print(f"Warning: Radare2 (r2blob) not found at {self.r2_path.absolute()}")

    async def scan_file(self, file_path: Path, scan_id: int) -> List[Dict[str, Any]]:
        if not self.r2_path.exists():
            return []
        
        # Check if it's an executable by extension at least
        if file_path.suffix.lower() not in ('.exe', '.dll', '.elf', '.apk', '.bin'):
            return []

        # Run r2 -qCi file to get class info and info extraction
        abs_target = str(file_path.absolute())
        cmd = [
            str(self.r2_path.absolute()),
            "-q",
            "-c", "iI; iH; ic; iv", 
            abs_target
        ]

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            output = stdout.decode('utf-8', errors='ignore')
            
            findings = []
            if output:
                findings.append({
                    "vulnerability_name": "Binary Intelligence Extraction",
                    "severity": "Info",
                    "description": "Extracted binary metadata, headers, and class information.",
                    "file_path": abs_target,
                    "line_number": None,
                    "raw_data": {"r2_output": output}
                })
                
                # Check for obvious binary weaknesses in output
                if "nx false" in output.lower():
                    findings.append({
                        "vulnerability_name": "Missing NX (No-Execute) Protection",
                        "severity": "High",
                        "description": "The binary was compiled without NX protection, making stack buffer overflows exploitable.",
                        "file_path": abs_target,
                        "line_number": None,
                        "raw_data": {}
                    })
                if "canary false" in output.lower():
                    findings.append({
                        "vulnerability_name": "Missing Stack Canary",
                        "severity": "High",
                        "description": "The binary lacks stack canaries, increasing vulnerability to stack-based buffer overflows.",
                        "file_path": abs_target,
                        "line_number": None,
                        "raw_data": {}
                    })
                    
            return findings
        except Exception as e:
            print(f"Radare2 scan error for {abs_target}: {e}")
            return []

    async def scan(self, target_path: str, scan_id: int) -> List[Dict[str, Any]]:
        all_findings = []
        p = Path(target_path).resolve()
        
        if p.is_file():
            all_findings.extend(await self.scan_file(p, scan_id))
        elif p.is_dir():
            for file_path in p.rglob("*"):
                if file_path.is_file():
                    all_findings.extend(await self.scan_file(file_path, scan_id))
        return all_findings
