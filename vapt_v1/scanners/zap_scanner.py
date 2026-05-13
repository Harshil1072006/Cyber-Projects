import asyncio
import json
import os
from pathlib import Path
from .base_scanner import BaseScanner
from typing import List, Dict, Any

class ZAPScanner(BaseScanner):
    def __init__(self):
        # zap directory from crossplatform zip
        self.zap_dir = Path("tools") / "zap"
        
        # the zap structure is ZAP_2.17.0/zap.bat since it extracts as a subfolder
        # Let's dynamically find zap.bat
        self.zap_bat = None
        if self.zap_dir.exists():
            for root, dirs, files in os.walk(str(self.zap_dir)):
                if "zap.bat" in files:
                    self.zap_bat = Path(root) / "zap.bat"
                    break
        
        if not self.zap_bat:
            print(f"Warning: ZAP zap.bat not found in {self.zap_dir}")

    async def scan(self, target_path: str, scan_id: int) -> List[Dict[str, Any]]:
        # ZAP is specifically for DAST - it needs a URL
        if not target_path.startswith("http"):
            return [] # Skip ZAP for file uploads
            
        if not self.zap_bat:
            return []

        # For security and stability, we use DAST in cmd mode
        output_file = Path("workdir") / str(scan_id) / "zap_out.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        cmd = [
            str(self.zap_bat.absolute()),
            "-cmd",
            "-quickurl", target_path,
            "-quickout", str(output_file.absolute()),
            "-quickprogress"
        ]

        print(f"Running ZAP: {' '.join(cmd)}")
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
        except FileNotFoundError:
            print(f"ZAP executable not found or failed to launch: {self.zap_bat}")
            return []
        except Exception as e:
            print(f"ZAP execution error: {e}")
            return []
        
        findings = []
        if output_file.exists():
            try:
                with open(output_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                # The format usually has site -> [alerts]
                site_alerts = data.get("site", [])
                for site in site_alerts:
                    for alert in site.get("alerts", []):
                        findings.append({
                            "vulnerability_name": alert.get("name", "Unknown Alert"),
                            "severity": alert.get("riskdesc", "Info").split(" ")[0],
                            "description": alert.get("desc", ""),
                            "file_path": alert.get("instances", [{}])[0].get("uri", target_path),
                            "line_number": None,
                            "raw_data": alert
                        })
            except Exception as e:
                print(f"Failed to parse ZAP output: {e}")
                
        return findings
