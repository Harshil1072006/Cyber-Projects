import os
import re
from pathlib import Path
from typing import List, Dict, Any
from .base_scanner import BaseScanner

class SastScanner(BaseScanner):
    def __init__(self):
        self.secret_patterns = {
            "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
            "AWS Secret Access Key": r"wJalrXUtnFEMI/K7MDENG/bPxRfiCY[0-9a-zA-Z]{10}",
            "Generic API Key": r"(?:key|api|token|secret|password|passwd)[\s:='\"]+[0-9a-zA-Z]{16,}",
            "Private Key": r"-----BEGIN (?:RSA|OPENSSH|PRIVATE) KEY-----"
        }
        
        self.code_patterns = {
            "SQL Injection (Generic)": r"(?:SELECT|INSERT|UPDATE|DELETE).*(?:\+|f['\"]|\.format|\$)",
            "Command Injection (Python)": r"os\.system\(.*|subprocess\..*\(.*|eval\(.*|exec\(.*",
            "Hardcoded Password": r"(?:password|passwd|pwd)\s*=\s*['\"][^'\"]+['\"]",
            "Shell Injection (NodeJS)": r"child_process\.(?:exec|spawn)\(.*",
            "Insecure Archive (ZipSlip)": r"extractall\(.*",
            "Vulnerable React Component": r"dangerouslySetInnerHTML"
        }

    async def scan_file(self, file_path: Path) -> List[Dict[str, Any]]:
        findings = []
        try:
            # Use absolute path for reporting
            abs_path = str(file_path.absolute())
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            lines = content.splitlines()
            
            for name, pattern in self.secret_patterns.items():
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    line_no = content.count('\n', 0, match.start()) + 1
                    findings.append({
                        "vulnerability_name": f"Leaked {name}",
                        "severity": "Critical",
                        "description": f"A potential {name} was found in the source code.",
                        "file_path": abs_path,
                        "line_number": line_no,
                        "raw_data": {"match": match.group()}
                    })
            
            for i, line in enumerate(lines):
                for vuln_name, pattern in self.code_patterns.items():
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append({
                            "vulnerability_name": vuln_name,
                            "severity": "High",
                            "description": f"Possible {vuln_name} detected.",
                            "file_path": abs_path,
                            "line_number": i + 1,
                            "raw_data": {"line_content": line.strip()}
                        })
        except Exception as e:
            print(f"Error scanning file {file_path}: {e}")
        return findings

    async def scan(self, target_path: str, scan_id: int) -> List[Dict[str, Any]]:
        all_findings = []
        # Ensure target_path is absolute and resolved
        p = Path(target_path).resolve()
        
        if p.is_file():
            all_findings.extend(await self.scan_file(p))
        elif p.is_dir():
            # Use rglob for more robust recursive discovery
            for file_path in p.rglob("*"):
                if file_path.is_file():
                    # Filter relevant source files
                    if file_path.suffix.lower() in ('.py', '.js', '.java', '.php', '.c', '.cpp', '.go', '.html', '.css', '.json', '.txt', '.env'):
                        all_findings.extend(await self.scan_file(file_path))
        return all_findings
