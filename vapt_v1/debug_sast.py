import asyncio
import os
from scanners.sast_scanner import SastScanner

async def debug():
    scanner = SastScanner()
    target = os.path.abspath("workdir/7")
    print(f"Scanning directory: {target}")
    findings = await scanner.scan(target, 7)
    print(f"Total findings: {len(findings)}")
    for f in findings:
        print(f" - [{f['severity']}] {f['vulnerability_name']} at {f['file_path']}:{f['line_number']}")

if __name__ == "__main__":
    asyncio.run(debug())
