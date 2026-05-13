import asyncio
from pathlib import Path
from typing import List, Dict, Any
from .base_scanner import BaseScanner
from .nuclei_scanner import NucleiScanner
from .trivy_scanner import TrivyScanner
from .zap_scanner import ZAPScanner
from .sast_scanner import SastScanner
from .binary_scanner import BinaryScanner

class ScannerOrchestrator:
    def __init__(self):
        self.scanners = {
            "sast": SastScanner(),
            "binary": BinaryScanner(),
            "nuclei": NucleiScanner(),
            "trivy": TrivyScanner(),
            "zap": ZAPScanner()
        }

    async def run_all(self, target_path: str, scan_id: int, scan_mode: str = "offline") -> List[Dict[str, Any]]:
        """
        Runs scanners based on scan_mode and aggregates results.
        - offline: SAST + Binary + Trivy (local file analysis)
        - online: SAST + Binary + Trivy + Nuclei + ZAP (includes network scanners)
        """
        p = Path(target_path).resolve()
        abs_target = str(p.absolute())
        is_url = target_path.startswith("http")
        
        print(f"Orchestrating scanners on {abs_target} (mode: {scan_mode})")
        
        with open("engine_debug.log", "a") as log:
            log.write(f"Orchestrator resolved target to: {abs_target} (mode: {scan_mode})\n")
            if not is_url and p.is_dir():
                contents = list(p.rglob("*"))
                log.write(f"Directory contains {len(contents)} files/folders.\n")
        
        # Determine which scanners to run based on mode
        if is_url:
            # URL target: only network scanners make sense
            active_scanners = ["nuclei", "zap"]
        elif scan_mode == "online":
            # Online mode with local file: run all local scanners + trivy with DB update
            active_scanners = ["sast", "binary", "trivy"]
        else:
            # Offline mode: local scanners only
            active_scanners = ["sast", "binary", "trivy"]
        
        findings_tasks = []
        scanner_names = []
        for name in active_scanners:
            scanner = self.scanners[name]
            if name == "trivy":
                task = self.run_single_scanner_with_mode(scanner, abs_target, scan_id, scan_mode)
            else:
                task = self.run_single_scanner(scanner, abs_target, scan_id)
            findings_tasks.append(task)
            scanner_names.append(name)
        
        results = await asyncio.gather(*findings_tasks, return_exceptions=True)
        
        all_findings = []
        for i, result in enumerate(results):
            s_name = scanner_names[i]
            if isinstance(result, Exception):
                print(f"Scanner {s_name} failed or timed out: {result}")
            elif isinstance(result, list):
                print(f"Scanner {s_name} returned {len(result)} findings")
                for item in result:
                    item['tool_name'] = self.scanners[s_name].__class__.__name__
                    all_findings.append(item)
                    
        return all_findings

    async def run_single_scanner(self, scanner: BaseScanner, target_path: str, scan_id: int):
        try:
            return await asyncio.wait_for(scanner.scan(target_path, scan_id), timeout=600)
        except asyncio.TimeoutError:
            print(f"CRITICAL: {scanner.__class__.__name__} timed out after 10 minutes.")
            return []
        except Exception as e:
            print(f"Error in {scanner.__class__.__name__}: {e}")
            return []

    async def run_single_scanner_with_mode(self, scanner, target_path: str, scan_id: int, scan_mode: str):
        try:
            return await asyncio.wait_for(scanner.scan(target_path, scan_id, scan_mode=scan_mode), timeout=600)
        except asyncio.TimeoutError:
            print(f"CRITICAL: {scanner.__class__.__name__} timed out after 10 minutes.")
            return []
        except Exception as e:
            print(f"Error in {scanner.__class__.__name__}: {e}")
            return []
