"""
Metrics Aggregator.
Calculates high-level metrics for the pipeline execution.
"""

from typing import List, Dict, Any

class MetricsAggregator:
    """Aggregates metrics for Prometheus/Grafana."""
    
    def calculate_metrics(self, findings: List[Dict[str, Any]], execution_times: Dict[str, float]) -> Dict[str, Any]:
        """Calculates security and performance metrics."""
        metrics = {
            "total_findings": len(findings),
            "critical_findings": 0,
            "high_findings": 0,
            "medium_findings": 0,
            "low_findings": 0,
            "tool_durations": execution_times
        }
        
        for finding in findings:
            sev = finding.get("severity", "low").lower()
            if sev == "critical": metrics["critical_findings"] += 1
            elif sev == "high": metrics["high_findings"] += 1
            elif sev == "medium": metrics["medium_findings"] += 1
            else: metrics["low_findings"] += 1
            
        return metrics
