"""
report_generator.py — Generates daily HTML and JSON summary reports.

Produces:
  - A JSON summary of top IOCs, feed statistics, threat categories
  - A self-contained HTML report (suitable for email or browser viewing)

Output location: data/reports/
"""

import json
import logging
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path

from sqlalchemy import func, desc
from sqlalchemy.orm import Session

from src.db.models import Indicator, IOCSource, EnrichmentData
from src.config import BASE_DIR

logger = logging.getLogger(__name__)

REPORTS_DIR = BASE_DIR / "data" / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


# ─── Data extraction ─────────────────────────────────────────────────────────

def _collect_report_data(session: Session, lookback_hours: int = 24) -> dict:
    """Query the database for all report metrics."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)

    # Total active IOCs by type
    type_counts = dict(
        session.query(Indicator.ioc_type, func.count(Indicator.id))
        .filter(Indicator.is_active == True)
        .group_by(Indicator.ioc_type)
        .all()
    )

    # New IOCs in the lookback window
    new_iocs = (
        session.query(func.count(Indicator.id))
        .filter(Indicator.first_seen >= cutoff)
        .scalar()
    ) or 0

    # Feed breakdown — how many IOCs each source reported
    feed_stats = dict(
        session.query(IOCSource.source_name, func.count(IOCSource.id))
        .group_by(IOCSource.source_name)
        .order_by(desc(func.count(IOCSource.id)))
        .all()
    )

    # Top 10 critical IOCs (highest risk score)
    critical_iocs = (
        session.query(Indicator)
        .filter(Indicator.is_active == True, Indicator.risk_score >= 60)
        .order_by(desc(Indicator.risk_score), desc(Indicator.confidence_score))
        .limit(10)
        .all()
    )

    # Enrichment coverage
    total_active = session.query(func.count(Indicator.id)).filter(Indicator.is_active == True).scalar() or 0
    enriched_count = (
        session.query(func.count(EnrichmentData.id))
        .join(Indicator)
        .filter(Indicator.is_active == True)
        .scalar()
    ) or 0

    # Top threat tags
    from sqlalchemy import text
    tag_rows = session.execute(
        text("""
            SELECT tag, COUNT(*) as cnt
            FROM indicators, unnest(tags) AS tag
            WHERE is_active = true
            GROUP BY tag
            ORDER BY cnt DESC
            LIMIT 10
        """)
    ).fetchall()
    top_tags = [(row[0], row[1]) for row in tag_rows]

    # Score distribution
    score_dist = {
        "critical": session.query(func.count(Indicator.id)).filter(
            Indicator.is_active == True, Indicator.risk_score >= 80
        ).scalar() or 0,
        "high": session.query(func.count(Indicator.id)).filter(
            Indicator.is_active == True,
            Indicator.risk_score >= 60,
            Indicator.risk_score < 80,
        ).scalar() or 0,
        "medium": session.query(func.count(Indicator.id)).filter(
            Indicator.is_active == True,
            Indicator.risk_score >= 40,
            Indicator.risk_score < 60,
        ).scalar() or 0,
        "low": session.query(func.count(Indicator.id)).filter(
            Indicator.is_active == True, Indicator.risk_score < 40
        ).scalar() or 0,
    }

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "lookback_hours": lookback_hours,
        "totals": {
            "active_iocs": total_active,
            "new_in_window": new_iocs,
            "enriched": enriched_count,
            "enrichment_coverage_pct": round((enriched_count / total_active * 100), 1)
            if total_active > 0
            else 0,
        },
        "by_type": type_counts,
        "by_feed": feed_stats,
        "score_distribution": score_dist,
        "top_tags": dict(top_tags),
        "critical_iocs": [
            {
                "value": ioc.ioc_value[:80],
                "type": ioc.ioc_type,
                "risk_score": round(ioc.risk_score, 1),
                "confidence_score": round(ioc.confidence_score, 1),
                "source_count": ioc.source_count,
                "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
                "tags": ioc.tags or [],
            }
            for ioc in critical_iocs
        ],
    }


# ─── JSON report ─────────────────────────────────────────────────────────────

def generate_json_report(session: Session, lookback_hours: int = 24) -> Path:
    """Generate and save a JSON summary report. Returns the file path."""
    data = _collect_report_data(session, lookback_hours)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    output_path = REPORTS_DIR / f"report_{timestamp}.json"

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)

    logger.info(f"JSON report saved: {output_path}")
    return output_path


# ─── HTML report ─────────────────────────────────────────────────────────────

def generate_html_report(session: Session, lookback_hours: int = 24) -> Path:
    """Generate and save a self-contained HTML report. Returns the file path."""
    data = _collect_report_data(session, lookback_hours)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    output_path = REPORTS_DIR / f"report_{timestamp}.html"

    totals = data["totals"]
    score_dist = data["score_distribution"]
    critical_iocs = data["critical_iocs"]
    by_feed = data["by_feed"]
    by_type = data["by_type"]
    top_tags = data["top_tags"]

    # Build IOC table rows
    ioc_rows = ""
    for ioc in critical_iocs:
        risk = ioc["risk_score"]
        if risk >= 80:
            badge = '<span style="background:#ef4444;color:#fff;padding:2px 8px;border-radius:4px;font-size:12px">CRITICAL</span>'
        elif risk >= 60:
            badge = '<span style="background:#f97316;color:#fff;padding:2px 8px;border-radius:4px;font-size:12px">HIGH</span>'
        else:
            badge = '<span style="background:#eab308;color:#fff;padding:2px 8px;border-radius:4px;font-size:12px">MEDIUM</span>'

        tags_str = ", ".join(ioc.get("tags", [])) or "—"
        ioc_rows += f"""
        <tr>
            <td style="font-family:monospace;font-size:13px;word-break:break-all">{ioc['value']}</td>
            <td>{ioc['type']}</td>
            <td>{badge}</td>
            <td>{ioc['risk_score']}</td>
            <td>{ioc['confidence_score']}</td>
            <td>{ioc['source_count']}</td>
            <td style="font-size:12px">{tags_str}</td>
        </tr>"""

    # Build feed rows
    feed_rows = "".join(
        f"<tr><td>{name}</td><td style='text-align:right'>{count:,}</td></tr>"
        for name, count in by_feed.items()
    )

    # Build type rows
    type_rows = "".join(
        f"<tr><td>{t}</td><td style='text-align:right'>{c:,}</td></tr>"
        for t, c in by_type.items()
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Threat Intelligence Report — {data['generated_at'][:10]}</title>
<style>
  body {{ font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; background:#0f172a; color:#e2e8f0; margin:0; padding:24px }}
  h1 {{ color:#38bdf8; margin:0 0 4px }}
  .subtitle {{ color:#64748b; font-size:14px; margin-bottom:32px }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:16px; margin-bottom:32px }}
  .card {{ background:#1e293b; border:1px solid #334155; border-radius:8px; padding:16px }}
  .card .val {{ font-size:32px; font-weight:700; color:#38bdf8 }}
  .card .label {{ font-size:12px; color:#64748b; margin-top:4px; text-transform:uppercase; letter-spacing:.05em }}
  .critical .val {{ color:#ef4444 }}
  .high .val {{ color:#f97316 }}
  .medium .val {{ color:#eab308 }}
  .low .val {{ color:#22c55e }}
  table {{ width:100%; border-collapse:collapse; background:#1e293b; border-radius:8px; overflow:hidden; margin-bottom:32px }}
  th {{ background:#0f172a; padding:10px 12px; text-align:left; font-size:12px; color:#64748b; text-transform:uppercase; letter-spacing:.05em }}
  td {{ padding:10px 12px; border-top:1px solid #334155; font-size:14px }}
  tr:hover td {{ background:#1e3a5f }}
  h2 {{ color:#94a3b8; font-size:16px; text-transform:uppercase; letter-spacing:.05em; margin:24px 0 8px }}
  .tags {{ display:flex; flex-wrap:wrap; gap:6px; margin-bottom:24px }}
  .tag {{ background:#1e293b; border:1px solid #475569; border-radius:4px; padding:2px 8px; font-size:12px }}
</style>
</head>
<body>
<h1>🛡️ Threat Intelligence Pipeline</h1>
<div class="subtitle">Daily Report &bull; Generated: {data['generated_at']} &bull; Lookback: {lookback_hours}h</div>

<h2>Summary</h2>
<div class="grid">
  <div class="card"><div class="val">{totals['active_iocs']:,}</div><div class="label">Active IOCs</div></div>
  <div class="card"><div class="val">{totals['new_in_window']:,}</div><div class="label">New (last {lookback_hours}h)</div></div>
  <div class="card"><div class="val">{totals['enrichment_coverage_pct']}%</div><div class="label">Enriched</div></div>
  <div class="card critical"><div class="val">{score_dist['critical']:,}</div><div class="label">Critical Risk</div></div>
  <div class="card high"><div class="val">{score_dist['high']:,}</div><div class="label">High Risk</div></div>
  <div class="card medium"><div class="val">{score_dist['medium']:,}</div><div class="label">Medium Risk</div></div>
  <div class="card low"><div class="val">{score_dist['low']:,}</div><div class="label">Low Risk</div></div>
</div>

<h2>Top Critical IOCs</h2>
<table>
<thead><tr>
  <th>IOC Value</th><th>Type</th><th>Severity</th>
  <th>Risk</th><th>Confidence</th><th>Sources</th><th>Tags</th>
</tr></thead>
<tbody>{ioc_rows or '<tr><td colspan="7" style="text-align:center;color:#64748b">No critical IOCs in this window</td></tr>'}</tbody>
</table>

<div style="display:grid;grid-template-columns:1fr 1fr;gap:24px">
  <div>
    <h2>IOCs by Feed</h2>
    <table><thead><tr><th>Feed</th><th>IOC Count</th></tr></thead>
    <tbody>{feed_rows}</tbody></table>
  </div>
  <div>
    <h2>IOCs by Type</h2>
    <table><thead><tr><th>Type</th><th>Count</th></tr></thead>
    <tbody>{type_rows}</tbody></table>
  </div>
</div>

<h2>Top Threat Tags</h2>
<div class="tags">
  {''.join(f'<span class="tag">{tag} ({count})</span>' for tag, count in top_tags.items()) or '<span style="color:#64748b">No tags yet</span>'}
</div>

<div style="color:#334155;font-size:12px;margin-top:32px">
  Generated by Threat Intelligence Pipeline &bull; {data['generated_at']}
</div>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    logger.info(f"HTML report saved: {output_path}")
    return output_path


def generate_all_reports(session: Session, lookback_hours: int = 24) -> dict:
    """Generate both JSON and HTML reports. Returns paths dict."""
    json_path = generate_json_report(session, lookback_hours)
    html_path = generate_html_report(session, lookback_hours)
    return {"json": str(json_path), "html": str(html_path)}
