"""
report_tasks.py — Celery task for generating daily reports.

Scheduled at 06:00 UTC via Beat.
"""

import logging

from src.tasks.celery_app import app
from src.db.session import get_session
from src.reporting.report_generator import generate_all_reports

logger = logging.getLogger(__name__)


@app.task(bind=True, name="src.tasks.report_tasks.generate_daily_report",
          max_retries=2, default_retry_delay=300)
def generate_daily_report(self):
    """Generate JSON and HTML summary reports for the last 24 hours."""
    try:
        with get_session() as session:
            paths = generate_all_reports(session, lookback_hours=24)
        logger.info(f"Daily reports generated: {paths}")
        return paths
    except Exception as exc:
        logger.error(f"Report generation failed: {exc}", exc_info=True)
        raise self.retry(exc=exc)
