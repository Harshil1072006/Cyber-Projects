"""
enrich_tasks.py — Celery task for running the enrichment pipeline.

Scheduled every 30 minutes via Beat to process unenriched IOCs.
"""

import logging

from src.tasks.celery_app import app
from src.db.session import get_session
from src.enrichment.enrichment_worker import process_enrichment_queue

logger = logging.getLogger(__name__)


@app.task(bind=True, name="src.tasks.enrich_tasks.run_enrichment",
          max_retries=2, default_retry_delay=120)
def run_enrichment(self):
    """Process the enrichment queue — up to 50 IOCs per run (API rate-limit safe)."""
    try:
        with get_session() as session:
            enriched = process_enrichment_queue(session, limit=50)
        logger.info(f"Enrichment run complete — {enriched} IOCs enriched.")
        return {"enriched": enriched}
    except Exception as exc:
        logger.error(f"Enrichment task failed: {exc}", exc_info=True)
        raise self.retry(exc=exc)
