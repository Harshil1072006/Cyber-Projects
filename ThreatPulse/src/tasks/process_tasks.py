"""
process_tasks.py — Celery tasks for scoring and SIEM push.

Runs as scheduled tasks via Celery Beat.
"""

import logging

from src.tasks.celery_app import app
from src.db.session import get_session
from src.db.models import Indicator
from src.scoring.confidence import calculate_confidence
from src.scoring.risk import calculate_risk
from src.siem.elastic_push import push_to_elastic

logger = logging.getLogger(__name__)


@app.task(bind=True, name="src.tasks.process_tasks.run_scoring",
          max_retries=2, default_retry_delay=120)
def run_scoring(self):
    """Re-calculate confidence and risk scores for all active IOCs."""
    try:
        with get_session() as session:
            indicators = session.query(Indicator).filter_by(is_active=True).all()
            scored = 0
            for ind in indicators:
                try:
                    conf = calculate_confidence(ind, ind.sources, ind.enrichment)
                    risk = calculate_risk(ind, ind.enrichment)
                    ind.confidence_score = conf
                    ind.risk_score = risk
                    scored += 1
                except Exception as exc:
                    logger.warning(f"Scoring failed for {ind.ioc_value[:40]}: {exc}")
            # Session auto-commits on context exit
        logger.info(f"Scored {scored}/{len(indicators)} active indicators.")
        return {"scored": scored, "total": len(indicators)}
    except Exception as exc:
        logger.error(f"Scoring task failed: {exc}", exc_info=True)
        raise self.retry(exc=exc)


@app.task(bind=True, name="src.tasks.process_tasks.push_to_siem",
          max_retries=2, default_retry_delay=120)
def push_to_siem(self):
    """Push high-confidence IOCs to Elastic SIEM."""
    try:
        with get_session() as session:
            pushed = push_to_elastic(session, limit=1000)
        logger.info(f"Pushed {pushed} IOCs to Elastic SIEM.")
        return {"pushed": pushed}
    except Exception as exc:
        logger.error(f"SIEM push task failed: {exc}", exc_info=True)
        raise self.retry(exc=exc)
