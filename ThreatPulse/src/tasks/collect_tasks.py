"""
collect_tasks.py — Celery tasks for each threat feed collector.

Each task is a thin wrapper that instantiates the collector,
runs it, and passes raw records to the processor.
"""

import logging

from src.tasks.celery_app import app
from src.db.session import get_session
from src.processor.deduplicator import process_and_store_records

logger = logging.getLogger(__name__)


def _run_collector(CollectorClass) -> dict:
    """Generic helper: collect → process → store. Returns stats dict."""
    collector = CollectorClass()
    try:
        raw_records = collector.collect()
        if not raw_records:
            logger.info(f"{collector.feed_name}: No records returned.")
            return {"new": 0, "updated": 0, "skipped": 0}
        with get_session() as session:
            stats = process_and_store_records(session, raw_records)
        logger.info(f"{collector.feed_name}: {stats}")
        return stats
    except Exception as exc:
        logger.error(f"{collector.feed_name} collection failed: {exc}", exc_info=True)
        raise


@app.task(bind=True, name="src.tasks.collect_tasks.collect_feodo",
          max_retries=3, default_retry_delay=300)
def collect_feodo(self):
    from src.collectors.feodo_tracker import FeodoTrackerCollector
    try:
        return _run_collector(FeodoTrackerCollector)
    except Exception as exc:
        raise self.retry(exc=exc)


@app.task(bind=True, name="src.tasks.collect_tasks.collect_urlhaus",
          max_retries=3, default_retry_delay=120)
def collect_urlhaus(self):
    from src.collectors.urlhaus import URLhausCollector
    try:
        return _run_collector(URLhausCollector)
    except Exception as exc:
        raise self.retry(exc=exc)


@app.task(bind=True, name="src.tasks.collect_tasks.collect_malwarebazaar",
          max_retries=3, default_retry_delay=300)
def collect_malwarebazaar(self):
    from src.collectors.malware_bazaar import MalwareBazaarCollector
    try:
        return _run_collector(MalwareBazaarCollector)
    except Exception as exc:
        raise self.retry(exc=exc)


@app.task(bind=True, name="src.tasks.collect_tasks.collect_abuseipdb",
          max_retries=3, default_retry_delay=300)
def collect_abuseipdb(self):
    from src.collectors.abuseipdb import AbuseIPDBCollector
    try:
        return _run_collector(AbuseIPDBCollector)
    except Exception as exc:
        raise self.retry(exc=exc)


@app.task(bind=True, name="src.tasks.collect_tasks.collect_alienvault",
          max_retries=3, default_retry_delay=300)
def collect_alienvault(self):
    from src.collectors.alienvault_otx import AlienVaultOTXCollector
    try:
        return _run_collector(AlienVaultOTXCollector)
    except Exception as exc:
        raise self.retry(exc=exc)


@app.task(bind=True, name="src.tasks.collect_tasks.collect_phishtank",
          max_retries=3, default_retry_delay=120)
def collect_phishtank(self):
    from src.collectors.phishtank import PhishTankCollector
    try:
        return _run_collector(PhishTankCollector)
    except Exception as exc:
        raise self.retry(exc=exc)


@app.task(bind=True, name="src.tasks.collect_tasks.collect_blocklist_de",
          max_retries=3, default_retry_delay=300)
def collect_blocklist_de(self):
    from src.collectors.blocklist_de import BlocklistDECollector
    try:
        return _run_collector(BlocklistDECollector)
    except Exception as exc:
        raise self.retry(exc=exc)


@app.task(bind=True, name="src.tasks.collect_tasks.collect_cins_army",
          max_retries=3, default_retry_delay=300)
def collect_cins_army(self):
    from src.collectors.cins_army import CINSArmyCollector
    try:
        return _run_collector(CINSArmyCollector)
    except Exception as exc:
        raise self.retry(exc=exc)


@app.task(bind=True, name="src.tasks.collect_tasks.collect_emerging_threats",
          max_retries=3, default_retry_delay=300)
def collect_emerging_threats(self):
    from src.collectors.emerging_threats import EmergingThreatsCollector
    try:
        return _run_collector(EmergingThreatsCollector)
    except Exception as exc:
        raise self.retry(exc=exc)
