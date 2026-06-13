"""
manual_run.py — Manual orchestrator to run the entire pipeline sequence.

Useful for testing MVP functionality without Celery/cron.
Sequence:
1. Init DB
2. Collect from Feeds
3. Process & Dedup -> DB
4. Enrich active IPs
5. Score indicators
6. Push to SIEM
"""

import logging
import sys

from src.db.session import init_db, get_session
from src.collectors.feodo_tracker import FeodoTrackerCollector
from src.collectors.urlhaus import URLhausCollector
from src.collectors.malware_bazaar import MalwareBazaarCollector
from src.collectors.abuseipdb import AbuseIPDBCollector
from src.collectors.alienvault_otx import AlienVaultOTXCollector
from src.collectors.phishtank import PhishTankCollector
from src.collectors.emerging_threats import EmergingThreatsCollector
from src.collectors.cins_army import CINSArmyCollector
from src.collectors.blocklist_de import BlocklistDECollector

from src.processor.deduplicator import process_and_store_records
from src.enrichment.enrichment_worker import process_enrichment_queue
from src.scoring.confidence import calculate_confidence
from src.scoring.risk import calculate_risk
from src.siem.elastic_push import push_to_elastic

from src.db.models import Indicator

# Configure simple stdout logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout
)
logger = logging.getLogger("manual_run")


def main():
    logger.info("=== Starting Threat Intelligence Pipeline Manual Run ===")
    
    logger.info("1. Initializing Database")
    init_db()
    
    collectors = [
        FeodoTrackerCollector(),
        URLhausCollector(),
        # MalwareBazaarCollector(), # Fast changing, heavy, enable if needed
        AbuseIPDBCollector(),
        # AlienVaultOTXCollector(), # Requires API key
        PhishTankCollector(),
        EmergingThreatsCollector(),
        CINSArmyCollector(),
        BlocklistDECollector()
    ]
    
    logger.info("2. Collecting & 3. Processing")
    for collector in collectors:
        try:
            logger.info(f"--- Running {collector.feed_name} ---")
            raw_records = collector.collect()
            
            if raw_records:
                with get_session() as session:
                    stats = process_and_store_records(session, raw_records)
                    logger.info(f"Stats for {collector.feed_name}: {stats}")
        except Exception as e:
            logger.error(f"Failed to run collector {collector.feed_name}: {e}")

    logger.info("4. Enriching (AbuseIPDB)")
    with get_session() as session:
        enriched = process_enrichment_queue(session, limit=100) # Free tier API limit awareness
        logger.info(f"Enriched {enriched} IPs")

    logger.info("5. Scoring")
    with get_session() as session:
        indicators = session.query(Indicator).filter_by(is_active=True).all()
        for ind in indicators:
            conf = calculate_confidence(ind, ind.sources, ind.enrichment)
            risk = calculate_risk(ind, ind.enrichment)
            ind.confidence_score = conf
            ind.risk_score = risk
        logger.info(f"Scored {len(indicators)} active indicators")
        # Session auto-commits on exit

    logger.info("6. Pushing to SIEM")
    with get_session() as session:
        pushed = push_to_elastic(session, limit=1000)
        logger.info(f"Pushed {pushed} high-confidence IOCs to Elastic")

    logger.info("=== Pipeline Run Complete ===")


if __name__ == "__main__":
    main()
