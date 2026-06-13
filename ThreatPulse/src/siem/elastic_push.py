"""
elastic_push.py — Push high-confidence IOCs to Elastic SIEM.

Fetches active indicators from the database with Risk >= 40 or Confidence >= 30,
and POSTs them to the Elasticsearch index configured in ELASTICSEARCH_INDEX.
"""

import json
import logging
import requests
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from src.db.models import Indicator, EnrichmentData
from src.config import ELASTICSEARCH_URL, ELASTICSEARCH_INDEX, SCORE_ACTIONS

logger = logging.getLogger(__name__)

def push_to_elastic(session: Session, limit: int = 1000) -> int:
    """
    Push high confidence/risk IOCs to Elastic SIEM.
    
    Args:
        session: Active SQLAlchemy session
        limit: Max number of IOCs to push in this batch
        
    Returns:
        Number of IOCs successfully pushed
    """
    # Fetch active IOCs meeting medium threshold or higher
    min_risk = SCORE_ACTIONS["medium"]["risk_min"]
    min_conf = SCORE_ACTIONS["medium"]["confidence_min"]
    
    iocs_to_push = (
        session.query(Indicator)
        .outerjoin(EnrichmentData)
        .filter(Indicator.is_active == True)
        .filter(
            (Indicator.risk_score >= min_risk) | 
            (Indicator.confidence_score >= min_conf)
        )
        .limit(limit)
        .all()
    )

    if not iocs_to_push:
        logger.info("No high-confidence IOCs found to push to Elastic.")
        return 0

    logger.info(f"Pushing {len(iocs_to_push)} IOCs to Elastic SIEM...")
    
    pushed_count = 0
    bulk_data = []
    
    for indicator in iocs_to_push:
        # Action line for Elasticsearch Bulk API
        action = {
            "index": {
                "_index": ELASTICSEARCH_INDEX,
                "_id": str(indicator.id)  # Use UUID to avoid duplicates in SIEM
            }
        }
        bulk_data.append(json.dumps(action))
        
        # Document
        doc = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "ioc_value": indicator.ioc_value,
            "ioc_type": indicator.ioc_type,
            "confidence_score": indicator.confidence_score,
            "risk_score": indicator.risk_score,
            "tags": indicator.tags,
            "first_seen": indicator.first_seen.isoformat() if indicator.first_seen else None,
            "last_seen": indicator.last_seen.isoformat() if indicator.last_seen else None,
            "source_count": indicator.source_count,
        }
        
        if indicator.enrichment:
            doc.update({
                "country_code": indicator.enrichment.country_code,
                "asn": indicator.enrichment.asn,
                "reputation_score": indicator.enrichment.reputation_score,
            })
            
        bulk_data.append(json.dumps(doc))
        pushed_count += 1
        
    # Send bulk request
    bulk_payload = "\n".join(bulk_data) + "\n"
    headers = {"Content-Type": "application/x-ndjson"}
    
    try:
        url = f"{ELASTICSEARCH_URL}/_bulk"
        response = requests.post(url, headers=headers, data=bulk_payload, timeout=30)
        
        if response.status_code in (200, 201):
            result = response.json()
            if result.get("errors"):
                logger.error("Some errors occurred during bulk insert to Elastic")
            else:
                logger.info(f"Successfully pushed {pushed_count} IOCs to Elastic")
            return pushed_count
        else:
            logger.error(f"Elastic SIEM push failed: {response.status_code} - {response.text}")
            return 0
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Connection error to Elastic SIEM: {e}")
        return 0
