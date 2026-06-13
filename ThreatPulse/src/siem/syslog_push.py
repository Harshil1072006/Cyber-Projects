"""
syslog_push.py — Push IOCs to Wazuh/Splunk via Syslog in CEF format.

Useful for SIEMs that rely on syslog ingest, like Wazuh or Splunk (via syslog-ng).
Formats IOCs into Common Event Format (CEF) and sends them via UDP.
"""

import logging
import socket
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from src.db.models import Indicator, EnrichmentData
from src.config import SCORE_ACTIONS

logger = logging.getLogger(__name__)

# Default Syslog Server config (could be moved to config.py)
SYSLOG_HOST = "localhost"
SYSLOG_PORT = 514

def format_cef(indicator: Indicator) -> str:
    """Format an indicator as a CEF (Common Event Format) string."""
    # CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|Extension
    version = "CEF:0"
    vendor = "ThreatIntelPipeline"
    product = "IOC_DB"
    dev_version = "1.0"
    event_id = f"IOC_{indicator.ioc_type.upper()}"
    name = f"Malicious {indicator.ioc_type.upper()} Detected"
    
    # Map risk (0-100) to CEF Severity (0-10)
    severity = int(indicator.risk_score / 10)
    
    # CEF Extensions
    extensions = {
        "msg": indicator.ioc_value,
        "cs1": indicator.confidence_score,
        "cs1Label": "ConfidenceScore",
        "cs2": indicator.risk_score,
        "cs2Label": "RiskScore",
        "cs3": ",".join(indicator.tags) if indicator.tags else "none",
        "cs3Label": "Tags",
    }
    
    if indicator.enrichment:
        if indicator.enrichment.country_code:
            extensions["cc"] = indicator.enrichment.country_code
        if indicator.enrichment.reputation_score:
            extensions["cs4"] = indicator.enrichment.reputation_score
            extensions["cs4Label"] = "ReputationScore"
            
    ext_str = " ".join([f"{k}={v}" for k, v in extensions.items()])
    
    return f"{version}|{vendor}|{product}|{dev_version}|{event_id}|{name}|{severity}|{ext_str}"

def push_to_syslog(session: Session, limit: int = 1000) -> int:
    """
    Push high confidence/risk IOCs to a Syslog receiver (Wazuh/Splunk).
    """
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
        logger.info("No IOCs to push to Syslog.")
        return 0
        
    logger.info(f"Pushing {len(iocs_to_push)} IOCs via Syslog to {SYSLOG_HOST}:{SYSLOG_PORT}")
    pushed_count = 0
    
    try:
        # Create UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        for indicator in iocs_to_push:
            cef_msg = format_cef(indicator)
            
            # Syslog priority <14> = User facility (1), Info severity (6) -> 1*8 + 6 = 14
            timestamp = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
            syslog_msg = f"<14>{timestamp} {SYSLOG_HOST} {cef_msg}\n"
            
            sock.sendto(syslog_msg.encode('utf-8'), (SYSLOG_HOST, SYSLOG_PORT))
            pushed_count += 1
            
        sock.close()
        logger.info(f"Successfully pushed {pushed_count} IOCs via Syslog.")
        
    except Exception as e:
        logger.error(f"Failed to push to Syslog: {e}")
        return 0
        
    return pushed_count
