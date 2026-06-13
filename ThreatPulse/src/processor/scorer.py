"""
scorer.py — Confidence and risk scoring engine.

Implements Section 9 of the blueprint.
Calculates trust (confidence_score) and threat severity (risk_score)
based on feed reputation, source count, and enrichment context.
"""

import logging
from sqlalchemy.orm import Session

from src.db.models import Indicator, IOCSource, EnrichmentData
from src.config import (
    FEED_TRUST_TIERS,
    TRUST_TIER_POINTS,
    LOW_FP_FEEDS,
    IOC_CATEGORY_RISK,
)

logger = logging.getLogger(__name__)


def score_indicator(session: Session, indicator: Indicator) -> None:
    """
    Calculate and update the confidence_score and risk_score for an indicator.
    Must be called within an active session. The caller must commit.
    """
    try:
        sources = session.query(IOCSource).filter_by(ioc_id=indicator.id).all()
        enrichment = session.query(EnrichmentData).filter_by(ioc_id=indicator.id).first()

        # 1. Calculate Confidence Score (Max 100)
        conf_score = 0.0
        
        for source in sources:
            source_name = source.source_name
            tier = FEED_TRUST_TIERS.get(source_name, 3)
            
            # Base points from trust tier
            conf_score += TRUST_TIER_POINTS.get(tier, 10)
            
            # Bonus for low false-positive feeds
            if source_name in LOW_FP_FEEDS:
                conf_score += 15.0
                
        # Bonus from enrichment (reputation)
        if enrichment:
            if enrichment.reputation_score and enrichment.reputation_score > 0:
                # e.g., AbuseIPDB score is 0-100, add a fraction
                conf_score += min(30.0, enrichment.reputation_score * 0.3)
                
            if enrichment.vt_detections and enrichment.vt_detections > 0:
                conf_score += min(40.0, enrichment.vt_detections * 5.0)

        indicator.confidence_score = min(100.0, conf_score)

        # 2. Calculate Risk Score (Max 100)
        risk_score = 0.0
        
        # Tags-based risk
        if indicator.tags:
            for tag in indicator.tags:
                tag_lower = tag.lower()
                for risk_category, points in IOC_CATEGORY_RISK.items():
                    if risk_category in tag_lower:
                        risk_score += points
                        break # Only count the highest matched category from this tag? No, add all.

        # Enrichment-based risk
        if enrichment:
            if enrichment.vt_detections and enrichment.vt_detections >= 5:
                risk_score += 40.0
            elif enrichment.vt_detections and enrichment.vt_detections >= 1:
                risk_score += 20.0
                
            if enrichment.reputation_score and enrichment.reputation_score >= 80:
                risk_score += 30.0

        indicator.risk_score = min(100.0, risk_score)

    except Exception as e:
        logger.error(f"Failed to score indicator {indicator.id}: {e}")


def run_scoring_batch(session: Session, limit: int = 100) -> int:
    """
    Score a batch of active indicators.
    Normally called by a scheduled task.
    """
    indicators = session.query(Indicator).filter_by(is_active=True).limit(limit).all()
    
    scored_count = 0
    for indicator in indicators:
        score_indicator(session, indicator)
        scored_count += 1
        
    try:
        session.commit()
    except Exception as e:
        session.rollback()
        logger.error(f"Failed to commit scoring batch: {e}")
        return 0
        
    return scored_count
