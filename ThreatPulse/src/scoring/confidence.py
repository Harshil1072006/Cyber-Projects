"""
confidence.py — Confidence Score Calculation (0-100)

Calculates how much to trust an IOC based on:
  - Number of sources reporting it
  - Highest trust tier of reporting sources
  - VirusTotal detections (if enriched)
  - Age penalty
  - Feed quality bonus
"""

from datetime import datetime, timezone

from src.db.models import Indicator, EnrichmentData, IOCSource
from src.config import TRUST_TIER_POINTS, FEED_TRUST_TIERS, LOW_FP_FEEDS

def calculate_confidence(indicator: Indicator, sources: list[IOCSource], enrichment: EnrichmentData | None = None) -> float:
    """Calculate confidence score (0-100) based on Section 9.2 of the blueprint."""
    score = 0.0

    # 1. Source Count (+5 per source, max 25)
    source_count = len(sources)
    score += min(source_count * 5, 25)

    # 2. Source Tier Weight (0-30 pts)
    # Find the best tier among sources (Tier 1 is best)
    best_tier = 3
    has_low_fp_feed = False
    
    for s in sources:
        tier = FEED_TRUST_TIERS.get(s.source_name, 3)
        if tier < best_tier:
            best_tier = tier
        if s.source_name in LOW_FP_FEEDS:
            has_low_fp_feed = True
            
    score += TRUST_TIER_POINTS.get(best_tier, 10)

    # 3. VirusTotal Detections (0-25 pts)
    if enrichment and enrichment.vt_detections is not None:
        vt = enrichment.vt_detections
        if vt >= 50:
            score += 25
        elif vt >= 20:
            score += 20
        elif vt >= 10:
            score += 10

    # 4. Age Penalty (Subtract 0-20 pts)
    now = datetime.now(timezone.utc)
    # last_seen should be timezone aware, but safety check
    last_seen = indicator.last_seen
    if last_seen:
        age_days = (now - last_seen).days
        if age_days >= 90:
            score -= 20
        elif age_days >= 31:
            score -= 15
        elif age_days >= 8:
            score -= 5
            
    # 5. Feed Quality Bonus (+5 pts)
    if has_low_fp_feed:
        score += 5

    # Ensure bounds
    return max(0.0, min(100.0, score))
