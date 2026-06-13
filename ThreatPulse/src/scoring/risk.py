"""
risk.py — Risk Score Calculation (0-100)

Calculates how dangerous an IOC is based on:
  - IOC Category (ransomware vs scanner)
  - AbuseIPDB Score
  - Shodan Open Ports
  - WHOIS Age
  - Threat Actor Attribution
"""

from datetime import datetime, timezone

from src.db.models import Indicator, EnrichmentData
from src.config import IOC_CATEGORY_RISK

def calculate_risk(indicator: Indicator, enrichment: EnrichmentData | None = None) -> float:
    """Calculate risk score (0-100) based on Section 9.3 of the blueprint."""
    score = 0.0

    # 1. IOC Category (0-40 pts)
    tags = [t.lower() for t in indicator.tags] if indicator.tags else []
    
    # Find the highest scoring category among tags
    best_category_score = 0
    for tag in tags:
        cat_score = IOC_CATEGORY_RISK.get(tag, 0)
        if cat_score > best_category_score:
            best_category_score = cat_score
            
    # Default minimum risk for known IOCs without specific categories
    if best_category_score == 0 and len(tags) > 0:
        best_category_score = 5
        
    score += best_category_score

    # Enrichment-based scoring
    if enrichment:
        # 2. AbuseIPDB Score (0-20 pts)
        if enrichment.reputation_score is not None:
            # Scale 0-100 to 0-20
            score += (enrichment.reputation_score / 100.0) * 20.0

        # 3. Shodan Open Ports (0-15 pts)
        if enrichment.open_ports:
            ports = enrichment.open_ports
            # Known exploit ports
            dangerous_ports = {4444, 8080, 9001, 23, 3389, 22}
            if any(p in dangerous_ports for p in ports):
                score += 15

        # 4. WHOIS Age (0-15 pts)
        if enrichment.whois_created:
            now = datetime.now(timezone.utc)
            age_days = (now - enrichment.whois_created).days
            if age_days < 7:
                score += 15
            elif age_days < 30:
                score += 10

    # 5. Threat Actor Attribution (0-10 pts)
    # Check if any tag matches a known APT or ransomware family pattern
    apt_keywords = {"apt", "lazarus", "fancybear", "cozybear", "lockbit", "conti", "ryuk", "emotet", "trickbot"}
    if any(any(apt in tag for apt in apt_keywords) for tag in tags):
        score += 10

    # Ensure bounds
    return max(0.0, min(100.0, score))
