"""
enrichment_worker.py — Worker logic for processing the enrichment queue.

Fetches unenriched IOCs from the database and runs them through all
configured OSINT APIs, saving the results to the enrichment_data table.

Enrichers used per IOC type:
  IP      → AbuseIPDB + VirusTotal + IPinfo + Shodan (InternetDB) + Reverse DNS
  Domain  → VirusTotal + WHOIS + DNS forward
  URL     → VirusTotal
  Hash    → VirusTotal
"""

import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from src.db.models import Indicator, EnrichmentData
from src.enrichment.abuseipdb_enrich import enrich_ip_abuseipdb
from src.enrichment.virustotal_enrich import (
    enrich_ip_virustotal,
    enrich_domain_virustotal,
    enrich_hash_virustotal,
    enrich_url_virustotal,
)
from src.enrichment.ipinfo_enrich import enrich_ip_ipinfo
from src.enrichment.shodan_enrich import enrich_ip_shodan
from src.enrichment.whois_enrich import enrich_domain_whois
from src.enrichment.dns_enrich import enrich_domain_dns, enrich_ip_reverse_dns

logger = logging.getLogger(__name__)


# ─── Merge helpers ───────────────────────────────────────────────────────────

def _merge(base: dict, update: dict | None) -> dict:
    """Merge update into base, only overwriting None values in base."""
    if not update:
        return base
    for key, value in update.items():
        if value is not None and base.get(key) is None:
            base[key] = value
    return base


def _best_reputation(current: float | None, incoming: float | None) -> float | None:
    """Return the higher of two reputation scores (most informative)."""
    if current is None:
        return incoming
    if incoming is None:
        return current
    return max(current, incoming)


# ─── Per-type enrichment pipelines ───────────────────────────────────────────

def _enrich_ip(ioc_value: str) -> dict:
    """Run all IP enrichers and merge results."""
    result: dict = {
        "country_code": None,
        "asn": None,
        "abuse_reports": None,
        "usage_type": None,
        "reputation_score": None,
        "vt_detections": None,
        "open_ports": None,
        "ptr_hostname": None,
    }

    # 1. AbuseIPDB — abuse reports + country + usage type
    abuse = enrich_ip_abuseipdb(ioc_value)
    if abuse:
        result["country_code"] = abuse.get("country_code")
        result["abuse_reports"] = abuse.get("abuse_reports")
        result["usage_type"] = abuse.get("usage_type")
        result["reputation_score"] = abuse.get("abuse_confidence_score")

    # 2. VirusTotal — malicious engine count
    vt = enrich_ip_virustotal(ioc_value)
    if vt:
        result["vt_detections"] = vt.get("vt_detections")
        # Only use VT country if AbuseIPDB didn't provide one
        if not result["country_code"]:
            result["country_code"] = vt.get("country_code")
        if not result["asn"]:
            result["asn"] = vt.get("asn")
        result["reputation_score"] = _best_reputation(
            result["reputation_score"], vt.get("reputation_score")
        )

    # 3. IPinfo — geolocation + ASN (free, no key needed)
    ipinfo = enrich_ip_ipinfo(ioc_value)
    if ipinfo:
        if not result["country_code"]:
            result["country_code"] = ipinfo.get("country_code")
        if not result["asn"]:
            result["asn"] = ipinfo.get("asn")

    # 4. Shodan InternetDB — open ports + CVEs (free, no key needed)
    shodan = enrich_ip_shodan(ioc_value)
    if shodan:
        result["open_ports"] = shodan.get("open_ports") or None

    # 5. Reverse DNS — hostname from PTR record
    ptr = enrich_ip_reverse_dns(ioc_value)
    if ptr:
        result["ptr_hostname"] = ptr.get("ptr_hostname")

    return result


def _enrich_domain(ioc_value: str) -> dict:
    """Run all domain enrichers and merge results."""
    result: dict = {
        "whois_registrar": None,
        "whois_created": None,
        "reputation_score": None,
        "vt_detections": None,
        "dns_records": None,
    }

    # 1. VirusTotal — detection count
    vt = enrich_domain_virustotal(ioc_value)
    if vt:
        result["vt_detections"] = vt.get("vt_detections")
        result["reputation_score"] = vt.get("reputation_score")

    # 2. WHOIS — registration details
    whois = enrich_domain_whois(ioc_value)
    if whois:
        result["whois_registrar"] = whois.get("whois_registrar")
        result["whois_created"] = whois.get("whois_created")

    # 3. DNS forward lookups — A, MX, NS, TXT records
    dns = enrich_domain_dns(ioc_value)
    if dns:
        result["dns_records"] = dns

    return result


def _enrich_url(ioc_value: str) -> dict:
    """Enrich a URL — VirusTotal only for MVP."""
    result: dict = {"vt_detections": None, "reputation_score": None}

    vt = enrich_url_virustotal(ioc_value)
    if vt:
        result["vt_detections"] = vt.get("vt_detections")
        result["reputation_score"] = vt.get("reputation_score")

    return result


def _enrich_hash(ioc_value: str) -> dict:
    """Enrich a file hash — VirusTotal only."""
    result: dict = {"vt_detections": None, "reputation_score": None}

    vt = enrich_hash_virustotal(ioc_value)
    if vt:
        result["vt_detections"] = vt.get("vt_detections")
        result["reputation_score"] = vt.get("reputation_score")

    return result


# ─── Main queue processor ────────────────────────────────────────────────────

def process_enrichment_queue(session: Session, limit: int = 50) -> int:
    """
    Fetch unenriched IOCs and process them through the full enrichment pipeline.

    Args:
        session: Active SQLAlchemy session.
        limit:   Max number of IOCs to enrich per run (rate-limit friendly).

    Returns:
        Number of IOCs successfully enriched.
    """
    # Fetch all active IOCs (any type) that have no enrichment record yet
    unenriched = (
        session.query(Indicator)
        .outerjoin(EnrichmentData)
        .filter(Indicator.is_active == True)
        .filter(EnrichmentData.id == None)
        .limit(limit)
        .all()
    )

    if not unenriched:
        logger.info("Enrichment queue is empty — all active IOCs are enriched.")
        return 0

    logger.info(f"Found {len(unenriched)} unenriched IOCs. Starting enrichment pipeline...")

    enriched_count = 0

    for indicator in unenriched:
        ioc_type = indicator.ioc_type
        ioc_value = indicator.ioc_value

        try:
            # Dispatch to the correct enrichment pipeline
            if ioc_type == "ip":
                enrichment_data = _enrich_ip(ioc_value)
            elif ioc_type == "domain":
                enrichment_data = _enrich_domain(ioc_value)
            elif ioc_type == "url":
                enrichment_data = _enrich_url(ioc_value)
            elif ioc_type in ("hash_md5", "hash_sha1", "hash_sha256"):
                enrichment_data = _enrich_hash(ioc_value)
            else:
                logger.warning(f"Unknown IOC type '{ioc_type}' — skipping enrichment.")
                continue

            # Only create a record if at least one enricher returned data
            if any(v is not None for v in enrichment_data.values()):
                ed = EnrichmentData(
                    ioc_id=indicator.id,
                    country_code=enrichment_data.get("country_code"),
                    asn=enrichment_data.get("asn"),
                    whois_registrar=enrichment_data.get("whois_registrar"),
                    whois_created=enrichment_data.get("whois_created"),
                    dns_records=enrichment_data.get("dns_records"),
                    reputation_score=enrichment_data.get("reputation_score"),
                    vt_detections=enrichment_data.get("vt_detections"),
                    open_ports=enrichment_data.get("open_ports"),
                    abuse_reports=enrichment_data.get("abuse_reports"),
                    usage_type=enrichment_data.get("usage_type"),
                    enriched_at=datetime.now(timezone.utc),
                )
                session.add(ed)
                enriched_count += 1
                logger.debug(f"Enriched {ioc_type} '{ioc_value[:60]}'")

        except Exception as exc:
            logger.error(f"Enrichment pipeline failed for '{ioc_value[:60]}': {exc}")
            continue

    # Commit in one batch for efficiency
    try:
        session.commit()
        logger.info(f"Enrichment complete — {enriched_count}/{len(unenriched)} IOCs enriched.")
    except Exception as exc:
        session.rollback()
        logger.error(f"Failed to commit enrichment batch: {exc}")
        return 0

    return enriched_count
