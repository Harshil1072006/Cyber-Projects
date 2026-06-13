"""
celery_app.py — Celery application factory for the Threat Intelligence Pipeline.

Uses Redis as both the broker and result backend.
Beat schedule is defined here to match the collection frequencies
from Section 5 of the blueprint.

Usage:
  Start worker:  celery -A src.tasks.celery_app worker --loglevel=info
  Start beat:    celery -A src.tasks.celery_app beat --loglevel=info
  Both at once:  celery -A src.tasks.celery_app worker --beat --loglevel=info
"""

from celery import Celery
from celery.schedules import crontab

from src.config import REDIS_URL

# ─── App factory ─────────────────────────────────────────────────────────────

app = Celery(
    "threat_intel_pipeline",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=[
        "src.tasks.collect_tasks",
        "src.tasks.process_tasks",
        "src.tasks.enrich_tasks",
        "src.tasks.report_tasks",
    ],
)

# ─── Celery configuration ────────────────────────────────────────────────────

app.conf.update(
    # Serialization
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    # Timezone
    timezone="UTC",
    enable_utc=True,
    # Task behaviour
    task_acks_late=True,               # Ack only after task completes (safer)
    task_reject_on_worker_lost=True,   # Re-queue if worker crashes
    worker_prefetch_multiplier=1,      # One task at a time (rate-limit safe)
    # Result expiry — keep results for 1 hour
    result_expires=3600,
    # Retry defaults
    task_max_retries=3,
    task_default_retry_delay=60,
)

# ─── Beat schedule — matches Section 5 collection frequencies ────────────────

app.conf.beat_schedule = {

    # ── Hourly feeds ──────────────────────────────────────────────────────────

    "collect-urlhaus-hourly": {
        "task": "src.tasks.collect_tasks.collect_urlhaus",
        "schedule": crontab(minute=0),                  # Every hour, on the hour
        "options": {"queue": "collectors"},
    },
    "collect-phishtank-hourly": {
        "task": "src.tasks.collect_tasks.collect_phishtank",
        "schedule": crontab(minute=10),                 # Offset by 10 min
        "options": {"queue": "collectors"},
    },

    # ── Every 6 hours ────────────────────────────────────────────────────────

    "collect-abuseipdb-6h": {
        "task": "src.tasks.collect_tasks.collect_abuseipdb",
        "schedule": crontab(minute=20, hour="*/6"),
        "options": {"queue": "collectors"},
    },
    "collect-alienvault-6h": {
        "task": "src.tasks.collect_tasks.collect_alienvault",
        "schedule": crontab(minute=30, hour="*/6"),
        "options": {"queue": "collectors"},
    },

    # ── Daily feeds ───────────────────────────────────────────────────────────

    "collect-feodo-daily": {
        "task": "src.tasks.collect_tasks.collect_feodo",
        "schedule": crontab(hour=2, minute=0),          # 02:00 UTC
        "options": {"queue": "collectors"},
    },
    "collect-malwarebazaar-daily": {
        "task": "src.tasks.collect_tasks.collect_malwarebazaar",
        "schedule": crontab(hour=2, minute=15),
        "options": {"queue": "collectors"},
    },
    "collect-blocklist-de-daily": {
        "task": "src.tasks.collect_tasks.collect_blocklist_de",
        "schedule": crontab(hour=2, minute=30),
        "options": {"queue": "collectors"},
    },
    "collect-cins-army-daily": {
        "task": "src.tasks.collect_tasks.collect_cins_army",
        "schedule": crontab(hour=2, minute=45),
        "options": {"queue": "collectors"},
    },
    "collect-emerging-threats-daily": {
        "task": "src.tasks.collect_tasks.collect_emerging_threats",
        "schedule": crontab(hour=3, minute=0),
        "options": {"queue": "collectors"},
    },

    # ── Enrichment — runs every 30 minutes ───────────────────────────────────

    "run-enrichment-30min": {
        "task": "src.tasks.enrich_tasks.run_enrichment",
        "schedule": crontab(minute="*/30"),
        "options": {"queue": "enrichment"},
    },

    # ── Scoring — runs every hour ─────────────────────────────────────────────

    "run-scoring-hourly": {
        "task": "src.tasks.process_tasks.run_scoring",
        "schedule": crontab(minute=55),                 # Just before the hour
        "options": {"queue": "processing"},
    },

    # ── SIEM push — runs every hour ───────────────────────────────────────────

    "push-siem-hourly": {
        "task": "src.tasks.process_tasks.push_to_siem",
        "schedule": crontab(minute=58),
        "options": {"queue": "processing"},
    },

    # ── Daily report ─────────────────────────────────────────────────────────

    "generate-report-daily": {
        "task": "src.tasks.report_tasks.generate_daily_report",
        "schedule": crontab(hour=6, minute=0),          # 06:00 UTC
        "options": {"queue": "reporting"},
    },
}
