# Centralized Log Analysis Pipeline — ELK Stack

A production-ready Logstash → Elasticsearch → Kibana pipeline with:
- Multi-format log ingestion (syslog, nginx, JSON app logs)
- Python log enricher that adds geolocation and severity scoring
- Alerting integration via Elastalert rules
- Docker Compose full-stack deployment
- Unit-tested Python enricher

## Quick Start
```bash
docker compose up -d
```
Then open http://localhost:5601 for Kibana.