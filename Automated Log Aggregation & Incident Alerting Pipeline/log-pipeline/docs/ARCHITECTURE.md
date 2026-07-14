# Architecture — Automated Log Aggregation & Incident Alerting Pipeline

## Overview

A centralized, ELK-based log aggregation pipeline that collects logs from multiple
Linux hosts, normalizes them to ECS format, applies semantic incident tagging, and
surfaces them in Kibana dashboards with automated error-rate alerting.

---

## Log Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     Multiple Linux Hosts / Containers                        │
│                                                                              │
│  ┌─────────────────┐   ┌─────────────────┐   ┌──────────────────┐          │
│  │  app-server-1   │   │  app-server-2   │   │  nginx-proxy-1   │          │
│  │ payment-service │   │  auth-service   │   │  access logs     │          │
│  │  app.log        │   │  app.log        │   │  nginx.log       │          │
│  └────────┬────────┘   └────────┬────────┘   └────────┬─────────┘          │
│           │                     │                     │                     │
│  ┌────────▼────────┐   ┌────────▼────────┐   ┌────────▼─────────┐          │
│  │  Filebeat       │   │  Filebeat       │   │  Filebeat        │          │
│  │ (host_name=     │   │ (host_name=     │   │ (host_name=      │          │
│  │  app-server-1)  │   │  app-server-2)  │   │  nginx-proxy-1)  │          │
│  └────────┬────────┘   └────────┬────────┘   └────────┬─────────┘          │
└───────────┼─────────────────────┼─────────────────────┼────────────────────┘
            │ Beats protocol      │                     │
            │ (port 5044)         │                     │
            └─────────────────────┼─────────────────────┘
                                  │
                    ┌─────────────▼──────────────────────┐
                    │           Logstash                  │
                    │                                     │
                    │  [01] Input: beats(:5044)           │
                    │        │                            │
                    │  [02] Filter: Format detection      │
                    │       ├── syslog → grok SYSLOG*    │
                    │       ├── app    → grok ISO8601     │
                    │       └── nginx  → grok COMBINED    │
                    │        │                            │
                    │  [03] Enrich: Tagging + extraction  │
                    │       ├── JSON log promotion        │
                    │       ├── Incident tagging          │
                    │       │   (auth-fail, 5xx, oom...)  │
                    │       └── Field normalization (ECS) │
                    │        │                            │
                    │  [04] Output → Elasticsearch        │
                    │       index: logs-{service}-{date}  │
                    └─────────────┬──────────────────────┘
                                  │ HTTP bulk API
                    ┌─────────────▼──────────────────────┐
                    │         Elasticsearch               │
                    │                                     │
                    │  Index: logs-payment-2026.07.13     │
                    │  Index: logs-auth-2026.07.13        │
                    │  Index: logs-nginx-2026.07.13       │
                    │                                     │
                    │  ILM Policy: logs-policy            │
                    │    hot  → 7 days  (read/write)      │
                    │    warm → 30 days (read-only)        │
                    │    delete after 30 days             │
                    └──────────┬──────────────────────────┘
                               │
              ┌────────────────┴────────────────────────┐
              │                                         │
  ┌───────────▼────────────┐             ┌─────────────▼──────────────┐
  │        Kibana           │             │   error_rate_alerter.py    │
  │                         │             │                            │
  │  Incident Overview      │             │  Queries ES every 60s:     │
  │  ├── Log volume/time    │             │  ├── Current 5m count      │
  │  ├── Error rate/service │             │  ├── 60m baseline average   │
  │  ├── Host breakdown     │             │  ├── Spike ratio = curr/avg │
  │  └── Top error messages │             │  └── Fire alert if:        │
  │                         │             │     count > 20 OR           │
  │  Alerting rules         │             │     spike > 3x baseline     │
  │  └── error-rate-spike   │             │        │                   │
  └─────────────────────────┘             │  ┌─────▼──────────────┐   │
                                          │  │   Slack Webhook    │   │
                                          │  │   Console stdout   │   │
                                          │  └────────────────────┘   │
                                          └────────────────────────────┘
```

---

## Component Details

| Component | Image | Port | Role |
|-----------|-------|------|------|
| Elasticsearch | `elasticsearch:8.13.4` | 9200, 9300 | Storage + search engine |
| Logstash | `logstash:8.13.4` | 5044 (beats), 9600 (API) | Parsing, filtering, routing |
| Kibana | `kibana:8.13.4` | 5601 | Dashboards + alerting UI |
| Filebeat × 3 | `filebeat:8.13.4` | — | Log shippers (one per host) |
| error_rate_alerter | Custom Python | — | Active ES-based alert polling |
| log-simulator | `bash:5.2` | — | Synthetic log generator |

---

## ECS Field Mapping

All log formats are normalized to [Elastic Common Schema (ECS) v8](https://www.elastic.co/guide/en/ecs/current/):

| ECS Field | Description | Example |
|-----------|-------------|---------|
| `@timestamp` | Event time (UTC ISO 8601) | `2026-07-13T08:14:22.000Z` |
| `host.name` | Source hostname | `app-server-1` |
| `service.name` | Application name | `payment-service` |
| `log.level` | Canonical level | `error` |
| `log.format` | Parser used | `syslog`, `app`, `nginx_access`, `json` |
| `log.original` | Raw message text | `Database connection failed...` |
| `tags` | Incident labels | `["auth-failure", "5xx-error"]` |
| `alert.severity` | Derived severity | `critical`, `high`, `medium`, `low` |
| `http.response.status_code` | HTTP status integer | `500` |
| `source.ip` | Client IP (nginx) | `203.0.113.45` |

---

## Index Lifecycle Management

```
Day 0 ──── hot phase ──── Day 7 ──── warm phase ──── Day 30 ──── delete
  │                          │                           │
  ├── read + write OK        ├── read-only              └── data removed
  ├── rollover at 10GB/1d    ├── priority lowered
  └── priority: 100          └── priority: 50
```

Configured in `scripts/setup.sh` via the `/_ilm/policy/logs-policy` API.

---

## Security Notes

- Elasticsearch security (`xpack.security`) is **disabled** for local dev.
- For production: enable TLS, set up users/roles, use `logstash_writer` role.
- Filebeat → Logstash communication is unencrypted in this setup.
- The alerter accesses ES without authentication credentials.
