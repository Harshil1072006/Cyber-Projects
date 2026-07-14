#!/usr/bin/env bash
# =============================================================================
#  setup.sh — Bootstrap script for the ELK log pipeline
#
#  What this does:
#    1. Waits for Elasticsearch to be ready
#    2. Creates the ILM (Index Lifecycle Management) policy for log retention
#    3. Creates the index template with correct field mappings
#    4. Creates the Kibana index pattern (logs-*)
#    5. Imports the Kibana dashboard from kibana/dashboards/
#    6. Prints a summary with all service URLs
#
#  Usage:
#    # Inside the project directory on your Linux/Mac host:
#    bash scripts/setup.sh
#
#    # With custom hosts:
#    ES_HOST=http://192.168.1.10:9200 KIBANA_HOST=http://192.168.1.10:5601 bash scripts/setup.sh
#
#  Idempotent: safe to run multiple times.
# =============================================================================
set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
ES_HOST="${ES_HOST:-http://localhost:9200}"
KIBANA_HOST="${KIBANA_HOST:-http://localhost:5601}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Colors
GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die()     { error "$@"; exit 1; }

# ── Wait for Elasticsearch ────────────────────────────────────────────────────
wait_for_es() {
    info "Waiting for Elasticsearch at ${ES_HOST}..."
    local attempts=0
    while ! curl -sf "${ES_HOST}/_cluster/health" | grep -qE '"status":"(green|yellow)"'; do
        (( attempts++ )) || true
        if (( attempts > 40 )); then
            die "Elasticsearch not available after ${attempts} attempts. Is it running?"
        fi
        printf "."
        sleep 3
    done
    echo ""
    success "Elasticsearch is ready"
}

# ── Wait for Kibana ───────────────────────────────────────────────────────────
wait_for_kibana() {
    info "Waiting for Kibana at ${KIBANA_HOST}..."
    local attempts=0
    while ! curl -sf "${KIBANA_HOST}/api/status" | grep -q '"level":"available"'; do
        (( attempts++ )) || true
        if (( attempts > 60 )); then
            warn "Kibana not available — skipping dashboard import"
            return 1
        fi
        printf "."
        sleep 5
    done
    echo ""
    success "Kibana is ready"
    return 0
}

# ── ILM Policy ────────────────────────────────────────────────────────────────
create_ilm_policy() {
    info "Creating ILM policy: logs-policy"
    curl -sf -X PUT "${ES_HOST}/_ilm/policy/logs-policy" \
        -H 'Content-Type: application/json' \
        -d '{
          "policy": {
            "phases": {
              "hot": {
                "min_age": "0ms",
                "actions": {
                  "rollover": {
                    "max_primary_shard_size": "10gb",
                    "max_age": "1d"
                  },
                  "set_priority": { "priority": 100 }
                }
              },
              "warm": {
                "min_age": "7d",
                "actions": {
                  "set_priority": { "priority": 50 },
                  "readonly": {}
                }
              },
              "delete": {
                "min_age": "30d",
                "actions": {
                  "delete": {}
                }
              }
            }
          }
        }' > /dev/null
    success "ILM policy created (hot=7d, warm=7-30d, delete after 30d)"
}

# ── Index Template ────────────────────────────────────────────────────────────
create_index_template() {
    info "Creating index template: logs-template"
    curl -sf -X PUT "${ES_HOST}/_index_template/logs-template" \
        -H 'Content-Type: application/json' \
        -d '{
          "index_patterns": ["logs-*"],
          "template": {
            "settings": {
              "number_of_shards": 1,
              "number_of_replicas": 0,
              "index.lifecycle.name": "logs-policy",
              "index.refresh_interval": "5s"
            },
            "mappings": {
              "dynamic": true,
              "dynamic_date_formats": ["ISO8601"],
              "properties": {
                "@timestamp":    { "type": "date" },
                "message":       { "type": "text",    "fields": { "keyword": { "type": "keyword", "ignore_above": 1024 } } },
                "log": {
                  "properties": {
                    "level":    { "type": "keyword" },
                    "format":   { "type": "keyword" },
                    "original": { "type": "text",   "fields": { "keyword": { "type": "keyword", "ignore_above": 2048 } } }
                  }
                },
                "host": {
                  "properties": {
                    "name": { "type": "keyword" }
                  }
                },
                "service": {
                  "properties": {
                    "name": { "type": "keyword" }
                  }
                },
                "http": {
                  "properties": {
                    "request":  { "properties": { "method": { "type": "keyword" } } },
                    "response": { "properties": { "status_code": { "type": "integer" } } }
                  }
                },
                "source": {
                  "properties": {
                    "ip": { "type": "ip" }
                  }
                },
                "url": {
                  "properties": {
                    "original": { "type": "keyword" }
                  }
                },
                "tags":           { "type": "keyword" },
                "alert": {
                  "properties": {
                    "severity": { "type": "keyword" },
                    "fired":    { "type": "boolean" }
                  }
                },
                "user": {
                  "properties": {
                    "id":   { "type": "keyword" },
                    "name": { "type": "keyword" }
                  }
                },
                "trace": {
                  "properties": {
                    "id": { "type": "keyword" }
                  }
                },
                "labels": {
                  "properties": {
                    "environment": { "type": "keyword" }
                  }
                },
                "event": {
                  "properties": {
                    "kind":    { "type": "keyword" },
                    "type":    { "type": "keyword" },
                    "dataset": { "type": "keyword" }
                  }
                }
              }
            }
          },
          "priority": 200
        }' > /dev/null
    success "Index template created with typed field mappings"
}

# ── Kibana Index Pattern ───────────────────────────────────────────────────────
create_kibana_data_view() {
    info "Creating Kibana data view: logs-*"
    # Kibana 8.x uses "data views" (formerly index patterns)
    curl -sf -X POST "${KIBANA_HOST}/api/data_views/data_view" \
        -H 'Content-Type: application/json' \
        -H 'kbn-xsrf: true' \
        -d '{
          "data_view": {
            "id": "logs-star",
            "title": "logs-*",
            "timeFieldName": "@timestamp",
            "name": "Log Pipeline"
          }
        }' > /dev/null 2>&1 || warn "Data view may already exist (OK)"
    success "Kibana data view configured"
}

# ── Import Dashboard ──────────────────────────────────────────────────────────
import_dashboard() {
    local ndjson_file="${PROJECT_ROOT}/kibana/dashboards/incident-overview.ndjson"
    if [[ ! -f "$ndjson_file" ]]; then
        warn "Dashboard file not found: ${ndjson_file}"
        return
    fi

    info "Importing Kibana dashboard: incident-overview"
    local response
    response=$(curl -sf -X POST \
        "${KIBANA_HOST}/api/saved_objects/_import?overwrite=true" \
        -H 'kbn-xsrf: true' \
        --form "file=@${ndjson_file}" 2>&1) || true

    if echo "$response" | grep -q '"success":true'; then
        success "Dashboard imported successfully"
    else
        warn "Dashboard import response: ${response}"
        warn "You can manually import via Kibana → Stack Management → Saved Objects → Import"
    fi
}

# ── Summary ───────────────────────────────────────────────────────────────────
print_summary() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  🚀 Log Pipeline Setup Complete!                     ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "  Service URLs:"
    echo -e "  ├── Kibana:         ${BLUE}${KIBANA_HOST}${NC}"
    echo -e "  ├── Elasticsearch:  ${BLUE}${ES_HOST}${NC}"
    echo -e "  └── Logstash API:   ${BLUE}http://localhost:9600${NC}"
    echo ""
    echo "  Next steps:"
    echo "  1. Start log simulation:"
    echo "     docker exec log-simulator bash /scripts/simulate_logs.sh &"
    echo ""
    echo "  2. Trigger the alerter manually:"
    echo "     docker exec error-rate-alerter python /app/error_rate_alerter.py --once"
    echo ""
    echo "  3. Trigger an incident burst:"
    echo "     docker exec log-simulator bash /scripts/simulate_logs.sh --incident-only &"
    echo "     # Wait 60s, then check Kibana and alerter output"
    echo ""
    echo -e "  ${YELLOW}Open Kibana → Dashboards → 'Incident Overview' to see logs${NC}"
    echo ""
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  Log Pipeline — Bootstrap Setup${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"

    wait_for_es
    create_ilm_policy
    create_index_template

    if wait_for_kibana; then
        create_kibana_data_view
        import_dashboard
    fi

    print_summary
}

main "$@"
