# 🏗️ Infrastructure Automation with Bash, Python & CI/CD

> 🤖 **Note:** This project and its documentation were generated with the assistance of AI.

> Replace manual server provisioning with version-controlled, idempotent automation scripts orchestrated by Python and wired into a CI/CD pipeline with automatic rollback support.

[![CI](https://github.com/yourname/infra-automation/actions/workflows/ci.yml/badge.svg)](https://github.com/yourname/infra-automation/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

---

## Architecture Overview

This project splits deployment into three distinct layers to ensure reliability, testability, and fast rollbacks:

1. **Bash Ops Scripts**: Low-level, purely idempotent execution on the target host.
2. **Python Orchestrator**: High-level controller (`deploy.py`) that manages the pipeline, validates configs, tracks state in a JSON manifest, and triggers `rollback.py` on failure.
3. **GitHub Actions**: The CI/CD frontend that lints, tests, and initiates the orchestrator.

For a deep dive into the rollback mechanism and why this stack was chosen over pure Ansible/Terraform, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Project Structure

```
infra-automation/
├── .github/workflows/
│   ├── ci.yml                 # PR checks (ShellCheck, Ruff, bats, pytest)
│   ├── deploy-staging.yml     # Auto-deploy to staging on merge
│   └── deploy-prod.yml        # Manual deploy to prod (supports approval gates)
├── scripts/
│   ├── bash/                  # Host-level ops scripts
│   │   ├── lib/common.sh      # Shared logging, exit codes, retry logic
│   │   ├── check_dependencies.sh
│   │   ├── setup_user.sh
│   │   ├── backup.sh
│   │   └── restart_service.sh
│   └── python/                # Orchestration layer
│       ├── deploy.py          # Executes stages, catches failures
│       ├── rollback.py        # Reverts to last known-good state
│       ├── config_validator.py# Validates .env schemas
│       └── release_tracker.py # Manages release_manifest.json
├── environments/
│   ├── staging.env            # Validated by config_validator before deploy
│   └── production.env
├── docker/
│   ├── Dockerfile.target-host # Simulates a clean Ubuntu server
│   ├── app.py                 # Minimal Flask app exposing /health
│   └── docker-compose.yml     # Spins up staging & prod hosts locally
├── tests/
│   ├── test_bash_scripts.bats # tests idempotency of bash scripts
│   └── test_python_orchestration.py # pytest suite (25 tests)
└── docs/
    ├── ARCHITECTURE.md
    ├── RUNBOOK.md             # SRE guide for handling deploy failures
    └── SCREENSHOTS.md         # CLI output of the rollback path
```

---

## Quickstart (Local Development)

You can run the entire deployment pipeline locally without touching real infrastructure. The target servers are simulated using Docker.

### 1. Prerequisites
- Docker & Docker Compose
- Python 3.12+
- `pip install flask requests pytest pytest-cov`
- `bats-core` (optional, for running bash tests locally)

### 2. Start the simulated target hosts
```bash
cd "C:\Cyber Project\Infrastructure Automation with Bash, Python & CI\infra-automation"
docker compose -f docker/docker-compose.yml up -d
```
This spins up `staging-host` (port 8080) and `production-host` (port 8081).

### 3. Run a deployment
```bash
# Deploys to staging
python scripts/python/deploy.py --env staging --version 1.0.0
```
Check the output. You should see all 7 stages execute successfully.

### 4. Verify the deployment
```bash
# Check the release manifest
python scripts/python/release_tracker.py status

# Query the live mock app
curl http://localhost:8080/health
```

---

## Demonstrating the Rollback Path

A core feature of this project is the **automatic rollback**. Let's trigger it.

```bash
# Pass the --break-for-demo flag. 
# This tells deploy.py to deliberately fail the "Deploy Artifact" stage.
python scripts/python/deploy.py --env staging --version 2.0.0 --break-for-demo
```

**What happens:**
1. `deploy.py` starts, validates config, creates a backup, sets up the user.
2. It hits the artifact stage and simulates a failure.
3. The orchestrator catches the failure, logs it, and immediately invokes `rollback.py`.
4. `rollback.py` looks at `release_manifest.json`, finds the last successful release (`1.0.0`), and extracts the backup for that version.
5. It restarts the service and waits for the health check.
6. The app is back online on version `1.0.0`.

---

## How to add a new Automation Script

If you need a new step (e.g., `migrate_database.sh`):

1. **Write the Bash script**: Create `scripts/bash/migrate_database.sh`.
2. **Make it idempotent**:
   ```bash
   source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
   # ... check if migration already applied ...
   if applied; then mark_already_done "migrations up to date"; conclude; fi
   # ... run migration ...
   mark_changed "applied 3 migrations"
   conclude
   ```
3. **Add tests**: Add bats tests to `tests/test_bash_scripts.bats` ensuring it returns exit code `2` (ALREADY_DONE) on the second run.
4. **Wire it into Python**: Open `scripts/python/deploy.py` and add a new method `stage_migrate_db()`.
5. **Add to pipeline**: Insert your new stage into the `stages` list in `deploy.py -> run()`.

---

## Exit Code Convention

All Bash scripts in this project adhere to a strict exit code contract enforced by `lib/common.sh`:

| Code | Constant | Meaning |
|------|----------|---------|
| `0` | `EXIT_SUCCESS` | Action performed successfully. |
| `1` | `EXIT_ERROR` | Unexpected failure. Triggers rollback. |
| `2` | `EXIT_ALREADY_DONE`| Idempotency check: Already in desired state, no action needed. Treated as success by `deploy.py`. |
| `3` | `EXIT_PRECONDITION`| Precondition not met (e.g., missing dependency, bad config). |
| `4` | `EXIT_PARTIAL` | Partial success, manual review needed. |
