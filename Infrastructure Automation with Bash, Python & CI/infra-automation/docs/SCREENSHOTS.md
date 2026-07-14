# Screenshots — Infrastructure Automation

> See it in action. Below is the expected output when running the pipeline locally against the simulated Docker hosts.

---

## 1. Config Validation

When running `python scripts/python/config_validator.py --env staging`:

```
═══════════════════════════════════════════════════════
  Config Validation: staging.env
═══════════════════════════════════════════════════════
  ⚠ [WARNING] SECRET_KEY (value: 'staging-secret-key-replace-me-wi...'): Value contains forbidden placeholder 'replace' — set a real value
  ℹ [INFO] CUSTOM_FIELD (value: 'foo'): Key not in schema — may be a custom or extra field (OK if intentional)

  Summary: 0 errors, 1 warnings, 1 info

  Required fields status:
    ✓  APP_NAME
    ✓  APP_VERSION
    ✓  APP_ENV
    ✓  APP_PORT
    ✓  DEPLOY_USER
    ✓  DEPLOY_DIR
    ✓  SECRET_KEY
    ✓  TARGET_HOST
═══════════════════════════════════════════════════════
  Result: ✓ VALID
═══════════════════════════════════════════════════════
```

---

## 2. A Successful Deployment

Running `python scripts/python/deploy.py --env staging` against a healthy target:

```
2026-07-13 14:00:00 [INFO] deploy: ╔══════════════════════════════════════════════════╗
2026-07-13 14:00:00 [INFO] deploy: ║  Starting Deployment                             ║
2026-07-13 14:00:00 [INFO] deploy: ╠══════════════════════════════════════════════════╣
2026-07-13 14:00:00 [INFO] deploy: ║  Env:     staging                                 ║
2026-07-13 14:00:00 [INFO] deploy: ║  SHA:     f83b1a9c                                ║
2026-07-13 14:00:00 [INFO] deploy: ║  Version: 1.0.0                                   ║
2026-07-13 14:00:00 [INFO] deploy: ╚══════════════════════════════════════════════════╝
2026-07-13 14:00:00 [INFO] deploy: ── Stage 1: Config Validation ──
2026-07-13 14:00:00 [INFO] deploy: Config validation passed (15 keys, 0 errors)
2026-07-13 14:00:00 [INFO] release_tracker: Release recorded: env=staging sha=f83b1a9c status=in_progress

2026-07-13 14:00:00 [INFO] deploy: ── Stage 2: Pre-Deploy Checks ──
2026-07-13 14:00:01 [INFO] deploy:   [check_dependencies.sh] ┌────────────────────────────────────────────────────────────┐
2026-07-13 14:00:01 [INFO] deploy:   [check_dependencies.sh] │  check_dependencies.sh — Dependency Verification             │
2026-07-13 14:00:01 [INFO] deploy:   [check_dependencies.sh] └────────────────────────────────────────────────────────────┘
2026-07-13 14:00:01 [INFO] deploy:   [check_dependencies.sh] [2026-07-13T14:00:01Z] [SUCCESS] [check_dependencies.sh] All required dependencies satisfied
2026-07-13 14:00:01 [INFO] deploy: ✓ PASS  pre-checks                      1.1s

...

2026-07-13 14:00:08 [INFO] deploy: ── Stage 6: Service Restart ──
2026-07-13 14:00:09 [INFO] deploy:   [restart_service.sh] [2026-07-13T14:00:09Z] [INFO   ] [restart_service.sh] Restarting via supervisorctl: app-server
2026-07-13 14:00:12 [INFO] deploy:   [restart_service.sh] [2026-07-13T14:00:12Z] [SUCCESS] [restart_service.sh] Service healthy after 2s: HTTP 200
2026-07-13 14:00:12 [INFO] deploy: ✓ PASS  restart-service                 4.2s

2026-07-13 14:00:12 [INFO] deploy: ── Stage 7: Post-Deploy Health Check ──
2026-07-13 14:00:12 [INFO] deploy: Health check: http://localhost:8080/health (timeout=30s)
2026-07-13 14:00:12 [INFO] deploy: Health check PASSED: HTTP 200 — {"env":"staging","sha":"f83b1a9c","status":"ok","version":"1.0.0"}

2026-07-13 14:00:12 [INFO] deploy: ✅ DEPLOYMENT SUCCESSFUL in 12.3s
2026-07-13 14:00:12 [INFO] release_tracker: Updated release status: env=staging sha=f83b1a9c → success
```

---

## 3. A Failed Deployment Triggering Auto-Rollback

Running `python scripts/python/deploy.py --env staging --break-for-demo`:

```
2026-07-13 14:05:00 [INFO] deploy: ── Stage 5: Deploy Artifact ──
2026-07-13 14:05:00 [ERROR] deploy: 🔥 DELIBERATE FAILURE INJECTED (--break-for-demo)
2026-07-13 14:05:00 [ERROR] deploy: This simulates a broken artifact deploy to trigger rollback
2026-07-13 14:05:00 [INFO] deploy: ✗ FAIL  deploy-artifact                 0.5s

2026-07-13 14:05:00 [ERROR] deploy: ❌ DEPLOYMENT FAILED at stage: deploy-artifact (after 4.2s)
2026-07-13 14:05:00 [INFO] release_tracker: Updated release status: env=staging sha=b72d9e1a → failed
2026-07-13 14:05:00 [WARNING] deploy: Invoking automatic rollback...
2026-07-13 14:05:00 [INFO] deploy: Running: python scripts/python/rollback.py --env staging --failed-sha b72d9e1a

2026-07-13 14:05:01 [INFO] rollback: ╔══════════════════════════════════════════════════╗
2026-07-13 14:05:01 [INFO] rollback: ║  ⚠  ROLLBACK INITIATED                          ║
2026-07-13 14:05:01 [INFO] rollback: ╠══════════════════════════════════════════════════╣
2026-07-13 14:05:01 [INFO] rollback: ║  Environment:     staging                         ║
2026-07-13 14:05:01 [INFO] rollback: ║  Failed SHA:      b72d9e1a                        ║
2026-07-13 14:05:01 [INFO] rollback: ║  Rolling back to: f83b1a9c                        ║
2026-07-13 14:05:01 [INFO] rollback: ║  Version:         1.0.0                           ║
2026-07-13 14:05:01 [INFO] rollback: ╚══════════════════════════════════════════════════╝
2026-07-13 14:05:01 [INFO] release_tracker: Release recorded: env=staging sha=f83b1a9c status=in_progress

2026-07-13 14:05:01 [INFO] rollback: ── Rollback Step: restore-artifact ──
2026-07-13 14:05:01 [INFO] rollback: Restoring from backup: /var/backups/app/pre-deploy-f83b1a9c_20260713_140003.tar.gz
2026-07-13 14:05:01 [INFO] rollback: Artifact restored from backup

2026-07-13 14:05:01 [INFO] rollback: ── Rollback Step: restart-service ──
2026-07-13 14:05:02 [INFO] rollback: Running: bash scripts/bash/restart_service.sh --service app-server --port 8080 --health-url http://localhost:8080/health --timeout 30 --force
2026-07-13 14:05:05 [INFO] rollback:   [restart_service.sh] [2026-07-13T14:05:05Z] [SUCCESS] [restart_service.sh] Service healthy after 2s: HTTP 200

2026-07-13 14:05:05 [INFO] rollback: ── Rollback Step: post-health-check ──
2026-07-13 14:05:05 [INFO] rollback: Post-rollback health check: http://localhost:8080/health (timeout=30s)
2026-07-13 14:05:05 [INFO] rollback: Health check PASSED: HTTP 200 — {"env":"staging","sha":"f83b1a9c","status":"ok","version":"1.0.0"}

2026-07-13 14:05:05 [INFO] rollback: ✅ ROLLBACK SUCCESSFUL in 4.5s
2026-07-13 14:05:05 [INFO] release_tracker: Updated release status: env=staging sha=f83b1a9c → rollback_success
2026-07-13 14:05:06 [INFO] deploy: Rollback completed successfully
```

---

## 4. Checking the Release Manifest

Running `python scripts/python/release_tracker.py status`:

```
═══════════════════════════════════════════════════════════════════════════
  Deployment Status Summary
═══════════════════════════════════════════════════════════════════════════

  Environment: PRODUCTION
    Current:   (no deployments)

  Environment: STAGING
    Current:   f83b1a9c  v1.0.0  [rollback_success]  2026-07-13T14:05:01
    Last Good: (same as current)
    Total releases: 3

═══════════════════════════════════════════════════════════════════════════
```

Running `python scripts/python/release_tracker.py list --env staging`:

```
─────────────────────────────────────────────────────────────────────────────────────
  TIMESTAMP                 SHA        VERSION      STATUS           TRIGGERED BY
─────────────────────────────────────────────────────────────────────────────────────
  2026-07-13 14:05:01       f83b1a9c   1.0.0        rollback_success rollback.py (auto) ◀ current
  2026-07-13 14:05:00       b72d9e1a   2.0.0        failed           CI-run-102
  2026-07-13 14:00:00       f83b1a9c   1.0.0        success          CI-run-101
─────────────────────────────────────────────────────────────────────────────────────
```
