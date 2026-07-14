# SRE Runbook — Infrastructure Automation Pipeline

> **Version:** 1.0.0 | **Audience:** On-call SRE  
> This runbook covers how to respond to deployment failures, how to manually
> invoke rollbacks, and how to debug the Bash execution layer.

---

## 🚨 Scenario 1: A Deployment Failed in CI/CD

If the `deploy-staging` or `deploy-prod` GitHub Action fails, the system should have **automatically rolled back**. 

### Step 1: Verify the auto-rollback was successful

1. Check the GitHub Actions run summary. At the bottom, look for the "Notify on failure" step output.
2. Check the `release_manifest.json` state for that environment:
   ```bash
   python scripts/python/release_tracker.py status
   ```
   You should see `Current: ... [rollback_success]`.
3. Check the live health endpoint:
   `curl -s http://<TARGET_HOST>:8080/health | jq`
   The version should match the *previous* known-good version, not the one you just tried to deploy.

### Step 2: Read the deploy logs

To figure out *why* it failed, look at the deploy logs:
1. Download the `deploy-logs` artifact from the failed GitHub Actions run.
2. Inside, open `deploy_summary.json`. Look at the `"steps"` array to find which step has `"success": false`.
3. Open the corresponding `*.log` file (e.g., `restart_service.sh.log`).
4. Look for the `ERROR` line.

**Common reasons for failure:**
- `check_dependencies.sh`: A required tool is missing on the target host, or a port is already bound.
- `setup_user.sh`: The SSH key was rejected, or the script didn't run as root (sudo configuration issue).
- `restart_service.sh`: The application crashed on startup, or took too long to bind to the health port.

---

## 🚨 Scenario 2: The Auto-Rollback Failed

If `deploy.py` fails, and then the automatic `rollback.py` invocation *also* fails, the environment is likely in a degraded state. 

### Step 1: Prevent further automated deploys

If this is production, temporarily lock deployments in GitHub until the issue is resolved.

### Step 2: Manually intervene on the host

SSH into the target host:
```bash
ssh deploy@<TARGET_HOST>
```

Check the state of the application service:
```bash
sudo supervisorctl status app-server
# OR
sudo systemctl status app-server
```

Check the application logs to see why the rollback version failed to start:
```bash
tail -n 100 /var/log/app/app.log
tail -n 100 /var/log/app/app.err
```

### Step 3: Manually restore from backup

If the automation is completely broken, you can manually extract the pre-deploy backup:
```bash
# Find the latest backup
ls -lt /var/backups/app/pre-deploy-*.tar.gz | head -1

# Extract it over the deploy dir
sudo tar -xzf /var/backups/app/pre-deploy-<SHA>.tar.gz -C /var/lib/app/

# Restart the service manually
sudo supervisorctl restart app-server
```

### Step 4: Update the release manifest

Once you manually fix the environment, inform the orchestrator by marking the release as rolled back:
```bash
python scripts/python/release_tracker.py record \
  --env production \
  --sha <MANUALLY_RESTORED_SHA> \
  --status rollback_success \
  --notes "Manually restored after auto-rollback failure"
```

---

## 🛠 Manual Operations

### How to trigger a manual rollback

If a bad deployment slipped past the health checks (e.g., a logic bug that doesn't break the `/health` endpoint), you can trigger a rollback manually from your local machine (assuming you have SSH access to the target):

```bash
# See what is currently deployed
python scripts/python/release_tracker.py status

# Find the SHA of the last known-good release you want to revert to
python scripts/python/release_tracker.py list --env production

# Execute the rollback
python scripts/python/rollback.py --env production --target-sha <KNOWN_GOOD_SHA>
```

### How to test a deployment locally without touching real infrastructure

Use the simulated Docker environment:

```bash
# 1. Start the simulated target host
docker compose up -d staging-host

# 2. Run the deployment against it (it reads environments/staging.env which points to localhost)
python scripts/python/deploy.py --env staging

# 3. Verify the mock app updated
curl http://localhost:8080/version
```

### How to simulate a failure to test the rollback path

```bash
# Deploy with a deliberate failure injected at the artifact stage
python scripts/python/deploy.py --env staging --break-for-demo
```
Watch the output. You will see `deploy.py` reach stage 5, log a deliberate error, and immediately invoke `rollback.py`.
