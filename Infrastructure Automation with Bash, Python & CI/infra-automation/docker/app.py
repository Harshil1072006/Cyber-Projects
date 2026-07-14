#!/usr/bin/env python3
"""
app.py — Minimal Flask application simulating a deployed service.
Used inside the Dockerfile.target-host container.
The health endpoint is what restart_service.sh and deploy.py check.
"""

import os
import json
from pathlib import Path
from datetime import datetime, timezone
from flask import Flask, jsonify

app = Flask(__name__)

VERSION_FILE = Path("/var/lib/app/DEPLOYED_VERSION")


def get_version_info() -> dict:
    if VERSION_FILE.exists():
        try:
            return json.loads(VERSION_FILE.read_text())
        except Exception:
            pass
    return {"version": "unknown", "sha": "unknown"}


@app.route("/health")
def health():
    version = get_version_info()
    return jsonify({
        "status":    "ok",
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "version":   version.get("version", "unknown"),
        "sha":       version.get("sha", "unknown"),
        "env":       os.getenv("APP_ENV", "unknown"),
    }), 200


@app.route("/version")
def version():
    return jsonify(get_version_info()), 200


@app.route("/")
def index():
    return jsonify({"message": "App server running", "health": "/health"}), 200


if __name__ == "__main__":
    port = int(os.getenv("APP_PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)
