#!/usr/bin/env bash
set -euo pipefail

# Start SSH daemon
/usr/sbin/sshd

# Start supervisor (manages the Flask app)
exec /usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf
