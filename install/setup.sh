#!/usr/bin/env bash
# Runs INSIDE the container (as root). Idempotent: run again to update.
# Fresh install:  REPO=user/repo BRANCH=main bash setup.sh
# Update:         bash /opt/privacy-scanner/install/setup.sh
set -Eeuo pipefail

# Everything lives in main() so bash parses the whole file before running it;
# that keeps `git pull` from rewriting this script while it executes.
main() {
  local REPO="${REPO:-}" BRANCH="${BRANCH:-main}"
  local APP_DIR=/opt/privacy-scanner DATA_DIR=/var/lib/privacy-scanner CONF_DIR=/etc/privacy-scanner
  export DEBIAN_FRONTEND=noninteractive

  echo "==> Installing system packages"
  apt-get update -qq
  apt-get install -y -qq python3 python3-venv python3-pip git curl ca-certificates sqlite3

  echo "==> Creating service user and directories"
  id pscan &>/dev/null || useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin pscan
  install -d -o pscan -g pscan -m 750 "$DATA_DIR" "$DATA_DIR/backups"
  install -d -m 750 "$CONF_DIR"

  echo "==> Fetching application code"
  if [[ -d "$APP_DIR/.git" ]]; then
    git -C "$APP_DIR" pull --ff-only
  else
    [[ -n "$REPO" ]] || { echo "REPO is not set (expected user/repo)"; exit 1; }
    git clone --depth 1 --branch "$BRANCH" "https://github.com/${REPO}.git" "$APP_DIR"
  fi

  echo "==> Installing Python dependencies"
  [[ -d "$APP_DIR/venv" ]] || python3 -m venv "$APP_DIR/venv"
  "$APP_DIR/venv/bin/pip" install --quiet --upgrade pip
  "$APP_DIR/venv/bin/pip" install --quiet --upgrade -r "$APP_DIR/app/requirements.txt"

  if [[ ! -f "$CONF_DIR/env" ]]; then
    echo "==> Writing $CONF_DIR/env"
    cat > "$CONF_DIR/env" <<EOF
SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
DATABASE_PATH=$DATA_DIR/app.db
# Set to 1 only if you put this behind an HTTPS reverse proxy
COOKIE_SECURE=0
# Optional: enables the Brave Search option (free tier at brave.com/search/api)
BRAVE_API_KEY=
# Seconds between searches; raise it if you hit rate limits
SCAN_DELAY=2.5
EOF
    chmod 600 "$CONF_DIR/env"
  fi

  echo "==> Installing systemd service"
  # One worker on purpose: the scan queue lives inside the process.
  cat > /etc/systemd/system/privacy-scanner.service <<EOF
[Unit]
Description=Privacy Scanner web app
After=network-online.target
Wants=network-online.target

[Service]
User=pscan
Group=pscan
WorkingDirectory=$APP_DIR/app
EnvironmentFile=$CONF_DIR/env
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=$APP_DIR/venv/bin/gunicorn --workers 1 --threads 8 --timeout 120 --bind 0.0.0.0:8080 app:app
Restart=on-failure
RestartSec=3
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

  echo "==> Installing nightly database backup (keeps 14 days)"
  cat > /etc/cron.daily/privacy-scanner-backup <<EOF
#!/bin/sh
f="$DATA_DIR/backups/app-\$(date +%F).db"
[ -f "$DATA_DIR/app.db" ] && sqlite3 "$DATA_DIR/app.db" ".backup '\$f'" && chown pscan:pscan "\$f" && chmod 600 "\$f"
find "$DATA_DIR/backups" -name 'app-*.db' -mtime +14 -delete
EOF
  chmod 755 /etc/cron.daily/privacy-scanner-backup

  systemctl daemon-reload
  systemctl enable privacy-scanner >/dev/null
  systemctl restart privacy-scanner

  echo "==> Waiting for the web app"
  for _ in $(seq 1 30); do
    if curl -fsS http://127.0.0.1:8080/healthz >/dev/null 2>&1; then
      echo "Privacy Scanner is running on port 8080."
      return 0
    fi
    sleep 1
  done
  echo "The service did not become healthy. Check: journalctl -u privacy-scanner -n 50"
  exit 1
}

main "$@"
