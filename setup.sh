#!/usr/bin/env bash
set -euo pipefail
BASE="/opt/security-audit"
mkdir -p "$BASE"
echo "Starting setup of Security Audit Platform..."
# Update & prerequisites
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y
apt-get install -y curl wget git unzip jq python3 python3-venv python3-pip docker.io docker-compose nginx apt-transport-https software-properties-common gnupg2

# enable docker
systemctl enable --now docker

# create venv
python3 -m venv "$BASE/venv"
source "$BASE/venv/bin/activate"
pip install --upgrade pip
pip install flask flask-login flask-wtf Flask-APScheduler Flask-SQLAlchemy pyotp qrcode[pil] requests pandas plotly jinja2 weasyprint python-magic python-dateutil passlib pyjwt apscheduler

# create directories
mkdir -p "$BASE/tools" "$BASE/scans" "$BASE/reports" "$BASE/logs" "$BASE/data" "$BASE/webapp" "$BASE/ansible" "$BASE/gvm"

# copy compose files
cp /usr/share/doc/docker/examples/docker-compose.yml "$BASE/tools/" 2>/dev/null || true

# Pull Docker images
docker pull owasp/zap2docker-stable:latest
docker pull sqlmapproject/sqlmap:latest
docker pull aquasecurity/trivy:latest
docker pull wpscanteam/wpscan:latest || true
# OpenVAS (GVM) docker image - using securecompliance/gvm as known image
docker pull securecompliance/gvm || true

# Install native scanners
apt-get install -y nmap nikto lynis clamav rkhunter chkrootkit openjdk-11-jre-headless

# Initialize config.json (user must edit)
cat > "$BASE/config.json" <<'JSON'
{
  "out_dir_base": "/var/security-scans",
  "nginx_sites_enabled": "/etc/nginx/sites-enabled",
  "zap": { "use_active_scan": false },
  "slack": { "webhook_url": "" },
  "smtp": { "host":"", "port":587, "username":"", "password":"", "from":"", "to":[""] },
  "zip_reports": true,
  "openvas_enabled": true,
  "vault": { "mode": "production", "addr": "https://127.0.0.1:8200" },
  "wazuh": { "deploy_manager": true }
}
JSON

# Create systemd unit for flask app (gunicorn)
cat > /etc/systemd/system/audit-portal.service <<'UNIT'
[Unit]
Description=Security Audit Portal
After=network.target

[Service]
User=root
WorkingDirectory=/opt/security-audit/webapp
Environment=PATH=/opt/security-audit/venv/bin
ExecStart=/opt/security-audit/venv/bin/gunicorn -w 4 -b 127.0.0.1:5005 app:app
Restart=always

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now audit-portal.service || true

echo "Setup finished. Edit /opt/security-audit/config.json and run scan.sh for a test run."
