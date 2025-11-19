#!/bin/bash
set -euo pipefail

DATE=$(date +%Y-%m-%d_%H-%M)
REPORT_DIR="/opt/security-audit/reports/$DATE"
mkdir -p "$REPORT_DIR"

echo "==============================================="
echo "   INTERNAL SECURITY BASELINE AUDIT (SAFE)"
echo "==============================================="
echo "Report Directory: $REPORT_DIR"
echo "Run Time: $(date)"
echo

#############################################
# 1. Server Security (Lynis)
#############################################
echo "▶ Running LYNIS baseline server audit..."
lynis audit system --quick --quiet > "$REPORT_DIR/lynis-server-baseline.txt" || true


#############################################
# 2. Firewall & System Integrity
#############################################
echo "▶ Checking firewall..."
ufw status verbose > "$REPORT_DIR/ufw-status.txt"

echo "▶ Checking Fail2Ban..."
fail2ban-client status > "$REPORT_DIR/fail2ban-status.txt" || true

echo "▶ Checking CrowdSec decisions..."
cscli decisions list > "$REPORT_DIR/crowdsec-decisions.txt" || true


#############################################
# 3. SSH Hardening Verification
#############################################
echo "▶ Auditing SSH configuration..."
sshd -T > "$REPORT_DIR/ssh-config-dump.txt" || true


#############################################
# 4. Nginx Security Audit
#############################################
NGINX_CONF_DIR="/etc/nginx"
echo "▶ Analyzing NGINX configuration..."

find /etc/nginx -type f \( -name "*.conf" -o -name "*site*" \) \
  | while read file; do
      echo "File: $file" >> "$REPORT_DIR/nginx-config-audit.txt"
      nginx -t 2>&1 | tee -a "$REPORT_DIR/nginx-config-audit.txt"
    done

echo "▶ Running testssl.sh for TLS audit..."
testssl --quiet --warnings-batch https://localhost \
  > "$REPORT_DIR/tls-testssl.txt" || true


#############################################
# 5. Web Application Fingerprinting (Laravel/React/Golang/WordPress)
#############################################
echo "▶ Detecting application stack..."

SITE_DIR="/etc/nginx/sites-enabled"
WEB_STACK_REPORT="$REPORT_DIR/web-stack-detection.txt"

touch "$WEB_STACK_REPORT"

for FILE in $SITE_DIR/*; do
  SERVER_NAME=$(grep -i "server_name" "$FILE" | awk '{print $2}' | sed 's/;//')

  echo "→ Found site: $SERVER_NAME" | tee -a "$WEB_STACK_REPORT"

  # Detect WordPress
  if grep -qi "wordpress" "$FILE"; then
    echo "  * Stack: WordPress" | tee -a "$WEB_STACK_REPORT"
  fi

  # Detect Laravel
  if grep -qi "index.php" "$FILE"; then
    echo "  * Stack: Laravel/PHP" | tee -a "$WEB_STACK_REPORT"
  fi

  # Detect React
  if grep -qi "index.html" "$FILE"; then
    echo "  * Stack: React/SPA" | tee -a "$WEB_STACK_REPORT"
  fi

  # Detect Golang
  if grep -qi "proxy_pass http" "$FILE" && grep -qi "go" "$FILE"; then
    echo "  * Stack: Golang API" | tee -a "$WEB_STACK_REPORT"
  fi
done


#############################################
# 6. Safe Web Scanning — Nikto + ZAP Baseline
#############################################
echo "▶ Running Nikto SAFE scan..."
nikto -h http://localhost > "$REPORT_DIR/nikto-safe.txt" || true

echo "▶ Running OWASP ZAP BASELINE scan..."
docker run --rm \
  -v "$REPORT_DIR:/zap/wrk" \
  zaproxy/zap-stable zap-baseline.py \
  -t http://localhost \
  -r zap-baseline-report.html || true


#############################################
# 7. Nmap Security Audit (Safe)
#############################################
echo "▶ Running Nmap safe security scan..."
nmap -sV --script-safe --script=vuln localhost \
  > "$REPORT_DIR/nmap-baseline.txt" || true


#############################################
# 8. Summary
#############################################
echo "==============================================="
echo "   ✔ BASELINE SECURITY AUDIT COMPLETE"
echo "   Reports saved in: $REPORT_DIR"
echo "==============================================="


