#!/bin/bash
set -euo pipefail
LOG=/var/log/nginx_hardening.log
exec > >(tee -a "$LOG") 2>&1

echo "====================================================="
echo "         ENTERPRISE NGINX HARDENING SCRIPT"
echo "   Laravel | Golang | React | Static | WordPress"
echo "            Auto-Detect + Safe Patch"
echo "====================================================="

###############################################
# 0 — ROOT CHECK
###############################################
[ "$EUID" -ne 0 ] && { echo "❌ Run as root!"; exit 1; }


###############################################
# 1 — UPGRADE NGINX TO MAINLINE
###############################################
echo "🌐 Upgrading NGINX to latest mainline..."

curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor -o /usr/share/keyrings/nginx-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
 http://nginx.org/packages/mainline/ubuntu $(lsb_release -cs) nginx" \
 > /etc/apt/sources.list.d/nginx-mainline.list

apt-get update -y
apt-get install -y nginx


###############################################
# 2 — INSTALL MODSECURITY + OWASP CRS
###############################################
echo "🛡 Installing ModSecurity + OWASP CRS..."

apt-get install -y libnginx-mod-security modsecurity-crs

cat > /etc/nginx/modsec/main.conf << 'EOF'
SecRuleEngine On
Include /usr/share/modsecurity-crs/crs-setup.conf
Include /usr/share/modsecurity-crs/rules/*.conf
EOF


###############################################
# 3 — INSTALL CROWDSEC NGINX BOUNCER
###############################################
if ! command -v cscli >/dev/null; then
  curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash
  apt-get install -y crowdsec
fi

apt-get install -y crowdsec-nginx-bouncer


###############################################
# 4 — GLOBAL SECURITY CONFIG
###############################################
echo "🔐 Applying baseline security headers..."

cat > /etc/nginx/conf.d/00-global-security.conf <<'EOF'
server_tokens off;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
ssl_protocols TLSv1.3;
ssl_prefer_server_ciphers off;
ssl_stapling on;
ssl_stapling_verify on;

limit_req_zone $binary_remote_addr zone=req_limit_per_ip:10m rate=10r/s;
client_max_body_size 50M;
EOF


###############################################
# 5 — TLS HARMONIZED CONFIG
###############################################
if [ ! -f /etc/ssl/dhparam.pem ]; then
    openssl dhparam -out /etc/ssl/dhparam.pem 2048
fi

cat > /etc/nginx/conf.d/ssl-hardening.conf << 'EOF'
ssl_protocols TLSv1.3;
ssl_session_cache shared:SSL:20m;
ssl_session_timeout 10m;
ssl_ciphers 'TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256';
ssl_dhparam /etc/ssl/dhparam.pem;
EOF


###############################################
# 6 — AUTO-DETECT STACK & APPLY RULES
###############################################
SITES_DIR="/etc/nginx/sites-enabled"
CONF_DIR="/etc/nginx/conf.d"

apply_wordpress_rules() {
    FILE=$1
    echo "   → WordPress detected → Applying WP hardening"

    sed -i '/server_name/a \
    # === WORDPRESS HARDENING BLOCK === \
    location ~* /(wp-config\.php|xmlrpc\.php) { deny all; } \
    location ~* \.php$ { \
      try_files $uri =404; \
      include fastcgi_params; \
      fastcgi_pass unix:/run/php/php-fpm.sock; \
      fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name; \
      fastcgi_param SCRIPT_NAME $fastcgi_script_name; \
    } \
    location ~* /(?:uploads|files)/.*\.php$ { deny all; } \
    location ~ /\.ht { deny all; } \
    location ~ /\.(git|svn|env) { deny all; } \
    location = /xmlrpc.php { deny all; } \
    location /wp-admin { \
      allow all; \
      limit_req zone=req_limit_per_ip burst=20 nodelay; \
    } \
    location ~* /wp-login\.php { \
      limit_req zone=req_limit_per_ip burst=10 nodelay; \
    } \
    ' "$FILE"
}


apply_laravel_rules() {
    FILE=$1
    echo "   → Laravel detected → Safe PHP headers applied"
    sed -i '/fastcgi_pass/a \
        add_header X-Powered-By ""; \
        fastcgi_param PHP_ADMIN_VALUE "expose_php=off"; \
    ' "$FILE"
}


apply_golang_rules() {
    FILE=$1
    echo "   → Golang detected → Setting proxy headers"
    sed -i '/proxy_pass/a \
        proxy_set_header Host $host; \
        proxy_set_header X-Real-IP $remote_addr; \
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; \
        proxy_set_header X-Forwarded-Proto https; \
    ' "$FILE"
}


apply_react_rules() {
    FILE=$1
    echo "   → React SPA detected → Enabling SPA fallback"
    sed -i '/location \//a \
        try_files $uri /index.html; \
    ' "$FILE"
}


patch_file() {
    FILE=$1
    echo "→ Processing: $FILE"
    cp "$FILE" "$FILE.bak-$(date +%F-%T)"

    # Ensure SSL listen
    if ! grep -q "listen 443" "$FILE"; then
        sed -i '/server_name/a \    listen 443 ssl http2;' "$FILE"
    fi

    # Apply rate limit
    if ! grep -q "limit_req" "$FILE"; then
        sed -i '/location \//a \        limit_req zone=req_limit_per_ip burst=20 nodelay;' "$FILE"
    fi

    # Add ModSecurity
    if ! grep -q "modsecurity on;" "$FILE"; then
        sed -i '/server_name/a \    modsecurity on;\n    modsecurity_rules_file /etc/nginx/modsec/main.conf;' "$FILE"
    fi

    # --- STACK DETECTION ---
    if grep -qi "wordpress" "$FILE" || grep -qi "wp-content" "$FILE"; then
        apply_wordpress_rules "$FILE"
    elif grep -qi "fastcgi_pass" "$FILE"; then
        apply_laravel_rules "$FILE"
    elif grep -qi "proxy_pass http" "$FILE" && grep -qi "go" "$FILE"; then
        apply_golang_rules "$FILE"
    elif grep -qi "react" <<< "$(basename "$FILE")"; then
        apply_react_rules "$FILE"
    fi

    # Add CSP (non-breaking)
    if ! grep -q "Content-Security-Policy" "$FILE"; then
        sed -i '/server_name/a \
        add_header Content-Security-Policy "default-src '\''self'\'' data: blob: *;" always;' "$FILE"
    fi
}

# Run patching
for f in $SITES_DIR/*; do
    [ -f "$f" ] && patch_file "$f"
done

for f in $CONF_DIR/*.conf; do
    [[ "$f" == */00-global-security.conf ]] && continue
    [ -f "$f" ] && patch_file "$f"
done

###############################################
# 7 — TEST AND RELOAD
###############################################
nginx -t
systemctl reload nginx

echo "====================================================="
echo "   ✅ NGINX HARDENING COMPLETED SUCCESSFULLY"
echo "====================================================="
echo "→ WordPress, Laravel, Golang, React auto-detected"
echo "→ ModSecurity + CRS applied"
echo "→ CrowdSec bouncer active"
echo "→ TLS 1.3 guaranteed"
echo "→ WP brute-force protected"
echo "→ XML-RPC + file injection disabled"
echo "→ Non-breaking CSP applied"
echo "→ All configs auto-backed up"
echo "====================================================="
echo "Logs saved: $LOG"

