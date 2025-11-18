#!/usr/bin/env bash
set -euo pipefail

echo "🔒 Security Audit Suite - Ubuntu 22.04 Jump Server Setup"
echo "=========================================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "⚠️  Please run as root or with sudo"
    exit 1
fi

# Check Docker installation
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    echo "   Run: curl -fsSL https://get.docker.com -o get-docker.sh && sh get-docker.sh"
    exit 1
fi

if ! docker info &> /dev/null; then
    echo "❌ Docker is not running. Starting Docker service..."
    systemctl start docker
    systemctl enable docker
fi

echo "✅ Docker is installed and running"

# Check docker-compose
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "⚠️  docker-compose not found. Installing..."
    apt-get update
    apt-get install -y docker-compose-plugin || apt-get install -y docker-compose
fi

echo "✅ Docker Compose is available"

# Get the directory where script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "📁 Working directory: $SCRIPT_DIR"

# Check if .env exists, create from template if not
if [ ! -f .env ]; then
    echo "⚠️  .env file not found. Creating from template..."
    cat > .env <<'ENVEOF'
# Security Audit Suite - Environment Configuration
# Configuration for Ubuntu Jump Server

# Flask Web Application
SECRET_KEY=$(openssl rand -hex 32)
FLASK_ENV=production

# Target VM Configuration
# Set this to the IP of VMs you want to scan from this jump server
TARGET_VM_IP=

# Path to target VM's nginx configs (mounted directory)
NGINX_CONFIG_PATH=./target-vm-nginx

# Optional: SSH key for accessing target VMs
TARGET_VM_SSH_KEY=

# Optional Service Versions
WAZUH_VERSION=4.7.0
VAULT_VERSION=1.15.2

# Timezone
TZ=UTC

# Vault Configuration (if using vault profile)
VAULT_ROOT_TOKEN=$(openssl rand -hex 16)
ENVEOF
    echo "✅ Created .env file - please edit with your settings"
else
    echo "✅ .env file exists"
fi

# Create config.json if it doesn't exist
if [ ! -f config.json ]; then
    echo "⚠️  config.json not found. Creating default..."
    cat > config.json <<'JSONEOF'
{
  "out_dir_base": "/var/security-scans",
  "nginx_sites_enabled": "/etc/nginx/sites-enabled",
  "zap": { "use_active_scan": false },
  "slack": { "webhook_url": "" },
  "smtp": { "host":"", "port":587, "username":"", "password":"", "from":"", "to":[""] },
  "zip_reports": true,
  "openvas_enabled": true,
  "vault": { "mode": "production", "addr": "http://vault:8200" },
  "wazuh": { "deploy_manager": true }
}
JSONEOF
    echo "✅ Created config.json"
else
    echo "✅ config.json exists"
fi

# Create necessary directories
mkdir -p ./target-vm-nginx
echo "✅ Created target-vm-nginx directory"

# Generate secure SECRET_KEY if not set in .env
if grep -q "SECRET_KEY=\$(openssl rand" .env 2>/dev/null; then
    SECRET_KEY=$(openssl rand -hex 32)
    sed -i "s|SECRET_KEY=\$(openssl rand -hex 32)|SECRET_KEY=$SECRET_KEY|" .env
    echo "✅ Generated secure SECRET_KEY"
fi

if grep -q "VAULT_ROOT_TOKEN=\$(openssl rand" .env 2>/dev/null; then
    VAULT_TOKEN=$(openssl rand -hex 16)
    sed -i "s|VAULT_ROOT_TOKEN=\$(openssl rand -hex 16)|VAULT_ROOT_TOKEN=$VAULT_TOKEN|" .env
    echo "✅ Generated secure VAULT_ROOT_TOKEN"
fi

# Build Docker images
echo ""
echo "🔨 Building Docker images (this may take a few minutes)..."
docker compose build --pull || docker-compose build --pull

# Pull additional scanner images
echo ""
echo "📥 Pulling scanner Docker images..."
docker pull owasp/zap2docker-stable:latest || echo "⚠️  Could not pull OWASP ZAP"
docker pull sqlmapproject/sqlmap:latest || echo "⚠️  Could not pull SQLMap"
docker pull aquasecurity/trivy:latest || echo "⚠️  Could not pull Trivy"
docker pull wpscanteam/wpscan:latest || echo "⚠️  Could not pull WPScan"

# Set proper permissions
chmod +x scan.sh docker-setup.sh 2>/dev/null || true

echo ""
echo "✅ Setup complete!"
echo ""
echo "📋 Next steps:"
echo "   1. Edit .env file: nano .env"
echo "      - Set TARGET_VM_IP if you have a default target"
echo "      - Configure other settings as needed"
echo ""
echo "   2. Start the stack:"
echo "      docker compose up -d"
echo "      (or: docker-compose up -d)"
echo ""
echo "   3. Access web portal:"
echo "      http://$(hostname -I | awk '{print $1}'):5005"
echo "      or: http://localhost:5005 (if accessed from jump server)"
echo ""
echo "   4. Default login credentials:"
echo "      Username: admin"
echo "      Password: ChangeMeNow!"
echo ""
echo "   5. View logs:"
echo "      docker compose logs -f"
echo ""
echo "   6. Run a test scan:"
echo "      docker compose exec scanner python3 /opt/security-audit/reporting/run_full_scan.py --config /opt/security-audit/config.json"
echo ""

