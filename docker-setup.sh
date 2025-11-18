#!/usr/bin/env bash
set -euo pipefail

echo "🔒 Security Audit Suite - Docker Setup for Mac M3"
echo "=================================================="

# Check if Docker is installed and running
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker Desktop for Mac."
    exit 1
fi

if ! docker info &> /dev/null; then
    echo "❌ Docker is not running. Please start Docker Desktop."
    exit 1
fi

echo "✅ Docker is installed and running"

# Check for .env file
if [ ! -f .env ]; then
    echo "⚠️  .env file not found. Creating from .env.example..."
    if [ -f .env.example ]; then
        cp .env.example .env
        echo "✅ Created .env file. Please edit it with your configuration."
        echo "   Important: Update TARGET_VM_IP and NGINX_CONFIG_PATH"
    else
        echo "❌ .env.example not found. Please create .env manually."
        exit 1
    fi
fi

# Create target-vm-nginx directory if it doesn't exist
if [ ! -d "./target-vm-nginx" ]; then
    mkdir -p ./target-vm-nginx
    echo "📁 Created ./target-vm-nginx directory"
    echo "   Place your target VM's nginx site configs here"
fi

# Create config.json if it doesn't exist
if [ ! -f config.json ]; then
    echo "⚠️  config.json not found. Creating default..."
    cat > config.json <<'JSON'
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
JSON
    echo "✅ Created config.json"
fi

# Build Docker images
echo ""
echo "🔨 Building Docker images..."
docker-compose build --pull

# Pull additional scanner images
echo ""
echo "📥 Pulling scanner Docker images..."
docker pull owasp/zap2docker-stable:latest || echo "⚠️  Could not pull OWASP ZAP"
docker pull sqlmapproject/sqlmap:latest || echo "⚠️  Could not pull SQLMap"
docker pull aquasecurity/trivy:latest || echo "⚠️  Could not pull Trivy"
docker pull wpscanteam/wpscan:latest || echo "⚠️  Could not pull WPScan"

echo ""
echo "✅ Setup complete!"
echo ""
echo "📋 Next steps:"
echo "   1. Edit .env file with your target VM IP and nginx config path"
echo "   2. Place target VM's nginx configs in ./target-vm-nginx/"
echo "   3. Start the stack: docker-compose up -d"
echo "   4. Access web portal: http://localhost:5005"
echo "   5. Default login: admin / ChangeMeNow!"
echo ""
echo "🚀 To start the stack:"
echo "   docker-compose up -d"
echo ""
echo "📊 To view logs:"
echo "   docker-compose logs -f webapp"
echo ""
echo "🛑 To stop the stack:"
echo "   docker-compose down"

