# Security Audit Suite - Ubuntu 22.04 Jump Server Setup Guide

## Prerequisites

- Ubuntu 22.04 VM (Jump Server)
- Docker and Docker Compose installed
- Git installed (for cloning)
- Root or sudo access
- Network access to target VMs

## Quick Setup Commands

### 1. Clone Repository (if not already cloned)

```bash
cd /opt  # or your preferred directory
git clone <your-github-repo-url> security-audit-suite-full
cd security-audit-suite-full
```

### 2. Run Automated Setup Script

```bash
chmod +x setup-ubuntu-jump-server.sh
sudo ./setup-ubuntu-jump-server.sh
```

This script will:
- ✅ Verify Docker installation
- ✅ Create `.env` file with secure keys
- ✅ Create `config.json`
- ✅ Build Docker images
- ✅ Pull scanner images
- ✅ Set up directories

### 3. Configure Environment

Edit the `.env` file:

```bash
sudo nano .env
```

**Key settings:**
- `TARGET_VM_IP` - Leave empty if scanning different VMs, or set default
- `SECRET_KEY` - Already generated securely
- `NGINX_CONFIG_PATH` - Path for nginx configs (default: ./target-vm-nginx)

### 4. Start the Stack

```bash
# Start core services
docker compose up -d

# Or with docker-compose (older syntax)
docker-compose up -d

# Start with all optional services (OpenVAS, Wazuh, Vault)
docker compose --profile full up -d
```

### 5. Access Web Portal

**From jump server:**
```bash
curl http://localhost:5005
```

**From your local machine (SSH tunnel):**
```bash
ssh -L 5005:localhost:5005 user@jump-server-ip
# Then open: http://localhost:5005
```

**Direct access (if firewall allows):**
```
http://<jump-server-ip>:5005
```

**Default credentials:**
- Username: `admin`
- Password: `ChangeMeNow!`
- ⚠️ **Change password immediately after first login!**

## Manual Setup (Alternative)

If you prefer manual setup:

### 1. Install Docker (if not installed)

```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo systemctl enable docker
sudo systemctl start docker
```

### 2. Install Docker Compose

```bash
sudo apt-get update
sudo apt-get install -y docker-compose-plugin
# Or for older versions:
sudo apt-get install -y docker-compose
```

### 3. Create Environment File

```bash
cat > .env <<'EOF'
SECRET_KEY=$(openssl rand -hex 32)
FLASK_ENV=production
TARGET_VM_IP=
NGINX_CONFIG_PATH=./target-vm-nginx
TZ=UTC
WAZUH_VERSION=4.7.0
VAULT_VERSION=1.15.2
VAULT_ROOT_TOKEN=$(openssl rand -hex 16)
EOF

# Generate actual secrets
SECRET_KEY=$(openssl rand -hex 32)
VAULT_TOKEN=$(openssl rand -hex 16)
sed -i "s|\$(openssl rand -hex 32)|$SECRET_KEY|" .env
sed -i "s|\$(openssl rand -hex 16)|$VAULT_TOKEN|" .env
```

### 4. Create Config File

```bash
cat > config.json <<'EOF'
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
EOF
```

### 5. Build and Start

```bash
mkdir -p ./target-vm-nginx
docker compose build
docker compose up -d
```

## Useful Commands

### View Status

```bash
# Check container status
docker compose ps

# View logs
docker compose logs -f

# View specific service logs
docker compose logs -f webapp
docker compose logs -f scanner
```

### Run a Scan

**Via Web UI:**
1. Access web portal
2. Log in
3. Click "Run Scan"

**Via Command Line:**
```bash
# Scan with default config
docker compose exec scanner python3 /opt/security-audit/reporting/run_full_scan.py --config /opt/security-audit/config.json

# Scan specific target IP (override env var)
TARGET_VM_IP=192.168.1.100 docker compose exec scanner python3 /opt/security-audit/reporting/run_full_scan.py --config /opt/security-audit/config.json
```

### Stop/Start/Restart

```bash
# Stop all services
docker compose down

# Start services
docker compose up -d

# Restart specific service
docker compose restart webapp
docker compose restart scanner

# Rebuild after code changes
docker compose build --no-cache
docker compose up -d
```

### Access Container Shell

```bash
# Web app container
docker compose exec webapp bash

# Scanner container
docker compose exec scanner bash
```

### View Scan Results

```bash
# List all scans
docker compose exec webapp ls -la /var/security-scans

# View specific scan
docker compose exec webapp ls -la /var/security-scans/<scan-timestamp>

# Download reports
docker compose exec webapp cat /var/security-scans/<scan-timestamp>/final_report/server_report.html
```

## Network Configuration

### Firewall Rules (UFW)

If UFW is enabled, allow port 5005:

```bash
sudo ufw allow 5005/tcp
sudo ufw status
```

### SSH Tunnel (Secure Access)

From your local machine:

```bash
ssh -L 5005:localhost:5005 user@jump-server-ip
# Then open: http://localhost:5005
```

### Access from Network

To allow network access to web portal:

1. **Check firewall:**
   ```bash
   sudo ufw allow 5005/tcp
   ```

2. **Access via:**
   ```
   http://<jump-server-ip>:5005
   ```

3. **For production, consider:**
   - Nginx reverse proxy with SSL
   - VPN access only
   - IP whitelisting

## Security Considerations

1. **Change default password immediately**
2. **Use strong SECRET_KEY** (already generated)
3. **Restrict network access** (firewall, VPN)
4. **Use HTTPS in production** (reverse proxy with nginx/HAProxy)
5. **Regular updates:** `docker compose pull && docker compose up -d`
6. **Backup scan data regularly**
7. **Rotate secrets periodically**

## Troubleshooting

### Port Already in Use

```bash
# Check what's using port 5005
sudo netstat -tlnp | grep 5005
# Or
sudo ss -tlnp | grep 5005

# Change port in docker-compose.yml
nano docker-compose.yml
# Edit: "5005:5005" to "5006:5005"
```

### Container Won't Start

```bash
# Check logs
docker compose logs webapp
docker compose logs scanner

# Check Docker daemon
sudo systemctl status docker

# Restart Docker
sudo systemctl restart docker
```

### Permission Issues

```bash
# Fix permissions
sudo chown -R $USER:$USER .
sudo chmod +x *.sh

# Docker socket permissions
sudo usermod -aG docker $USER
newgrp docker
```

### Scanner Can't Reach Target VMs

```bash
# Test connectivity from jump server
ping <target-vm-ip>

# Test from scanner container
docker compose exec scanner ping <target-vm-ip>

# Check network configuration
docker compose exec scanner ip addr
```

### Rebuild After Updates

```bash
# Pull latest code
git pull

# Rebuild containers
docker compose build --no-cache

# Restart services
docker compose down
docker compose up -d
```

## Next Steps

1. ✅ Test scan on jump server itself
2. ✅ Verify web portal access
3. ✅ Test scanning a target VM
4. ✅ Configure Ansible for multi-VM deployment
5. ✅ Set up automated scans
6. ✅ Configure notifications (Slack/Email)

## Production Deployment Tips

1. **Use systemd service** for auto-start:
   ```bash
   sudo tee /etc/systemd/system/security-audit.service <<EOF
   [Unit]
   Description=Security Audit Suite
   Requires=docker.service
   After=docker.service
   
   [Service]
   Type=oneshot
   RemainAfterExit=yes
   WorkingDirectory=/opt/security-audit-suite-full
   ExecStart=/usr/bin/docker compose up -d
   ExecStop=/usr/bin/docker compose down
   
   [Install]
   WantedBy=multi-user.target
   EOF
   
   sudo systemctl enable security-audit.service
   sudo systemctl start security-audit.service
   ```

2. **Set up reverse proxy with SSL:**
   ```bash
   sudo apt-get install -y nginx certbot python3-certbot-nginx
   # Configure nginx to proxy to localhost:5005
   # Use certbot for SSL certificates
   ```

3. **Backup scan data:**
   ```bash
   # Backup script
   docker run --rm -v security-audit-suite-full_scan-data:/data \
     -v /backup:/backup alpine \
     tar czf /backup/scan-data-$(date +%Y%m%d).tar.gz -C /data .
   ```

4. **Monitor disk space** (scans generate large reports)

---

## Support

For issues:
1. Check logs: `docker compose logs -f`
2. Verify configuration: `.env` and `config.json`
3. Test connectivity to target VMs
4. Check Docker status: `sudo systemctl status docker`

