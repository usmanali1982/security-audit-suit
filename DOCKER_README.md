# Security Audit Suite - Docker Setup Guide

## Quick Start for Mac M3

This guide will help you set up and run the Security Audit Suite on your Mac M3 using Docker.

### Prerequisites

- Docker Desktop for Mac (with M3/ARM64 support)
- Basic terminal knowledge

### Step 1: Initial Setup

1. **Run the setup script:**
   ```bash
   ./docker-setup.sh
   ```

   This script will:
   - Check Docker installation
   - Create `.env` file from template
   - Create necessary directories
   - Build Docker images
   - Pull scanner images

2. **Configure your environment:**
   Edit the `.env` file with your settings:
   ```bash
   nano .env
   ```
   
   **Important settings:**
   - `TARGET_VM_IP`: IP address of the VM you want to scan
   - `NGINX_CONFIG_PATH`: Path to target VM's nginx configs (relative to project root)
   - `SECRET_KEY`: Change to a secure random key

3. **Copy target VM's nginx configs:**
   ```bash
   # Copy nginx configs from your target VM to ./target-vm-nginx/
   scp user@target-vm:/etc/nginx/sites-enabled/* ./target-vm-nginx/
   ```

### Step 2: Start the Stack

**Start core services (webapp + scanner):**
```bash
docker-compose up -d
```

**Start with all optional services (OpenVAS, Wazuh, Vault):**
```bash
docker-compose --profile full up -d
```

### Step 3: Access the Web Portal

1. Open your browser: http://localhost:5005

2. **Default credentials:**
   - Username: `admin`
   - Password: `ChangeMeNow!`
   - MFA Token: Use your authenticator app (QR code shown after first login)

⚠️ **Important**: Change the default password immediately after first login!

### Step 4: Run Your First Scan

1. Log in to the web portal
2. Click "Run Scan" button
3. Monitor the scan progress
4. View reports when scan completes

**Or trigger scan via Docker:**
```bash
docker-compose exec scanner python3 /opt/security-audit/reporting/run_full_scan.py --config /opt/security-audit/config.json
```

## Container Architecture

### Core Services (Always Running)

- **webapp**: Flask web application (port 5005)
- **scanner**: Scanning engine with all tools

### Optional Services (Use `--profile full`)

- **openvas**: OpenVAS/GVM vulnerability scanner (port 9392)
- **wazuh**: Wazuh SIEM manager (ports 1514/1515/55000)
- **wazuh-dashboard**: Wazuh dashboard (port 5601)
- **vault**: HashiCorp Vault for secrets (port 8200)

## Useful Commands

### View logs
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f webapp
docker-compose logs -f scanner
```

### Stop services
```bash
docker-compose down
```

### Restart a service
```bash
docker-compose restart webapp
```

### Execute commands in containers
```bash
# Access scanner container shell
docker-compose exec scanner bash

# Run a scan manually
docker-compose exec scanner python3 /opt/security-audit/reporting/run_full_scan.py --config /opt/security-audit/config.json
```

### Rebuild after code changes
```bash
docker-compose build --no-cache
docker-compose up -d
```

## Volume Mounts

Data persists in Docker volumes:
- `scan-data`: All scan results (`/var/security-scans`)
- `app-data`: Application data, database (`/opt/security-audit/data`)

To backup scan data:
```bash
docker run --rm -v security-audit-suite-full_scan-data:/data -v $(pwd):/backup alpine tar czf /backup/scan-data-backup.tar.gz -C /data .
```

## Network Access

The scanner container uses `host` network mode to access your target VMs on the local network. Make sure:
- Target VMs are reachable from your Mac
- Firewall rules allow scanning from your Mac's IP
- SSH keys are configured if needed

## Troubleshooting

### Port already in use
If port 5005 is in use, edit `docker-compose.yml` to change the port mapping.

### Scanner can't access target VM
- Check network connectivity: `ping <TARGET_VM_IP>`
- Verify firewall rules on target VM
- Check that scanner container has network access

### Database issues
Reset the database:
```bash
docker-compose down
docker volume rm security-audit-suite-full_app-data
docker-compose up -d
```

### ARM64 compatibility issues
All images are ARM64 compatible for Mac M3. If you encounter issues:
```bash
docker-compose build --no-cache --build-arg BUILDPLATFORM=linux/arm64
```

## Next Steps

1. Test scanning your target VM
2. Review generated reports
3. Configure notifications (Slack/Email) in `config.json`
4. Set up Ansible for production deployment

## Support

For issues or questions:
1. Check logs: `docker-compose logs -f`
2. Verify configuration in `.env` and `config.json`
3. Ensure Docker Desktop is running

