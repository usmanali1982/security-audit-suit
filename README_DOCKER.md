# Security Audit Suite - Docker Quick Start

## 🚀 Quick Setup on Mac M3

### Prerequisites
- Docker Desktop for Mac (ARM64/M3 compatible)
- Terminal access

### Step-by-Step Setup

1. **Run the setup script:**
   ```bash
   ./docker-setup.sh
   ```

2. **Ensure the shared data directory is writable (needed for SQLite inside Docker):**
   ```bash
   mkdir -p ./data
   chmod 777 ./data
   ```

3. **Edit `.env` file:**
   ```bash
   nano .env
   ```
   Set `TARGET_VM_IP` to your target VM's IP address.

4. **Copy target VM's nginx configs (if available):**
   ```bash
   mkdir -p ./target-vm-nginx
   # Copy nginx configs from your target VM:
   scp user@target-vm:/etc/nginx/sites-enabled/* ./target-vm-nginx/
   ```

5. **Start the stack:**
   ```bash
   docker-compose up -d
   ```

6. **Access the web portal:**
   Open http://localhost:5005
   - Username: `admin`
   - Password: `ChangeMeNow!`

### Run a Scan

**Via Web UI:**
- Log in and click "Run Scan"

**Via Command Line:**
```bash
docker-compose exec scanner python3 /opt/security-audit/reporting/run_full_scan.py --config /opt/security-audit/config.json
```

### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f webapp
docker-compose logs -f scanner
```

### Stop Services

```bash
docker-compose down
```

### Start with Optional Services

```bash
docker-compose --profile full up -d
```

This starts OpenVAS, Wazuh, and Vault in addition to the core services.

---

## 📋 What's Changed for Docker

- ✅ All services containerized
- ✅ ARM64 compatible for Mac M3
- ✅ Persistent volumes for data
- ✅ Environment variable configuration
- ✅ Docker socket access for scanner containers
- ✅ Network configuration for target VM scanning

---

## 🔧 Troubleshooting

**Port 5005 already in use:**
Edit `docker-compose.yml` and change the port mapping.

**`sqlite3.OperationalError: unable to open database file`:**
- Make sure the host `./data` directory exists and run `chmod 777 ./data`
- Re-run `./docker-setup.sh` (it now creates the directory automatically)
- Restart the stack: `docker-compose up -d --force-recreate`

**Scanner can't reach target VM:**
- Ensure target VM is reachable: `ping <TARGET_VM_IP>`
- Check firewall rules on target VM
- Verify network connectivity

**Database reset:**
```bash
docker-compose down
docker volume rm security-audit-suite-full_app-data
docker-compose up -d
```

