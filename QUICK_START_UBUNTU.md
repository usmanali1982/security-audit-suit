# Quick Start - Ubuntu 22.04 Jump Server

## 🚀 Fastest Setup (Copy-Paste Ready)

```bash
# 1. Navigate to your cloned repository
cd /path/to/security-audit-suite-full

# 2. Make setup script executable and run it
chmod +x setup-ubuntu-jump-server.sh
sudo ./setup-ubuntu-jump-server.sh

# 3. Start the stack
docker compose up -d

# 4. Check status
docker compose ps

# 5. View logs
docker compose logs -f webapp
```

## 🌐 Access Web Portal

**Option 1: SSH Tunnel (Recommended for Security)**
```bash
# From your local machine
ssh -L 5005:localhost:5005 user@jump-server-ip
# Then open: http://localhost:5005
```

**Option 2: Direct Access (if firewall allows)**
```bash
# Allow port in firewall
sudo ufw allow 5005/tcp

# Access via browser
http://<jump-server-ip>:5005
```

**Login:**
- Username: `admin`
- Password: `ChangeMeNow!`
- ⚠️ **Change immediately after first login!**

## 🔍 Run Your First Scan

**Via Web UI:**
1. Log in to portal
2. Click "Run Scan" button
3. Wait for completion
4. View reports

**Via Command Line:**
```bash
# Scan jump server itself
docker compose exec scanner python3 /opt/security-audit/reporting/run_full_scan.py --config /opt/security-audit/config.json

# Scan specific target VM
TARGET_VM_IP=192.168.1.100 docker compose exec scanner python3 /opt/security-audit/reporting/run_full_scan.py --config /opt/security-audit/config.json
```

## 📊 View Results

```bash
# List scans
docker compose exec webapp ls -la /var/security-scans

# View latest scan
LATEST=$(docker compose exec webapp ls -t /var/security-scans | head -1)
docker compose exec webapp ls -la /var/security-scans/$LATEST/final_report/
```

## 🛠️ Common Commands

```bash
# Stop services
docker compose down

# Restart services
docker compose restart

# View logs
docker compose logs -f

# Update and rebuild
git pull
docker compose build --no-cache
docker compose up -d
```

---

**That's it!** Your security audit suite is ready. See `UBUNTU_JUMP_SERVER_SETUP.md` for detailed documentation.

