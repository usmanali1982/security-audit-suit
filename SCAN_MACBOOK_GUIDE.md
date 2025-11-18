# Scanning Your MacBook as Target VM

## Setup Complete ✅

I've created the `.env` file configured to scan your MacBook. Here's what's set up:

### Configuration

**`.env` file created with:**
- `TARGET_VM_IP=127.0.0.1` - Scanning localhost (your MacBook)
- `NGINX_CONFIG_PATH=./target-vm-nginx` - Directory for nginx configs
- All other settings configured

**`config.json` created with default settings**

### Quick Start

1. **Build and start Docker containers:**
   ```bash
   docker-compose build
   docker-compose up -d
   ```

2. **Verify containers are running:**
   ```bash
   docker-compose ps
   ```

3. **Access the web portal:**
   ```
   http://localhost:5005
   ```
   - Username: `admin`
   - Password: `ChangeMeNow!`

4. **Start a scan:**

   **Option A: Via Web UI**
   - Log in to the portal
   - Click "Run Scan" button

   **Option B: Via Command Line**
   ```bash
   docker-compose exec scanner python3 /opt/security-audit/reporting/run_full_scan.py --config /opt/security-audit/config.json
   ```

### What Will Be Scanned

When scanning `127.0.0.1` (localhost), the scanner will:
- ✅ Run Lynis system audit
- ✅ Scan with Trivy for vulnerabilities
- ✅ Run nmap on localhost (if services are running)
- ✅ Scan any nginx domains found in `./target-vm-nginx/`
- ✅ Run Nikto scans on discovered domains
- ✅ Run OWASP ZAP baseline scans
- ✅ Malware/rootkit checks (may be limited in Docker)

### Important Notes for MacBook Scanning

1. **Services must be running:**
   - For web scans: nginx/web server should be running
   - For port scans: services should be listening

2. **Nginx configs:**
   - I've created `./target-vm-nginx/` directory
   - If you have nginx running, copy your configs:
     ```bash
     # For Homebrew nginx
     cp /opt/homebrew/etc/nginx/servers/*.conf ./target-vm-nginx/
     
     # For standard install
     cp /usr/local/etc/nginx/servers/*.conf ./target-vm-nginx/
     ```

3. **Network scanning from container:**
   - Container uses bridge network
   - `127.0.0.1` scans will scan the container itself
   - To scan your MacBook from container, you may need to use `host.docker.internal`

### Alternative: Scan MacBook's Network IP

If you want to scan your MacBook from the container perspective:

1. **Edit `.env`:**
   ```bash
   # Use your Mac's network IP instead
   TARGET_VM_IP=192.168.88.150  # Your detected IP
   ```

2. **Restart scanner:**
   ```bash
   docker-compose restart scanner
   ```

### Monitor Scan Progress

**View scanner logs:**
```bash
docker-compose logs -f scanner
```

**View all logs:**
```bash
docker-compose logs -f
```

### View Results

1. **Via Web Portal:**
   - After scan completes, click on the scan timestamp in the list
   - Download HTML/PDF reports

2. **Via Command Line:**
   ```bash
   # List scan directories
   docker-compose exec webapp ls -la /var/security-scans
   
   # View a specific scan
   docker-compose exec webapp ls -la /var/security-scans/<scan-timestamp>
   ```

### Testing Individual Scans

You can test individual tools:

```bash
# Test nmap from scanner container
docker-compose exec scanner nmap -sV 127.0.0.1

# Test trivy
docker-compose exec scanner trivy fs --severity HIGH,CRITICAL /opt

# Test lynis
docker-compose exec scanner lynis audit system --quick
```

### Troubleshooting

**Container can't scan localhost:**
- The scanner container's `127.0.0.1` is the container itself
- Use `host.docker.internal` to reach your Mac from container
- Or use your Mac's network IP (`192.168.88.150`)

**No nginx configs found:**
- Place nginx config files in `./target-vm-nginx/`
- Or modify the scanner to scan specific domains manually

**Scan takes too long:**
- Some scans (ClamAV full system, Trivy full filesystem) can take time
- Timeouts are set, but initial runs may be slow

---

## Next Steps

1. ✅ Start containers: `docker-compose up -d`
2. ✅ Access web portal and run scan
3. ✅ Review generated reports
4. ✅ When satisfied, proceed to Step 2 improvements

