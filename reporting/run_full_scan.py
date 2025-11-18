#!/usr/bin/env python3
import os, sys, json, subprocess, argparse, datetime, shutil
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--config", required=True)
args = parser.parse_args()
cfg = json.load(open(args.config))
OUT_BASE = cfg.get("out_dir_base", "/var/security-scans")
ts = datetime.datetime.utcnow().strftime("%Y-%m-%d_%H%M%S")
OUT = os.path.join(OUT_BASE, ts)
os.makedirs(OUT, exist_ok=True)
print("Scan output:", OUT)

# 1. Discover nginx server_names
domains_file = os.path.join(OUT, "nginx_domains.txt")
sites_dir = cfg.get("nginx_sites_enabled", "/etc/nginx/sites-enabled")
domains = set()
if os.path.isdir(sites_dir):
    for p in Path(sites_dir).glob("*"):
        try:
            txt = p.read_text()
            for line in txt.splitlines():
                if 'server_name' in line:
                    part = line.split('server_name',1)[1]
                    for tok in part.replace(';',' ').split():
                        if tok.strip():
                            domains.add(tok.strip())
        except Exception:
            pass
with open(domains_file,"w") as f:
    f.write("\n".join(sorted(domains)))
print("Domains discovered:", len(domains))

# 2. Run host-level scans
print("Running Lynis...")
subprocess.run(["lynis","audit","system","--quiet","--logfile", os.path.join(OUT,"lynis.log")])
print("Running Trivy fs...")
# Try Trivy via Docker if not available natively
try:
    # First try native trivy
    subprocess.run(["trivy","fs","--severity","HIGH,CRITICAL","/"], 
                   stdout=open(os.path.join(OUT,"trivy-fs.json"),"w"), 
                   stderr=subprocess.DEVNULL, check=False, timeout=600)
except (FileNotFoundError, subprocess.TimeoutExpired):
    # Fallback to Docker Trivy
    try:
        print("Using Trivy via Docker...")
        docker_cmd = ["docker", "run", "--rm", "-v", f"{OUT}:/output:rw",
                     "aquasecurity/trivy:latest", "fs", "--severity", "HIGH,CRITICAL",
                     "--format", "json", "/"]
        result = subprocess.run(docker_cmd, capture_output=True, text=True, timeout=600, check=False)
        with open(os.path.join(OUT,"trivy-fs.json"),"w") as f:
            f.write(result.stdout)
    except Exception as e:
        print(f"Trivy scan failed: {e}")

# 3. Nmap local (get target IP from config or environment)
target_ip = os.environ.get('TARGET_VM_IP', None)
if target_ip:
    print(f"Scanning target VM: {target_ip}")
    subprocess.run(["nmap","-sV","-O","-Pn","--script","vuln", target_ip, "-oN", os.path.join(OUT,"nmap-local.txt")], check=False)
else:
    # Fallback to local IP detection
    try:
        local_ip = subprocess.check_output(["hostname","-I"]).decode().split()[0]
        if local_ip:
            subprocess.run(["nmap","-sV","-O","-Pn","--script","vuln", local_ip, "-oN", os.path.join(OUT,"nmap-local.txt")], check=False)
    except Exception:
        print("Warning: Could not determine IP for nmap scan")

# 4. Run nikto and zap baseline for domains
zap_out = os.path.join(OUT,"zap")
os.makedirs(zap_out, exist_ok=True)
with open(domains_file) as f:
    for d in [l.strip() for l in f if l.strip()]:
        safe = d.replace('/','_').replace(':','_')
        print("Scanning domain:", d)
        subprocess.run(["nikto","-host",f"http://{d}","-output",os.path.join(OUT,f"nikto-http-{safe}.txt")], stderr=subprocess.DEVNULL)
        subprocess.run(["nikto","-host",f"https://{d}","-output",os.path.join(OUT,f"nikto-https-{safe}.txt")], stderr=subprocess.DEVNULL)
        # zap baseline via docker (if docker available)
        try:
            # Check if we're in a container with docker socket or have docker CLI
            # Try new image name first (zaproxy/zap-stable), fallback to old name
            zap_images = ["zaproxy/zap-stable", "owasp/zap2docker-stable"]
            zap_image = None
            for img in zap_images:
                # Check if image exists locally, if not try to pull
                result = subprocess.run(["docker", "images", "-q", img], 
                                       capture_output=True, text=True, timeout=5)
                if result.returncode == 0 and result.stdout.strip():
                    zap_image = img
                    break
                # Try to pull if not available
                pull_result = subprocess.run(["docker", "pull", img], 
                                            capture_output=True, stderr=subprocess.DEVNULL, timeout=60)
                if pull_result.returncode == 0:
                    zap_image = img
                    break
            
            if not zap_image:
                print(f"⚠️  ZAP image not available, skipping ZAP scan for {d}")
                continue
                
            docker_cmd = ["docker", "run", "--rm", "--network", "host", 
                         "-v", f"{zap_out}:/zap/wrk:rw",
                         zap_image, 
                         "zap-baseline.py", "-t", f"http://{d}", 
                         "-r", f"{safe}-baseline.html", 
                         "-J", f"{safe}-baseline.json", 
                         "-z", "-config", "api.disablekey=true"]
            # Try with docker socket mount if available
            if os.path.exists("/var/run/docker.sock"):
                docker_cmd.insert(2, "-v")
                docker_cmd.insert(3, "/var/run/docker.sock:/var/run/docker.sock")
            subprocess.run(docker_cmd, check=False, timeout=300)
        except subprocess.TimeoutExpired:
            print(f"ZAP scan for {d} timed out")
        except Exception as e:
            print(f"ZAP scan for {d} failed: {e}")

# 5. Malware/rootkit (skip full system scans in container, only scan mounted volumes if needed)
print("Running malware/rootkit scans...")
# Note: These tools scan the full filesystem. In Docker, we might want to skip or limit scope
try:
    subprocess.run(["clamscan","-r","/","--quiet","--infected"], 
                   stdout=open(os.path.join(OUT,"clamav.txt"),"w"), 
                   stderr=subprocess.DEVNULL, timeout=1800, check=False)
except subprocess.TimeoutExpired:
    print("ClamAV scan timed out (skipping)")

try:
    subprocess.run(["rkhunter","--update"], stderr=subprocess.DEVNULL, timeout=300, check=False)
    subprocess.run(["rkhunter","-c","--sk","--rwo"], 
                   stdout=open(os.path.join(OUT,"rkhunter.txt"),"w"), 
                   timeout=600, check=False)
except (subprocess.TimeoutExpired, FileNotFoundError):
    print("rkhunter not available or timed out")

try:
    subprocess.run(["chkrootkit"], 
                   stdout=open(os.path.join(OUT,"chkrootkit.txt"),"w"), 
                   timeout=600, check=False)
except (subprocess.TimeoutExpired, FileNotFoundError):
    print("chkrootkit not available or timed out")

# 6. Copy logs and metadata
shutil.copy("/var/log/syslog", os.path.join(OUT,"syslog_tail.txt")) if os.path.exists("/var/log/syslog") else None
open(os.path.join(OUT,"summary.txt"),"w").write("Scan completed: "+ts)
# 7. Generate report (call report engine)
report_script = os.path.join("/opt/security-audit","generate_report.py")
if os.path.exists(report_script):
    subprocess.run(["python3", report_script, "--scan-dir", OUT, "--config", args.config])
else:
    print("Report generator not found at", report_script)
print("Scan finished")
