###################################################
#✅ Layer 2 — Host Security
#✔ This script → hardens server ✔ CrowdSec host IPS ✔ Fail2Ban ✔ Sysctl protections ✔ SSH hardened & upgraded
##################################################

#!/bin/bash
set -euo pipefail
LOG=/var/log/server_hardening.log
exec > >(tee -a "$LOG") 2>&1

echo "=============================================="
echo "     SERVER HARDENING SCRIPT (FINAL BUILD)"
echo "     Ubuntu 22.04 / 24.04  – DevOps Grade"
echo "=============================================="
echo "Run time: $(date)"
echo

#############################################
# 0. REQUIRE ROOT
#############################################
if [ "$EUID" -ne 0 ]; then
  echo "❌ This script must be run as root."
  exit 1
fi

#############################################
# 1. UPGRADE OPENSSH TO LATEST VERSION
#############################################
echo "🔐 [1/12] Upgrading OpenSSH to latest version..."

apt-get update -y
apt-get install -y openssh-server

echo "→ Installed OpenSSH Version:"
ssh -V || true

# OPTIONAL: Install latest OpenSSH from SOURCE (commented)
cat > /root/OPENSSH_SOURCE_INSTALL.txt <<'EOF'
To install latest OpenSSH manually:

apt install -y build-essential zlib1g-dev libssl-dev libpam0g-dev libselinux1-dev

wget https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-X.YpZ.tar.gz
tar xvf openssh-*.tar.gz
cd openssh-*
./configure --prefix=/usr --sysconfdir=/etc/ssh
make
make install

This **replaces system SSH** — ONLY for expert use.
EOF

#############################################
# 2. SYSTEM UPDATE + BASICS
#############################################
echo "📦 [2/12] Updating system and installing tools..."

apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

apt-get install -y \
  ufw fail2ban logwatch iftop htop git curl wget unzip \
  gnupg2 ca-certificates software-properties-common \
  lynis clamav apt-transport-https

freshclam || true

#############################################
# 3. SSH HARDENING
#############################################
echo "🔐 [3/12] Hardening SSH configuration..."

SSHD=/etc/ssh/sshd_config
cp -n $SSHD ${SSHD}.bak-$(date +%F-%T)

sed -i 's/^#\?Port .*/Port 9977/' $SSHD
sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin no/' $SSHD
sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication no/' $SSHD
sed -i 's/^#\?ChallengeResponseAuthentication .*/ChallengeResponseAuthentication no/' $SSHD
sed -i 's/^#\?UsePAM .*/UsePAM yes/' $SSHD

systemctl reload sshd || systemctl restart sshd
echo "→ SSH hardened & moved to port 9977."

#############################################
# 4. FIREWALL HARDENING
#############################################
echo "🧱 [4/12] Configuring UFW firewall..."

ufw --force reset

ufw allow 443/tcp               # HTTPS
ufw allow from 39.45.101.112 to any port 9977 proto tcp  # LAHORE OFFICE PTCL IP
ufw allow from 80.238.236.152 to any port 9977 proto tcp  # VPN SERVER IP
ufw deny 80/tcp                 # Force HTTPS at app level
ufw allow out on lo

ufw --force enable

#############################################
# 5. SYSCTL KERNEL HARDENING
#############################################
echo "⚙️ [5/12] Applying sysctl kernel hardening..."

cat > /etc/sysctl.d/99-kernel-hardening.conf <<'EOF'
# Disable IP forwarding
net.ipv4.ip_forward = 0

# Anti-spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# SYN flood protection
net.ipv4.tcp_syncookies = 1

# Log suspicious packets
net.ipv4.conf.all.log_martians = 1

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Ignore bogus ICMP messages
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Increase conntrack table size
net.netfilter.nf_conntrack_max = 262144
EOF

sysctl --system

#############################################
# 6. DISABLE UNNECESSARY SERVICES
#############################################
echo "🚫 [6/12] Disabling unused services..."

SERVICES=(apache2 rpcbind nfs-kernel-server exim4 cups smbd)
for svc in "${SERVICES[@]}"; do
  systemctl disable --now $svc 2>/dev/null || true
done

#############################################
# 7. FAIL2BAN CONFIG
#############################################
echo "🛡️ [7/12] Configuring Fail2Ban..."

cat > /etc/fail2ban/jail.d/security.local <<'EOF'
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 3

[sshd]
enabled = true
port = 9977
logpath = /var/log/auth.log
EOF

systemctl enable --now fail2ban

#############################################
# 8. CROWDSEC (Primary Host IPS)
#############################################
echo "🛡️ [8/12] Installing CrowdSec..."

curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash
apt-get install -y crowdsec crowdsec-firewall-bouncer-iptables

systemctl enable --now crowdsec
systemctl enable --now crowdsec-firewall-bouncer

#############################################
# 9. LOGWATCH SETUP
#############################################
echo "📨 [9/12] Configuring Logwatch..."

if [ -f /etc/logwatch/conf/logwatch.conf ]; then
  sed -i 's/^Output = .*/Output = mail/' /etc/logwatch/conf/logwatch.conf
fi

#############################################
# 10. LYNIS (Periodic Auditing)
#############################################
echo "🕵️ [10/12] Setting weekly Lynis audit..."

cat > /etc/cron.weekly/lynis_audit <<'EOF'
#!/bin/bash
/usr/sbin/lynis audit system --quiet > /var/log/lynis-weekly.log
EOF
chmod +x /etc/cron.weekly/lynis_audit

#############################################
# 11. PERMISSIONS & FINAL TOUCHES
#############################################
echo "🔒 [11/12] Securing file permissions..."

chmod 600 /root/.bash_history 2>/dev/null || true

#############################################
# 12. FINISHED
#############################################
echo
echo "=============================================="
echo "   ✅ SERVER HARDENING COMPLETE SUCCESSFULLY"
echo "=============================================="
echo "SSH Port: 9977"
echo "CrowdSec: Enabled"
echo "Fail2Ban: Enabled"
echo "Sysctl: Hardened"
echo "UFW: Active"
echo
echo "Logs saved at: $LOG"

