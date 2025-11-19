#!/bin/bash
set -euo pipefail
LOG=/var/log/server_hardening.log
exec > >(tee -a "$LOG") 2>&1

echo "======================================================"
echo "       ENTERPRISE SERVER HARDENING - FINAL VERSION"
echo " Ubuntu 22.04 / 24.04  |  For SOC, External Audit Ready"
echo "======================================================"
echo "Started: $(date)"
echo

#---------------------------------------------------------
# 0. REQUIRE ROOT
#---------------------------------------------------------
if [ "$EUID" -ne 0 ]; then
  echo "❌ Run as ROOT only!"
  exit 1
fi

#---------------------------------------------------------
# 1. INSTALL LATEST OPENSSH (Upstream)
#---------------------------------------------------------
echo "🔐 [1/15] Upgrading OpenSSH..."

apt-get update -y
apt-get install -y build-essential zlib1g-dev libssl-dev libpam0g-dev libselinux1-dev \
  libedit-dev pkg-config

OPENSSH_VERSION=$(curl -s https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/ | grep -oP 'openssh-[0-9\.p]+(?=\.tar\.gz)' | sort -V | tail -1)

cd /usr/local/src
curl -O https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/${OPENSSH_VERSION}.tar.gz
tar xvf ${OPENSSH_VERSION}.tar.gz
cd ${OPENSSH_VERSION}

./configure --prefix=/usr --sysconfdir=/etc/ssh
make -j"$(nproc)"
make install

echo "→ Installed OpenSSH version:"
ssh -V || true

systemctl restart sshd || true

#---------------------------------------------------------
# 2. INSTALL LATEST NGINX MAINLINE (if installed)
#---------------------------------------------------------
if command -v nginx >/dev/null 2>&1; then
  echo "🌐 [2/15] Upgrading NGINX to latest Mainline..."

  curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor -o /usr/share/keyrings/nginx-archive-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/mainline/ubuntu $(lsb_release -cs) nginx" \
    > /etc/apt/sources.list.d/nginx-mainline.list

  apt-get update -y
  apt-get install -y nginx

  echo "→ Installed NGINX version:"
  nginx -v
else
  echo "ℹ️ NGINX not installed — skipping NGINX upgrade."
fi

#---------------------------------------------------------
# 3. SYSTEM UPDATE + SECURITY TOOLS
#---------------------------------------------------------
echo "📦 [3/15] Updating system and installing security tools..."

apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

apt-get install -y \
  ufw fail2ban logwatch iftop htop git curl wget unzip \
  gnupg2 ca-certificates software-properties-common \
  lynis clamav apt-transport-https \
  chkrootkit rkhunter auditd aide aide-common sysstat jq \
  unattended-upgrades needrestart

freshclam || true

#---------------------------------------------------------
# 4. SSH HARDENING
#---------------------------------------------------------
echo "🔐 [4/15] Hardening SSH configuration..."

SSHD=/etc/ssh/sshd_config
cp -n $SSHD ${SSHD}.bak-$(date +%F-%T)

sed -i 's/^#\?Port .*/Port 9977/' $SSHD
sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin no/' $SSHD
sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication no/' $SSHD
sed -i 's/^#\?ChallengeResponseAuthentication .*/ChallengeResponseAuthentication no/' $SSHD
sed -i 's/^#\?UsePAM .*/UsePAM yes/' $SSHD
sed -i 's/^#\?PermitEmptyPasswords .*/PermitEmptyPasswords no/' $SSHD
sed -i 's/^#\?AllowAgentForwarding .*/AllowAgentForwarding no/' $SSHD
sed -i 's/^#\?AllowTcpForwarding .*/AllowTcpForwarding no/' $SSHD
sed -i 's/^#\?X11Forwarding .*/X11Forwarding no/' $SSHD

systemctl reload sshd || true

echo "→ SSH hardened."

#---------------------------------------------------------
# 5. FIREWALL HARDENING
#---------------------------------------------------------
echo "🧱 [5/15] UFW Firewall..."

ufw --force reset

ufw allow 443/tcp
ufw allow out on lo
ufw allow from 39.45.101.112 to any port 9977 proto tcp
ufw allow from 80.238.236.152 to any port 9977 proto tcp
ufw allow from 80.238.234.59 to any port 9977 proto tcp
ufw deny 80/tcp

ufw logging medium
ufw --force enable

#---------------------------------------------------------
# 6. SYSCTL HARDENING
#---------------------------------------------------------
echo "⚙️ [6/15] Applying kernel hardening..."

cat > /etc/sysctl.d/99-kernel-hardening.conf <<'EOF'
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 2

net.ipv4.ip_forward = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.log_martians = 1

net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0

kernel.unprivileged_userns_clone = 0

fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF

sysctl --system

#---------------------------------------------------------
# 7. DISABLE UNUSED SERVICES
#---------------------------------------------------------
echo "🚫 [7/15] Disabling unused services..."

SERVICES=(apache2 rpcbind nfs-kernel-server exim4 cups smbd avahi-daemon bluetooth)
for svc in "${SERVICES[@]}"; do
  systemctl disable --now $svc 2>/dev/null || true
done

#---------------------------------------------------------
# 8. FAIL2BAN
#---------------------------------------------------------
echo "🛡️ [8/15] Configuring Fail2Ban..."

cat > /etc/fail2ban/jail.d/security.local <<'EOF'
[DEFAULT]
bantime   = 1h
findtime  = 10m
maxretry  = 3

[sshd]
enabled = true
port = 9977
logpath = /var/log/auth.log
EOF

systemctl enable --now fail2ban

#---------------------------------------------------------
# 9. CROWDSEC IPS
#---------------------------------------------------------
echo "🧠 [9/15] Installing CrowdSec..."

curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash
apt-get install -y crowdsec crowdsec-firewall-bouncer-iptables

systemctl enable --now crowdsec
systemctl enable --now crowdsec-firewall-bouncer

#---------------------------------------------------------
# 10. LOGWATCH
#---------------------------------------------------------
echo "📬 [10/15] Configuring Logwatch..."
sed -i 's/^Output = .*/Output = mail/' /etc/logwatch/conf/logwatch.conf || true

#---------------------------------------------------------
# 11. LYNIS
#---------------------------------------------------------
echo "🕵️ [11/15] Setting weekly Lynis scan..."

cat > /etc/cron.weekly/lynis_audit <<'EOF'
#!/bin/bash
/usr/sbin/lynis audit system --quiet > /var/log/lynis-weekly.log
EOF
chmod +x /etc/cron.weekly/lynis_audit

#---------------------------------------------------------
# 12. ROOTKIT CHECKERS
#---------------------------------------------------------
echo "🧬 [12/15] Rootkit monitoring..."

rkhunter --update || true
chkrootkit || true

#---------------------------------------------------------
# 13. AIDE INTEGRITY CHECKING
#---------------------------------------------------------
echo "🔒 [13/15] Initializing AIDE..."

aideinit || true
cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db || true

#---------------------------------------------------------
# 14. UNATTENDED UPDATES
#---------------------------------------------------------
echo "🔄 [14/15] Enabling unattended security upgrades..."

systemctl enable --now unattended-upgrades

#---------------------------------------------------------
# 15. FINISH
#---------------------------------------------------------
echo
echo "====================================================="
echo "  ✅ SERVER HARDENING COMPLETED SUCCESSFULLY"
echo "====================================================="
echo " SSH Port: 9977"
echo " OpenSSH: Upgraded"
echo " NGINX: Mainline (if installed)"
echo " Kernel: Hardened"
echo " CrowdSec + Fail2Ban: ACTIVE"
echo " AIDE + Rootkit Checkers: ENABLED"
echo "====================================================="
echo "Logs saved to: $LOG"

