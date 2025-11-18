Security Audit Suite - Starter production package

Files:
- setup.sh        : installer (run as root)
- scan.sh         : triggers scan driver
- reporting/run_full_scan.py : main scanning driver
- generate_report.py : report generator
- webapp/         : Flask web portal
- tools/          : docker-compose templates (OpenVAS, Wazuh, Vault)
- ansible/        : skeleton playbooks & roles

Usage:
1. Upload ZIP to jump server.
2. sudo bash setup.sh
3. Edit /opt/security-audit/config.json
4. Start app: systemctl start audit-portal.service
5. Run scan test: sudo /opt/security-audit/scan.sh
