#!/usr/bin/env python3
"""
Ansible Integration Module for Security Audit Suite
Handles Ansible playbook execution and inventory management
"""
import os
import json
import subprocess
import tempfile
import yaml
from datetime import datetime
from pathlib import Path

class AnsibleRunner:
    def __init__(self, base_path="/opt/security-audit"):
        self.base_path = base_path
        self.ansible_path = os.path.join(base_path, "ansible")
        self.inventory_path = os.path.join(base_path, "ansible", "inventory", "hosts.ini")
        os.makedirs(os.path.join(base_path, "ansible", "inventory"), exist_ok=True)
    
    def generate_inventory(self, hosts):
        """Generate Ansible inventory file from host list"""
        inventory_content = "[all]\n"
        for host in hosts:
            if host.get('is_active', True):
                line = f"{host['hostname']} ansible_host={host['ip_address']}"
                if host.get('ssh_user'):
                    line += f" ansible_user={host['ssh_user']}"
                if host.get('ssh_port'):
                    line += f" ansible_port={host['ssh_port']}"
                if host.get('ssh_key_path'):
                    line += f" ansible_ssh_private_key_file={host['ssh_key_path']}"
                inventory_content += line + "\n"
        
        with open(self.inventory_path, 'w') as f:
            f.write(inventory_content)
        
        return self.inventory_path
    
    def run_playbook(self, playbook_name, extra_vars=None, hosts=None):
        """Run an Ansible playbook"""
        playbook_path = os.path.join(self.ansible_path, playbook_name)
        
        cmd = [
            'ansible-playbook',
            '-i', self.inventory_path,
            playbook_path
        ]
        
        if extra_vars:
            cmd.extend(['-e', json.dumps(extra_vars)])
        
        if hosts:
            cmd.extend(['--limit', ','.join(hosts)])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600,
                cwd=self.ansible_path
            )
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Playbook execution timed out'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def setup_tools(self, hosts):
        """Setup security tools on all hosts"""
        self.generate_inventory(hosts)
        return self.run_playbook('playbook.yaml')
    
    def setup_web_security(self, hosts):
        """Setup web server security on all hosts"""
        self.generate_inventory(hosts)
        return self.run_playbook('playbook.yaml', extra_vars={'task': 'web_security'})
    
    def run_scan(self, hosts, scan_type='full', scan_id=None):
        """Run security scan on hosts"""
        self.generate_inventory(hosts)
        timestamp = datetime.utcnow().strftime("%Y-%m-%d_%H%M%S")
        
        extra_vars = {
            'scan_type': scan_type,
            'scan_output_dir': f"{scan_id or timestamp}",
            'scan_results_path': f"/var/security-scans/ansible/{scan_id or timestamp}"
        }
        
        return self.run_playbook('playbook-scan.yml', extra_vars=extra_vars)

