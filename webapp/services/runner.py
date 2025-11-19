import os
import uuid
import threading
import subprocess
from dataclasses import dataclass
from typing import List, Optional, Dict, Callable


@dataclass
class RunRequest:
    run_type: str  # setup | baseline | pentest
    hosts: List[Dict]
    scripts: List[str]
    created_by: int
    extra_vars: Dict


@dataclass
class RunResult:
    run_id: str
    success: bool
    message: str
    artifacts: Dict


class OrchestratorService:
    """
    Responsible for generating dynamic inventory/playbooks, invoking Ansible,
    and notifying callbacks with log output.
    """

    def __init__(
        self,
        base_path: str,
        scripts_root: str,
        log_callback: Optional[Callable[[str, str], None]] = None,
        status_callback: Optional[Callable[[str, bool, str], None]] = None,
    ):
        self.base_path = base_path
        self.scripts_root = scripts_root
        self.log_callback = log_callback or (lambda run_id, line: None)
        self.status_callback = status_callback or (lambda run_id, success, message: None)

    def run(self, request: RunRequest, run_id: Optional[str] = None) -> RunResult:
        run_id = run_id or uuid.uuid4().hex
        thread = threading.Thread(target=self._execute, args=(run_id, request), daemon=True)
        thread.start()
        return RunResult(run_id=run_id, success=True, message="started", artifacts={})

    def _execute(self, run_id: str, request: RunRequest):
        inventory_path = self._build_inventory(run_id, request)
        playbook_path = self._build_playbook(run_id, request)
        env = os.environ.copy()
        env["ANSIBLE_STDOUT_CALLBACK"] = "unixy"
        cmd = [
            "ansible-playbook",
            "-i",
            inventory_path,
            playbook_path,
        ]
        for key, value in request.extra_vars.items():
            cmd.extend(["-e", f"{key}={value}"])

        success = True
        message = "completed"
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=self.base_path,
                text=True,
                env=env,
            )
            for line in iter(proc.stdout.readline, ""):
                self.log_callback(run_id, line.rstrip())
            proc.wait()
            if proc.returncode != 0:
                self.log_callback(run_id, f"[ERROR] ansible-playbook exited with {proc.returncode}")
                success = False
                message = f"ansible exited with {proc.returncode}"
        except FileNotFoundError:
            self.log_callback(run_id, "[ERROR] ansible-playbook not found in PATH")
            success = False
            message = "ansible-playbook missing"
        except Exception as exc:
            self.log_callback(run_id, f"[ERROR] {exc}")
            success = False
            message = str(exc)
        finally:
            self._cleanup(run_id, [inventory_path, playbook_path])
            self.status_callback(run_id, success, message)

    def _build_inventory(self, run_id: str, request: RunRequest) -> str:
        inv_dir = os.path.join(self.base_path, "data", "inventory")
        os.makedirs(inv_dir, exist_ok=True)
        path = os.path.join(inv_dir, f"{run_id}.ini")
        lines = ["[targets]"]
        for host in request.hosts:
            line = f"{host['hostname']} ansible_host={host['ip_address']} ansible_user={host['ssh_user']} ansible_port={host['ssh_port']}"
            if host.get("ssh_key_path"):
                line += f" ansible_ssh_private_key_file={host['ssh_key_path']}"
            lines.append(line)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        return path

    def _build_playbook(self, run_id: str, request: RunRequest) -> str:
        playbook_dir = os.path.join(self.base_path, "data", "playbooks")
        os.makedirs(playbook_dir, exist_ok=True)
        path = os.path.join(playbook_dir, f"{run_id}.yml")
        tasks = []
        for script in request.scripts:
            tasks.append(
                {
                    "name": f"Run script {script}",
                    "script": os.path.join(self.scripts_root, script),
                }
            )
        playbook = [
            {
                "name": f"{request.run_type} run {run_id}",
                "hosts": "targets",
                "become": True,
                "gather_facts": False,
                "tasks": tasks,
            }
        ]
        # simple yaml dump
        import yaml

        with open(path, "w", encoding="utf-8") as fh:
            yaml.safe_dump(playbook, fh)
        return path

    def _cleanup(self, run_id: str, paths: List[str]):
        for path in paths:
            try:
                if path and os.path.exists(path):
                    os.remove(path)
            except Exception:
                pass

