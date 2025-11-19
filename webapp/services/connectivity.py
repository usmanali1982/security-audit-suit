import subprocess
import time
from dataclasses import dataclass, asdict
from typing import List, Optional

DEFAULT_SSH_TIMEOUT = 10


@dataclass
class ConnectivityResult:
    host_id: int
    hostname: str
    ip: str
    ok: bool
    latency_ms: Optional[float]
    message: str
    checked_at: float

    def to_dict(self):
        data = asdict(self)
        return data


class SSHConnectivityService:
    """Simple SSH health checks using system ssh binary."""

    def __init__(self, jump_host: Optional[dict] = None):
        self.jump_host = jump_host or {}

    def check_host(self, ssh_user: str, ip: str, port: int, key_path: Optional[str] = None) -> ConnectivityResult:
        cmd = [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            f"ConnectTimeout={DEFAULT_SSH_TIMEOUT}",
            "-p",
            str(port),
        ]

        if key_path:
            cmd.extend(["-i", key_path])

        proxy_command = self._build_proxy_command()
        if proxy_command:
            cmd.extend(["-o", f"ProxyCommand={proxy_command}"])

        cmd.append(f"{ssh_user}@{ip}")
        cmd.append("exit")

        start = time.time()
        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                text=True,
            )
            latency = (time.time() - start) * 1000
            ok = proc.returncode == 0
            message = proc.stderr.strip() or proc.stdout.strip()
        except FileNotFoundError:
            ok = False
            latency = None
            message = "ssh binary not found"
        except Exception as exc:
            ok = False
            latency = None
            message = str(exc)

        return ConnectivityResult(
            host_id=-1,
            hostname="",
            ip=ip,
            ok=ok,
            latency_ms=round(latency, 2) if latency else None,
            message=message or ("OK" if ok else "Unknown error"),
            checked_at=time.time(),
        )

    def _build_proxy_command(self) -> Optional[str]:
        host = self.jump_host.get("host")
        user = self.jump_host.get("user")
        port = self.jump_host.get("port", 22)
        key = self.jump_host.get("key")
        if not host or not user:
            return None
        parts = ["ssh", f"{user}@{host}", "-W", "%h:%p", "-p", str(port)]
        if key:
            parts.extend(["-i", key])
        return " ".join(parts)

