import os
import hashlib
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional


SCRIPT_TYPES = {
    "setup": os.path.join("scripts", "setup"),
    "baseline": os.path.join("scripts", "scan", "baseline"),
    "pentest": os.path.join("scripts", "scan", "pentest"),
}


@dataclass
class ScriptInfo:
    """Metadata describing a runnable script."""

    id: str
    name: str
    category: str
    description: str
    path: str
    relative_path: str
    checksum: str

    def to_dict(self):
        data = asdict(self)
        return data


class ScriptRegistry:
    """
    Discover scripts under the configured directories and expose metadata
    for the frontend/API.
    """

    def __init__(self, base_path: str):
        self.base_path = base_path
        self.scripts: Dict[str, ScriptInfo] = {}
        self.refresh()

    def refresh(self):
        scripts = {}
        for category, rel_path in SCRIPT_TYPES.items():
            absolute_root = os.path.join(self.base_path, rel_path)
            if not os.path.isdir(absolute_root):
                continue
            for root, _, files in os.walk(absolute_root):
                for filename in files:
                    script_path = os.path.join(root, filename)
                    rel = os.path.relpath(script_path, self.base_path)
                    script_id = self._build_id(category, rel)
                    scripts[script_id] = ScriptInfo(
                        id=script_id,
                        name=filename,
                        category=category,
                        description=self._derive_description(script_path),
                        path=script_path,
                        relative_path=rel,
                        checksum=self._checksum(script_path),
                    )
        self.scripts = scripts

    def _build_id(self, category: str, rel_path: str) -> str:
        return f"{category}:{rel_path}"

    def _derive_description(self, path: str) -> str:
        doc_path = f"{path}.md"
        if os.path.exists(doc_path):
            try:
                with open(doc_path, "r", encoding="utf-8") as fh:
                    first_line = fh.readline().strip()
                    return first_line or "Security script"
            except Exception:
                return "Security script"
        return "Security script"

    def _checksum(self, path: str) -> str:
        h = hashlib.sha256()
        try:
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except FileNotFoundError:
            return ""

    def list(self, category: Optional[str] = None) -> List[ScriptInfo]:
        if category:
            return [s for s in self.scripts.values() if s.category == category]
        return list(self.scripts.values())

    def get(self, script_id: str) -> Optional[ScriptInfo]:
        return self.scripts.get(script_id)

