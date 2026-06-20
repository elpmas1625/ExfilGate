import json
from dataclasses import asdict
from pathlib import Path

from app.audit.models import AuditEvent


class JsonlAuditLogger:
    def __init__(self, path: str) -> None:
        self.path = Path(path)

    def write(self, event: AuditEvent) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(asdict(event), separators=(",", ":")) + "\n")
