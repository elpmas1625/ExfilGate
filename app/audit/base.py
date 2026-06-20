from typing import Protocol

from app.audit.models import AuditEvent


class AuditLogger(Protocol):
    def write(self, event: AuditEvent) -> None:
        ...
