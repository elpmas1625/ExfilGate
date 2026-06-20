from dataclasses import dataclass
from datetime import UTC, datetime

from app.policy.models import PolicyDecision


@dataclass(frozen=True)
class AuditEvent:
    timestamp: str
    request_id: str
    provider: str
    direction: str
    detections: list[str]
    actions: list[str]
    blocked: bool
    reason: str | None
    scan_truncated: bool

    @classmethod
    def from_decision(
        cls,
        *,
        request_id: str,
        provider: str,
        direction: str,
        decision: PolicyDecision,
        scan_truncated: bool,
    ) -> "AuditEvent":
        return cls(
            timestamp=datetime.now(UTC).isoformat(),
            request_id=request_id,
            provider=provider,
            direction=direction,
            detections=sorted({detection.type for detection in decision.detections}),
            actions=decision.actions,
            blocked=decision.blocked,
            reason="policy_block" if decision.blocked else None,
            scan_truncated=scan_truncated,
        )

    @classmethod
    def blocked_event(cls, *, request_id: str, provider: str, direction: str, reason: str) -> "AuditEvent":
        return cls(
            timestamp=datetime.now(UTC).isoformat(),
            request_id=request_id,
            provider=provider,
            direction=direction,
            detections=[],
            actions=["block"],
            blocked=True,
            reason=reason,
            scan_truncated=False,
        )
