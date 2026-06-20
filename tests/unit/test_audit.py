import json

from app.audit.jsonl import JsonlAuditLogger
from app.audit.models import AuditEvent


def test_jsonl_audit_logger_writes_sanitized_event(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    logger = JsonlAuditLogger(str(path))

    logger.write(
        AuditEvent(
            timestamp="2026-06-20T00:00:00+00:00",
            request_id="req_test",
            provider="deepseek",
            direction="request",
            detections=["email"],
            actions=["mask"],
            blocked=False,
            reason=None,
            scan_truncated=False,
        )
    )

    event = json.loads(path.read_text(encoding="utf-8"))
    assert event["detections"] == ["email"]
    assert "alice@example.com" not in path.read_text(encoding="utf-8")
