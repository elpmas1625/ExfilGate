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


def test_jsonl_audit_logger_does_not_persist_raw_prompt_or_provider_values(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    logger = JsonlAuditLogger(str(path))
    event = AuditEvent(
        timestamp="2026-06-20T00:00:00+00:00",
        request_id="req_1",
        provider="test",
        direction="request",
        detections=["openai_key", "email"],
        actions=["block", "mask"],
        blocked=True,
        reason="content_blocked",
        scan_truncated=False,
    )

    logger.write(event)
    audit_text = path.read_text(encoding="utf-8")

    assert "Prompt本文" not in audit_text
    assert "Provider Response本文" not in audit_text
    assert "Authorization: Bearer dummy-client-token" not in audit_text
    assert "DEEPSEEK_API_KEY=dummy-provider-key" not in audit_text
