from app.config.settings import PolicySettings
from app.detectors.regex_pii import RegexPIIDetector
from app.detectors.regex_secret import RegexSecretDetector
from app.policy.engine import PolicyEngine
from app.scanning.service import ScanService

DUMMY_OPENAI_KEY = "sk-" + "proj-" + "a" * 36
DUMMY_GITHUB_TOKEN = "gh" + "p_" + "a" * 36


def test_masks_only_message_content_fields() -> None:
    payload = {
        "model": "test",
        "messages": [
            {"role": "user", "content": "email alice@example.com"},
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "call +1 415 555 1212"},
                    {"type": "image_url", "image_url": {"url": "https://example.com/alice@example.com.png"}},
                ],
            },
        ],
        "tools": [{"function": {"description": "contact bob@example.com"}}],
    }
    scanner = ScanService(detectors=[RegexPIIDetector()], max_scan_chars=10000)

    result = scanner.scan_request(payload)
    masked = scanner.mask_request(payload, result.detections)

    assert masked["messages"][0]["content"] == "email [REDACTED:EMAIL]"
    assert masked["messages"][1]["content"][0]["text"] == "call [REDACTED:PHONE]"
    assert masked["messages"][1]["content"][1]["image_url"]["url"] == "https://example.com/alice@example.com.png"
    assert masked["tools"][0]["function"]["description"] == "contact bob@example.com"


def test_mixed_secret_and_pii_request_blocks_masks_and_skips_non_text_fields() -> None:
    scanner = ScanService([RegexSecretDetector(), RegexPIIDetector()], max_scan_chars=10000)
    payload = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": (
                            f"key {DUMMY_OPENAI_KEY} "
                            f"token {DUMMY_GITHUB_TOKEN} "
                            "email alice@example.com phone 415 555 1212"
                        ),
                    },
                    {
                        "type": "image_url",
                        "image_url": {"url": "https://example.com/alice@example.com.png"},
                    },
                ],
                "tool_calls": [
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "lookup", "arguments": "{\"email\":\"alice@example.com\"}"},
                    }
                ],
            }
        ]
    }

    result = scanner.scan_request(payload)
    detection_types = {targeted.detection.type for targeted in result.detections}
    decision = PolicyEngine(
        PolicySettings(
            rules={
                "openai_key": "block",
                "github_token": "block",
                "email": "mask",
                "phone": "mask",
            }
        )
    ).decide([targeted.detection for targeted in result.detections])
    masked = scanner.mask_request(payload, result.detections)

    assert {"openai_key", "github_token", "email", "phone"} <= detection_types
    assert decision.final_action == "block"
    assert "block" in decision.actions
    assert "mask" in decision.actions
    assert masked["messages"][0]["content"][1]["image_url"]["url"] == "https://example.com/alice@example.com.png"
    assert masked["messages"][0]["tool_calls"][0]["function"]["arguments"] == "{\"email\":\"alice@example.com\"}"


def test_scan_truncation_is_reported() -> None:
    payload = {"messages": [{"role": "user", "content": "alice@example.com"}]}
    scanner = ScanService(detectors=[RegexPIIDetector()], max_scan_chars=5)

    result = scanner.scan_request(payload)

    assert result.scan_truncated is True
