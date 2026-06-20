from app.detectors.regex_pii import RegexPIIDetector
from app.scanning.service import ScanService


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


def test_scan_truncation_is_reported() -> None:
    payload = {"messages": [{"role": "user", "content": "alice@example.com"}]}
    scanner = ScanService(detectors=[RegexPIIDetector()], max_scan_chars=5)

    result = scanner.scan_request(payload)

    assert result.scan_truncated is True
