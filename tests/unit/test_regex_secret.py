import pytest

from app.detectors.regex_secret import RegexSecretDetector


def dummy_secret(*parts: str) -> str:
    return "".join(parts)


@pytest.mark.parametrize(
    ("secret_text", "expected_type"),
    [
        (dummy_secret("sk-", "proj-", "a" * 36), "openai_key"),
        (dummy_secret("gh", "p_", "a" * 36), "github_token"),
        (dummy_secret("AK", "IA", "A" * 16), "aws_access_key"),
        (dummy_secret("aws_secret_access_key=", "a" * 34), "aws_secret"),
        (dummy_secret("sk-", "ant-", "a" * 36), "anthropic_key"),
        (dummy_secret("sk-", "a" * 36), "deepseek_key"),
        (dummy_secret("xo", "xb-", "1" * 12, "-", "a" * 20), "slack_token"),
    ],
)
def test_regex_secret_detector_matches_supported_dummy_patterns(
    secret_text: str, expected_type: str
) -> None:
    detections = RegexSecretDetector().detect(secret_text)

    assert expected_type in {detection.type for detection in detections}
