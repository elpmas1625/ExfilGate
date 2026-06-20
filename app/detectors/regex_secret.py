import re

from app.detectors.base import Detection


class RegexSecretDetector:
    name = "regex_secret"

    PATTERNS: dict[str, re.Pattern[str]] = {
        "openai_key": re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
        "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
        "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        "aws_secret": re.compile(r"(?i)\baws(?:_|\s|-)?(?:secret|secret_access_key)\b\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{30,}['\"]?"),
        "anthropic_key": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
        "deepseek_key": re.compile(r"\bsk-[A-Za-z0-9]{32,}\b"),
        "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    }

    def detect(self, text: str) -> list[Detection]:
        detections: list[Detection] = []
        for detection_type, pattern in self.PATTERNS.items():
            for match in pattern.finditer(text):
                detections.append(
                    Detection(
                        type=detection_type,
                        start=match.start(),
                        end=match.end(),
                        detector=self.name,
                    )
                )
        return sorted(detections, key=lambda item: (item.start, item.end))
