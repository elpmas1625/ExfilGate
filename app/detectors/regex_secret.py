import re

from app.detectors.base import Detection


class RegexSecretDetector:
    name = "regex_secret"

    ASCII_BOUNDARY_LEFT = r"(?<![A-Za-z0-9_])"
    ASCII_BOUNDARY_RIGHT = r"(?![A-Za-z0-9_])"

    PATTERNS: dict[str, re.Pattern[str]] = {
        "openai_key": re.compile(rf"{ASCII_BOUNDARY_LEFT}sk-(?:proj-)?[A-Za-z0-9_-]{{20,}}{ASCII_BOUNDARY_RIGHT}"),
        "github_token": re.compile(rf"{ASCII_BOUNDARY_LEFT}gh[pousr]_[A-Za-z0-9_]{{20,}}{ASCII_BOUNDARY_RIGHT}"),
        "aws_access_key": re.compile(rf"{ASCII_BOUNDARY_LEFT}(?:AKIA|ASIA)[A-Z0-9]{{16}}{ASCII_BOUNDARY_RIGHT}"),
        "aws_secret": re.compile(rf"(?i){ASCII_BOUNDARY_LEFT}aws(?:_|\s|-)?(?:secret|secret_access_key){ASCII_BOUNDARY_RIGHT}\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{{30,}}['\"]?"),
        "anthropic_key": re.compile(rf"{ASCII_BOUNDARY_LEFT}sk-ant-[A-Za-z0-9_-]{{20,}}{ASCII_BOUNDARY_RIGHT}"),
        "deepseek_key": re.compile(rf"{ASCII_BOUNDARY_LEFT}sk-[A-Za-z0-9]{{32,}}{ASCII_BOUNDARY_RIGHT}"),
        "slack_token": re.compile(rf"{ASCII_BOUNDARY_LEFT}xox[baprs]-[A-Za-z0-9-]{{20,}}{ASCII_BOUNDARY_RIGHT}"),
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
