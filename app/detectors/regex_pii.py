import re

from app.detectors.base import Detection


class RegexPIIDetector:
    name = "regex_pii"

    PATTERNS: dict[str, re.Pattern[str]] = {
        "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "phone": re.compile(r"(?<!\w)(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)?\d{3,4}[-.\s]?\d{4}(?!\w)"),
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
