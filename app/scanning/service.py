from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from app.detectors.base import Detection, Detector
from app.scanning.targets import ScanTarget, extract_request_targets, extract_response_targets


@dataclass(frozen=True)
class TargetedDetection:
    target: ScanTarget
    detection: Detection

    @property
    def type(self) -> str:
        return self.detection.type


@dataclass(frozen=True)
class ScanResult:
    detections: list[TargetedDetection]
    scan_truncated: bool


REPLACEMENTS = {
    "email": "[REDACTED:EMAIL]",
    "phone": "[REDACTED:PHONE]",
    "openai_key": "[REDACTED:OPENAI_KEY]",
    "github_token": "[REDACTED:GITHUB_TOKEN]",
    "aws_access_key": "[REDACTED:AWS_ACCESS_KEY]",
    "aws_secret": "[REDACTED:AWS_SECRET]",
    "anthropic_key": "[REDACTED:ANTHROPIC_KEY]",
    "deepseek_key": "[REDACTED:DEEPSEEK_KEY]",
    "slack_token": "[REDACTED:SLACK_TOKEN]",
    "secret": "[REDACTED:SECRET]",
}


class ScanService:
    def __init__(self, detectors: list[Detector], max_scan_chars: int) -> None:
        self.detectors = detectors
        self.max_scan_chars = max_scan_chars

    def scan_request(self, payload: dict[str, Any]) -> ScanResult:
        return self._scan_targets(extract_request_targets(payload))

    def scan_response(self, payload: dict[str, Any]) -> ScanResult:
        return self._scan_targets(extract_response_targets(payload))

    def mask_request(self, payload: dict[str, Any], detections: list[TargetedDetection]) -> dict[str, Any]:
        return self._mask_payload(payload, detections)

    def mask_response(self, payload: dict[str, Any], detections: list[TargetedDetection]) -> dict[str, Any]:
        return self._mask_payload(payload, detections)

    def _scan_targets(self, targets: list[ScanTarget]) -> ScanResult:
        targeted: list[TargetedDetection] = []
        scanned_chars = 0
        truncated = False
        for target in targets:
            remaining = self.max_scan_chars - scanned_chars
            if remaining <= 0:
                truncated = True
                break
            scan_text = target.text[:remaining]
            if len(scan_text) < len(target.text):
                truncated = True
            scanned_chars += len(scan_text)
            for detector in self.detectors:
                for detection in detector.detect(scan_text):
                    targeted.append(TargetedDetection(target=target, detection=detection))
        return ScanResult(detections=targeted, scan_truncated=truncated)

    def _mask_payload(self, payload: dict[str, Any], detections: list[TargetedDetection]) -> dict[str, Any]:
        masked = deepcopy(payload)
        grouped: dict[tuple[Any, ...], list[Detection]] = {}
        for item in detections:
            grouped.setdefault(item.target.path, []).append(item.detection)

        for path, path_detections in grouped.items():
            original = self._get_path(masked, path)
            if not isinstance(original, str):
                continue
            self._set_path(masked, path, mask_text(original, path_detections))
        return masked

    def _get_path(self, payload: dict[str, Any], path: tuple[Any, ...]) -> Any:
        current: Any = payload
        for part in path:
            current = current[part]
        return current

    def _set_path(self, payload: dict[str, Any], path: tuple[Any, ...], value: str) -> None:
        current: Any = payload
        for part in path[:-1]:
            current = current[part]
        current[path[-1]] = value


def mask_text(text: str, detections: list[Detection]) -> str:
    if not detections:
        return text

    result: list[str] = []
    cursor = 0
    for detection in sorted(detections, key=lambda item: (item.start, item.end)):
        if detection.start < cursor:
            continue
        result.append(text[cursor : detection.start])
        result.append(REPLACEMENTS.get(detection.type, "[REDACTED]"))
        cursor = detection.end
    result.append(text[cursor:])
    return "".join(result)
