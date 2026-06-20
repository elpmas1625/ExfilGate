import logging
import shutil
import subprocess
import tempfile

from app.detectors.base import Detection

logger = logging.getLogger(__name__)


class GitleaksDetector:
    name = "gitleaks"

    def __init__(self, timeout_seconds: float = 3.0) -> None:
        self.timeout_seconds = timeout_seconds
        self.executable = shutil.which("gitleaks")
        if self.executable is None:
            logger.warning("gitleaks_enabled_but_cli_not_found detector=gitleaks")

    def detect(self, text: str) -> list[Detection]:
        if self.executable is None:
            return []

        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".txt") as handle:
            handle.write(text)
            handle.flush()
            try:
                result = subprocess.run(
                    [self.executable, "detect", "--no-git", "--redact", "--source", handle.name],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                logger.warning("gitleaks_scan_failed error=%s", exc.__class__.__name__)
                return []

        if result.returncode == 0:
            return []
        logger.warning("gitleaks_detected_secret output_redacted=true")
        return [Detection(type="secret", start=0, end=0, detector=self.name)]
