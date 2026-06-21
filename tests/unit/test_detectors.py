import subprocess

from app.detectors.gitleaks import GitleaksDetector
from app.detectors.regex_pii import RegexPIIDetector
from app.detectors.regex_secret import RegexSecretDetector


def test_regex_secret_detector_finds_openai_key() -> None:
    detector = RegexSecretDetector()
    detections = detector.detect("key sk-proj-abcdefghijklmnopqrstuvwxyz1234567890")

    assert [detection.type for detection in detections] == ["openai_key"]


def test_regex_secret_detector_finds_key_next_to_japanese_text() -> None:
    detector = RegexSecretDetector()
    detections = detector.detect("こんにちはsk-proj-abcdefghijklmnopqrstuvwxyz1234567890です。")

    assert [detection.type for detection in detections] == ["openai_key"]


def test_regex_pii_detector_finds_email_and_phone() -> None:
    detector = RegexPIIDetector()
    detections = detector.detect("alice@example.com +1 415 555 1212")

    assert {detection.type for detection in detections} == {"email", "phone"}


def test_regex_pii_detector_finds_phone_next_to_japanese_text() -> None:
    detector = RegexPIIDetector()
    detections = detector.detect("こんにちは！私の電話番号は090-8376-3728です。")

    assert [detection.type for detection in detections] == ["phone"]


def test_regex_pii_detector_finds_email_next_to_japanese_text() -> None:
    detector = RegexPIIDetector()
    detections = detector.detect("こんにちは！私のメールアドレスはadmin@example.comです。")

    assert [detection.type for detection in detections] == ["email"]


def test_gitleaks_missing_cli_does_not_fail_startup(monkeypatch) -> None:
    monkeypatch.setattr("app.detectors.gitleaks.shutil.which", lambda _: None)

    detector = GitleaksDetector()

    assert detector.detect("sk-proj-abcdefghijklmnopqrstuvwxyz1234567890") == []


def test_gitleaks_enabled_missing_cli_emits_warning_without_failure(monkeypatch, caplog) -> None:
    monkeypatch.setattr("app.detectors.gitleaks.shutil.which", lambda _: None)

    detector = GitleaksDetector()

    assert detector.executable is None
    assert "gitleaks_enabled_but_cli_not_found" in caplog.text


def test_gitleaks_detector_reports_secret_when_cli_finds_leak(monkeypatch) -> None:
    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 1, stdout="", stderr="")

    monkeypatch.setattr("app.detectors.gitleaks.shutil.which", lambda _: "gitleaks")
    monkeypatch.setattr("app.detectors.gitleaks.subprocess.run", fake_run)

    detector = GitleaksDetector(timeout_seconds=1.5)
    detections = detector.detect("github_pat_11AAAAAAAA0abcdefghijklmnopqrstuvwxyz1234567890")

    assert [detection.type for detection in detections] == ["secret"]
    assert detections[0].detector == "gitleaks"
    assert calls[0][0][:4] == ["gitleaks", "detect", "--no-git", "--redact"]
    assert calls[0][1]["timeout"] == 1.5


def test_gitleaks_detector_returns_no_detection_when_cli_finds_no_leak(monkeypatch) -> None:
    def fake_run(args, **kwargs):
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr("app.detectors.gitleaks.shutil.which", lambda _: "gitleaks")
    monkeypatch.setattr("app.detectors.gitleaks.subprocess.run", fake_run)

    detector = GitleaksDetector()

    assert detector.detect("plain text") == []
