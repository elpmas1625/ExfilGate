from app.api import routes
from app.detectors.gitleaks import GitleaksDetector


def test_runtime_includes_gitleaks_detector_by_default(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("AICF_CONFIG", raising=False)
    monkeypatch.setenv("AICF_AUDIT_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setattr("app.detectors.gitleaks.shutil.which", lambda _: None)

    _, _, scanner, _, _ = routes.build_runtime()

    assert any(isinstance(detector, GitleaksDetector) for detector in scanner.detectors)
