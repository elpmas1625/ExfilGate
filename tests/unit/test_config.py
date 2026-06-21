from pathlib import Path

import pytest

from app.config.policy_loader import load_yaml_config
from app.config.settings import ProviderSettings, Settings


def test_missing_config_path_fails_fast(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="Config file not found"):
        load_yaml_config(str(tmp_path / "missing.yaml"))


def test_empty_config_path_uses_defaults() -> None:
    assert load_yaml_config(None) == {}


def test_gitleaks_detector_is_enabled_by_default() -> None:
    settings = Settings()

    assert settings.detectors.gitleaks.enabled is True
    assert settings.detectors.gitleaks.timeout_seconds == 3.0


def test_default_example_config_uses_generic_openai_compatible_provider() -> None:
    raw = load_yaml_config("examples/config.yaml")
    settings = Settings.model_validate(raw)

    assert settings.provider.name == "openai-compatible"
    assert settings.provider.api_key_env == "AICF_PROVIDER_API_KEY"


def test_deepseek_example_config_sets_provider_request_overrides() -> None:
    raw = load_yaml_config("examples/config.deepseek.yaml")
    settings = Settings.model_validate(raw)

    assert settings.provider.name == "deepseek"
    assert settings.provider.base_url == "https://api.deepseek.com"
    assert settings.provider.api_key_env == "DEEPSEEK_API_KEY"
    assert settings.provider.request_overrides == {
        "thinking": {"type": "enabled"},
        "reasoning_effort": "high",
    }


def test_custom_provider_api_key_env_does_not_fallback_to_default(monkeypatch) -> None:
    monkeypatch.setenv("AICF_PROVIDER_API_KEY", "wrong-key")
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)

    settings = ProviderSettings(api_key_env="DEEPSEEK_API_KEY")

    assert settings.api_key == ""


def test_default_example_config_enables_gitleaks() -> None:
    settings = Settings.model_validate(load_yaml_config("examples/config.yaml"))

    assert settings.detectors.gitleaks.enabled is True
    assert settings.detectors.gitleaks.timeout_seconds == 3.0


def test_example_config_builds_default_policy_actions() -> None:
    settings = Settings.model_validate(load_yaml_config("examples/config.yaml"))

    for secret_type in [
        "openai_key",
        "github_token",
        "aws_access_key",
        "aws_secret",
        "anthropic_key",
        "deepseek_key",
        "slack_token",
        "secret",
    ]:
        assert settings.policy.rules[secret_type] == "block"

    assert settings.policy.rules["email"] == "mask"
    assert settings.policy.rules["phone"] == "mask"
    assert settings.policy.default_action == "allow"
