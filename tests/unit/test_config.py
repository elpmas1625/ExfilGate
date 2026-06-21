from pathlib import Path

import pytest

from app.config.policy_loader import load_yaml_config
from app.config.settings import Settings


def test_missing_config_path_fails_fast(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="Config file not found"):
        load_yaml_config(str(tmp_path / "missing.yaml"))


def test_empty_config_path_uses_defaults() -> None:
    assert load_yaml_config(None) == {}


def test_default_example_config_uses_generic_openai_compatible_provider() -> None:
    raw = load_yaml_config("examples/config.yaml")
    settings = Settings.model_validate(raw)

    assert settings.provider.name == "openai-compatible"
    assert settings.provider.api_key_env == "AICF_PROVIDER_API_KEY"


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
