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
