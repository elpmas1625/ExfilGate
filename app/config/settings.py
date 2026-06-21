import os
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.config.policy_loader import load_yaml_config


class ServerSettings(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8000


class ProviderSettings(BaseModel):
    name: str = "openai_compatible"
    base_url: str = "https://api.openai.com/v1"
    api_key_env: str = "AICF_PROVIDER_API_KEY"
    timeout_seconds: float = 60.0
    request_overrides: dict[str, Any] = Field(default_factory=dict)

    @property
    def api_key(self) -> str:
        return os.getenv(self.api_key_env, "")


class AuditSettings(BaseModel):
    type: Literal["jsonl"] = "jsonl"
    path: str = "/data/audit.jsonl"


class EnabledDetectorSettings(BaseModel):
    enabled: bool = True


class GitleaksSettings(BaseModel):
    enabled: bool = True
    timeout_seconds: float = 3.0


class DetectorSettings(BaseModel):
    regex_secrets: EnabledDetectorSettings = Field(default_factory=EnabledDetectorSettings)
    gitleaks: GitleaksSettings = Field(default_factory=GitleaksSettings)
    regex_pii: EnabledDetectorSettings = Field(default_factory=EnabledDetectorSettings)


class LimitSettings(BaseModel):
    max_request_bytes: int = 1_048_576
    max_response_bytes: int = 1_048_576
    max_scan_chars: int = 200_000


class PolicySettings(BaseModel):
    default_action: Literal["allow", "warn", "mask", "block"] = "allow"
    rules: dict[str, Literal["allow", "warn", "mask", "block"]] = Field(default_factory=dict)


class StreamSettings(BaseModel):
    heartbeat_interval_seconds: float = 15.0
    heartbeat_mode: Literal["comment", "empty_delta"] = "comment"


class Settings(BaseModel):
    server: ServerSettings = Field(default_factory=ServerSettings)
    provider: ProviderSettings = Field(default_factory=ProviderSettings)
    audit: AuditSettings = Field(default_factory=AuditSettings)
    detectors: DetectorSettings = Field(default_factory=DetectorSettings)
    limits: LimitSettings = Field(default_factory=LimitSettings)
    policy: PolicySettings = Field(default_factory=PolicySettings)
    stream: StreamSettings = Field(default_factory=StreamSettings)


def load_settings() -> Settings:
    raw = load_yaml_config(os.getenv("AICF_CONFIG"))
    settings = Settings.model_validate(raw)

    if os.getenv("AICF_AUDIT_PATH"):
        settings.audit.path = os.environ["AICF_AUDIT_PATH"]
    if os.getenv("AICF_PROVIDER_BASE_URL"):
        settings.provider.base_url = os.environ["AICF_PROVIDER_BASE_URL"]
    if os.getenv("AICF_STREAM_HEARTBEAT_INTERVAL_SECONDS"):
        settings.stream.heartbeat_interval_seconds = float(os.environ["AICF_STREAM_HEARTBEAT_INTERVAL_SECONDS"])
    if os.getenv("AICF_STREAM_HEARTBEAT_MODE"):
        heartbeat_mode = os.environ["AICF_STREAM_HEARTBEAT_MODE"]
        if heartbeat_mode in ("comment", "empty_delta"):
            settings.stream.heartbeat_mode = heartbeat_mode
    return settings
