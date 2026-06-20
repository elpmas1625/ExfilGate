import pytest
from fastapi.testclient import TestClient

from app.api import routes
from app.audit.jsonl import JsonlAuditLogger
from app.config.settings import (
    AuditSettings,
    DetectorSettings,
    EnabledDetectorSettings,
    GitleaksSettings,
    LimitSettings,
    PolicySettings,
    ProviderSettings,
    Settings,
)
from app.detectors.regex_pii import RegexPIIDetector
from app.detectors.regex_secret import RegexSecretDetector
from app.main import create_app
from app.policy.engine import PolicyEngine
from app.providers.openai_compatible import ProviderError
from app.scanning.service import ScanService


class FakeProvider:
    def __init__(self, response: dict | None = None) -> None:
        self.payload = None
        self.response = response or {
            "id": "chatcmpl_test",
            "object": "chat.completion",
            "choices": [{"message": {"role": "assistant", "content": "ok"}}],
        }

    async def chat_completions(self, payload: dict) -> dict:
        self.payload = payload
        return self.response


class ErrorProvider:
    def __init__(self, error: ProviderError) -> None:
        self.error = error

    async def chat_completions(self, payload: dict) -> dict:
        raise self.error


def make_settings(audit_path: str, *, max_request_bytes: int = 1048576, max_response_bytes: int = 1048576) -> Settings:
    return Settings(
        provider=ProviderSettings(name="test", base_url="https://example.test/v1", api_key_env="NO_KEY"),
        audit=AuditSettings(path=audit_path),
        detectors=DetectorSettings(
            regex_secrets=EnabledDetectorSettings(enabled=True),
            gitleaks=GitleaksSettings(enabled=False),
            regex_pii=EnabledDetectorSettings(enabled=True),
        ),
        limits=LimitSettings(max_request_bytes=max_request_bytes, max_response_bytes=max_response_bytes, max_scan_chars=10000),
        policy=PolicySettings(
            default_action="allow",
            rules={
                "openai_key": "block",
                "email": "mask",
                "phone": "mask",
            },
        ),
    )


@pytest.fixture
def client_factory(monkeypatch, tmp_path):
    def factory(provider=None, settings=None):
        fake_provider = provider or FakeProvider()
        runtime_settings = settings or make_settings(str(tmp_path / "audit.jsonl"))

        def fake_runtime():
            return (
                runtime_settings,
                JsonlAuditLogger(runtime_settings.audit.path),
                ScanService([RegexSecretDetector(), RegexPIIDetector()], runtime_settings.limits.max_scan_chars),
                PolicyEngine(runtime_settings.policy),
                fake_provider,
            )

        monkeypatch.setattr(routes, "build_runtime", fake_runtime)
        return TestClient(create_app()), fake_provider

    return factory


@pytest.fixture
def client(client_factory):
    return client_factory()


def test_streaming_is_rejected(client) -> None:
    test_client, _ = client

    response = test_client.post(
        "/v1/chat/completions",
        json={"model": "test", "messages": [{"role": "user", "content": "hello"}], "stream": True},
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "streaming_not_supported"


def test_request_secret_is_blocked(client) -> None:
    test_client, fake_provider = client

    response = test_client.post(
        "/v1/chat/completions",
        json={
            "model": "test",
            "messages": [{"role": "user", "content": "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"}],
        },
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "content_blocked"
    assert fake_provider.payload is None


def test_request_pii_is_masked_before_provider(client) -> None:
    test_client, fake_provider = client

    response = test_client.post(
        "/v1/chat/completions",
        json={"model": "test", "messages": [{"role": "user", "content": "email alice@example.com"}]},
    )

    assert response.status_code == 200
    assert fake_provider.payload["messages"][0]["content"] == "email [REDACTED:EMAIL]"


def test_response_secret_is_blocked(client_factory) -> None:
    provider = FakeProvider(
        response={
            "id": "chatcmpl_test",
            "object": "chat.completion",
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "leaked sk-proj-abcdefghijklmnopqrstuvwxyz1234567890",
                    }
                }
            ],
        }
    )
    test_client, _ = client_factory(provider=provider)

    response = test_client.post(
        "/v1/chat/completions",
        json={"model": "test", "messages": [{"role": "user", "content": "hello"}]},
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "content_blocked"


def test_response_pii_is_masked(client_factory) -> None:
    provider = FakeProvider(
        response={
            "id": "chatcmpl_test",
            "object": "chat.completion",
            "choices": [{"message": {"role": "assistant", "content": "contact alice@example.com or +1 415 555 1212"}}],
        }
    )
    test_client, _ = client_factory(provider=provider)

    response = test_client.post(
        "/v1/chat/completions",
        json={"model": "test", "messages": [{"role": "user", "content": "hello"}]},
    )

    assert response.status_code == 200
    assert response.json()["choices"][0]["message"]["content"] == "contact [REDACTED:EMAIL] or [REDACTED:PHONE]"


def test_provider_error_json_is_forwarded(client_factory) -> None:
    provider = ErrorProvider(
        ProviderError(
            status_code=401,
            response_json={
                "error": {
                    "message": "bad key",
                    "type": "invalid_request_error",
                    "param": None,
                    "code": "invalid_api_key",
                }
            },
        )
    )
    test_client, _ = client_factory(provider=provider)

    response = test_client.post(
        "/v1/chat/completions",
        json={"model": "test", "messages": [{"role": "user", "content": "hello"}]},
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_api_key"


def test_request_size_limit_returns_413(client_factory, tmp_path) -> None:
    settings = make_settings(str(tmp_path / "audit.jsonl"), max_request_bytes=20)
    test_client, _ = client_factory(settings=settings)

    response = test_client.post(
        "/v1/chat/completions",
        json={"model": "test", "messages": [{"role": "user", "content": "too large"}]},
    )

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "request_too_large"


def test_response_size_limit_returns_502(client_factory, tmp_path) -> None:
    provider = FakeProvider(
        response={
            "id": "chatcmpl_test",
            "object": "chat.completion",
            "choices": [{"message": {"role": "assistant", "content": "x" * 200}}],
        }
    )
    settings = make_settings(str(tmp_path / "audit.jsonl"), max_response_bytes=100)
    test_client, _ = client_factory(provider=provider, settings=settings)

    response = test_client.post(
        "/v1/chat/completions",
        json={"model": "test", "messages": [{"role": "user", "content": "hello"}]},
    )

    assert response.status_code == 502
    assert response.json()["error"]["code"] == "upstream_response_too_large"
