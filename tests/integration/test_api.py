import asyncio

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
    StreamSettings,
)
from app.detectors.regex_pii import RegexPIIDetector
from app.detectors.regex_secret import RegexSecretDetector
from app.main import create_app
from app.policy.engine import PolicyEngine
from app.providers.openai_compatible import ProviderError
from app.scanning.service import ScanService

DUMMY_OPENAI_KEY = "sk-" + "proj-" + "a" * 36
DUMMY_GITHUB_TOKEN = "gh" + "p_" + "a" * 36


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


class SlowProvider(FakeProvider):
    async def chat_completions(self, payload: dict) -> dict:
        self.payload = payload
        await asyncio.sleep(0.03)
        return self.response


def make_settings(
    audit_path: str,
    *,
    max_request_bytes: int = 1048576,
    max_response_bytes: int = 1048576,
    heartbeat_interval_seconds: float = 15.0,
) -> Settings:
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
        stream=StreamSettings(heartbeat_interval_seconds=heartbeat_interval_seconds),
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


def test_streaming_request_returns_sse_and_forces_upstream_non_stream(client) -> None:
    test_client, fake_provider = client

    response = test_client.post(
        "/v1/chat/completions",
        json={"model": "test", "messages": [{"role": "user", "content": "hello"}], "stream": True},
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert '"content":"ok"' in response.text
    assert "data: [DONE]" in response.text
    assert fake_provider.payload["stream"] is False


def test_streaming_request_sends_comment_heartbeat(client_factory, tmp_path) -> None:
    settings = make_settings(str(tmp_path / "audit.jsonl"), heartbeat_interval_seconds=0.01)
    test_client, _ = client_factory(provider=SlowProvider(), settings=settings)

    response = test_client.post(
        "/v1/chat/completions",
        json={"model": "test", "messages": [{"role": "user", "content": "hello"}], "stream": True},
    )

    assert response.status_code == 200
    assert ": ping\n\n" in response.text
    assert "data: [DONE]" in response.text


def test_streaming_request_policy_block_still_returns_json_403(client) -> None:
    test_client, fake_provider = client

    response = test_client.post(
        "/v1/chat/completions",
        json={
            "model": "test",
            "messages": [{"role": "user", "content": DUMMY_OPENAI_KEY}],
            "stream": True,
        },
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "content_blocked"
    assert fake_provider.payload is None


def test_streaming_response_policy_block_returns_sse_error(client_factory) -> None:
    provider = FakeProvider(
        response={
            "id": "chatcmpl_test",
            "object": "chat.completion",
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": f"leaked {DUMMY_OPENAI_KEY}",
                    }
                }
            ],
        }
    )
    test_client, _ = client_factory(provider=provider)

    response = test_client.post(
        "/v1/chat/completions",
        json={"model": "test", "messages": [{"role": "user", "content": "hello"}], "stream": True},
    )

    assert response.status_code == 200
    assert '"code":"content_blocked"' in response.text
    assert "data: [DONE]" in response.text


def test_streaming_provider_error_returns_sse_error(client_factory) -> None:
    provider = ErrorProvider(ProviderError(status_code=502))
    test_client, _ = client_factory(provider=provider)

    response = test_client.post(
        "/v1/chat/completions",
        json={"model": "test", "messages": [{"role": "user", "content": "hello"}], "stream": True},
    )

    assert response.status_code == 200
    assert '"code":"provider_error"' in response.text
    assert "data: [DONE]" in response.text


def test_request_secret_is_blocked(client) -> None:
    test_client, fake_provider = client

    response = test_client.post(
        "/v1/chat/completions",
        json={
            "model": "test",
            "messages": [{"role": "user", "content": DUMMY_OPENAI_KEY}],
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
                        "content": f"leaked {DUMMY_OPENAI_KEY}",
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


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"messages": "not-a-list"},
        {"messages": [{"role": "user", "content": {"unexpected": "shape"}}]},
    ],
)
def test_invalid_request_payloads_return_400_without_provider_call(client_factory, body) -> None:
    fake_provider = FakeProvider()
    client, _ = client_factory(provider=fake_provider)

    response = client.post("/v1/chat/completions", json=body)

    assert response.status_code == 400
    assert response.json()["error"]["type"] == "invalid_request_error"
    assert fake_provider.payload is None


def test_invalid_json_returns_400_without_provider_call(client_factory) -> None:
    fake_provider = FakeProvider()
    client, _ = client_factory(provider=fake_provider)

    response = client.post(
        "/v1/chat/completions",
        content="{",
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 400
    assert response.json()["error"]["type"] == "invalid_request_error"
    assert fake_provider.payload is None


def test_oversized_request_returns_413_without_provider_call(client_factory, tmp_path) -> None:
    fake_provider = FakeProvider()
    settings = make_settings(str(tmp_path / "audit.jsonl"), max_request_bytes=10)
    client, _ = client_factory(provider=fake_provider, settings=settings)

    response = client.post(
        "/v1/chat/completions",
        json={"messages": [{"role": "user", "content": "hello"}]},
    )

    assert response.status_code == 413
    assert fake_provider.payload is None


def test_blocked_mixed_request_does_not_call_provider(client_factory) -> None:
    fake_provider = FakeProvider()
    client, _ = client_factory(provider=fake_provider)

    response = client.post(
        "/v1/chat/completions",
        json={
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": (
                                f"key {DUMMY_OPENAI_KEY} "
                                f"token {DUMMY_GITHUB_TOKEN} "
                                "email alice@example.com phone 415 555 1212"
                            ),
                        },
                        {
                            "type": "image_url",
                            "image_url": {"url": "https://example.com/alice@example.com.png"},
                        },
                    ],
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {"name": "lookup", "arguments": "{\"email\":\"alice@example.com\"}"},
                        }
                    ],
                }
            ]
        },
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "content_blocked"
    assert fake_provider.payload is None
