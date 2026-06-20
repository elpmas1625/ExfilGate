import asyncio
import json
import logging
import time
from typing import Any, AsyncIterator
from uuid import uuid4

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from app.api.errors import (
    content_blocked_response,
    openai_error_response,
    upstream_error_response,
    upstream_response_too_large_response,
)
from app.audit.jsonl import JsonlAuditLogger
from app.audit.models import AuditEvent
from app.config.settings import Settings, load_settings
from app.detectors.gitleaks import GitleaksDetector
from app.detectors.regex_pii import RegexPIIDetector
from app.detectors.regex_secret import RegexSecretDetector
from app.policy.engine import PolicyEngine
from app.providers.openai_compatible import OpenAICompatibleProviderClient, ProviderError
from app.scanning.service import ScanService

logger = logging.getLogger(__name__)
router = APIRouter()


def build_runtime() -> tuple[Settings, JsonlAuditLogger, ScanService, PolicyEngine, OpenAICompatibleProviderClient]:
    settings = load_settings()
    detectors = []
    if settings.detectors.regex_secrets.enabled:
        detectors.append(RegexSecretDetector())
    if settings.detectors.regex_pii.enabled:
        detectors.append(RegexPIIDetector())
    if settings.detectors.gitleaks.enabled:
        detectors.append(GitleaksDetector(timeout_seconds=settings.detectors.gitleaks.timeout_seconds))

    return (
        settings,
        JsonlAuditLogger(settings.audit.path),
        ScanService(detectors=detectors, max_scan_chars=settings.limits.max_scan_chars),
        PolicyEngine(settings.policy),
        OpenAICompatibleProviderClient(settings.provider),
    )


def audit_safely(logger_: JsonlAuditLogger, event: AuditEvent) -> None:
    try:
        logger_.write(event)
    except OSError as exc:
        logger.warning("audit_log_write_failed request_id=%s error=%s", event.request_id, exc.__class__.__name__)


def sse_data(payload: dict[str, Any] | str) -> str:
    if isinstance(payload, str):
        return f"data: {payload}\n\n"
    return f"data: {json.dumps(payload, separators=(',', ':'))}\n\n"


def sse_error(*, message: str, error_type: str, code: str, param: str | None = None) -> str:
    return sse_data(
        {
            "error": {
                "message": message,
                "type": error_type,
                "param": param,
                "code": code,
            }
        }
    )


def stream_heartbeat(settings: Settings, stream_id: str, model: str | None) -> str:
    if settings.stream.heartbeat_mode == "empty_delta":
        return sse_data(
            {
                "id": stream_id,
                "object": "chat.completion.chunk",
                "created": int(time.time()),
                "model": model,
                "choices": [{"index": 0, "delta": {"content": ""}, "finish_reason": None}],
            }
        )
    return ": ping\n\n"


def chat_completion_to_sse_chunks(payload: dict[str, Any]) -> list[str]:
    stream_id = str(payload.get("id") or f"chatcmpl_{uuid4().hex}")
    model = payload.get("model")
    created = payload.get("created")
    if not isinstance(created, int):
        created = int(time.time())

    chunks: list[str] = []
    choices = payload.get("choices")
    if not isinstance(choices, list):
        choices = []

    for choice_index, choice in enumerate(choices):
        if not isinstance(choice, dict):
            continue
        index = choice.get("index")
        if not isinstance(index, int):
            index = choice_index

        message = choice.get("message")
        if not isinstance(message, dict):
            continue

        role = message.get("role")
        if isinstance(role, str):
            chunks.append(
                sse_data(
                    {
                        "id": stream_id,
                        "object": "chat.completion.chunk",
                        "created": created,
                        "model": model,
                        "choices": [{"index": index, "delta": {"role": role}, "finish_reason": None}],
                    }
                )
            )

        content = message.get("content")
        if isinstance(content, str) and content:
            chunks.append(
                sse_data(
                    {
                        "id": stream_id,
                        "object": "chat.completion.chunk",
                        "created": created,
                        "model": model,
                        "choices": [{"index": index, "delta": {"content": content}, "finish_reason": None}],
                    }
                )
            )

        tool_calls = message.get("tool_calls")
        if isinstance(tool_calls, list):
            delta_tool_calls = []
            for tool_index, tool_call in enumerate(tool_calls):
                if not isinstance(tool_call, dict):
                    continue
                delta_tool_call: dict[str, Any] = {"index": tool_index}
                if isinstance(tool_call.get("id"), str):
                    delta_tool_call["id"] = tool_call["id"]
                if isinstance(tool_call.get("type"), str):
                    delta_tool_call["type"] = tool_call["type"]
                function = tool_call.get("function")
                if isinstance(function, dict):
                    delta_tool_call["function"] = {}
                    if isinstance(function.get("name"), str):
                        delta_tool_call["function"]["name"] = function["name"]
                    if isinstance(function.get("arguments"), str):
                        delta_tool_call["function"]["arguments"] = function["arguments"]
                delta_tool_calls.append(delta_tool_call)
            if delta_tool_calls:
                chunks.append(
                    sse_data(
                        {
                            "id": stream_id,
                            "object": "chat.completion.chunk",
                            "created": created,
                            "model": model,
                            "choices": [{"index": index, "delta": {"tool_calls": delta_tool_calls}, "finish_reason": None}],
                        }
                    )
                )

        finish_reason = choice.get("finish_reason") or ("tool_calls" if message.get("tool_calls") else "stop")
        chunks.append(
            sse_data(
                {
                    "id": stream_id,
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": model,
                    "choices": [{"index": index, "delta": {}, "finish_reason": finish_reason}],
                }
            )
        )

    if not chunks:
        chunks.append(
            sse_data(
                {
                    "id": stream_id,
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": model,
                    "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                }
            )
        )
    return chunks


async def stream_chat_completions(
    *,
    settings: Settings,
    audit_logger: JsonlAuditLogger,
    scanner: ScanService,
    policy: PolicyEngine,
    provider: OpenAICompatibleProviderClient,
    request_id: str,
    upstream_payload: dict[str, Any],
) -> AsyncIterator[str]:
    done_sent = False
    upstream_task: asyncio.Task[dict[str, Any]] | None = None
    stream_id = f"chatcmpl_{uuid4().hex}"
    model = upstream_payload.get("model") if isinstance(upstream_payload.get("model"), str) else None

    try:
        non_stream_payload = dict(upstream_payload)
        non_stream_payload["stream"] = False
        upstream_task = asyncio.create_task(provider.chat_completions(non_stream_payload))

        heartbeat_interval = max(settings.stream.heartbeat_interval_seconds, 0.001)
        while not upstream_task.done():
            done, _ = await asyncio.wait({upstream_task}, timeout=heartbeat_interval)
            if done:
                break
            yield stream_heartbeat(settings, stream_id, model)

        upstream_response = await upstream_task
        response_size = len(json.dumps(upstream_response, separators=(",", ":")).encode("utf-8"))
        if response_size > settings.limits.max_response_bytes:
            audit_safely(
                audit_logger,
                AuditEvent.blocked_event(
                    request_id=request_id,
                    provider=settings.provider.name,
                    direction="response",
                    reason="response_too_large",
                ),
            )
            yield sse_error(
                message="Upstream provider response is too large.",
                error_type="upstream_provider_error",
                code="upstream_response_too_large",
            )
            return

        response_result = scanner.scan_response(upstream_response)
        response_decision = policy.decide(response_result.detections)
        audit_safely(
            audit_logger,
            AuditEvent.from_decision(
                request_id=request_id,
                provider=settings.provider.name,
                direction="response",
                decision=response_decision,
                scan_truncated=response_result.scan_truncated,
            ),
        )

        if response_decision.blocked:
            yield sse_error(
                message="Response blocked by AI Coding Firewall policy.",
                error_type="security_policy_violation",
                code="content_blocked",
            )
            return

        response_payload = upstream_response
        if response_decision.should_mask:
            response_payload = scanner.mask_response(upstream_response, response_result.detections)

        for chunk in chat_completion_to_sse_chunks(response_payload):
            yield chunk
    except ProviderError as exc:
        audit_safely(
            audit_logger,
            AuditEvent.blocked_event(
                request_id=request_id,
                provider=settings.provider.name,
                direction="request",
                reason="provider_error",
            ),
        )
        if exc.response_json is not None:
            yield sse_data(exc.response_json)
        else:
            yield sse_error(
                message="Upstream provider request failed.",
                error_type="upstream_provider_error",
                code="provider_error",
            )
    except Exception:
        logger.exception("streaming_chat_completion_failed request_id=%s", request_id)
        yield sse_error(
            message="Streaming proxy failed.",
            error_type="upstream_provider_error",
            code="streaming_proxy_error",
        )
    finally:
        if upstream_task is not None and not upstream_task.done():
            upstream_task.cancel()
        if not done_sent:
            done_sent = True
            yield sse_data("[DONE]")


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.post("/v1/chat/completions")
async def chat_completions(request: Request) -> Response:
    settings, audit_logger, scanner, policy, provider = build_runtime()
    request_id = f"req_{uuid4().hex}"

    raw_body = await request.body()
    if len(raw_body) > settings.limits.max_request_bytes:
        return openai_error_response(
            status_code=413,
            message="Request body is too large.",
            error_type="invalid_request_error",
            param=None,
            code="request_too_large",
        )

    try:
        payload: dict[str, Any] = json.loads(raw_body)
    except json.JSONDecodeError:
        return openai_error_response(
            status_code=400,
            message="Request body must be valid JSON.",
            error_type="invalid_request_error",
            param=None,
            code="invalid_json",
        )

    request_result = scanner.scan_request(payload)
    request_decision = policy.decide(request_result.detections)
    audit_safely(
        audit_logger,
        AuditEvent.from_decision(
            request_id=request_id,
            provider=settings.provider.name,
            direction="request",
            decision=request_decision,
            scan_truncated=request_result.scan_truncated,
        ),
    )

    if request_decision.blocked:
        return content_blocked_response("request")

    upstream_payload = payload
    if request_decision.should_mask:
        upstream_payload = scanner.mask_request(payload, request_result.detections)

    if payload.get("stream") is True:
        return StreamingResponse(
            stream_chat_completions(
                settings=settings,
                audit_logger=audit_logger,
                scanner=scanner,
                policy=policy,
                provider=provider,
                request_id=request_id,
                upstream_payload=upstream_payload,
            ),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    try:
        upstream_response = await provider.chat_completions(upstream_payload)
    except ProviderError as exc:
        audit_safely(
            audit_logger,
            AuditEvent.blocked_event(
                request_id=request_id,
                provider=settings.provider.name,
                direction="request",
                reason="provider_error",
            ),
        )
        if exc.response_json is not None:
            return JSONResponse(status_code=exc.status_code, content=exc.response_json)
        return upstream_error_response()

    response_size = len(json.dumps(upstream_response, separators=(",", ":")).encode("utf-8"))
    if response_size > settings.limits.max_response_bytes:
        audit_safely(
            audit_logger,
            AuditEvent.blocked_event(
                request_id=request_id,
                provider=settings.provider.name,
                direction="response",
                reason="response_too_large",
            ),
        )
        return upstream_response_too_large_response()

    response_result = scanner.scan_response(upstream_response)
    response_decision = policy.decide(response_result.detections)
    audit_safely(
        audit_logger,
        AuditEvent.from_decision(
            request_id=request_id,
            provider=settings.provider.name,
            direction="response",
            decision=response_decision,
            scan_truncated=response_result.scan_truncated,
        ),
    )

    if response_decision.blocked:
        return content_blocked_response("response")

    response_payload = upstream_response
    if response_decision.should_mask:
        response_payload = scanner.mask_response(upstream_response, response_result.detections)

    return JSONResponse(status_code=200, content=response_payload)
