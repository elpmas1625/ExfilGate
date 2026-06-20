import json
import logging
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from app.api.errors import (
    content_blocked_response,
    openai_error_response,
    streaming_not_supported_response,
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

    if payload.get("stream") is True:
        audit_safely(
            audit_logger,
            AuditEvent.blocked_event(
                request_id=request_id,
                provider=settings.provider.name,
                direction="request",
                reason="streaming_not_supported",
            ),
        )
        return streaming_not_supported_response()

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
