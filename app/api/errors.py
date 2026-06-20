from fastapi.responses import JSONResponse


def openai_error_response(
    *,
    status_code: int,
    message: str,
    error_type: str,
    code: str,
    param: str | None = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "message": message,
                "type": error_type,
                "param": param,
                "code": code,
            }
        },
    )


def streaming_not_supported_response() -> JSONResponse:
    return openai_error_response(
        status_code=400,
        message="Streaming is not supported by this AI Coding Firewall MVP. Set stream to false.",
        error_type="invalid_request_error",
        param="stream",
        code="streaming_not_supported",
    )


def content_blocked_response(direction: str) -> JSONResponse:
    return openai_error_response(
        status_code=403,
        message=f"{direction.capitalize()} blocked by AI Coding Firewall policy.",
        error_type="security_policy_violation",
        param=None,
        code="content_blocked",
    )


def upstream_error_response() -> JSONResponse:
    return openai_error_response(
        status_code=502,
        message="Upstream provider request failed.",
        error_type="upstream_provider_error",
        param=None,
        code="provider_error",
    )


def upstream_response_too_large_response() -> JSONResponse:
    return openai_error_response(
        status_code=502,
        message="Upstream provider response is too large.",
        error_type="upstream_provider_error",
        param=None,
        code="upstream_response_too_large",
    )
