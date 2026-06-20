# Changelog

## v0.1.0 - 2026-06-20

Initial MVP release.

### Added

- FastAPI OpenAI-compatible proxy for `POST /v1/chat/completions`.
- Request and response scanning before data leaves or returns through the firewall.
- Regex secret detection for OpenAI, GitHub, AWS, Anthropic, DeepSeek, and Slack token patterns.
- Regex PII detection for email and phone numbers.
- Policy engine with `allow`, `warn`, `mask`, and `block` actions.
- OpenAI-compatible error objects for policy blocks, invalid JSON, unsupported streaming, and size limits.
- JSONL audit logging with sanitized metadata only.
- Optional Gitleaks detector adapter, disabled by default.
- Provider abstraction and Headroom extension stub.
- Dockerfile and Docker Compose scaffolding.
- OpenCode connection example.
- `.env.example` for local setup.

### Security

- Audit logs do not store prompt text, response text, secret values, PII values, authorization headers, or provider API keys.
- `stream: true` is explicitly rejected in v0.1 to avoid partial unscanned output.

### Known Limits

- Only `POST /v1/chat/completions` is implemented.
- Streaming is not supported.
- PII detection is limited to email and phone regexes.
- Gitleaks JSON finding parsing is deferred to v0.2.
- Docker build and Compose runtime verification need to be rerun after the local Colima/Docker daemon is healthy.
