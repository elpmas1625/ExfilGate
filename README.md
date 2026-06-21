# ExfilGate: AI Coding Firewall MVP

ExfilGate is a minimal AI coding firewall for OpenAI-compatible chat completion APIs.
It sits between an AI coding tool and an OpenAI-compatible LLM provider, scans request
and response text, applies policy, and writes sanitized JSONL audit logs.

## Quick Start

Prerequisites:

- Python 3.12+
- `uv`
- An API key for an OpenAI-compatible provider in `AICF_PROVIDER_API_KEY`

Prepare environment variables:

```bash
cp .env.example .env
```

Edit `.env` and set `AICF_PROVIDER_API_KEY`. If your provider does not use
`https://api.openai.com/v1`, also set `AICF_PROVIDER_BASE_URL`.

Install dependencies:

```bash
uv sync --extra dev
```

Run ExfilGate:

```bash
set -a
source .env
set +a
uv run uvicorn app.main:app --host 0.0.0.0 --port 8000
```

In another terminal, verify the firewall:

```bash
curl http://localhost:8000/health
```

Send a non-streaming chat completion request:

```bash
curl http://localhost:8000/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d @examples/chat_completion_request.json
```

Audit events are written to `./data/audit.jsonl` when using `.env.example`.

## MVP Scope

- API: `POST /v1/chat/completions` only
- Provider: OpenAI-compatible HTTP API only
- Audit log: JSONL by default at `/data/audit.jsonl`
- Streaming: supported for `stream: true` by calling the upstream provider with a non-streaming request, then converting the completed response into OpenAI-compatible SSE chunks.
- PII detection: Regex email and phone only
- Secret detection: Regex required, Gitleaks optional and disabled by default
- Future extension points: Headroom, Presidio, GLiNER, SQLite, PostgreSQL

Audit logs never store prompt text, response text, secret values, PII values,
Authorization headers, or provider API keys.

## v0.1 Features

- FastAPI OpenAI-compatible proxy for `POST /v1/chat/completions`
- Request scanning before upstream provider calls
- Response scanning before returning provider output to the AI tool
- Regex secret detection for OpenAI, GitHub, AWS, Anthropic, DeepSeek, and Slack token patterns
- Regex PII detection for email and phone numbers
- Policy actions: `allow`, `warn`, `mask`, `block`
- OpenAI-compatible error objects for blocked content, invalid JSON, unsupported streaming, and size limits
- JSONL audit logging with sanitized metadata only
- Optional Gitleaks adapter, disabled by default
- Provider abstraction with a Headroom extension stub
- Dockerfile and Docker Compose for self-hosting

## v0.1 Limits

- Only `POST /v1/chat/completions` is implemented
- Streaming is rejected with `streaming_not_supported`
- Only OpenAI-compatible HTTP providers are supported
- PII detection is limited to email and phone regexes
- Gitleaks is optional; v0.1 does not parse Gitleaks JSON findings into detailed detection types
- Masking is intentionally limited to message text fields and response message content
- Redis is present only as an optional Compose service and is not used by the MVP runtime
- Audit logging is JSONL only; SQLite and PostgreSQL are future extensions

## Next Phase

- v0.2: Parse Gitleaks JSON output and map findings to richer detection types
- Add SQLite and PostgreSQL audit logger implementations behind the `AuditLogger` interface
- Add Presidio and GLiNER PII detector implementations behind the detector interface
- Add Headroom provider routing behind the provider interface
- Add streaming support with explicit buffering and policy behavior
- Add Git-aware scanning for `git diff`, patches, and staged changes
- Add agent-aware scanning for tool outputs, MCP results, grep output, and terminal output
- Add rate limiting, async scan workers, and detector result caching if Redis becomes required

## Provider Configuration

`examples/config.yaml` is configured for a generic OpenAI-compatible API:

```yaml
provider:
  name: openai-compatible
  base_url: https://api.openai.com/v1
  api_key_env: AICF_PROVIDER_API_KEY
  timeout_seconds: 60
```

Set `AICF_PROVIDER_BASE_URL` when using another OpenAI-compatible provider.
DeepSeek-specific settings are available in `examples/config.deepseek.yaml`.

The sample request uses a placeholder model name. Replace it with a model
supported by your provider:

```json
{
  "model": "replace-with-provider-model",
  "messages": [
    {
      "role": "user",
      "content": "Write a short hello world in Python."
    }
  ],
  "stream": false
}
```

## Local Run

Install dependencies:

```bash
uv sync --extra dev
```

Run the API:

```bash
AICF_CONFIG=examples/config.yaml \
AICF_AUDIT_PATH=./data/audit.jsonl \
AICF_PROVIDER_API_KEY=your_key \
uv run uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Health check:

```bash
curl http://localhost:8000/health
```

Sample request:

```bash
curl http://localhost:8000/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d @examples/chat_completion_request.json
```

## Docker Compose

```bash
AICF_PROVIDER_API_KEY=your_key docker compose up --build firewall
```

The audit log is persisted in the `aicf_data` volume at `/data/audit.jsonl`.
Redis is present under the optional profile and is not required for the MVP:

```bash
docker compose --profile optional up redis
```

For a provider other than `https://api.openai.com/v1`, set
`AICF_PROVIDER_BASE_URL` as well.

## OpenCode Connection

Configure the AI coding tool to use this firewall as an OpenAI-compatible base URL:

```text
base_url: http://localhost:8000/v1
api_key: any non-empty value accepted by the client
model: a model supported by your upstream provider
```

The firewall uses the provider API key configured by `provider.api_key_env` in
`examples/config.yaml`, defaulting to `AICF_PROVIDER_API_KEY`.

Example OpenCode config:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "provider": {
    "exfilgate": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "ExfilGate",
      "options": {
        "baseURL": "http://localhost:8000/v1"
      },
      "models": {
        "replace-with-provider-model": {
          "name": "Provider Model via ExfilGate"
        }
      }
    }
  },
  "model": "exfilgate/replace-with-provider-model"
}
```

If OpenCode asks for credentials through `/connect`, enter a local placeholder
value. ExfilGate does not use that client-side key for upstream authentication;
it reads the real upstream key from `AICF_PROVIDER_API_KEY` by default.

## Policy

Default policy is in `examples/config.yaml`:

```yaml
policy:
  default_action: allow
  rules:
    openai_key: block
    github_token: block
    aws_access_key: block
    aws_secret: block
    anthropic_key: block
    deepseek_key: block
    slack_token: block
    secret: block
    email: mask
    phone: mask
```

Action priority is:

```text
block > mask > warn > allow
```

Masking is deliberately limited to:

- `messages[].content` when it is a string
- `messages[].content[]` entries where `type: text`
- `choices[].message.content` in provider responses

The MVP does not mutate `tools`, `tool_choice`, `response_format`, or other JSON
structures, which avoids breaking request syntax.

## Errors

Streaming is rejected:

```json
{
  "error": {
    "message": "Streaming is not supported by this AI Coding Firewall MVP. Set stream to false.",
    "type": "invalid_request_error",
    "param": "stream",
    "code": "streaming_not_supported"
  }
}
```

Policy blocks return:

```json
{
  "error": {
    "message": "Request blocked by AI Coding Firewall policy.",
    "type": "security_policy_violation",
    "param": null,
    "code": "content_blocked"
  }
}
```

## Gitleaks

Gitleaks is optional and disabled by default. If enabled but the `gitleaks` CLI is
not installed, ExfilGate emits a sanitized warning and continues running.

```yaml
detectors:
  gitleaks:
    enabled: true
    timeout_seconds: 3
```

## Tests

```bash
uv run --extra dev pytest
```
