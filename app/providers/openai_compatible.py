from typing import Any

import httpx

from app.config.settings import ProviderSettings


class ProviderError(Exception):
    def __init__(
        self,
        status_code: int,
        response_json: dict[str, Any] | None = None,
        message: str = "Upstream provider request failed.",
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_json = response_json
        self.message = message


class OpenAICompatibleProviderClient:
    def __init__(self, settings: ProviderSettings) -> None:
        self.settings = settings

    async def chat_completions(self, payload: dict[str, Any]) -> dict[str, Any]:
        headers = {"Content-Type": "application/json"}
        if self.settings.api_key:
            headers["Authorization"] = f"Bearer {self.settings.api_key}"

        url = f"{self.settings.base_url.rstrip('/')}/chat/completions"
        async with httpx.AsyncClient(timeout=self.settings.timeout_seconds) as client:
            try:
                response = await client.post(url, json=payload, headers=headers)
            except httpx.HTTPError as exc:
                raise ProviderError(
                    status_code=502,
                    message=f"Upstream provider request failed before receiving a response: {exc.__class__.__name__}.",
                ) from exc

        if response.status_code >= 400:
            try:
                response_json = response.json()
            except ValueError:
                body = response.text.strip().replace("\n", " ")[:500]
                message = f"Upstream provider returned HTTP {response.status_code}."
                if body:
                    message = f"{message} Body: {body}"
                raise ProviderError(status_code=response.status_code, message=message)
            raise ProviderError(status_code=response.status_code, response_json=response_json)

        try:
            loaded = response.json()
        except ValueError as exc:
            raise ProviderError(
                status_code=502,
                message="Upstream provider returned a non-JSON success response.",
            ) from exc

        if not isinstance(loaded, dict):
            raise ProviderError(
                status_code=502,
                message="Upstream provider returned a JSON response that was not an object.",
            )
        return loaded
