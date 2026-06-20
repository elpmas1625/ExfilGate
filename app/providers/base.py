from typing import Any, Protocol


class ProviderClient(Protocol):
    async def chat_completions(self, payload: dict[str, Any]) -> dict[str, Any]:
        ...
