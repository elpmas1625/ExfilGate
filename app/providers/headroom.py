from typing import Any


class HeadroomProviderClient:
    async def chat_completions(self, payload: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError("Headroom provider support is a future extension point.")
