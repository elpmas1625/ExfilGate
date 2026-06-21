import logging
from typing import Any

from headroom import compress as headroom_compress
from headroom.compress import CompressResult

from app.config.settings import ProviderSettings
from app.providers.openai_compatible import OpenAICompatibleProviderClient, ProviderError

logger = logging.getLogger(__name__)


class HeadroomProviderClient:
    def __init__(self, settings: ProviderSettings) -> None:
        self._openai_client = OpenAICompatibleProviderClient(settings)
        self.last_compression: CompressResult | None = None

    async def chat_completions(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.last_compression = None
        messages = payload.get("messages")
        if isinstance(messages, list) and messages:
            try:
                result = headroom_compress(messages)
                logger.info(
                    "headroom_compression tokens_before=%d tokens_after=%d tokens_saved=%d "
                    "compression_ratio=%.3f transforms=%s",
                    result.tokens_before,
                    result.tokens_after,
                    result.tokens_saved,
                    result.compression_ratio,
                    result.transforms_applied,
                )
                self.last_compression = result
                payload = {**payload, "messages": list(result.messages)}
            except Exception as exc:
                raise ProviderError(
                    status_code=502,
                    message=f"Headroom compression failed: {exc}",
                ) from exc

        return await self._openai_client.chat_completions(payload)
