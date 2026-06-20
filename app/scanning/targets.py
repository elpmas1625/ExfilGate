from dataclasses import dataclass
from typing import Any, Literal


TargetKind = Literal["message_content", "content_array_text", "response_message_content"]


@dataclass(frozen=True)
class ScanTarget:
    path: tuple[Any, ...]
    text: str
    kind: TargetKind


def extract_request_targets(payload: dict[str, Any]) -> list[ScanTarget]:
    targets: list[ScanTarget] = []
    messages = payload.get("messages")
    if not isinstance(messages, list):
        return targets

    for message_index, message in enumerate(messages):
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if isinstance(content, str):
            targets.append(ScanTarget(path=("messages", message_index, "content"), text=content, kind="message_content"))
        elif isinstance(content, list):
            for content_index, item in enumerate(content):
                if isinstance(item, dict) and item.get("type") == "text" and isinstance(item.get("text"), str):
                    targets.append(
                        ScanTarget(
                            path=("messages", message_index, "content", content_index, "text"),
                            text=item["text"],
                            kind="content_array_text",
                        )
                    )
    return targets


def extract_response_targets(payload: dict[str, Any]) -> list[ScanTarget]:
    targets: list[ScanTarget] = []
    choices = payload.get("choices")
    if not isinstance(choices, list):
        return targets

    for choice_index, choice in enumerate(choices):
        if not isinstance(choice, dict):
            continue
        message = choice.get("message")
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if isinstance(content, str):
            targets.append(
                ScanTarget(
                    path=("choices", choice_index, "message", "content"),
                    text=content,
                    kind="response_message_content",
                )
            )
    return targets
