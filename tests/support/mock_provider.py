from fastapi import FastAPI, Request

app = FastAPI(title="Mock OpenAI-Compatible Provider")


@app.post("/v1/chat/completions")
async def chat_completions(request: Request) -> dict:
    payload = await request.json()
    messages = payload.get("messages", [])
    last_content = ""
    if messages and isinstance(messages[-1], dict):
        content = messages[-1].get("content", "")
        if isinstance(content, str):
            last_content = content
        elif isinstance(content, list):
            parts = [item.get("text", "") for item in content if isinstance(item, dict) and item.get("type") == "text"]
            last_content = " ".join(parts)

    return {
        "id": "chatcmpl_mock",
        "object": "chat.completion",
        "created": 1781890000,
        "model": payload.get("model", "mock-model"),
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": f"mock response: {last_content}",
                },
                "finish_reason": "stop",
            }
        ],
    }
