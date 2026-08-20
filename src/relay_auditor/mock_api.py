import hashlib
import time
import uuid
from collections import defaultdict
from itertools import accumulate

from fastapi import APIRouter

from relay_auditor.schemas import MockChatRequest

router = APIRouter(prefix="/mock/v1", tags=["local-mock"])
_counters: defaultdict[str, int] = defaultdict(int)


REFERENCE_PROFILE = {
    "number100": [("42", 0.58), ("73", 0.22), ("7", 0.12), ("17", 0.08)],
    "number10": [("7", 0.62), ("3", 0.22), ("5", 0.16)],
    "letter": [("K", 0.55), ("Q", 0.25), ("M", 0.20)],
    "color": [("blue", 0.62), ("green", 0.23), ("purple", 0.15)],
    "coin": [("heads", 0.68), ("tails", 0.32)],
    "animal": [("elephant", 0.55), ("tiger", 0.30), ("dolphin", 0.15)],
    "city": [("Paris", 0.55), ("Tokyo", 0.30), ("London", 0.15)],
    "favorite": [("42", 0.68), ("7", 0.22), ("13", 0.10)],
}

SUBSTITUTE_PROFILE = {
    "number100": [("57", 0.60), ("37", 0.23), ("13", 0.12), ("88", 0.05)],
    "number10": [("4", 0.58), ("8", 0.27), ("2", 0.15)],
    "letter": [("A", 0.58), ("S", 0.27), ("Z", 0.15)],
    "color": [("red", 0.65), ("yellow", 0.22), ("orange", 0.13)],
    "coin": [("tails", 0.76), ("heads", 0.24)],
    "animal": [("cat", 0.62), ("dog", 0.28), ("fox", 0.10)],
    "city": [("Berlin", 0.58), ("Rome", 0.27), ("Madrid", 0.15)],
    "favorite": [("9", 0.62), ("3", 0.23), ("21", 0.15)],
}


def _task_for(prompt: str) -> str:
    lowered = prompt.lower()
    if any(token in lowered for token in ("favorite number", "favourite number", "最喜欢", "最爱")):
        return "favorite"
    if any(token in lowered for token in ("1 and 100", "1 to 100", "1 到 100", "1 至 100")):
        return "number100"
    if any(token in lowered for token in ("1 and 10", "1 to 10", "1 到 10")):
        return "number10"
    if "letter" in lowered or "字母" in lowered:
        return "letter"
    if "color" in lowered or "颜色" in lowered:
        return "color"
    if "coin" in lowered or "硬币" in lowered:
        return "coin"
    if "animal" in lowered or "动物" in lowered:
        return "animal"
    if "city" in lowered or "城市" in lowered:
        return "city"
    return "smoke"


def _weighted_choice(model: str, prompt: str) -> str:
    task = _task_for(prompt)
    if task == "smoke":
        return "AUDIT_OK"
    profile = SUBSTITUTE_PROFILE if "substitute" in model.lower() else REFERENCE_PROFILE
    choices = profile[task]
    counter = _counters[model]
    _counters[model] += 1
    digest = hashlib.sha256(f"{model}|{task}|{counter}|{prompt}".encode()).digest()
    unit = int.from_bytes(digest[:8], "big") / 2**64
    thresholds = accumulate(weight for _, weight in choices)
    for (answer, _), threshold in zip(choices, thresholds, strict=True):
        if unit <= threshold:
            return answer
    return choices[-1][0]


@router.get("/models")
async def list_models() -> dict[str, object]:
    return {
        "object": "list",
        "data": [
            {"id": "reference-model", "object": "model", "owned_by": "local"},
            {"id": "substitute-model", "object": "model", "owned_by": "local"},
        ],
    }


@router.post("/chat/completions")
async def chat_completions(request: MockChatRequest) -> dict[str, object]:
    prompt = request.messages[-1].content if request.messages else ""
    answer = _weighted_choice(request.model, prompt)
    prompt_tokens = max(1, len(prompt.encode("utf-8")) // 4)
    return {
        "id": f"chatcmpl-mock-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": request.model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": answer},
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": 1,
            "total_tokens": prompt_tokens + 1,
        },
    }
