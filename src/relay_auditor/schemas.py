from typing import Any, Literal

from pydantic import AnyHttpUrl, BaseModel, Field, field_validator


class EndpointSpec(BaseModel):
    base_url: AnyHttpUrl
    model: str = Field(min_length=1, max_length=255)
    api_key_env: str | None = Field(default=None, pattern=r"^[A-Z_][A-Z0-9_]*$")


class SmokeAuditRequest(BaseModel):
    target: EndpointSpec
    prompt: str = Field(default="Reply with exactly: AUDIT_OK", min_length=1, max_length=500)


class FingerprintCollectRequest(BaseModel):
    endpoint: EndpointSpec
    cells: int = Field(default=4, ge=1, le=16)
    samples: int = Field(default=15, ge=10, le=100)
    concurrency: int = Field(default=6, ge=1, le=20)


class FingerprintVerifyRequest(FingerprintCollectRequest):
    reference_artifact_id: str

    @field_validator("reference_artifact_id")
    @classmethod
    def validate_artifact_id(cls, value: str) -> str:
        if not value or any(char not in "0123456789abcdef-" for char in value):
            raise ValueError("reference_artifact_id must be a lowercase UUID")
        return value


class AuditResponse(BaseModel):
    audit_id: str
    detector: str
    status: Literal["completed", "failed"]
    verdict: str
    artifact_id: str | None = None
    artifact_sha256: str | None = None
    result: dict[str, Any]


class MockChatMessage(BaseModel):
    role: str
    content: str


class MockChatRequest(BaseModel):
    model: str
    messages: list[MockChatMessage]
    max_tokens: int | None = None
    temperature: float | None = None
    stream: bool = False
