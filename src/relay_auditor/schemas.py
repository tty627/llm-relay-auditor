from typing import Any, Literal

from pydantic import AnyHttpUrl, BaseModel, Field, SecretStr, field_validator


def reject_url_userinfo(value: AnyHttpUrl) -> AnyHttpUrl:
    """API base URLs are endpoints, never a credential transport."""

    if value.username is not None or value.password is not None:
        raise ValueError("base_url must not contain username or password credentials")
    return value


class EndpointSpec(BaseModel):
    base_url: AnyHttpUrl
    model: str = Field(min_length=1, max_length=255)
    api_key_env: str | None = Field(default=None, pattern=r"^[A-Z_][A-Z0-9_]*$")

    _reject_base_url_userinfo = field_validator("base_url")(reject_url_userinfo)


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


class EphemeralConnectionSpec(BaseModel):
    base_url: AnyHttpUrl
    api_key: SecretStr | None = Field(default=None, max_length=4096)

    _reject_base_url_userinfo = field_validator("base_url")(reject_url_userinfo)

    def reveal_api_key(self) -> str | None:
        return self.api_key.get_secret_value() if self.api_key is not None else None


class EphemeralEndpointSpec(EphemeralConnectionSpec):
    """Endpoint credentials accepted only by the local browser console."""

    model: str = Field(min_length=1, max_length=255)

    def public_endpoint(self) -> EndpointSpec:
        return EndpointSpec(base_url=self.base_url, model=self.model)


class ConsoleFingerprintCollectRequest(BaseModel):
    endpoint: EphemeralEndpointSpec
    cells: int = Field(default=4, ge=1, le=16)
    samples: int = Field(default=15, ge=10, le=100)
    concurrency: int = Field(default=4, ge=1, le=20)


class ConsoleComparisonContext(BaseModel):
    batch_id: str
    total_items: int = Field(ge=1, le=500)
    station_name: str = Field(min_length=1, max_length=80)
    reference_name: str = Field(min_length=1, max_length=100)
    reference_model: str = Field(min_length=1, max_length=255)

    @field_validator("batch_id")
    @classmethod
    def validate_batch_id(cls, value: str) -> str:
        if not value or any(char not in "0123456789abcdef-" for char in value):
            raise ValueError("batch_id must be a lowercase UUID")
        return value


class ConsoleComparisonBatchItemRequest(BaseModel):
    endpoint: EphemeralEndpointSpec
    reference_artifact_id: str
    station_name: str = Field(min_length=1, max_length=80)
    reference_name: str = Field(min_length=1, max_length=100)
    reference_model: str = Field(min_length=1, max_length=255)
    priority: int = Field(default=50, ge=0, le=100)

    @field_validator("reference_artifact_id")
    @classmethod
    def validate_reference_artifact_id(cls, value: str) -> str:
        if not value or any(char not in "0123456789abcdef-" for char in value):
            raise ValueError("reference_artifact_id must be a lowercase UUID")
        return value


class ConsoleComparisonBatchRequest(BaseModel):
    items: list[ConsoleComparisonBatchItemRequest] = Field(min_length=1, max_length=500)
    cells: int = Field(default=4, ge=1, le=16)
    samples: int = Field(default=15, ge=10, le=100)
    concurrency: int = Field(default=4, ge=1, le=20)
    concurrency_mode: Literal["auto", "fixed"] = "fixed"
    request_timeout_seconds: float = Field(default=15, ge=3, le=120)
    model_timeout_seconds: float = Field(default=300, ge=30, le=1800)


class ConsoleFingerprintVerifyRequest(ConsoleFingerprintCollectRequest):
    reference_artifact_id: str
    comparison_context: ConsoleComparisonContext | None = None

    @field_validator("reference_artifact_id")
    @classmethod
    def validate_artifact_id(cls, value: str) -> str:
        if not value or any(char not in "0123456789abcdef-" for char in value):
            raise ValueError("reference_artifact_id must be a lowercase UUID")
        return value


class ConsoleModelDiscoveryRequest(BaseModel):
    endpoint: EphemeralConnectionSpec


class ConsoleReferenceCollectRequest(ConsoleFingerprintCollectRequest):
    reference_name: str = Field(min_length=1, max_length=60)
    provider: str = Field(default="user_reference", min_length=1, max_length=100)
    valid_days: int = Field(default=14, ge=1, le=90)


class TokenizerCollectRequest(BaseModel):
    endpoint: EndpointSpec
    samples_per_point: int = Field(default=2, ge=1, le=5)
    concurrency: int = Field(default=6, ge=1, le=20)


class TokenizerVerifyRequest(TokenizerCollectRequest):
    reference_artifact_id: str

    @field_validator("reference_artifact_id")
    @classmethod
    def validate_reference_id(cls, value: str) -> str:
        if not value or any(char not in "0123456789abcdef-" for char in value):
            raise ValueError("reference_artifact_id must be a lowercase UUID")
        return value


class ManagedEndpointCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    provider: str = Field(min_length=1, max_length=100)
    base_url: AnyHttpUrl
    model: str = Field(min_length=1, max_length=255)
    protocol: Literal["openai_chat"] = "openai_chat"
    api_key_env: str | None = Field(default=None, pattern=r"^[A-Z_][A-Z0-9_]*$")

    _reject_base_url_userinfo = field_validator("base_url")(reject_url_userinfo)


class BaselineCreateRequest(BaseModel):
    endpoint_id: str
    detector: Literal["one_token", "tokenizer"]
    artifact_id: str
    valid_days: int = Field(default=14, ge=1, le=90)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("endpoint_id", "artifact_id")
    @classmethod
    def validate_uuid_like(cls, value: str) -> str:
        if not value or any(char not in "0123456789abcdef-" for char in value):
            raise ValueError("value must be a lowercase UUID")
        return value


class AuditResponse(BaseModel):
    audit_id: str
    detector: str
    status: Literal["completed", "failed"]
    verdict: str
    artifact_id: str | None = None
    artifact_sha256: str | None = None
    result: dict[str, Any]


class ConsoleReferenceCollectResponse(AuditResponse):
    saved_reference: dict[str, Any]


class MockChatMessage(BaseModel):
    role: str
    content: str


class MockChatRequest(BaseModel):
    model: str
    messages: list[MockChatMessage]
    max_tokens: int | None = None
    temperature: float | None = None
    stream: bool = False
