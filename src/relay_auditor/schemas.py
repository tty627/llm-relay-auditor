from typing import Any, Literal

from pydantic import (
    AnyHttpUrl,
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)

LEGACY_ONE_TOKEN_PROFILE = "legacy-one-token/v1"
PAPER_ONE_TOKEN_PROFILE = "bruckner-2026-canonical40/v1"
OneTokenMethodProfileId = Literal[
    "legacy-one-token/v1",
    "bruckner-2026-canonical40/v1",
]


def reject_url_userinfo(value: AnyHttpUrl) -> AnyHttpUrl:
    """API base URLs are origins/paths, never a credential transport."""

    if value.username is not None or value.password is not None:
        raise ValueError("base_url must not contain username or password credentials")
    if value.query or value.fragment:
        raise ValueError("base_url must not contain query parameters or fragments")
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
    method_profile_id: OneTokenMethodProfileId = LEGACY_ONE_TOKEN_PROFILE
    cells: int = Field(default=4, ge=1, le=40)
    samples: int = Field(default=15, ge=10, le=100)
    concurrency: int = Field(default=6, ge=1, le=20)

    @model_validator(mode="after")
    def validate_profile_cells(self):
        if self.method_profile_id == LEGACY_ONE_TOKEN_PROFILE and self.cells > 16:
            raise ValueError("legacy-one-token/v1 supports at most 16 cells")
        if self.method_profile_id == PAPER_ONE_TOKEN_PROFILE and self.cells != 40:
            raise ValueError("bruckner-2026-canonical40/v1 requires exactly 40 cells")
        return self


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
        if self.api_key is None:
            return None
        return self.api_key.get_secret_value().strip()


class EphemeralEndpointSpec(EphemeralConnectionSpec):
    """Endpoint credentials accepted only by the local browser console."""

    model: str = Field(min_length=1, max_length=255)

    def public_endpoint(self) -> EndpointSpec:
        return EndpointSpec(base_url=self.base_url, model=self.model)


class ConsoleFingerprintCollectRequest(BaseModel):
    endpoint: EphemeralEndpointSpec
    method_profile_id: OneTokenMethodProfileId = LEGACY_ONE_TOKEN_PROFILE
    cells: int = Field(default=4, ge=1, le=40)
    samples: int = Field(default=15, ge=10, le=100)
    concurrency: int = Field(default=4, ge=1, le=20)

    @model_validator(mode="after")
    def validate_profile_cells(self):
        if self.method_profile_id == LEGACY_ONE_TOKEN_PROFILE and self.cells > 16:
            raise ValueError("legacy-one-token/v1 supports at most 16 cells")
        if self.method_profile_id == PAPER_ONE_TOKEN_PROFILE and self.cells != 40:
            raise ValueError("bruckner-2026-canonical40/v1 requires exactly 40 cells")
        return self


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
    cells: int = Field(default=4, ge=1, le=40)
    samples: int = Field(default=15, ge=10, le=100)
    concurrency: int = Field(default=4, ge=1, le=20)
    concurrency_mode: Literal["auto", "fixed"] = "fixed"
    request_timeout_seconds: float = Field(default=15, ge=3, le=120)
    model_timeout_seconds: float = Field(default=300, ge=30, le=1800)


class ConsoleFingerprintVerifyRequest(ConsoleFingerprintCollectRequest):
    model_config = ConfigDict(extra="forbid")

    reference_artifact_id: str

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


class ConsoleReferenceCollectionRequest(BaseModel):
    reference_name: str = Field(min_length=1, max_length=60)
    provider: str = Field(default="user_reference", min_length=1, max_length=100)
    endpoint: EphemeralConnectionSpec
    models: list[str] = Field(min_length=1, max_length=200)
    method_profile_id: OneTokenMethodProfileId = LEGACY_ONE_TOKEN_PROFILE
    cells: int = Field(default=4, ge=1, le=40)
    samples: int = Field(default=15, ge=10, le=100)
    concurrency: int = Field(default=4, ge=1, le=20)
    concurrency_mode: Literal["auto", "fixed"] = "fixed"
    request_timeout_seconds: float = Field(default=15, ge=3, le=120)
    model_timeout_seconds: float = Field(default=300, ge=30, le=1800)
    valid_days: int = Field(default=14, ge=1, le=90)

    @field_validator("models")
    @classmethod
    def validate_models(cls, values: list[str]) -> list[str]:
        models: list[str] = []
        seen: set[str] = set()
        for value in values:
            model = value.strip()
            if not model or len(model) > 255:
                raise ValueError("each model must contain 1 to 255 characters")
            if model in seen:
                raise ValueError(f"duplicate model: {model}")
            seen.add(model)
            models.append(model)
        return models

    @model_validator(mode="after")
    def validate_profile_cells(self):
        if self.method_profile_id == LEGACY_ONE_TOKEN_PROFILE and self.cells > 16:
            raise ValueError("legacy-one-token/v1 supports at most 16 cells")
        if self.method_profile_id == PAPER_ONE_TOKEN_PROFILE and self.cells != 40:
            raise ValueError("bruckner-2026-canonical40/v1 requires exactly 40 cells")
        return self


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
