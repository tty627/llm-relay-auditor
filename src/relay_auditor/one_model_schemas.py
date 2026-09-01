from __future__ import annotations

from typing import Annotated

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field, StringConstraints, model_validator

from relay_auditor.schemas import CredentialSpec, reject_url_userinfo

SafeRowId = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    ),
]


class OneModelTargetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    row_id: SafeRowId
    station_name: str = Field(min_length=1, max_length=80)
    base_url: AnyHttpUrl
    credential: CredentialSpec
    model_id: str | None = Field(default=None, min_length=1, max_length=255)

    _reject_base_url_userinfo = __import__("pydantic").field_validator("base_url")(
        reject_url_userinfo
    )


class OneModelBatchCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reference_set_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    default_model_id: str = Field(min_length=1, max_length=255)
    targets: list[OneModelTargetRequest] = Field(min_length=1, max_length=20)
    max_parallel_stations: int = Field(default=4, ge=1, le=8)
    per_station_concurrency: int = Field(default=3, ge=1, le=4)
    global_request_concurrency: int = Field(default=12, ge=1, le=16)
    request_timeout_seconds: float = Field(default=30, ge=3, le=120)
    station_timeout_seconds: float = Field(default=7200, ge=60, le=7200)
    batch_timeout_seconds: float = Field(default=43200, ge=60, le=43200)
    retry_budget: int = Field(default=240, ge=0, le=240)

    @model_validator(mode="after")
    def validate_batch_contract(self):
        row_ids: set[str] = set()
        endpoint_models: set[tuple[str, str]] = set()
        for item in self.targets:
            if item.row_id in row_ids:
                raise ValueError(f"duplicate row_id: {item.row_id}")
            row_ids.add(item.row_id)
            model = (item.model_id or self.default_model_id).strip()
            normalized_url = str(item.base_url).rstrip("/").casefold()
            identity = (normalized_url, model)
            if identity in endpoint_models:
                raise ValueError("duplicate normalized base_url and model_id")
            endpoint_models.add(identity)
        maximum_useful = self.max_parallel_stations * self.per_station_concurrency
        if self.global_request_concurrency > maximum_useful:
            raise ValueError(
                "global_request_concurrency cannot exceed "
                "max_parallel_stations * per_station_concurrency"
            )
        return self
