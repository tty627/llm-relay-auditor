import os
import re
from pathlib import Path

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Relay Model Auditor"
    database_url: str = "sqlite:///./data/relay_auditor.db"
    evidence_dir: Path = Path("./data/evidence")
    fingerprint_cli_path: Path = Path("./llm-fingerprint-detector/dist/cli.js")
    request_timeout_seconds: float = 30.0
    allowed_api_key_envs: str = ""
    access_token: SecretStr | None = None

    model_config = SettingsConfigDict(
        env_prefix="AUDITOR_",
        env_file=".env.local",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    def api_key_env_allowlist(self) -> frozenset[str]:
        names = frozenset(
            name.strip() for name in self.allowed_api_key_envs.split(",") if name.strip()
        )
        invalid = sorted(
            name for name in names if re.fullmatch(r"[A-Z_][A-Z0-9_]*", name) is None
        )
        if invalid:
            raise ValueError("AUDITOR_ALLOWED_API_KEY_ENVS contains invalid variable names")
        return names

    def require_allowed_api_key_env(self, name: str | None) -> None:
        if name is not None and name not in self.api_key_env_allowlist():
            raise ValueError(
                "api_key_env is not allowed; add it to AUDITOR_ALLOWED_API_KEY_ENVS first"
            )

    def resolve_api_key(self, name: str | None) -> str | None:
        if name is None:
            return None
        self.require_allowed_api_key_env(name)
        value = os.environ.get(name)
        if not value:
            raise ValueError("the allowed api_key_env is not set in the service environment")
        return value

    def reveal_access_token(self) -> str | None:
        return self.access_token.get_secret_value() if self.access_token is not None else None
