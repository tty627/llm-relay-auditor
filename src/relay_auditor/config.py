from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Relay Model Auditor"
    database_url: str = "sqlite:///./data/relay_auditor.db"
    evidence_dir: Path = Path("./data/evidence")
    fingerprint_cli_path: Path = Path("./llm-fingerprint-detector/dist/cli.js")
    request_timeout_seconds: float = 30.0

    model_config = SettingsConfigDict(
        env_prefix="AUDITOR_",
        env_file=".env.local",
        env_file_encoding="utf-8",
        extra="ignore",
    )
