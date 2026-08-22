import json
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Relay Model Auditor"
    database_url: str = "sqlite:///./data/relay_auditor.db"
    evidence_dir: Path = Path("./data/evidence")
    fingerprint_cli_path: Path = Path("./llm-fingerprint-detector/dist/cli.js")
    request_timeout_seconds: float = 30.0
    allowed_api_key_envs: str = ""
    api_key_base_url_bindings: str = "{}"
    access_token: SecretStr | None = None
    management_token: SecretStr | None = None

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
        reserved = {
            "PATH",
            "LANG",
            "LC_ALL",
            "LC_CTYPE",
            "TMPDIR",
            "SYSTEMROOT",
            "NODE_EXTRA_CA_CERTS",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
        }
        invalid = sorted(
            name
            for name in names
            if re.fullmatch(r"[A-Z_][A-Z0-9_]*", name) is None
            or name in reserved
            or name.startswith("AUDITOR_")
        )
        if invalid:
            raise ValueError("AUDITOR_ALLOWED_API_KEY_ENVS contains invalid variable names")
        return names

    def require_allowed_api_key_env(self, name: str | None) -> None:
        if name is not None and name not in self.api_key_env_allowlist():
            raise ValueError(
                "api_key_env is not allowed; add it to AUDITOR_ALLOWED_API_KEY_ENVS first"
            )

    def api_key_base_url_bindings_map(self) -> dict[str, frozenset[str]]:
        try:
            payload = json.loads(self.api_key_base_url_bindings)
        except json.JSONDecodeError as error:
            raise ValueError(
                "AUDITOR_API_KEY_BASE_URL_BINDINGS must be a JSON object"
            ) from error
        if not isinstance(payload, dict):
            raise ValueError("AUDITOR_API_KEY_BASE_URL_BINDINGS must be a JSON object")

        unknown = sorted(set(payload) - self.api_key_env_allowlist())
        if unknown:
            raise ValueError(
                "AUDITOR_API_KEY_BASE_URL_BINDINGS contains variables outside the allowlist"
            )
        result: dict[str, frozenset[str]] = {}
        for name, values in payload.items():
            if not isinstance(values, list) or not values:
                raise ValueError(
                    "AUDITOR_API_KEY_BASE_URL_BINDINGS values must be non-empty URL arrays"
                )
            if any(not isinstance(value, str) or not value.strip() for value in values):
                raise ValueError(
                    "AUDITOR_API_KEY_BASE_URL_BINDINGS values must be non-empty URL arrays"
                )
            result[name] = frozenset(value.strip() for value in values)
        return result

    def api_key_base_url_allowlist(self, name: str) -> frozenset[str]:
        return self.api_key_base_url_bindings_map().get(name, frozenset())

    def require_api_key_base_url_binding(self, name: str | None, base_url: str) -> None:
        if name is None:
            return
        self.require_allowed_api_key_env(name)
        from relay_auditor.detectors.preflight import normalize_fingerprint_base_url

        try:
            requested = normalize_fingerprint_base_url(base_url)
            allowed = {
                normalize_fingerprint_base_url(value)
                for value in self.api_key_base_url_allowlist(name)
            }
        except (TypeError, ValueError, RuntimeError) as error:
            raise ValueError("invalid API key Base URL binding configuration") from error
        parsed = urlsplit(requested)
        loopback_http = parsed.scheme == "http" and parsed.hostname in {
            "127.0.0.1",
            "::1",
            "localhost",
        }
        if parsed.scheme != "https" and not loopback_http:
            raise ValueError(
                "managed API credentials require HTTPS except for explicit loopback URLs"
            )
        if requested not in allowed:
            raise ValueError(
                "api_key_env is not bound to this base_url in "
                "AUDITOR_API_KEY_BASE_URL_BINDINGS"
            )

    def management_token_value(self) -> str | None:
        if self.management_token is not None:
            value = self.management_token.get_secret_value()
            return value if value else None
        return self.reveal_access_token()

    def validate_managed_credential_configuration(self) -> None:
        names = self.api_key_env_allowlist()
        bindings = self.api_key_base_url_bindings_map()
        token = self.management_token_value()
        if names and token is None and not bindings:
            # An allowlist alone is inert. Keep the service usable in explicitly
            # disabled mode so operators can configure the token and bindings
            # together without exposing any credential in the interim.
            return
        missing = sorted(names - bindings.keys())
        if missing:
            raise ValueError(
                "every allowed API key environment variable needs a Base URL binding"
            )
        if names and (
            token is None or re.fullmatch(r"[A-Za-z0-9._~-]{24,512}", token) is None
        ):
            raise ValueError(
                "AUDITOR_MANAGEMENT_TOKEN or AUDITOR_ACCESS_TOKEN must contain "
                "24-512 URL-safe ASCII characters when managed API credentials "
                "are enabled"
            )
        for name, base_urls in bindings.items():
            for base_url in base_urls:
                self.require_api_key_base_url_binding(name, base_url)

    def resolve_api_key(self, name: str | None) -> str | None:
        if name is None:
            return None
        self.require_allowed_api_key_env(name)
        value = os.environ.get(name)
        if value is None or not value.strip():
            raise ValueError("the allowed api_key_env is not set in the service environment")
        return value.strip()

    def reveal_access_token(self) -> str | None:
        return self.access_token.get_secret_value() if self.access_token is not None else None
