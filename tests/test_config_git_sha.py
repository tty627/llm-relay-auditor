import re
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError

import relay_auditor.config as config_module
from relay_auditor.config import Settings
from relay_auditor.main import create_app


def test_explicit_git_sha_is_normalized_and_has_priority(monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected_run(*_args, **_kwargs):
        raise AssertionError("git must not run when AUDITOR_GIT_SHA is explicit")

    monkeypatch.setattr(config_module.subprocess, "run", unexpected_run)
    monkeypatch.setenv("AUDITOR_GIT_SHA", " ABCDEF1 ")
    settings = Settings(_env_file=None)

    assert settings.resolved_git_sha() == "abcdef1"


@pytest.mark.parametrize(
    "value",
    ["unknown", "abcdef", "g234567", "a" * 65, "abc1234; echo unsafe"],
)
def test_explicit_git_sha_rejects_non_hex_or_wrong_length(value: str) -> None:
    with pytest.raises(ValidationError, match="7 to 64 character hex SHA"):
        Settings(git_sha=value)


def test_git_sha_defaults_to_current_repository_head() -> None:
    repository = Path(__file__).resolve().parents[1]
    expected = subprocess.run(
        ["git", "rev-parse", "--verify", "HEAD^{commit}"],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    resolved = Settings(git_sha=None).resolved_git_sha(repository)

    assert re.fullmatch(r"[0-9a-f]{7,64}", resolved)
    assert resolved == expected


def test_git_sha_resolution_fails_closed_outside_checkout(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="AUDITOR_GIT_SHA is required"):
        Settings(git_sha=None).resolved_git_sha(tmp_path)


def test_create_app_passes_resolved_git_sha_to_formal_batch_manager(
    tmp_path: Path,
) -> None:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        evidence_dir=tmp_path / "evidence",
        fingerprint_cli_path=tmp_path / "unused.js",
        git_sha="deadbee",
    )

    app = create_app(settings)

    assert app.state.git_sha == "deadbee"
    assert app.state.one_model_batches.git_sha == "deadbee"
