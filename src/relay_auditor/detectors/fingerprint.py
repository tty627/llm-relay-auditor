import asyncio
import json
import os
from pathlib import Path
from typing import Any

from relay_auditor.schemas import EndpointSpec


class FingerprintRunner:
    def __init__(self, cli_path: Path) -> None:
        self.cli_path = cli_path.resolve()

    def ensure_ready(self) -> None:
        if not self.cli_path.is_file():
            raise FileNotFoundError(
                f"One Token CLI not built: {self.cli_path}. "
                "Run `cd llm-fingerprint-detector && npm ci && npm run build`."
            )

    async def collect(
        self,
        endpoint: EndpointSpec,
        *,
        output_path: Path,
        cells: int,
        samples: int,
        concurrency: int,
    ) -> dict[str, Any]:
        arguments = self._base_arguments(endpoint, cells, samples, concurrency)
        arguments.extend(["fingerprint", "--out", str(output_path), "--json", "--quiet"])
        return await self._execute(arguments, accepted_exit_codes={0})

    async def verify(
        self,
        endpoint: EndpointSpec,
        *,
        reference_path: Path,
        output_path: Path,
        cells: int,
        samples: int,
        concurrency: int,
    ) -> tuple[str, dict[str, Any]]:
        arguments = self._base_arguments(endpoint, cells, samples, concurrency)
        arguments.extend(
            [
                "verify",
                "--reference",
                str(reference_path),
                "--out",
                str(output_path),
                "--json",
                "--quiet",
            ]
        )
        exit_code, payload = await self._execute_with_code(
            arguments,
            accepted_exit_codes={0, 2, 3, 4},
        )
        verdict_by_exit = {0: "match", 2: "mismatch", 3: "uncertain", 4: "insufficient"}
        return verdict_by_exit[exit_code], payload

    def _base_arguments(
        self,
        endpoint: EndpointSpec,
        cells: int,
        samples: int,
        concurrency: int,
    ) -> list[str]:
        self.ensure_ready()
        arguments = ["node", str(self.cli_path)]
        # 子命令在调用方追加；其余选项可以位于子命令之后。
        common = [
            "--base-url",
            str(endpoint.base_url).rstrip("/"),
            "--model",
            endpoint.model,
            "--cells",
            str(cells),
            "--samples",
            str(samples),
            "--concurrency",
            str(concurrency),
        ]
        if endpoint.api_key_env:
            if not os.environ.get(endpoint.api_key_env):
                raise ValueError(f"environment variable is not set: {endpoint.api_key_env}")
            common.extend(["--api-key-env", endpoint.api_key_env])
        arguments.extend(common)
        return arguments

    async def _execute(
        self,
        arguments: list[str],
        *,
        accepted_exit_codes: set[int],
    ) -> dict[str, Any]:
        _, payload = await self._execute_with_code(
            arguments,
            accepted_exit_codes=accepted_exit_codes,
        )
        return payload

    async def _execute_with_code(
        self,
        arguments: list[str],
        *,
        accepted_exit_codes: set[int],
    ) -> tuple[int, dict[str, Any]]:
        # CLI 语法要求子命令紧跟程序名，把调用方追加的子命令移到索引 2。
        command = arguments[:2]
        subcommand_index = next(
            index
            for index, value in enumerate(arguments[2:], start=2)
            if value in {"fingerprint", "verify"}
        )
        command.append(arguments[subcommand_index])
        command.extend(arguments[2:subcommand_index])
        command.extend(arguments[subcommand_index + 1 :])

        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=os.environ.copy(),
        )
        stdout, stderr = await process.communicate()
        stderr_text = stderr.decode(errors="replace").strip()
        if process.returncode not in accepted_exit_codes:
            raise RuntimeError(
                f"One Token CLI failed with exit code {process.returncode}: {stderr_text[-2000:]}"
            )
        try:
            payload = json.loads(stdout.decode())
        except json.JSONDecodeError as error:
            message = f"One Token CLI returned invalid JSON: {stderr_text[-1000:]}"
            raise RuntimeError(message) from error
        if not isinstance(payload, dict):
            raise RuntimeError("One Token CLI returned a non-object JSON payload")
        return process.returncode, payload
