from contextlib import asynccontextmanager
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, HTTPException

from relay_auditor.config import Settings
from relay_auditor.database import Database
from relay_auditor.detectors.fingerprint import FingerprintRunner
from relay_auditor.detectors.smoke import run_smoke
from relay_auditor.evidence import EvidenceStore
from relay_auditor.mock_api import router as mock_router
from relay_auditor.schemas import (
    AuditResponse,
    FingerprintCollectRequest,
    FingerprintVerifyRequest,
    SmokeAuditRequest,
)


def create_app(settings: Settings | None = None) -> FastAPI:
    configured = settings or Settings()
    database = Database(configured.database_url)
    evidence = EvidenceStore(configured.evidence_dir)
    fingerprint = FingerprintRunner(configured.fingerprint_cli_path)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        database.initialize()
        evidence.initialize()
        yield

    app = FastAPI(
        title=configured.app_name,
        version="0.1.0",
        description="大模型中转站黑盒验真与质量审计 MVP",
        lifespan=lifespan,
    )
    app.state.settings = configured
    app.state.database = database
    app.state.evidence = evidence
    app.state.fingerprint = fingerprint
    app.include_router(mock_router)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": "0.1.0"}

    @app.get("/api/v1/audits")
    async def list_audits(limit: int = 50) -> dict[str, Any]:
        safe_limit = min(max(limit, 1), 200)
        return {"items": [run.as_dict() for run in database.list_runs(safe_limit)]}

    @app.post("/api/v1/audits/smoke", response_model=AuditResponse)
    async def smoke_audit(payload: SmokeAuditRequest) -> AuditResponse:
        audit_id = str(uuid4())
        database.create_run(
            audit_id=audit_id,
            detector="smoke",
            target_base_url=str(payload.target.base_url),
            model=payload.target.model,
        )
        try:
            result = await run_smoke(
                payload.target,
                payload.prompt,
                timeout_seconds=configured.request_timeout_seconds,
            )
            artifact = evidence.write_json("smoke", audit_id, result)
            database.finish_run(
                audit_id,
                status="completed",
                verdict=str(result["verdict"]),
                artifact_path=str(artifact.path),
                artifact_sha256=artifact.sha256,
            )
            return AuditResponse(
                audit_id=audit_id,
                detector="smoke",
                status="completed",
                verdict=str(result["verdict"]),
                artifact_id=audit_id,
                artifact_sha256=artifact.sha256,
                result=result,
            )
        except Exception as error:
            database.finish_run(
                audit_id,
                status="failed",
                verdict="error",
                error_message=str(error),
            )
            raise HTTPException(status_code=502, detail=str(error)) from error

    @app.post("/api/v1/fingerprints/collect", response_model=AuditResponse)
    async def collect_fingerprint(payload: FingerprintCollectRequest) -> AuditResponse:
        audit_id = str(uuid4())
        database.create_run(
            audit_id=audit_id,
            detector="one_token_collect",
            target_base_url=str(payload.endpoint.base_url),
            model=payload.endpoint.model,
        )
        output_path = evidence.fingerprint_path(audit_id)
        try:
            result = await fingerprint.collect(
                payload.endpoint,
                output_path=output_path,
                cells=payload.cells,
                samples=payload.samples,
                concurrency=payload.concurrency,
            )
            digest = evidence.digest_file(output_path)
            database.finish_run(
                audit_id,
                status="completed",
                verdict="recorded",
                artifact_path=str(output_path),
                artifact_sha256=digest,
            )
            return AuditResponse(
                audit_id=audit_id,
                detector="one_token_collect",
                status="completed",
                verdict="recorded",
                artifact_id=audit_id,
                artifact_sha256=digest,
                result=result,
            )
        except Exception as error:
            database.finish_run(
                audit_id,
                status="failed",
                verdict="error",
                error_message=str(error),
            )
            raise HTTPException(status_code=502, detail=str(error)) from error

    @app.post("/api/v1/fingerprints/verify", response_model=AuditResponse)
    async def verify_fingerprint(payload: FingerprintVerifyRequest) -> AuditResponse:
        audit_id = str(uuid4())
        database.create_run(
            audit_id=audit_id,
            detector="one_token_verify",
            target_base_url=str(payload.endpoint.base_url),
            model=payload.endpoint.model,
        )
        try:
            reference_path = evidence.fingerprint_path(
                payload.reference_artifact_id,
                must_exist=True,
            )
            target_path = evidence.fingerprint_path(audit_id)
            verdict, result = await fingerprint.verify(
                payload.endpoint,
                reference_path=reference_path,
                output_path=target_path,
                cells=payload.cells,
                samples=payload.samples,
                concurrency=payload.concurrency,
            )
            artifact = evidence.write_json("verification", audit_id, result)
            database.finish_run(
                audit_id,
                status="completed",
                verdict=verdict,
                artifact_path=str(artifact.path),
                artifact_sha256=artifact.sha256,
            )
            return AuditResponse(
                audit_id=audit_id,
                detector="one_token_verify",
                status="completed",
                verdict=verdict,
                artifact_id=audit_id,
                artifact_sha256=artifact.sha256,
                result=result,
            )
        except FileNotFoundError as error:
            database.finish_run(
                audit_id,
                status="failed",
                verdict="error",
                error_message=str(error),
            )
            raise HTTPException(status_code=404, detail=str(error)) from error
        except Exception as error:
            database.finish_run(
                audit_id,
                status="failed",
                verdict="error",
                error_message=str(error),
            )
            raise HTTPException(status_code=502, detail=str(error)) from error

    return app


app = create_app()
