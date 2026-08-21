import hashlib
import hmac
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlparse
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request, Response, Security
from fastapi.responses import FileResponse
from fastapi.security import APIKeyHeader
from fastapi.staticfiles import StaticFiles
from sqlalchemy.exc import IntegrityError

from relay_auditor import __version__
from relay_auditor.batches import ComparisonBatchManager
from relay_auditor.config import Settings
from relay_auditor.database import Database
from relay_auditor.detectors.fingerprint import (
    FingerprintRunner,
    safeguard_verification_result,
)
from relay_auditor.detectors.models import discover_models
from relay_auditor.detectors.preflight import normalize_fingerprint_base_url
from relay_auditor.detectors.smoke import run_smoke
from relay_auditor.detectors.tokenizer import (
    collect_tokenizer_fingerprint,
    compare_tokenizer_fingerprints,
)
from relay_auditor.evidence import EvidenceStore
from relay_auditor.mock_api import router as mock_router
from relay_auditor.schemas import (
    AuditResponse,
    BaselineCreateRequest,
    ConsoleComparisonBatchRequest,
    ConsoleFingerprintCollectRequest,
    ConsoleFingerprintVerifyRequest,
    ConsoleModelDiscoveryRequest,
    ConsoleReferenceCollectRequest,
    ConsoleReferenceCollectResponse,
    EndpointSpec,
    EphemeralConnectionSpec,
    FingerprintCollectRequest,
    FingerprintVerifyRequest,
    ManagedEndpointCreateRequest,
    SmokeAuditRequest,
    TokenizerCollectRequest,
    TokenizerVerifyRequest,
)


def create_app(settings: Settings | None = None) -> FastAPI:
    configured = settings or Settings()
    configured.validate_managed_credential_configuration()
    database = Database(configured.database_url)
    evidence = EvidenceStore(configured.evidence_dir)
    fingerprint = FingerprintRunner(configured.fingerprint_cli_path)
    batches = ComparisonBatchManager(database, evidence, fingerprint)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        database.initialize()
        database.interrupt_orphaned_comparison_batches()
        evidence.initialize()
        try:
            yield
        finally:
            await batches.shutdown()

    app = FastAPI(
        title=configured.app_name,
        version=__version__,
        description="大模型中转站黑盒验真与质量审计 MVP",
        lifespan=lifespan,
    )
    app.state.settings = configured
    app.state.database = database
    app.state.evidence = evidence
    app.state.fingerprint = fingerprint
    app.state.batches = batches
    app.include_router(mock_router)
    management_token_header = APIKeyHeader(
        name="X-Relay-Auditor-Token",
        scheme_name="ManagedCredentialToken",
        description="Local management token required when api_key_env is used.",
        auto_error=False,
    )

    @app.middleware("http")
    async def disable_console_api_caching(request: Request, call_next):
        response = await call_next(request)
        if request.url.path.startswith("/api/v1/console/") or request.headers.get(
            "x-relay-auditor-token"
        ) is not None:
            response.headers["Cache-Control"] = "no-store"
        return response

    web_dir = Path(__file__).parent / "web"
    app.mount("/assets", StaticFiles(directory=web_dir), name="assets")

    def browser_headers() -> dict[str, str]:
        return {
            "Cache-Control": "no-store",
            "Content-Security-Policy": (
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
                "base-uri 'none'; form-action 'self'"
            ),
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
        }

    def redact_error(error: Exception, api_key: str | None) -> str:
        detail = str(error)
        if api_key:
            detail = detail.replace(api_key, "[REDACTED]")
        return detail

    def require_management_token(presented: str | None) -> None:
        expected = configured.management_token_value()
        if expected is None:
            raise HTTPException(
                status_code=503,
                detail="managed credential access is not configured",
            )
        valid = presented is not None and hmac.compare_digest(
            presented.encode("utf-8"),
            expected.encode("ascii"),
        )
        if not valid:
            raise HTTPException(
                status_code=401,
                detail="valid X-Relay-Auditor-Token header required",
            )

    def resolve_managed_api_key(endpoint: Any, presented_token: str | None) -> str | None:
        """Resolve only explicitly allowed credentials bound to this endpoint tuple."""

        try:
            if endpoint.api_key_env is None:
                return None
            require_management_token(presented_token)
            configured.require_api_key_base_url_binding(
                endpoint.api_key_env,
                str(endpoint.base_url),
            )
            normalized_base_url = normalize_fingerprint_base_url(str(endpoint.base_url))
            bound = any(
                managed.enabled
                and managed.api_key_env == endpoint.api_key_env
                and managed.model == endpoint.model
                and normalize_fingerprint_base_url(managed.base_url) == normalized_base_url
                for managed in database.list_endpoints()
            )
            if not bound:
                raise ValueError(
                    "api_key_env is not bound to this base_url and model in the endpoint registry"
                )
            return configured.resolve_api_key(endpoint.api_key_env)
        except (ValueError, RuntimeError) as error:
            raise HTTPException(status_code=400, detail=str(error)) from error

    @app.get("/", include_in_schema=False)
    async def console() -> FileResponse:
        return FileResponse(
            web_dir / "index.html",
            headers=browser_headers(),
        )

    @app.get("/history", include_in_schema=False)
    async def comparison_history() -> FileResponse:
        return FileResponse(web_dir / "history.html", headers=browser_headers())

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/api/v1/audits")
    async def list_audits(limit: int = 50) -> dict[str, Any]:
        safe_limit = min(max(limit, 1), 200)
        return {"items": [run.as_dict() for run in database.list_runs(safe_limit)]}

    @app.post("/api/v1/endpoints", status_code=201)
    async def create_endpoint(
        payload: ManagedEndpointCreateRequest,
        management_token: Annotated[str | None, Security(management_token_header)],
    ) -> dict[str, object]:
        if payload.api_key_env is not None:
            require_management_token(management_token)
        try:
            configured.require_api_key_base_url_binding(
                payload.api_key_env,
                str(payload.base_url),
            )
            endpoint = database.create_endpoint(
                endpoint_id=str(uuid4()),
                name=payload.name,
                provider=payload.provider,
                base_url=normalize_fingerprint_base_url(str(payload.base_url)),
                model=payload.model,
                protocol=payload.protocol,
                api_key_env=payload.api_key_env,
            )
        except (ValueError, RuntimeError) as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
        except IntegrityError as error:
            raise HTTPException(status_code=409, detail="endpoint name already exists") from error
        return endpoint.as_dict()

    @app.get("/api/v1/endpoints")
    async def list_endpoints() -> dict[str, object]:
        return {"items": [endpoint.as_dict() for endpoint in database.list_endpoints()]}

    @app.post("/api/v1/endpoints/{endpoint_id}/models")
    async def discover_managed_endpoint_models(
        endpoint_id: str,
        response: Response,
        management_token: Annotated[str | None, Security(management_token_header)],
    ) -> dict[str, Any]:
        """Discover models without accepting a plaintext credential in the request."""

        response.headers["Cache-Control"] = "no-store"
        managed = database.get_endpoint(endpoint_id)
        if managed is None:
            raise HTTPException(status_code=404, detail="managed endpoint not found")
        if not managed.enabled:
            raise HTTPException(status_code=409, detail="managed endpoint is disabled")
        endpoint = EndpointSpec(
            base_url=managed.base_url,
            model=managed.model,
            api_key_env=managed.api_key_env,
        )
        api_key = resolve_managed_api_key(endpoint, management_token)
        try:
            result = await discover_models(
                EphemeralConnectionSpec(base_url=managed.base_url),
                timeout_seconds=configured.request_timeout_seconds,
                api_key=api_key,
            )
        except Exception as error:
            detail = redact_error(error, api_key)
            raise HTTPException(status_code=502, detail=detail) from error
        return {
            **result,
            "endpoint_id": managed.id,
            "registered_model": managed.model,
            "credential_source": "env_ref" if managed.api_key_env else "none",
        }

    @app.post("/api/v1/baselines", status_code=201)
    async def create_baseline(payload: BaselineCreateRequest) -> dict[str, object]:
        endpoint = database.get_endpoint(payload.endpoint_id)
        if endpoint is None:
            raise HTTPException(status_code=404, detail="managed endpoint not found")
        run = database.get_run(payload.artifact_id)
        if run is None or run.status != "completed":
            raise HTTPException(status_code=404, detail="completed audit artifact not found")
        expected_detector = {
            "one_token": "one_token_collect",
            "tokenizer": "tokenizer_collect",
        }[payload.detector]
        if run.detector != expected_detector:
            raise HTTPException(status_code=409, detail="artifact detector does not match baseline")
        if run.model != endpoint.model or normalize_fingerprint_base_url(
            run.target_base_url
        ) != normalize_fingerprint_base_url(endpoint.base_url):
            raise HTTPException(status_code=409, detail="artifact endpoint does not match baseline")
        if not run.artifact_path or not Path(run.artifact_path).is_file():
            raise HTTPException(status_code=409, detail="artifact evidence file is missing")
        valid_from = datetime.now(UTC)
        baseline = database.create_baseline(
            baseline_id=str(uuid4()),
            endpoint_id=payload.endpoint_id,
            detector=payload.detector,
            artifact_id=payload.artifact_id,
            valid_from=valid_from,
            expires_at=valid_from + timedelta(days=payload.valid_days),
            metadata=payload.metadata,
        )
        return baseline.as_dict()

    @app.get("/api/v1/baselines")
    async def list_baselines(endpoint_id: str | None = None) -> dict[str, object]:
        return {"items": [baseline.as_dict() for baseline in database.list_baselines(endpoint_id)]}

    @app.post("/api/v1/audits/smoke", response_model=AuditResponse)
    async def smoke_audit(
        payload: SmokeAuditRequest,
        management_token: Annotated[str | None, Security(management_token_header)],
    ) -> AuditResponse:
        api_key = resolve_managed_api_key(payload.target, management_token)
        audit_id = str(uuid4())
        database.create_run(
            audit_id=audit_id,
            detector="smoke",
            target_base_url=normalize_fingerprint_base_url(str(payload.target.base_url)),
            model=payload.target.model,
        )
        try:
            result = await run_smoke(
                payload.target,
                payload.prompt,
                timeout_seconds=configured.request_timeout_seconds,
                api_key=api_key,
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
            detail = redact_error(error, api_key)
            database.finish_run(
                audit_id,
                status="failed",
                verdict="error",
                error_message=detail,
            )
            raise HTTPException(status_code=502, detail=detail) from error

    @app.post("/api/v1/fingerprints/collect", response_model=AuditResponse)
    async def collect_fingerprint(
        payload: FingerprintCollectRequest,
        management_token: Annotated[str | None, Security(management_token_header)],
    ) -> AuditResponse:
        api_key = resolve_managed_api_key(payload.endpoint, management_token)
        audit_id = str(uuid4())
        database.create_run(
            audit_id=audit_id,
            detector="one_token_collect",
            target_base_url=normalize_fingerprint_base_url(str(payload.endpoint.base_url)),
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
                api_key=api_key,
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
            detail = redact_error(error, api_key)
            database.finish_run(
                audit_id,
                status="failed",
                verdict="error",
                error_message=detail,
            )
            raise HTTPException(status_code=502, detail=detail) from error

    @app.post("/api/v1/fingerprints/verify", response_model=AuditResponse)
    async def verify_fingerprint(
        payload: FingerprintVerifyRequest,
        management_token: Annotated[str | None, Security(management_token_header)],
    ) -> AuditResponse:
        api_key = resolve_managed_api_key(payload.endpoint, management_token)
        audit_id = str(uuid4())
        target_path: Path | None = None
        database.create_run(
            audit_id=audit_id,
            detector="one_token_verify",
            target_base_url=normalize_fingerprint_base_url(str(payload.endpoint.base_url)),
            model=payload.endpoint.model,
        )
        try:
            reference_path = evidence.fingerprint_path(
                payload.reference_artifact_id,
                must_exist=True,
            )
            reference_metadata = database.get_reference_metadata(payload.reference_artifact_id)
            target_path = evidence.fingerprint_path(audit_id)
            verdict, result = await fingerprint.verify(
                payload.endpoint,
                reference_path=reference_path,
                output_path=target_path,
                cells=payload.cells,
                samples=payload.samples,
                concurrency=payload.concurrency,
                api_key=api_key,
            )
            verdict, result = safeguard_verification_result(
                verdict,
                result,
                reference_metadata=reference_metadata,
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
            detail = redact_error(error, api_key)
            database.finish_run(
                audit_id,
                status="failed",
                verdict="error",
                error_message=detail,
            )
            raise HTTPException(status_code=404, detail=detail) from error
        except Exception as error:
            detail = redact_error(error, api_key)
            partial_path = str(target_path) if target_path and target_path.is_file() else None
            partial_sha = (
                evidence.digest_file(target_path) if partial_path and target_path else None
            )
            database.finish_run(
                audit_id,
                status="failed",
                verdict="error",
                artifact_path=partial_path,
                artifact_sha256=partial_sha,
                error_message=detail,
            )
            raise HTTPException(status_code=502, detail=detail) from error

    def read_comparison_result(run: Any) -> dict[str, Any] | None:
        if not run.artifact_path:
            return None
        artifact_path = Path(run.artifact_path).resolve()
        if evidence.root not in artifact_path.parents or not artifact_path.is_file():
            return None
        try:
            return evidence.read_json(artifact_path)
        except (OSError, ValueError):
            return None

    def comparison_item(
        row: tuple[Any, Any, Any],
        *,
        include_result: bool = False,
    ) -> dict[str, Any]:
        run, record, batch = row
        result = read_comparison_result(run)
        comparison = result.get("comparison", {}) if result else {}
        target = result.get("target", {}) if result else {}
        reference = result.get("reference", {}) if result else {}
        execution = result.get("execution", {}) if result else {}
        raw_mean_jsd = comparison.get(
            "meanJsd",
            result.get("meanJsd") if result else None,
        )
        decision_node = result.get("decision") if result else None
        stored_decision = decision_node if isinstance(decision_node, dict) else None
        raw_legacy_candidates = (
            stored_decision.get("legacyVerdict") if stored_decision else None,
            result.get("legacyVerdict") if result else None,
            comparison.get("verdict") if isinstance(comparison, dict) else None,
            result.get("verdict") if result else None,
            run.verdict,
        )
        legacy_verdict = next(
            (
                value
                for value in raw_legacy_candidates
                if value in {"match", "uncertain", "mismatch", "insufficient"}
            ),
            None,
        )
        decision: dict[str, Any] | None = None
        decision_status: str | None = None
        decision_reasons: list[str] = []
        verdict_semantics = "stored"
        operational_verdict = run.verdict or run.status
        if stored_decision is not None:
            decision = dict(stored_decision)
            candidate_operational = decision.get("operationalVerdict")
            if isinstance(candidate_operational, str) and candidate_operational:
                operational_verdict = candidate_operational
            candidate_status = decision.get("status")
            if isinstance(candidate_status, str) and candidate_status:
                decision_status = candidate_status
            candidate_reasons = decision.get("reasons")
            if isinstance(candidate_reasons, list):
                decision_reasons = [
                    str(reason).strip() for reason in candidate_reasons if str(reason).strip()
                ]
            elif candidate_reasons is not None and str(candidate_reasons).strip():
                decision_reasons = [str(candidate_reasons).strip()]
            if legacy_verdict is None:
                candidate_legacy = decision.get("legacyVerdict")
                if isinstance(candidate_legacy, str) and candidate_legacy:
                    legacy_verdict = candidate_legacy
            stored_semantics = result.get("verdictSemantics") if result else None
            verdict_semantics = (
                stored_semantics
                if isinstance(stored_semantics, str) and stored_semantics
                else "operational-v1"
            )
        elif run.detector == "one_token_verify" and run.status == "completed":
            # Artifacts written before the safe decision gate only contain the
            # detector's exploratory verdict.  Preserve it for diagnostics but
            # never expose it as an operational identity conclusion.
            operational_verdict = "unverifiable"
            decision_status = "legacy_unmigrated"
            decision_reasons = ["legacy_result_without_safe_decision"]
            verdict_semantics = "legacy-unmigrated"
            decision = {
                "operationalVerdict": operational_verdict,
                "status": decision_status,
                "reasons": decision_reasons,
                "legacyVerdict": legacy_verdict,
                "rawMeanJsd": raw_mean_jsd,
                "decisionEligible": False,
            }
        preflight = execution.get("preflight") if isinstance(execution, dict) else None
        partial_evidence = bool(result and result.get("partial") is True)
        if result is None:
            evidence_state = "none"
        elif partial_evidence:
            evidence_state = "partial"
        elif isinstance(result.get("comparison"), dict):
            evidence_state = "verification"
        elif result.get("formatVersion") == 1 and isinstance(result.get("cells"), dict):
            evidence_state = "target_fingerprint"
        else:
            evidence_state = "artifact"
        parsed = urlparse(run.target_base_url)
        station_name = record.station_name if record else parsed.netloc or run.target_base_url
        elapsed = None
        if run.completed_at is not None:
            elapsed = max(0, round((run.completed_at - run.started_at).total_seconds() * 1000))
        progress = database.get_task_progress(run.id)
        task_options = database.get_task_options(run.id)
        if run.status == "canceled" and (
            task_options is None or task_options.effective_concurrency is None
        ):
            elapsed = None
        item: dict[str, Any] = {
            "audit_id": run.id,
            "detector": run.detector,
            "batch_id": record.batch_id if record else run.id,
            "batch": batch.as_dict() if batch else None,
            "station_name": station_name,
            "target_base_url": run.target_base_url,
            "target_model": run.model,
            "reference_artifact_id": record.reference_artifact_id if record else None,
            "reference_name": record.reference_name if record else "历史参考端",
            "reference_model": record.reference_model if record else reference.get("model"),
            "status": run.status,
            "verdict": operational_verdict,
            "decision": decision,
            "legacy_verdict": legacy_verdict,
            "operational_verdict": operational_verdict,
            "decision_status": decision_status,
            "reasons": decision_reasons,
            "decision_reasons": decision_reasons,
            "verdict_semantics": verdict_semantics,
            "mean_jsd": raw_mean_jsd,
            "comparable_cell_count": comparison.get("comparableCellCount"),
            "error_count": target.get("errorCount"),
            "duration_ms": target.get("durationMs", elapsed),
            "started_at": run.as_dict()["started_at"],
            "completed_at": run.as_dict()["completed_at"],
            "artifact_id": run.id if result is not None else None,
            "artifact_sha256": run.artifact_sha256,
            "evidence_available": result is not None,
            "evidence_state": evidence_state,
            "partial_evidence": partial_evidence,
            "partial_sample_count": (
                result.get("completedSamples") if partial_evidence and result else None
            ),
            "partial_expected_samples": (
                result.get("expectedSamples") if partial_evidence and result else None
            ),
            "partial_error_count": (
                result.get("errorCount") if partial_evidence and result else None
            ),
            "preflight": preflight if isinstance(preflight, dict) else None,
            "error_message": run.error_message,
            "progress": progress.as_dict() if progress else None,
            "task_options": task_options.as_dict() if task_options else None,
            "priority": task_options.priority if task_options else 50,
            "identification": result.get("identification") if result else None,
        }
        if include_result and result is not None and run.status == "completed":
            response_result = result
            if stored_decision is None and decision is not None:
                response_result = {
                    **result,
                    "decision": decision,
                    "legacyVerdict": legacy_verdict,
                    "verdict": operational_verdict,
                    "verdictSemantics": verdict_semantics,
                }
            item["response"] = {
                "audit_id": run.id,
                "detector": run.detector,
                "status": run.status,
                "verdict": operational_verdict,
                "decision": decision,
                "legacy_verdict": legacy_verdict,
                "operational_verdict": operational_verdict,
                "decision_status": decision_status,
                "reasons": decision_reasons,
                "verdict_semantics": verdict_semantics,
                "artifact_id": run.id,
                "artifact_sha256": run.artifact_sha256,
                "result": response_result,
            }
        return item

    @app.get("/api/v1/console/comparisons")
    async def console_list_comparisons(
        limit: int = 50,
        offset: int = 0,
        station: str | None = None,
        model: str | None = None,
        verdict: str | None = None,
    ) -> dict[str, Any]:
        safe_limit = min(max(limit, 1), 200)
        safe_offset = max(offset, 0)
        requested_verdict = verdict.strip() if verdict else None
        rows, total = database.list_comparison_rows(
            limit=safe_limit,
            offset=safe_offset,
            station=station.strip() if station else None,
            model=model.strip() if model else None,
            verdict=requested_verdict,
        )
        items = [comparison_item(row) for row in rows]
        lifecycle_statuses = {
            "queued",
            "running",
            "paused",
            "canceling",
            "canceled",
            "interrupted",
        }
        if requested_verdict and requested_verdict not in lifecycle_statuses:
            items = [
                item
                for item in items
                if item.get("operational_verdict") == requested_verdict
            ]
            total = len(items)
            items = items[safe_offset : safe_offset + safe_limit]
        return {
            "items": items,
            "total": total,
            "limit": safe_limit,
            "offset": safe_offset,
        }

    @app.get("/api/v1/console/comparisons/latest")
    async def console_latest_comparisons() -> dict[str, Any]:
        rows = database.latest_comparison_rows()
        items = [comparison_item(row, include_result=True) for row in rows]
        return {
            "batch_id": items[0]["batch_id"] if items else None,
            "items": items,
        }

    def comparison_batch_payload(batch_id: str) -> dict[str, Any]:
        batch = database.get_comparison_batch(batch_id)
        if batch is None:
            raise LookupError(f"comparison batch not found: {batch_id}")
        rows = database.get_batch_comparison_rows(batch_id)
        items = [comparison_item(row, include_result=True) for row in rows]
        status_rank = {
            "running": 0,
            "canceling": 0,
            "queued": 1,
            "paused": 1,
            "completed": 2,
            "failed": 2,
            "canceled": 2,
            "interrupted": 2,
        }
        items.sort(
            key=lambda item: (
                status_rank.get(str(item["status"]), 1),
                -int(item.get("priority") or 50),
                str(item["started_at"]),
            )
        )
        queue_position = 0
        for item in items:
            if item["status"] in {"queued", "paused"}:
                queue_position += 1
                item["queue_position"] = queue_position
            else:
                item["queue_position"] = None
        return {
            "batch": batch.as_dict(),
            "items": items,
        }

    @app.post("/api/v1/console/comparison-batches", status_code=202)
    async def console_create_comparison_batch(
        payload: ConsoleComparisonBatchRequest,
        response: Response,
    ) -> dict[str, Any]:
        response.headers["Cache-Control"] = "no-store"
        try:
            batch_id = batches.start(payload)
        except FileNotFoundError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        return comparison_batch_payload(batch_id)

    @app.get("/api/v1/console/comparison-batches/active")
    async def console_active_comparison_batch() -> dict[str, Any]:
        batch = database.latest_active_comparison_batch()
        if batch is None:
            return {"batch": None, "items": []}
        return comparison_batch_payload(batch.id)

    @app.get("/api/v1/console/comparison-batches/{batch_id}")
    async def console_get_comparison_batch(batch_id: str) -> dict[str, Any]:
        try:
            return comparison_batch_payload(batch_id)
        except LookupError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error

    @app.post("/api/v1/console/comparison-batches/{batch_id}/pause")
    async def console_pause_comparison_batch(batch_id: str) -> dict[str, Any]:
        try:
            await batches.pause(batch_id)
            return comparison_batch_payload(batch_id)
        except LookupError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        except ValueError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error

    @app.post("/api/v1/console/comparison-batches/{batch_id}/resume")
    async def console_resume_comparison_batch(batch_id: str) -> dict[str, Any]:
        try:
            await batches.resume(batch_id)
            return comparison_batch_payload(batch_id)
        except LookupError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        except ValueError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error

    @app.post("/api/v1/console/comparison-batches/{batch_id}/cancel")
    async def console_cancel_comparison_batch(batch_id: str) -> dict[str, Any]:
        try:
            await batches.cancel_batch(batch_id)
            return comparison_batch_payload(batch_id)
        except LookupError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        except ValueError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error

    @app.post("/api/v1/console/comparison-batches/{batch_id}/items/{audit_id}/cancel")
    async def console_cancel_comparison_item(
        batch_id: str,
        audit_id: str,
    ) -> dict[str, Any]:
        try:
            await batches.cancel_item(batch_id, audit_id)
            return comparison_batch_payload(batch_id)
        except LookupError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        except ValueError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error

    @app.post("/api/v1/console/comparison-batches/{batch_id}/items/{audit_id}/prioritize")
    async def console_prioritize_comparison_item(
        batch_id: str,
        audit_id: str,
    ) -> dict[str, Any]:
        try:
            await batches.prioritize_item(batch_id, audit_id)
            return comparison_batch_payload(batch_id)
        except LookupError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        except ValueError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error

    @app.post("/api/v1/console/models")
    async def console_discover_models(
        payload: ConsoleModelDiscoveryRequest,
        response: Response,
    ) -> dict[str, Any]:
        response.headers["Cache-Control"] = "no-store"
        api_key = payload.endpoint.reveal_api_key()
        try:
            return await discover_models(
                payload.endpoint,
                timeout_seconds=configured.request_timeout_seconds,
            )
        except Exception as error:
            detail = redact_error(error, api_key)
            raise HTTPException(status_code=502, detail=detail) from error

    @app.get("/api/v1/console/references")
    async def console_list_references(include_inactive: bool = False) -> dict[str, Any]:
        items = database.list_reference_catalog(active_only=not include_inactive)
        for item in items:
            baseline = item["baseline"]
            if isinstance(baseline, dict):
                run = database.get_run(str(baseline["artifact_id"]))
                item["evidence_available"] = bool(
                    run and run.artifact_path and Path(run.artifact_path).is_file()
                )
        return {"items": items}

    @app.delete("/api/v1/console/references/{baseline_id}")
    async def console_delete_reference(
        baseline_id: str,
        response: Response,
    ) -> dict[str, Any]:
        response.headers["Cache-Control"] = "no-store"
        baseline = database.delete_reference(baseline_id)
        if baseline is None:
            raise HTTPException(status_code=404, detail="reference model not found")
        return {
            "baseline_id": baseline.id,
            "artifact_id": baseline.artifact_id,
            "status": baseline.status,
            "evidence_preserved": True,
        }

    @app.get("/api/v1/console/evidence/{artifact_id}", include_in_schema=False)
    async def console_download_evidence(artifact_id: str) -> FileResponse:
        run = database.get_run(artifact_id)
        if run is None or not run.artifact_path:
            raise HTTPException(status_code=404, detail="audit evidence not found")
        artifact_path = Path(run.artifact_path).resolve()
        if evidence.root not in artifact_path.parents or not artifact_path.is_file():
            raise HTTPException(status_code=404, detail="audit evidence file is missing")
        return FileResponse(
            artifact_path,
            media_type="application/json",
            filename=f"{run.detector}-{artifact_id}.json",
            headers={
                "Cache-Control": "no-store",
                "X-Evidence-SHA256": run.artifact_sha256 or "",
            },
        )

    @app.post("/api/v1/console/fingerprints/collect", response_model=AuditResponse)
    async def console_collect_fingerprint(
        payload: ConsoleFingerprintCollectRequest,
        response: Response,
    ) -> AuditResponse:
        response.headers["Cache-Control"] = "no-store"
        endpoint = payload.endpoint.public_endpoint()
        api_key = payload.endpoint.reveal_api_key()
        audit_id = str(uuid4())
        database.create_run(
            audit_id=audit_id,
            detector="one_token_collect",
            target_base_url=normalize_fingerprint_base_url(str(endpoint.base_url)),
            model=endpoint.model,
        )
        output_path = evidence.fingerprint_path(audit_id)
        try:
            result = await fingerprint.collect(
                endpoint,
                output_path=output_path,
                cells=payload.cells,
                samples=payload.samples,
                concurrency=payload.concurrency,
                api_key=api_key,
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
            detail = redact_error(error, api_key)
            database.finish_run(
                audit_id,
                status="failed",
                verdict="error",
                error_message=detail,
            )
            raise HTTPException(status_code=502, detail=detail) from error

    @app.post(
        "/api/v1/console/references/collect",
        response_model=ConsoleReferenceCollectResponse,
    )
    async def console_collect_reference(
        payload: ConsoleReferenceCollectRequest,
        response: Response,
    ) -> ConsoleReferenceCollectResponse:
        audit = await console_collect_fingerprint(payload, response)
        endpoint = payload.endpoint.public_endpoint()
        raw_name = f"{payload.reference_name.strip()} · {endpoint.model}"
        if len(raw_name) > 100:
            suffix = hashlib.sha256(raw_name.encode()).hexdigest()[:8]
            raw_name = f"{raw_name[:89]}-{suffix}"
        managed = database.upsert_endpoint(
            endpoint_id=str(uuid4()),
            name=raw_name,
            provider=payload.provider,
            base_url=str(endpoint.base_url),
            model=endpoint.model,
            protocol="openai_chat",
        )
        valid_from = datetime.now(UTC)
        baseline = database.create_baseline(
            baseline_id=str(uuid4()),
            endpoint_id=managed.id,
            detector="one_token",
            artifact_id=audit.audit_id,
            valid_from=valid_from,
            expires_at=valid_from + timedelta(days=payload.valid_days),
            metadata={
                "source": "local_console",
                "reference_name": payload.reference_name.strip(),
                "cells": payload.cells,
                "samples": payload.samples,
                "concurrency": payload.concurrency,
                "protocol": "one-token/v1",
                "method_profile_id": "legacy-one-token/v1",
                "ground_truth": "unverified_user_reference",
                "decision_eligible": False,
                "calibration_policy_id": None,
            },
        )
        return ConsoleReferenceCollectResponse(
            **audit.model_dump(),
            saved_reference={
                "baseline_id": baseline.id,
                "endpoint_id": managed.id,
                "reference_name": payload.reference_name.strip(),
                "base_url": managed.base_url,
                "model": managed.model,
                "artifact_id": audit.audit_id,
                "artifact_sha256": audit.artifact_sha256,
                "status": baseline.status,
                "valid_from": baseline.as_dict()["valid_from"],
                "expires_at": baseline.as_dict()["expires_at"],
            },
        )

    @app.post("/api/v1/console/fingerprints/verify", response_model=AuditResponse)
    async def console_verify_fingerprint(
        payload: ConsoleFingerprintVerifyRequest,
        response: Response,
    ) -> AuditResponse:
        response.headers["Cache-Control"] = "no-store"
        endpoint = payload.endpoint.public_endpoint()
        api_key = payload.endpoint.reveal_api_key()
        audit_id = str(uuid4())
        target_path: Path | None = None
        database.create_run(
            audit_id=audit_id,
            detector="one_token_verify",
            target_base_url=normalize_fingerprint_base_url(str(endpoint.base_url)),
            model=endpoint.model,
        )
        try:
            context = payload.comparison_context
            if context is not None:
                database.create_comparison_record(
                    audit_id=audit_id,
                    batch_id=context.batch_id,
                    total_items=context.total_items,
                    station_name=context.station_name,
                    reference_artifact_id=payload.reference_artifact_id,
                    reference_name=context.reference_name,
                    reference_model=context.reference_model,
                    cells=payload.cells,
                    samples=payload.samples,
                    concurrency=payload.concurrency,
                )
            reference_path = evidence.fingerprint_path(
                payload.reference_artifact_id,
                must_exist=True,
            )
            reference_metadata = database.get_reference_metadata(payload.reference_artifact_id)
            target_path = evidence.fingerprint_path(audit_id)
            verdict, result = await fingerprint.verify(
                endpoint,
                reference_path=reference_path,
                output_path=target_path,
                cells=payload.cells,
                samples=payload.samples,
                concurrency=payload.concurrency,
                api_key=api_key,
            )
            verdict, result = safeguard_verification_result(
                verdict,
                result,
                reference_metadata=reference_metadata,
            )
            result = {
                **result,
                "reference_artifact_id": payload.reference_artifact_id,
            }
            artifact = evidence.write_json("verification", audit_id, result)
            database.finish_run(
                audit_id,
                status="completed",
                verdict=verdict,
                artifact_path=str(artifact.path),
                artifact_sha256=artifact.sha256,
            )
            database.finish_comparison_record(audit_id)
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
            detail = redact_error(error, api_key)
            database.finish_run(
                audit_id,
                status="failed",
                verdict="error",
                error_message=detail,
            )
            database.finish_comparison_record(audit_id)
            raise HTTPException(status_code=404, detail=detail) from error
        except Exception as error:
            detail = redact_error(error, api_key)
            partial_path = str(target_path) if target_path and target_path.is_file() else None
            partial_sha = (
                evidence.digest_file(target_path) if partial_path and target_path else None
            )
            database.finish_run(
                audit_id,
                status="failed",
                verdict="error",
                artifact_path=partial_path,
                artifact_sha256=partial_sha,
                error_message=detail,
            )
            database.finish_comparison_record(audit_id)
            raise HTTPException(status_code=502, detail=detail) from error

    @app.post("/api/v1/tokenizers/collect", response_model=AuditResponse)
    async def collect_tokenizer(
        payload: TokenizerCollectRequest,
        management_token: Annotated[str | None, Security(management_token_header)],
    ) -> AuditResponse:
        api_key = resolve_managed_api_key(payload.endpoint, management_token)
        audit_id = str(uuid4())
        database.create_run(
            audit_id=audit_id,
            detector="tokenizer_collect",
            target_base_url=normalize_fingerprint_base_url(str(payload.endpoint.base_url)),
            model=payload.endpoint.model,
        )
        try:
            result = await collect_tokenizer_fingerprint(
                payload.endpoint,
                timeout_seconds=configured.request_timeout_seconds,
                samples_per_point=payload.samples_per_point,
                concurrency=payload.concurrency,
                api_key=api_key,
            )
            artifact = evidence.write_json("tokenizers", audit_id, result)
            database.finish_run(
                audit_id,
                status="completed",
                verdict="recorded",
                artifact_path=str(artifact.path),
                artifact_sha256=artifact.sha256,
            )
            return AuditResponse(
                audit_id=audit_id,
                detector="tokenizer_collect",
                status="completed",
                verdict="recorded",
                artifact_id=audit_id,
                artifact_sha256=artifact.sha256,
                result=result,
            )
        except Exception as error:
            detail = redact_error(error, api_key)
            database.finish_run(
                audit_id,
                status="failed",
                verdict="error",
                error_message=detail,
            )
            raise HTTPException(status_code=502, detail=detail) from error

    @app.post("/api/v1/tokenizers/verify", response_model=AuditResponse)
    async def verify_tokenizer(
        payload: TokenizerVerifyRequest,
        management_token: Annotated[str | None, Security(management_token_header)],
    ) -> AuditResponse:
        api_key = resolve_managed_api_key(payload.endpoint, management_token)
        audit_id = str(uuid4())
        database.create_run(
            audit_id=audit_id,
            detector="tokenizer_verify",
            target_base_url=normalize_fingerprint_base_url(str(payload.endpoint.base_url)),
            model=payload.endpoint.model,
        )
        try:
            reference_path = evidence.tokenizer_path(
                payload.reference_artifact_id,
                must_exist=True,
            )
            reference = evidence.read_json(reference_path)
            target = await collect_tokenizer_fingerprint(
                payload.endpoint,
                timeout_seconds=configured.request_timeout_seconds,
                samples_per_point=payload.samples_per_point,
                concurrency=payload.concurrency,
                api_key=api_key,
            )
            comparison = compare_tokenizer_fingerprints(reference, target)
            result = {"reference_artifact_id": payload.reference_artifact_id, "target": target}
            result["comparison"] = comparison
            artifact = evidence.write_json("tokenizer_verification", audit_id, result)
            verdict = str(comparison["verdict"])
            database.finish_run(
                audit_id,
                status="completed",
                verdict=verdict,
                artifact_path=str(artifact.path),
                artifact_sha256=artifact.sha256,
            )
            return AuditResponse(
                audit_id=audit_id,
                detector="tokenizer_verify",
                status="completed",
                verdict=verdict,
                artifact_id=audit_id,
                artifact_sha256=artifact.sha256,
                result=result,
            )
        except FileNotFoundError as error:
            detail = redact_error(error, api_key)
            database.finish_run(
                audit_id,
                status="failed",
                verdict="error",
                error_message=detail,
            )
            raise HTTPException(status_code=404, detail=detail) from error
        except Exception as error:
            detail = redact_error(error, api_key)
            database.finish_run(
                audit_id,
                status="failed",
                verdict="error",
                error_message=detail,
            )
            raise HTTPException(status_code=502, detail=detail) from error

    return app


app = create_app()
