import base64
import binascii
import hashlib
import ipaddress
import secrets
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
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
from relay_auditor.detectors.smoke import run_smoke
from relay_auditor.detectors.tokenizer import (
    collect_tokenizer_fingerprint,
    compare_tokenizer_fingerprints,
)
from relay_auditor.evidence import EvidenceIntegrityError, EvidenceStore
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
    FingerprintCollectRequest,
    FingerprintVerifyRequest,
    ManagedEndpointCreateRequest,
    SmokeAuditRequest,
    TokenizerCollectRequest,
    TokenizerVerifyRequest,
)


def create_app(settings: Settings | None = None) -> FastAPI:
    configured = settings or Settings()
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

    @app.exception_handler(RequestValidationError)
    async def redact_request_validation_error(
        _: Request,
        error: RequestValidationError,
    ) -> JSONResponse:
        errors: list[dict[str, Any]] = []
        for item in error.errors():
            sanitized = dict(item)
            if "input" in sanitized:
                # Validation failures may contain whole nested request objects,
                # misspelled credential fields, or URL-embedded secrets. The
                # location/message is sufficient for clients to correct input;
                # never reflect submitted values into responses or proxy logs.
                sanitized["input"] = "[REDACTED]"
            errors.append(sanitized)
        return JSONResponse(
            status_code=422,
            content={"detail": jsonable_encoder(errors)},
        )

    def is_local_client(request: Request) -> bool:
        if request.client is None:
            return False
        client_host = request.client.host
        if client_host == "testclient":
            return True
        try:
            return ipaddress.ip_address(client_host).is_loopback
        except ValueError:
            return False

    def has_valid_access_token(request: Request) -> bool:
        expected = configured.reveal_access_token()
        if not expected:
            return False
        authorization = request.headers.get("authorization", "")
        scheme, _, encoded = authorization.partition(" ")
        if scheme.lower() == "bearer":
            return secrets.compare_digest(encoded, expected)
        if scheme.lower() != "basic":
            return False
        try:
            decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
            username, password = decoded.split(":", 1)
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return False
        return username == "auditor" and secrets.compare_digest(password, expected)

    def require_server_credential_access(request: Request) -> None:
        if not configured.reveal_access_token():
            raise HTTPException(
                status_code=403,
                detail=(
                    "server-managed credentials are disabled until "
                    "AUDITOR_ACCESS_TOKEN is configured"
                ),
            )
        if not has_valid_access_token(request):
            raise HTTPException(
                status_code=401,
                detail="valid access credentials are required for server-managed credentials",
                headers={"WWW-Authenticate": 'Basic realm="Relay Auditor"'},
            )

    def endpoint_response_payload(
        endpoint_payload: dict[str, Any],
        *,
        authenticated: bool,
    ) -> dict[str, Any]:
        item = dict(endpoint_payload)
        credential_configured = item.get("api_key_env") is not None
        if credential_configured and not authenticated:
            item["api_key_env"] = None
        item["credential_configured"] = credential_configured
        return item

    def same_origin(request: Request, origin: str) -> bool:
        try:
            parsed = urlparse(origin)
            if (
                parsed.scheme not in {"http", "https"}
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path not in {"", "/"}
                or parsed.params
                or parsed.query
                or parsed.fragment
            ):
                return False
            origin_port = parsed.port or (443 if parsed.scheme == "https" else 80)
            request_port = request.url.port or (443 if request.url.scheme == "https" else 80)
            return (
                parsed.hostname == request.url.hostname
                and origin_port == request_port
                and parsed.scheme == request.url.scheme
            )
        except ValueError:
            return False

    @app.middleware("http")
    async def disable_console_api_caching(request: Request, call_next):
        local_client = is_local_client(request)
        authenticated = has_valid_access_token(request)
        if request.url.path != "/health" and not (local_client or authenticated):
            token_configured = bool(configured.reveal_access_token())
            return JSONResponse(
                status_code=401 if token_configured else 403,
                content={
                    "detail": (
                        "valid local access credentials are required"
                        if token_configured
                        else "non-local access is disabled until AUDITOR_ACCESS_TOKEN is set"
                    )
                },
                headers=(
                    {"WWW-Authenticate": 'Basic realm="Relay Auditor"'}
                    if token_configured
                    else None
                ),
            )
        is_console_api = request.url.path.startswith("/api/v1/console/")
        is_api = request.url.path.startswith("/api/v1/")
        allowed_hosts = {"127.0.0.1", "localhost", "::1", "testserver"}
        request_host = request.url.hostname
        if request.url.path != "/health" and (
            (local_client and not authenticated and request_host not in allowed_hosts)
            or (is_console_api and request_host not in allowed_hosts)
        ):
            return JSONResponse(
                status_code=403,
                content={"detail": "unauthenticated local access requires a local Host"},
            )
        origin = request.headers.get("origin")
        if is_api and origin and not same_origin(request, origin):
            return JSONResponse(
                status_code=403,
                content={"detail": "API origin is not allowed"},
            )
        response = await call_next(request)
        if is_console_api:
            response.headers["Cache-Control"] = "no-store"
            response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
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

    def resolve_managed_api_key(endpoint: Any, request: Request) -> str | None:
        try:
            if endpoint.api_key_env is None:
                return None
            require_server_credential_access(request)
            configured.require_allowed_api_key_env(endpoint.api_key_env)
            normalized_base_url = str(endpoint.base_url).rstrip("/")
            bound = any(
                managed.enabled
                and managed.api_key_env == endpoint.api_key_env
                and managed.model == endpoint.model
                and managed.base_url.rstrip("/") == normalized_base_url
                for managed in database.list_endpoints()
            )
            if not bound:
                raise ValueError(
                    "api_key_env is not bound to this base_url and model in the endpoint registry"
                )
            return configured.resolve_api_key(endpoint.api_key_env)
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error

    def verified_reference_path(
        artifact_id: str,
        *,
        category: str,
        detector: str,
    ) -> Path:
        run = database.get_run(artifact_id)
        if run is None or run.status != "completed":
            raise FileNotFoundError(f"completed reference artifact not found: {artifact_id}")
        if run.detector != detector:
            raise EvidenceIntegrityError("reference artifact detector does not match")
        return evidence.verify_registered_path(
            run.artifact_path,
            run.artifact_sha256,
            expected_path=evidence.path_for(category, artifact_id),
        )

    def expected_run_artifact_path(run: Any) -> Path | None:
        category: str | None
        if run.detector == "smoke":
            category = "smoke"
        elif run.detector == "one_token_collect":
            category = "fingerprints"
        elif run.detector == "one_token_verify":
            category = "verification" if run.status == "completed" else "fingerprints"
        elif run.detector == "one_token_recovered":
            category = "verification"
        elif run.detector == "tokenizer_collect":
            category = "tokenizers"
        elif run.detector == "tokenizer_verify":
            category = "tokenizer_verification"
        else:
            category = None
        return evidence.path_for(category, run.id) if category else None

    def read_run_result(run: Any) -> tuple[dict[str, Any] | None, str]:
        if not run.artifact_path:
            return None, "missing"
        try:
            return (
                evidence.read_verified_json(
                    run.artifact_path,
                    run.artifact_sha256,
                    expected_path=expected_run_artifact_path(run),
                ),
                "verified",
            )
        except FileNotFoundError:
            return None, "missing"
        except (EvidenceIntegrityError, OSError):
            return None, "corrupt"

    def audit_run_item(run: Any) -> dict[str, Any]:
        item = run.as_dict()
        result, integrity = read_run_result(run)
        item["evidence_integrity"] = integrity
        if (
            run.detector
            not in {"one_token_verify", "one_token_recovered", "tokenizer_verify"}
            or run.status != "completed"
        ):
            return item
        is_tokenizer = run.detector == "tokenizer_verify"
        decision = result.get("decision") if result else None
        operational = decision.get("operationalVerdict") if isinstance(decision, dict) else None
        if (
            isinstance(operational, str)
            and operational
            and (not is_tokenizer or operational == "unverifiable")
        ):
            item["verdict"] = operational
            item["verdict_semantics"] = "operational-v1"
            return item
        legacy_values = {"match", "uncertain", "mismatch", "unstable"}
        legacy = run.verdict if run.verdict in legacy_values else None
        status = "legacy_uncalibrated" if is_tokenizer else "legacy_unmigrated"
        reason = (
            "legacy_tokenizer_result_without_calibrated_policy"
            if is_tokenizer
            else "legacy_result_without_safe_decision"
        )
        decision = {
            "operationalVerdict": "unverifiable",
            "status": status,
            "reasons": [reason],
            "legacyVerdict": legacy,
            "decisionEligible": False,
        }
        if is_tokenizer:
            decision["exploratoryVerdict"] = legacy
        item.update(
            {
                "verdict": "unverifiable",
                "legacy_verdict": legacy,
                "verdict_semantics": (
                    "legacy-uncalibrated" if is_tokenizer else "legacy-unmigrated"
                ),
                "decision": decision,
            }
        )
        return item

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
        return {"items": [audit_run_item(run) for run in database.list_runs(safe_limit)]}

    @app.post("/api/v1/endpoints", status_code=201)
    async def create_endpoint(
        payload: ManagedEndpointCreateRequest,
        request: Request,
    ) -> dict[str, object]:
        if payload.api_key_env is not None:
            require_server_credential_access(request)
        try:
            configured.require_allowed_api_key_env(payload.api_key_env)
            endpoint = database.create_endpoint(
                endpoint_id=str(uuid4()),
                name=payload.name,
                provider=payload.provider,
                base_url=str(payload.base_url),
                model=payload.model,
                protocol=payload.protocol,
                api_key_env=payload.api_key_env,
            )
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
        except IntegrityError as error:
            raise HTTPException(status_code=409, detail="endpoint name already exists") from error
        return endpoint.as_dict()

    @app.get("/api/v1/endpoints")
    async def list_endpoints(request: Request) -> dict[str, object]:
        authenticated = has_valid_access_token(request)
        items = [
            endpoint_response_payload(
                endpoint.as_dict(),
                authenticated=authenticated,
            )
            for endpoint in database.list_endpoints()
        ]
        return {"items": items}

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
        if run.model != endpoint.model or run.target_base_url.rstrip(
            "/"
        ) != endpoint.base_url.rstrip("/"):
            raise HTTPException(status_code=409, detail="artifact endpoint does not match baseline")
        category = {"one_token": "fingerprints", "tokenizer": "tokenizers"}[
            payload.detector
        ]
        try:
            evidence.verify_registered_path(
                run.artifact_path,
                run.artifact_sha256,
                expected_path=evidence.path_for(category, payload.artifact_id),
            )
        except (FileNotFoundError, EvidenceIntegrityError) as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
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
    async def smoke_audit(payload: SmokeAuditRequest, request: Request) -> AuditResponse:
        api_key = resolve_managed_api_key(payload.target, request)
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
        request: Request,
    ) -> AuditResponse:
        api_key = resolve_managed_api_key(payload.endpoint, request)
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
        request: Request,
    ) -> AuditResponse:
        api_key = resolve_managed_api_key(payload.endpoint, request)
        audit_id = str(uuid4())
        target_path: Path | None = None
        database.create_run(
            audit_id=audit_id,
            detector="one_token_verify",
            target_base_url=str(payload.endpoint.base_url),
            model=payload.endpoint.model,
        )
        try:
            reference_path = verified_reference_path(
                payload.reference_artifact_id,
                category="fingerprints",
                detector="one_token_collect",
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
        except EvidenceIntegrityError as error:
            detail = redact_error(error, api_key)
            database.finish_run(
                audit_id,
                status="failed",
                verdict="error",
                error_message=detail,
            )
            raise HTTPException(status_code=409, detail=detail) from error
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

    def redact_error(error: Exception, api_key: str | None) -> str:
        detail = str(error)
        if api_key:
            detail = detail.replace(api_key, "[REDACTED]")
        return detail

    def comparison_item(
        row: tuple[Any, Any, Any],
        *,
        include_result: bool = False,
    ) -> dict[str, Any]:
        run, record, batch = row
        result, artifact_integrity = read_run_result(run)
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
        if artifact_integrity == "corrupt":
            evidence_state = "corrupt"
        elif result is None:
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
            "evidence_integrity": artifact_integrity,
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
        except ValueError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
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
    async def console_list_references(
        request: Request,
        include_inactive: bool = False,
    ) -> dict[str, Any]:
        items = database.list_reference_catalog(active_only=not include_inactive)
        for item in items:
            endpoint_payload = item.get("endpoint")
            if isinstance(endpoint_payload, dict):
                item["endpoint"] = endpoint_response_payload(
                    endpoint_payload,
                    authenticated=has_valid_access_token(request),
                )
            baseline = item["baseline"]
            if isinstance(baseline, dict):
                run = database.get_run(str(baseline["artifact_id"]))
                try:
                    if run is None:
                        raise FileNotFoundError
                    category = (
                        "tokenizers" if baseline.get("detector") == "tokenizer" else "fingerprints"
                    )
                    evidence.verify_registered_path(
                        run.artifact_path,
                        run.artifact_sha256,
                        expected_path=evidence.path_for(category, run.id),
                    )
                    item["evidence_available"] = True
                    item["evidence_integrity"] = "verified"
                except FileNotFoundError:
                    item["evidence_available"] = False
                    item["evidence_integrity"] = "missing"
                except EvidenceIntegrityError:
                    item["evidence_available"] = False
                    item["evidence_integrity"] = "corrupt"
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
    async def console_download_evidence(artifact_id: str) -> Response:
        run = database.get_run(artifact_id)
        if run is None or not run.artifact_path:
            raise HTTPException(status_code=404, detail="audit evidence not found")
        try:
            _, encoded = evidence.read_verified_bytes(
                run.artifact_path,
                run.artifact_sha256,
                expected_path=expected_run_artifact_path(run),
            )
        except FileNotFoundError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        except EvidenceIntegrityError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        return Response(
            content=encoded,
            media_type="application/json",
            headers={
                "Cache-Control": "no-store",
                "X-Evidence-SHA256": run.artifact_sha256 or "",
                "Content-Disposition": (
                    f'attachment; filename="{run.detector}-{artifact_id}.json"'
                ),
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
            target_base_url=str(endpoint.base_url),
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
            target_base_url=str(endpoint.base_url),
            model=endpoint.model,
        )
        try:
            reference_path = verified_reference_path(
                payload.reference_artifact_id,
                category="fingerprints",
                detector="one_token_collect",
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
        except EvidenceIntegrityError as error:
            detail = redact_error(error, api_key)
            database.finish_run(
                audit_id,
                status="failed",
                verdict="error",
                error_message=detail,
            )
            raise HTTPException(status_code=409, detail=detail) from error
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

    @app.post("/api/v1/tokenizers/collect", response_model=AuditResponse)
    async def collect_tokenizer(
        payload: TokenizerCollectRequest,
        request: Request,
    ) -> AuditResponse:
        api_key = resolve_managed_api_key(payload.endpoint, request)
        audit_id = str(uuid4())
        database.create_run(
            audit_id=audit_id,
            detector="tokenizer_collect",
            target_base_url=str(payload.endpoint.base_url),
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
        request: Request,
    ) -> AuditResponse:
        api_key = resolve_managed_api_key(payload.endpoint, request)
        audit_id = str(uuid4())
        database.create_run(
            audit_id=audit_id,
            detector="tokenizer_verify",
            target_base_url=str(payload.endpoint.base_url),
            model=payload.endpoint.model,
        )
        try:
            reference_path = verified_reference_path(
                payload.reference_artifact_id,
                category="tokenizers",
                detector="tokenizer_collect",
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
            exploratory_verdict = str(comparison["verdict"])
            decision = {
                "operationalVerdict": "unverifiable",
                "status": "uncalibrated",
                "reasons": ["validated_tokenizer_threshold_policy_missing"],
                "exploratoryVerdict": exploratory_verdict,
                "normalizedL1": comparison.get("normalized_l1"),
                "decisionEligible": False,
            }
            result = {
                "reference_artifact_id": payload.reference_artifact_id,
                "target": target,
                "comparison": comparison,
                "exploratoryVerdict": exploratory_verdict,
                "verdict": "unverifiable",
                "verdictSemantics": "operational-v1",
                "decision": decision,
            }
            artifact = evidence.write_json("tokenizer_verification", audit_id, result)
            verdict = "unverifiable"
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
        except EvidenceIntegrityError as error:
            detail = redact_error(error, api_key)
            database.finish_run(
                audit_id,
                status="failed",
                verdict="error",
                error_message=detail,
            )
            raise HTTPException(status_code=409, detail=detail) from error
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
