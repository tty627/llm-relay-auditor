from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import DateTime, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker


class Base(DeclarativeBase):
    pass


class AuditRun(Base):
    __tablename__ = "audit_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    detector: Mapped[str] = mapped_column(String(32), index=True)
    status: Mapped[str] = mapped_column(String(16), index=True)
    verdict: Mapped[str | None] = mapped_column(String(32), nullable=True)
    target_base_url: Mapped[str] = mapped_column(Text)
    model: Mapped[str] = mapped_column(String(255))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    artifact_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    artifact_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "detector": self.detector,
            "status": self.status,
            "verdict": self.verdict,
            "target_base_url": self.target_base_url,
            "model": self.model,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "artifact_path": self.artifact_path,
            "artifact_sha256": self.artifact_sha256,
            "error_message": self.error_message,
        }


class Database:
    def __init__(self, url: str) -> None:
        if url.startswith("sqlite:///") and not url.endswith(":memory:"):
            database_path = Path(url.removeprefix("sqlite:///"))
            database_path.parent.mkdir(parents=True, exist_ok=True)
        connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
        self.engine = create_engine(url, connect_args=connect_args)
        self.sessions = sessionmaker(self.engine, expire_on_commit=False)

    def initialize(self) -> None:
        Base.metadata.create_all(self.engine)

    def session(self) -> Iterator[Session]:
        with self.sessions() as session:
            yield session

    def create_run(
        self,
        *,
        audit_id: str,
        detector: str,
        target_base_url: str,
        model: str,
    ) -> AuditRun:
        run = AuditRun(
            id=audit_id,
            detector=detector,
            status="running",
            target_base_url=target_base_url,
            model=model,
            started_at=datetime.now(UTC),
        )
        with self.sessions() as session:
            session.add(run)
            session.commit()
        return run

    def finish_run(
        self,
        audit_id: str,
        *,
        status: str,
        verdict: str | None = None,
        artifact_path: str | None = None,
        artifact_sha256: str | None = None,
        error_message: str | None = None,
    ) -> AuditRun:
        with self.sessions() as session:
            run = session.get(AuditRun, audit_id)
            if run is None:
                raise LookupError(f"audit run not found: {audit_id}")
            run.status = status
            run.verdict = verdict
            run.completed_at = datetime.now(UTC)
            run.artifact_path = artifact_path
            run.artifact_sha256 = artifact_sha256
            run.error_message = error_message
            session.commit()
            session.refresh(run)
            return run

    def list_runs(self, limit: int = 50) -> list[AuditRun]:
        with self.sessions() as session:
            statement = select(AuditRun).order_by(AuditRun.started_at.desc()).limit(limit)
            return list(session.scalars(statement))
