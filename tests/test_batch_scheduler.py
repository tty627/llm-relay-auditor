from types import SimpleNamespace

from relay_auditor import batches
from relay_auditor.batches import ComparisonBatchManager


def test_cooldown_expiry_between_scheduler_clock_reads_keeps_item_queued(
    monkeypatch,
) -> None:
    run = SimpleNamespace(status="queued")
    database = SimpleNamespace(get_run=lambda audit_id: run)
    manager = ComparisonBatchManager(database, None, None)  # type: ignore[arg-type]
    item = SimpleNamespace(
        audit_id="queued-audit",
        preflight_retry_at=10.05,
        priority=0,
        sequence=0,
        request=SimpleNamespace(station_name="Relay A"),
    )
    runtime = SimpleNamespace(
        items=[item],
        station_retry_at={},
        station_order=[],
        station_cursor_by_priority={},
    )
    clock = iter((10.0, 10.1))
    monkeypatch.setattr(batches, "monotonic", lambda: next(clock))

    assert manager._next_item(runtime) is None
    assert manager._next_retry_delay(runtime) == 0.0
