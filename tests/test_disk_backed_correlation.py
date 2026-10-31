from datetime import datetime, timedelta, timezone

from backend.correlation.disk_backed import DiskBackedStreamingCorrelator
from backend.models import Detection, NormalizedEvent


def _event(
    event_id: str,
    timestamp: datetime,
    process: str,
    parent: str,
    user: str = "alice",
    host: str = "WS-01",
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        event_kind="process",
        category="process",
        action="execute",
        severity="high",
        host=host,
        user=user,
        process_name=process,
        parent_process=parent,
    )


def _detection(event: NormalizedEvent, detection_id: str, rule: str) -> Detection:
    return Detection(
        detection_id=detection_id,
        event_id=event.event_id,
        rule_id=rule,
        rule_name=rule,
        severity="high",
        technique_id="T1059.001",
        technique_name="PowerShell",
        tactic="Execution",
        confidence=0.85,
        evidence={"host": event.host, "user": event.user},
    )


def test_disk_backed_correlator_preserves_cross_batch_process_lineage(tmp_path):
    now = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
    first = _event("evt-1", now, "winword.exe", "explorer.exe")
    second = _event("evt-2", now + timedelta(minutes=2), "powershell.exe", "winword.exe")
    correlator = DiskBackedStreamingCorrelator(window_minutes=60, temp_dir=tmp_path)
    try:
        # Separate add calls model detections arriving from separate ingestion chunks.
        correlator.add(_detection(first, "det-1", "CS-OFFICE-001"), first)
        correlator.add(_detection(second, "det-2", "CS-PS-001"), second)
        incidents = correlator.incidents()
        assert len(incidents) == 1
        assert incidents[0].detection_count == 2
        assert set(incidents[0].evidence_event_ids) == {"evt-1", "evt-2"}
        assert any("lineage" in reason.lower() for reason in incidents[0].correlation_reasons)
    finally:
        correlator.close()


def test_disk_backed_correlator_keeps_independent_attacks_separate(tmp_path):
    now = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
    first = _event("evt-1", now, "svchost.exe", "services.exe", user="alice")
    second = _event("evt-2", now + timedelta(minutes=5), "updater.exe", "taskeng.exe", user="bob")
    correlator = DiskBackedStreamingCorrelator(window_minutes=60, temp_dir=tmp_path)
    try:
        correlator.add(_detection(first, "det-1", "CS-REG-001"), first)
        correlator.add(_detection(second, "det-2", "CS-C2-001"), second)
        incidents = correlator.incidents()
        assert len(incidents) == 2
        assert {item.detection_count for item in incidents} == {1}
    finally:
        correlator.close()


def test_disk_backed_correlator_expires_old_items_from_ram_but_keeps_them_on_disk(tmp_path):
    now = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
    first = _event("evt-1", now, "winword.exe", "explorer.exe")
    second = _event("evt-2", now + timedelta(hours=2), "powershell.exe", "cmd.exe")
    correlator = DiskBackedStreamingCorrelator(window_minutes=60, temp_dir=tmp_path)
    try:
        correlator.add(_detection(first, "det-1", "CS-OFFICE-001"), first)
        correlator.add(_detection(second, "det-2", "CS-PS-001"), second)
        assert len(correlator.active_detections) == 1
        assert correlator._db.execute("SELECT COUNT(*) FROM detections").fetchone()[0] == 2
        assert len(correlator.incidents()) == 2
    finally:
        correlator.close()


def test_disk_backed_duplicate_id_index_is_persisted_outside_ram(tmp_path):
    correlator = DiskBackedStreamingCorrelator(window_minutes=60, temp_dir=tmp_path)
    try:
        assert not correlator.has_event_id("evt-duplicate")
        correlator.remember_event_id("evt-duplicate")
        assert correlator.has_event_id("evt-duplicate")
    finally:
        correlator.close()
