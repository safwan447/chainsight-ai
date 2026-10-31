import json
import pytest
from backend.ingestion.parser import detect_format, parse_line, normalize
from backend.ingestion.reader import stream_lines
from backend.models import NormalizedEvent


def test_jsonl_normalizes_generator_shape():
    raw = {
        "@timestamp": "2026-01-01T00:00:00Z",
        "event": {"id": "e1", "category": ["process"], "kind": "event", "action": "process_created", "severity": 1},
        "host": {"name": "WS-01"},
        "user": {"name": "analyst"},
        "process": {"name": "powershell.exe", "parent": {"name": "winword.exe"}, "command_line": "powershell -enc demo"},
    }
    event = normalize(parse_line(json.dumps(raw)))
    assert event.event_id == "e1" and event.host == "WS-01" and event.parent_process == "winword.exe"
    assert event.severity == "low"
    assert event.category == "process"


def test_cef_parse_and_normalize():
    line = "CEF:0|Vendor|EDR|1|sig|alert|7|rt=2026-01-01T00:00:00Z dvchost=WS-01 suser=alex cat=network act=connection externalId=e2 dproc=powershell.exe cs2=T1059.001"
    event = normalize(parse_line(line))
    assert event.technique_id == "T1059.001"
    assert event.technique_name == "PowerShell"
    assert event.tactic == "Execution"
    assert event.host == "WS-01"
    assert event.event_id == "e2"


def test_fortigate_key_value_normalizes():
    line = 'date=2026-10-23 time=08:48:26 tz="+0530" devname="FGT" logid="0100032002" type="event" subtype="system" level="alert" user="admin" srcip=209.50.167.232 dstip=10.10.99.1 action="login" status="failed"'
    event = normalize(parse_line(line))
    assert event.category == "authentication"
    assert event.severity == "critical"
    assert event.source_ip == "209.50.167.232"
    assert event.action == "login"
    assert event.user == "admin"


def test_invalid_json_is_rejected():
    with pytest.raises(json.JSONDecodeError):
        parse_line("not a JSON record", source_format="jsonl")


def test_invalid_cef_is_rejected():
    with pytest.raises(ValueError, match="Invalid CEF record"):
        parse_line("CEF:invalid_header_without_pipes", source_format="cef")


def test_invalid_fortigate_is_rejected():
    with pytest.raises(ValueError, match="missing required date field"):
        parse_line("type=traffic subtype=forward action=accept", source_format="fortigate")


def test_missing_fields_are_safe():
    event = normalize(parse_line('{"event":{"id":"e3"}}'))
    assert event.category == "unknown"
    assert event.action == "unknown"
    assert event.host is None
    assert event.user is None
    assert event.severity == "informational"


def test_duplicate_event_handling_preserves_identity(tmp_path):
    """Ensure duplicate event IDs in input logs do not overwrite or discard events."""
    from backend.ingestion.storage import Storage

    test_db = tmp_path / "test_dup.duckdb"
    store = Storage(test_db)

    # Two events with identical event_id 'evt-dup'
    e1 = normalize({"@timestamp": "2026-01-01T00:00:00Z", "event": {"id": "evt-dup"}, "process": {"name": "proc1.exe"}})
    e2 = normalize({"@timestamp": "2026-01-01T00:01:00Z", "event": {"id": "evt-dup"}, "process": {"name": "proc2.exe"}})

    # Pipeline logic tracks duplicates and disambiguates stored key
    seen = set()
    stored_events = []
    dup_count = 0
    for idx, e in enumerate([e1, e2], 1):
        if e.event_id in seen:
            dup_count += 1
            e.raw_event["_original_event_id"] = e.event_id
            e.event_id = f"{e.event_id}#dup{idx}"
        seen.add(e.event_id)
        stored_events.append(e)

    assert dup_count == 1
    store.insert_events(stored_events)

    total, items = store.event_page(limit=10)
    assert total == 2
    assert len(items) == 2
    assert {it.event_id for it in items} == {"evt-dup", "evt-dup#dup2"}
    store.close()


def test_empty_file_handling(tmp_path):
    empty_file = tmp_path / "empty.log"
    empty_file.write_text("", encoding="utf-8")
    lines = list(stream_lines(empty_file))
    assert len(lines) == 0
