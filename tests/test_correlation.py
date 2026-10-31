from datetime import timedelta

from backend.correlation.correlator import correlate
from backend.models import Detection
from tests.test_detection import make


def detection(ident, event):
    return Detection(
        detection_id=ident,
        event_id=event.event_id,
        rule_id="rule-" + ident,
        rule_name="Test detection",
        severity="high",
        technique_id="T1059.001",
        technique_name="PowerShell",
        tactic="Execution",
        confidence=0.8,
        evidence={},
    )


def test_same_host_and_user_correlate_within_window():
    a, b = make(), make()
    a.event_id, b.event_id = "a", "b"
    a.host = b.host = "WS-01"
    a.user = b.user = "analyst"
    b.timestamp = a.timestamp + timedelta(minutes=30)
    incidents = correlate([a, b], [detection("a", a), detection("b", b)])
    assert len(incidents) == 1
    assert incidents[0].detection_count == 2


def test_shared_host_alone_does_not_correlate():
    a, b = make(), make()
    a.event_id, b.event_id = "a", "b"
    a.host = b.host = "WS-01"
    b.timestamp = a.timestamp + timedelta(minutes=5)
    incidents = correlate([a, b], [detection("a", a), detection("b", b)])
    assert len(incidents) == 2


def test_same_public_ip_across_hosts_does_not_correlate():
    a, b = make(), make()
    a.event_id, b.event_id = "a", "b"
    a.host, b.host = "WS-01", "WS-02"
    a.source_ip = b.source_ip = "203.0.113.10"
    incidents = correlate([a, b], [detection("a", a), detection("b", b)])
    assert len(incidents) == 2


def test_same_host_user_outside_window_does_not_correlate():
    a, b = make(), make()
    a.event_id, b.event_id = "a", "b"
    a.host = b.host = "WS-01"
    a.user = b.user = "analyst"
    b.timestamp = a.timestamp + timedelta(hours=2)
    incidents = correlate([a, b], [detection("a", a), detection("b", b)])
    assert len(incidents) == 2


def test_duplicate_event_membership_is_counted_once():
    a = make()
    a.event_id = "same-event"
    incidents = correlate([a], [detection("a", a), detection("b", a)])
    assert len(incidents) == 1
    assert incidents[0].event_count == 1
    assert incidents[0].detection_count == 2
