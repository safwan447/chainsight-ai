from datetime import datetime, timezone
from backend.correlation.correlator import correlate
from backend.models import Detection, NormalizedEvent
from tests.test_detection import make


def _det(ident: str, event: NormalizedEvent, rule_id: str = "CS-PS-001", tech_id: str = "T1059.001", tech_name: str = "PowerShell", tactic: str = "Execution", sev: str = "high", conf: float = 0.85) -> Detection:
    return Detection(
        detection_id=ident,
        event_id=event.event_id,
        rule_id=rule_id,
        rule_name=rule_id,
        severity=sev,
        technique_id=tech_id,
        technique_name=tech_name,
        tactic=tactic,
        confidence=conf,
        evidence={"host": event.host, "user": event.user},
    )


def test_process_lineage_correlates():
    """Strong correlation: parent process spawning suspicious child on same host forms 1 incident."""
    e1 = make(process="winword.exe", parent="explorer.exe", command="winword.exe invoice.doc")
    e1.event_id = "e1"
    e1.host = "WS-01"
    e1.user = "alice"
    e1.timestamp = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)

    e2 = make(process="powershell.exe", parent="winword.exe", command="powershell.exe -enc AAAA")
    e2.event_id = "e2"
    e2.host = "WS-01"
    e2.user = "alice"
    e2.timestamp = datetime(2026, 1, 1, 10, 2, 0, tzinfo=timezone.utc)

    d1 = _det("d1", e1, rule_id="CS-OFFICE-001", tech_id="T1059", tech_name="Scripting", tactic="Execution")
    d2 = _det("d2", e2, rule_id="CS-PS-001", tech_id="T1059.001", tech_name="PowerShell", tactic="Execution")

    incidents = correlate([e1, e2], [d1, d2])
    assert len(incidents) == 1
    assert incidents[0].detection_count == 2
    assert "WS-01" in incidents[0].hosts
    assert any("lineage" in r.lower() for r in incidents[0].correlation_reasons)


def test_user_sequential_tactics_correlate():
    """Strong correlation: same user and host exhibiting sequential MITRE tactic progression forms 1 incident."""
    e1 = make(process="lsass.exe", parent="services.exe", command="")
    e1.event_id = "e1"
    e1.host = "SRV-01"
    e1.user = "admin"
    e1.timestamp = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    e2 = make(process="powershell.exe", parent="cmd.exe", command="powershell -enc malicious")
    e2.event_id = "e2"
    e2.host = "SRV-01"
    e2.user = "admin"
    e2.timestamp = datetime(2026, 1, 1, 12, 10, 0, tzinfo=timezone.utc)

    d1 = _det("d1", e1, rule_id="CS-AUTH-001", tech_id="T1110", tech_name="Brute Force", tactic="Credential Access")
    d2 = _det("d2", e2, rule_id="CS-PS-001", tech_id="T1059.001", tech_name="PowerShell", tactic="Execution")

    incidents = correlate([e1, e2], [d1, d2])
    assert len(incidents) == 1
    assert incidents[0].detection_count == 2
    assert "Credential Access" in str(incidents[0].correlation_reasons)


def test_network_pivot_correlates():
    """Strong correlation: source IP to destination IP connection correlates lateral movement."""
    e1 = make()
    e1.event_id = "e1"
    e1.host = "WS-01"
    e1.source_ip = "10.0.0.5"
    e1.destination_ip = "10.0.0.20"
    e1.timestamp = datetime(2026, 1, 1, 14, 0, 0, tzinfo=timezone.utc)

    e2 = make()
    e2.event_id = "e2"
    e2.host = "SRV-DC"
    e2.source_ip = "10.0.0.20"
    e2.destination_ip = "10.0.0.20"
    e2.timestamp = datetime(2026, 1, 1, 14, 5, 0, tzinfo=timezone.utc)

    d1 = _det("d1", e1, rule_id="CS-C2-001", tech_id="T1071.001", tech_name="Web Protocols", tactic="Command and Control")
    d2 = _det("d2", e2, rule_id="CS-PS-001", tech_id="T1059.001", tech_name="PowerShell", tactic="Execution")

    incidents = correlate([e1, e2], [d1, d2])
    assert len(incidents) == 1
    assert any("lateral" in r.lower() or "network" in r.lower() for r in incidents[0].correlation_reasons)


def test_shared_host_alone_does_not_merge_unrelated_events():
    """Negative example: Shared host alone without shared user, lineage or C2 does NOT merge incidents."""
    e1 = make(process="svchost.exe", parent="services.exe", command="")
    e1.event_id = "e1"
    e1.host = "WS-01"
    e1.user = "alice"
    e1.timestamp = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)

    e2 = make(process="updater.exe", parent="taskeng.exe", command="")
    e2.event_id = "e2"
    e2.host = "WS-01"
    e2.user = "bob"
    e2.timestamp = datetime(2026, 1, 1, 10, 20, 0, tzinfo=timezone.utc)

    d1 = _det("d1", e1, rule_id="CS-REG-001", tech_id="T1547.001", tech_name="Registry Run Keys", tactic="Persistence")
    d2 = _det("d2", e2, rule_id="CS-C2-001", tech_id="T1071.001", tech_name="Web Protocols", tactic="Command and Control")

    incidents = correlate([e1, e2], [d1, d2])
    # Must remain two distinct incidents!
    assert len(incidents) == 2
    assert {inc.detection_count for inc in incidents} == {1}


def test_multiple_simultaneous_attacks_on_same_host():
    """Negative example: Two completely independent attack chains on the same host stay separate."""
    # Attack 1: User Alice spearphished via Word -> PowerShell
    e1 = make(process="winword.exe", parent="explorer.exe", command="winword.exe")
    e1.event_id = "e1"
    e1.host = "WS-SERVER"
    e1.user = "alice"
    e1.timestamp = datetime(2026, 1, 1, 9, 0, 0, tzinfo=timezone.utc)

    e2 = make(process="powershell.exe", parent="winword.exe", command="powershell.exe -enc payload1")
    e2.event_id = "e2"
    e2.host = "WS-SERVER"
    e2.user = "alice"
    e2.timestamp = datetime(2026, 1, 1, 9, 5, 0, tzinfo=timezone.utc)

    # Attack 2: User Charlie via web app -> mass ransomware rename
    e3 = make(process="sqlservr.exe", parent="services.exe", command="")
    e3.event_id = "e3"
    e3.host = "WS-SERVER"
    e3.user = "charlie"
    e3.timestamp = datetime(2026, 1, 1, 9, 2, 0, tzinfo=timezone.utc)

    e4 = make(process="vssadmin.exe", parent="sqlservr.exe", command="vssadmin delete shadows")
    e4.event_id = "e4"
    e4.host = "WS-SERVER"
    e4.user = "charlie"
    e4.timestamp = datetime(2026, 1, 1, 9, 8, 0, tzinfo=timezone.utc)

    d1 = _det("d1", e1, rule_id="CS-OFFICE-001", tech_id="T1059", tech_name="Office Script", tactic="Execution")
    d2 = _det("d2", e2, rule_id="CS-PS-001", tech_id="T1059.001", tech_name="PowerShell", tactic="Execution")
    d3 = _det("d3", e3, rule_id="CS-FGT-IPS-001", tech_id="T1190", tech_name="Exploit App", tactic="Initial Access")
    d4 = _det("d4", e4, rule_id="CS-FILE-001", tech_id="T1486", tech_name="Ransomware", tactic="Impact")

    incidents = correlate([e1, e2, e3, e4], [d1, d2, d3, d4])
    # Must separate into 2 distinct incidents on WS-SERVER!
    assert len(incidents) == 2
    assert all(inc.detection_count == 2 for inc in incidents)
    assert {inc.hosts[0] for inc in incidents} == {"WS-SERVER"}


def test_deterministic_reproducible_incidents():
    """Ensure incident reconstruction produces exact same deterministic incident IDs on repeated runs."""
    e1 = make(process="winword.exe", parent="explorer.exe")
    e1.event_id = "e1"; e1.host = "WS-01"; e1.user = "alice"
    e2 = make(process="powershell.exe", parent="winword.exe")
    e2.event_id = "e2"; e2.host = "WS-01"; e2.user = "alice"

    d1 = _det("d1", e1, rule_id="CS-OFFICE-001", tech_id="T1059", tech_name="Office", tactic="Execution")
    d2 = _det("d2", e2, rule_id="CS-PS-001", tech_id="T1059.001", tech_name="PowerShell", tactic="Execution")

    run1 = correlate([e1, e2], [d1, d2])
    run2 = correlate([e1, e2], [d1, d2])

    assert len(run1) == 1 and len(run2) == 1
    assert run1[0].incident_id == run2[0].incident_id
    assert run1[0].risk_score == run2[0].risk_score
