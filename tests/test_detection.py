from backend.detection.engine import DetectionEngine
from backend.ingestion.parser import normalize
from backend.mitre import mapping


def make(
    process="powershell.exe",
    parent="winword.exe",
    command="powershell -enc demo",
    category="process",
    domain=None,
    registry=None,
    file_path=None,
    severity="informational",
):
    raw = {
        "@timestamp": "2026-01-01T00:00:00Z",
        "event": {"id": "x", "category": [category], "severity": severity},
        "process": {"name": process, "parent": {"name": parent}, "command_line": command},
    }
    if domain:
        raw["destination"] = {"domain": domain}
    if registry:
        raw["registry"] = {"path": registry}
    if file_path:
        raw["file"] = {"path": file_path}
    return normalize(raw)


def test_office_child_detection():
    detections = DetectionEngine().detect([make()])
    assert any(x.rule_id == "CS-OFFICE-001" for x in detections)


def test_benign_powershell_without_context_is_not_auto_alerted():
    """Ensure benign PowerShell commands without obfuscation or office parents are not alerted."""
    detections = DetectionEngine().detect([make(parent="explorer.exe", command="powershell Get-Date")])
    assert not detections


def test_suspicious_powershell_encoded_command():
    detections = DetectionEngine().detect([make(parent="explorer.exe", command="powershell.exe -EncodedCommand AAAA")])
    assert any(x.rule_id == "CS-PS-001" for x in detections)


def test_c2_suspicious_domain_detection():
    event = make(category="network", domain="c2-suspicious-beacon.com")
    detections = DetectionEngine().detect([event])
    assert any(x.rule_id == "CS-C2-001" for x in detections)


def test_registry_run_key_persistence():
    event = make(category="registry", registry=r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Backdoor")
    detections = DetectionEngine().detect([event])
    assert any(x.rule_id == "CS-REG-001" for x in detections)


def test_ransomware_mass_rename_detection():
    event = make(category="file", file_path=r"C:\Users\victim\Documents\finance.docx.locked")
    detections = DetectionEngine().detect([event])
    assert any(x.rule_id == "CS-FILE-001" for x in detections)


def test_mitre_mapping_technique_id():
    name, tactic = mapping("T1059.001")
    assert name == "PowerShell"
    assert tactic == "Execution"

    name, tactic = mapping("T1110")
    assert name == "Brute Force"
    assert tactic == "Credential Access"

    name, tactic = mapping("T1486")
    assert name == "Data Encrypted for Impact"
    assert tactic == "Impact"


def test_case_insensitive_matching():
    """Ensure detection engine handles uppercase extensions and arguments robustly."""
    event = make(process="POWERSHELL.EXE", parent="WINWORD.EXE", command="POWERSHELL -ENC ABCD")
    detections = DetectionEngine().detect([event])
    rule_ids = {d.rule_id for d in detections}
    assert "CS-OFFICE-001" in rule_ids
    assert "CS-PS-001" in rule_ids
