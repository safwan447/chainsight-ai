from __future__ import annotations

MITRE: dict[str, tuple[str, str]] = {
    "T1110": ("Brute Force", "Credential Access"),
    "T1110.001": ("Password Guessing", "Credential Access"),
    "T1110.003": ("Password Spraying", "Credential Access"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1059.001": ("PowerShell", "Execution"),
    "T1059.003": ("Windows Command Shell", "Execution"),
    "T1059.005": ("Visual Basic", "Execution"),
    "T1547": ("Boot or Logon Autostart Execution", "Persistence"),
    "T1547.001": ("Registry Run Keys / Startup Folder", "Persistence"),
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1071.001": ("Web Protocols", "Command and Control"),
    "T1071.004": ("DNS", "Command and Control"),
    "T1486": ("Data Encrypted for Impact", "Impact"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1566": ("Phishing", "Initial Access"),
    "T1566.001": ("Spearphishing Attachment", "Initial Access"),
    "T1566.002": ("Spearphishing Link", "Initial Access"),
    "T1021": ("Remote Services", "Lateral Movement"),
    "T1021.001": ("Remote Desktop Protocol", "Lateral Movement"),
    "T1021.002": ("SMB/Windows Admin Shares", "Lateral Movement"),
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1082": ("System Information Discovery", "Discovery"),
    "T1083": ("File and Directory Discovery", "Discovery"),
    "T1003": ("OS Credential Dumping", "Credential Access"),
    "T1078": ("Valid Accounts", "Defense Evasion"),
    "T1562": ("Impair Defenses", "Defense Evasion"),
}


def mapping(technique_id: str | None) -> tuple[str | None, str | None]:
    if not technique_id:
        return None, None
    tid = technique_id.strip().upper()
    if tid in MITRE:
        return MITRE[tid]
    # Check parent technique if subtechnique is given (e.g. T1059.001 -> T1059)
    if "." in tid:
        parent = tid.split(".")[0]
        if parent in MITRE:
            name, tactic = MITRE[parent]
            return f"{name} ({tid})", tactic
    return None, None
