from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

CEF_PREFIX = re.compile(
    r"^CEF:\d+\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|(?P<version>[^|]*)\|"
    r"(?P<signature>[^|]*)\|(?P<name>[^|]*)\|(?P<severity>[^|]*)\|(?P<extension>.*)$"
)
CEF_EXTENSION = re.compile(r"(?P<key>[A-Za-z][A-Za-z0-9]*)=(?P<value>.*?)(?=\s+[A-Za-z][A-Za-z0-9]*=|$)")
FORTI_PAIR = re.compile(r'(?P<key>[A-Za-z][A-Za-z0-9_]*)=(?:"(?P<quoted>[^"]*)"|(?P<plain>[^\s]+))')

SEVERITY_INT_MAP = {
    0: "informational",
    1: "low",
    2: "low",
    3: "medium",
    4: "medium",
    5: "high",
    6: "high",
    7: "high",
    8: "critical",
    9: "critical",
    10: "critical",
}

FORTI_SEVERITY_MAP = {
    "emergency": "critical",
    "alert": "critical",
    "critical": "critical",
    "error": "high",
    "warning": "medium",
    "notice": "low",
    "information": "informational",
    "debug": "informational",
}


def detect_format(sample: str) -> str:
    stripped = sample.lstrip()
    if stripped.startswith("CEF:"):
        return "cef"
    if stripped.startswith("{"):
        return "jsonl"
    if "date=" in stripped and "type=" in stripped:
        return "fortigate"
    return "jsonl"


def parse_line(line: str, source_format: str | None = None) -> dict[str, Any]:
    fmt = source_format or detect_format(line)
    if fmt == "jsonl":
        loaded = json.loads(line)
        if isinstance(loaded.get("event"), dict) and "sourcetype" in loaded:
            # Unwrap Splunk/wrapper style logs while preserving raw context
            unwrapped = loaded["event"]
            if isinstance(unwrapped, dict):
                return unwrapped
        return loaded

    if fmt == "fortigate":
        values: dict[str, Any] = {}
        for match in FORTI_PAIR.finditer(line):
            key = match.group("key")
            quoted = match.group("quoted")
            values[key] = quoted if quoted is not None else match.group("plain")

        if not values or "date" not in values:
            raise ValueError("Invalid FortiGate key/value record: missing required date field")
        values["_format"] = "fortigate"
        return values

    if fmt == "cef":
        match = CEF_PREFIX.match(line.strip())
        if not match:
            raise ValueError("Invalid CEF record: header does not match CEF standard")
        value = match.groupdict()
        ext = {m.group("key"): m.group("value") for m in CEF_EXTENSION.finditer(value.pop("extension", ""))}
        value["extension"] = ext
        return value

    raise ValueError(f"Unsupported log format: {fmt}")


def _text(value: Any) -> str | None:
    if value is None:
        return None
    s = str(value).strip()
    return s if s else None


def _parse_timestamp(val: Any) -> datetime:
    if isinstance(val, datetime):
        return val
    if isinstance(val, (int, float)):
        # Check if timestamp is in nanoseconds, microseconds, or milliseconds
        if val > 1e16:  # nanoseconds
            return datetime.fromtimestamp(val / 1e9, tz=timezone.utc)
        if val > 1e13:  # microseconds
            return datetime.fromtimestamp(val / 1e6, tz=timezone.utc)
        if val > 1e10:  # milliseconds
            return datetime.fromtimestamp(val / 1e3, tz=timezone.utc)
        return datetime.fromtimestamp(val, tz=timezone.utc)
    if isinstance(val, str):
        val = val.strip()
        try:
            return datetime.fromisoformat(val.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            pass
    return datetime.now(timezone.utc)


def normalize(raw: dict[str, Any], line_no: int | None = None) -> NormalizedEvent:
    from backend.mitre import mapping
    from backend.models import NormalizedEvent

    if line_no is not None and "_line_no" not in raw:
        raw["_line_no"] = line_no

    if raw.get("_format") == "fortigate":
        return normalize_fortigate(raw, line_no=line_no)

    # CEF normalization
    if "extension" in raw and "vendor" in raw:
        x = raw.get("extension", {})
        tid = (x.get("cs2") or "").split(",")[0].strip() or None
        technique_name, tactic = mapping(tid)

        rt_raw = x.get("rt")
        timestamp = _parse_timestamp(rt_raw) if rt_raw else datetime.now(timezone.utc)

        sev_str = str(raw.get("severity", "informational")).lower()
        event_kind = "alert" if sev_str not in ("0", "", "informational", "low") else "event"

        event_id = x.get("externalId") or (f"cef-{line_no}" if line_no else str(uuid4()))

        return NormalizedEvent(
            event_id=str(event_id),
            timestamp=timestamp,
            event_kind=event_kind,
            category=_text(x.get("cat")) or "unknown",
            action=_text(x.get("act") or raw.get("name")) or "unknown",
            severity=sev_str if sev_str in ("low", "medium", "high", "critical") else "informational",
            host=_text(x.get("dvchost")),
            user=_text(x.get("suser")),
            source_ip=_text(x.get("src")),
            destination_ip=_text(x.get("dst")),
            process_name=_text(x.get("dproc")),
            command_line=_text(x.get("cs1") if x.get("cs1Label") == "cmdline" else None),
            technique_id=tid,
            technique_name=technique_name,
            tactic=tactic,
            raw_event=raw,
        )

    # JSONL / ECS normalization
    event_dict = raw.get("event") if isinstance(raw.get("event"), dict) else {}
    host_dict = raw.get("host") if isinstance(raw.get("host"), dict) else {}
    user_dict = raw.get("user") if isinstance(raw.get("user"), dict) else {}
    proc_dict = raw.get("process") if isinstance(raw.get("process"), dict) else {}
    net_dict = raw.get("network") if isinstance(raw.get("network"), dict) else {}
    threat_dict = raw.get("threat") if isinstance(raw.get("threat"), dict) else {}

    # Extract MITRE technique ID
    tid = None
    if isinstance(threat_dict.get("technique"), dict):
        tech_id_field = threat_dict["technique"].get("id")
        if isinstance(tech_id_field, list) and tech_id_field:
            tid = str(tech_id_field[0])
        elif isinstance(tech_id_field, str):
            tid = tech_id_field
    if not tid and "technique_id" in raw:
        tid = str(raw["technique_id"])

    tname, tactic = mapping(tid)

    # Timestamp
    ts_raw = raw.get("@timestamp") or raw.get("timestamp") or event_dict.get("created")
    timestamp = _parse_timestamp(ts_raw)

    # Category
    cat_val = event_dict.get("category", raw.get("category", "unknown"))
    if isinstance(cat_val, list):
        category = str(cat_val[0]) if cat_val else "unknown"
    else:
        category = str(cat_val) if cat_val else "unknown"

    # Severity normalization
    sev_raw = event_dict.get("severity", raw.get("severity", "informational"))
    if isinstance(sev_raw, int):
        sev = SEVERITY_INT_MAP.get(sev_raw, "informational")
    else:
        s = str(sev_raw).lower()
        sev = s if s in ("low", "medium", "high", "critical", "informational") else "informational"

    # Domain
    dns_dict = raw.get("dns") if isinstance(raw.get("dns"), dict) else {}
    dns_q = dns_dict.get("question") if isinstance(dns_dict.get("question"), dict) else {}
    domain = dns_q.get("name")
    if not domain and isinstance(raw.get("destination"), dict):
        domain = raw["destination"].get("domain")
    if not domain:
        domain = raw.get("domain")

    # Host, user, process
    host = host_dict.get("name") or raw.get("host")
    user = user_dict.get("name") or raw.get("user")
    process_name = proc_dict.get("name") or raw.get("process_name")
    process_id = proc_dict.get("pid") or raw.get("process_id")

    parent_proc = None
    if isinstance(proc_dict.get("parent"), dict):
        parent_proc = proc_dict["parent"].get("name")
    if not parent_proc:
        parent_proc = raw.get("parent_process")

    cmdline = proc_dict.get("command_line") or raw.get("command_line")

    # Source & Destination IP
    src_ip = None
    if isinstance(raw.get("source"), dict):
        src_ip = raw["source"].get("ip")
    src_ip = src_ip or raw.get("source_ip") or net_dict.get("source_ip")

    dst_ip = None
    if isinstance(raw.get("destination"), dict):
        dst_ip = raw["destination"].get("ip")
    dst_ip = dst_ip or raw.get("destination_ip") or net_dict.get("destination_ip")

    # Event ID
    ev_id = event_dict.get("id") or raw.get("event_id")
    if not ev_id:
        ev_id = f"evt-{line_no}" if line_no else str(uuid4())

    return NormalizedEvent(
        event_id=str(ev_id),
        timestamp=timestamp,
        event_kind=str(event_dict.get("kind", raw.get("event_kind", "event"))),
        category=str(category).lower(),
        action=str(event_dict.get("action") or raw.get("action") or "unknown"),
        severity=sev,
        host=_text(host),
        source_ip=_text(src_ip),
        destination_ip=_text(dst_ip),
        user=_text(user),
        process_name=_text(process_name),
        process_id=_text(process_id),
        parent_process=_text(parent_proc),
        command_line=_text(cmdline),
        file_path=_text((raw.get("file") or {}).get("path") if isinstance(raw.get("file"), dict) else raw.get("file_path")),
        registry_path=_text((raw.get("registry") or {}).get("path") if isinstance(raw.get("registry"), dict) else raw.get("registry_path")),
        domain=_text(domain),
        technique_id=tid,
        technique_name=tname,
        tactic=tactic,
        raw_event=raw,
    )


def normalize_fortigate(raw: dict[str, Any], line_no: int | None = None) -> NormalizedEvent:
    from backend.mitre import mapping
    from backend.models import NormalizedEvent

    date = raw.get("date")
    clock = raw.get("time")
    tz = raw.get("tz", "+0000")

    try:
        timestamp = datetime.fromisoformat(f"{date}T{clock}{tz}")
    except (TypeError, ValueError):
        ev_time = raw.get("eventtime")
        if ev_time:
            try:
                timestamp = _parse_timestamp(int(ev_time))
            except (ValueError, TypeError):
                timestamp = datetime.now(timezone.utc)
        else:
            timestamp = datetime.now(timezone.utc)

    type_name = raw.get("type", "")
    subtype = raw.get("subtype", "")

    if type_name == "event" and raw.get("status") in {"failed", "success"}:
        category = "authentication"
    elif subtype == "ips":
        category = "intrusion"
    elif subtype == "virus":
        category = "malware"
    elif type_name in {"traffic", "utm"}:
        category = "network"
    else:
        category = type_name or "unknown"

    level = raw.get("level", "information").lower()
    severity = FORTI_SEVERITY_MAP.get(level, "informational")

    # Construct high-entropy event key to avoid collisions across identical flows
    key_parts = [
        str(raw.get(k, ""))
        for k in ("eventtime", "devid", "logid", "sessionid", "srcip", "srcport", "dstip", "dstport", "action", "user")
    ]
    if line_no is not None:
        key_parts.append(str(line_no))
    event_key = "|".join(key_parts)
    event_id = hashlib.sha256(event_key.encode()).hexdigest()[:32]

    action = raw.get("action", "unknown")
    event_kind = "alert" if severity in {"high", "critical"} or action in {"blocked", "dropped", "detected", "deny"} else "event"

    tid = None
    if category == "intrusion":
        tid = "T1190"
    elif category == "authentication" and raw.get("status") == "failed":
        tid = "T1110"
    elif "phishing" in str(raw.get("catdesc", "")).lower():
        tid = "T1566"

    tname, tactic = mapping(tid)

    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        event_kind=event_kind,
        category=category,
        action=action,
        severity=severity,
        host=_text(raw.get("devname") or raw.get("devid")),
        source_ip=_text(raw.get("srcip")),
        destination_ip=_text(raw.get("dstip")),
        user=_text(raw.get("user")),
        process_name=_text(raw.get("app")),
        process_id=_text(raw.get("sessionid")),
        command_line=_text(raw.get("msg") or raw.get("logdesc")),
        file_path=_text(raw.get("filename")),
        domain=_text(raw.get("hostname")),
        technique_id=tid,
        technique_name=tname,
        tactic=tactic,
        raw_event=raw,
    )
