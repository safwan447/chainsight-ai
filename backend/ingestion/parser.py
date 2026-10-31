from __future__ import annotations
import json, re, hashlib
from datetime import datetime, timezone
from uuid import uuid4
from typing import Any

CEF_PREFIX = re.compile(r"^CEF:\d+\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|(?P<version>[^|]*)\|(?P<signature>[^|]*)\|(?P<name>[^|]*)\|(?P<severity>[^|]*)\|(?P<extension>.*)$")
CEF_EXTENSION = re.compile(r"(?P<key>[A-Za-z][A-Za-z0-9]*)(?:=)(?P<value>.*?)(?=\s+[A-Za-z][A-Za-z0-9]*=|$)")
FORTI_PAIR = re.compile(r'(?P<key>[A-Za-z][A-Za-z0-9_]*)=(?:"(?P<quoted>[^"]*)"|(?P<plain>[^\s]+))')

def detect_format(sample: str) -> str:
    stripped=sample.lstrip()
    if stripped.startswith("CEF:"): return "cef"
    if stripped.startswith("{"): return "jsonl"
    if "date=" in stripped and "type=" in stripped: return "fortigate"
    return "jsonl"

def parse_line(line: str, source_format: str | None = None) -> dict[str, Any]:
    fmt = source_format or detect_format(line)
    if fmt == "jsonl":
        loaded = json.loads(line)
        return loaded.get("event", loaded) if isinstance(loaded.get("event"), dict) and "sourcetype" in loaded else loaded
    if fmt == "fortigate":
        values={match.group("key"): match.group("quoted") if match.group("quoted") is not None else match.group("plain") for match in FORTI_PAIR.finditer(line)}
        if not values or "date" not in values: raise ValueError("invalid FortiGate key/value record")
        values["_format"]="fortigate"
        return values
    match = CEF_PREFIX.match(line.strip())
    if not match: raise ValueError("invalid CEF record")
    value = match.groupdict(); ext = {m.group("key"): m.group("value") for m in CEF_EXTENSION.finditer(value.pop("extension"))}
    value["extension"] = ext
    return value

def _text(value: Any) -> str | None:
    return None if value is None else str(value)

def normalize(raw: dict[str, Any]):
    from backend.models import NormalizedEvent
    from backend.mitre import mapping
    if raw.get("_format") == "fortigate":
        return normalize_fortigate(raw)
    if "extension" in raw and "vendor" in raw:
        x = raw["extension"]; tid = (x.get("cs2") or "").split(",")[0] or None
        technique_name, tactic = mapping(tid)
        stamp = x.get("rt") or datetime.now(timezone.utc).isoformat()
        return NormalizedEvent(event_id=x.get("externalId") or str(uuid4()), timestamp=stamp, event_kind="alert" if raw.get("severity") not in ("0", "") else "event", category=x.get("cat", "unknown"), action=x.get("act", raw.get("name", "unknown")), severity=str(raw.get("severity", "informational")), host=x.get("dvchost"), user=x.get("suser"), source_ip=x.get("src"), destination_ip=x.get("dst"), process_name=x.get("dproc"), command_line=x.get("cs1") if x.get("cs1Label") == "cmdline" else None, technique_id=tid, technique_name=technique_name, tactic=tactic, raw_event=raw)
    event = raw.get("event", {}); host = raw.get("host", {}); user = raw.get("user", {}); proc = raw.get("process", {}); net = raw.get("network", {}); threat = raw.get("threat", {})
    techs = threat.get("technique", {}).get("id", []) if isinstance(threat.get("technique"), dict) else []
    tid = techs[0] if isinstance(techs, list) and techs else (techs if isinstance(techs, str) else None)
    tname, tactic = mapping(tid)
    timestamp = raw.get("@timestamp") or raw.get("timestamp") or datetime.now(timezone.utc).isoformat()
    category = event.get("category", raw.get("category", "unknown")); category = category[0] if isinstance(category, list) and category else category
    sev = event.get("severity", raw.get("severity", "informational")); sev = {1:"low",2:"low",3:"medium",4:"medium",5:"high",6:"high",7:"high",8:"critical",9:"critical",10:"critical"}.get(sev, str(sev).lower()) if isinstance(sev, int) else str(sev).lower()
    domain = raw.get("dns", {}).get("question", {}).get("name") if isinstance(raw.get("dns", {}).get("question"), dict) else None
    domain = domain or raw.get("destination", {}).get("domain") or raw.get("domain")
    return NormalizedEvent(event_id=_text(event.get("id") or raw.get("event_id") or uuid4()), timestamp=timestamp, event_kind=event.get("kind", raw.get("event_kind", "event")), category=_text(category) or "unknown", action=_text(event.get("action") or raw.get("action")) or "unknown", severity=sev, host=_text(host.get("name") or raw.get("host")), source_ip=_text(raw.get("source", {}).get("ip") or raw.get("source_ip") or net.get("source_ip")), destination_ip=_text(raw.get("destination", {}).get("ip") or raw.get("destination_ip") or net.get("destination_ip")), user=_text(user.get("name") or raw.get("user")), process_name=_text(proc.get("name") or raw.get("process_name")), process_id=_text(proc.get("pid") or raw.get("process_id")), parent_process=_text(proc.get("parent", {}).get("name") if isinstance(proc.get("parent"), dict) else proc.get("parent_process")), command_line=_text(proc.get("command_line") or raw.get("command_line")), file_path=_text(raw.get("file", {}).get("path") or raw.get("file_path")), registry_path=_text(raw.get("registry", {}).get("path") or raw.get("registry_path")), domain=_text(domain), technique_id=tid, technique_name=tname, tactic=tactic, raw_event=raw)

def normalize_fortigate(raw: dict[str, Any]):
    """Map FortiGate's space-delimited key/value export without losing fields."""
    from backend.models import NormalizedEvent
    date,clock,tz=raw.get("date"),raw.get("time"),raw.get("tz","+0000")
    try: timestamp=datetime.fromisoformat(f"{date}T{clock}{tz}")
    except (TypeError, ValueError): timestamp=datetime.now(timezone.utc)
    type_name, subtype=raw.get("type",""),raw.get("subtype","")
    category="authentication" if type_name=="event" and raw.get("status") in {"failed","success"} else "intrusion" if subtype=="ips" else "malware" if subtype=="virus" else "network" if type_name in {"traffic","utm"} else type_name or "unknown"
    severity={"emergency":"critical","alert":"critical","critical":"critical","error":"high","warning":"medium","notice":"low","information":"informational","debug":"informational"}.get(raw.get("level","information").lower(),"informational")
    event_key="|".join(str(raw.get(k,"")) for k in ("eventtime","devid","logid","sessionid","srcip","dstip","action","user"))
    return NormalizedEvent(event_id=hashlib.sha256(event_key.encode()).hexdigest()[:32],timestamp=timestamp,event_kind="alert" if severity in {"high","critical"} or raw.get("action") in {"blocked","dropped","detected","deny"} else "event",category=category,action=raw.get("action","unknown"),severity=severity,host=raw.get("devname") or raw.get("devid"),source_ip=raw.get("srcip"),destination_ip=raw.get("dstip"),user=raw.get("user"),process_name=raw.get("app"),process_id=raw.get("sessionid"),command_line=raw.get("msg") or raw.get("logdesc"),file_path=raw.get("filename"),domain=raw.get("hostname"),raw_event=raw)
