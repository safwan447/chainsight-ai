from __future__ import annotations
import json
from collections import defaultdict, deque
from datetime import timedelta
from uuid import uuid4
from backend.config import RULES_PATH
from backend.mitre import mapping
from backend.models import Detection, NormalizedEvent

class DetectionEngine:
    def __init__(self, rule_path=RULES_PATH):
        self.rules=json.loads(rule_path.read_text(encoding="utf-8"))
        self.failed=defaultdict(deque)
    @staticmethod
    def _contains(text, needles): return bool(text) and any(n.lower() in text.lower() for n in needles)
    def detect(self, events: list[NormalizedEvent]) -> list[Detection]:
        self.failed.clear()
        return self.detect_batch(events)
    def detect_batch(self, events: list[NormalizedEvent]) -> list[Detection]:
        """Evaluate one bounded event batch while retaining compact auth-window state."""
        found=[]
        for event in events:
            outcome=event.raw_event.get("event",{}).get("outcome") if isinstance(event.raw_event.get("event"),dict) else None
            if event.category == "authentication" and (outcome == "failure" or event.raw_event.get("status") == "failed"):
                key=(event.host,event.user); failures=self.failed[key]; failures.append((event.timestamp,event.event_id))
                cutoff=event.timestamp-timedelta(minutes=15)
                while failures and failures[0][0]<cutoff: failures.popleft()
                if len(failures)>=5:
                    rule={"id":"CS-AUTH-001","name":"Repeated failed authentication","severity":"medium","technique_id":"T1110"}
                    found.append(self._alert(event,rule,min(0.95,0.55+len(failures)*.05),{"failed_attempts":len(failures),"window_minutes":15,"host":event.host,"user":event.user,"source_ip":event.source_ip}))
            for rule in self.rules:
                conf=rule["confidence"]; matches=True; config=rule.get("event",{})
                for key, expected in config.items():
                    actual=getattr(event,key,None)
                    values=expected if isinstance(expected,list) else [expected]
                    if not actual or not any(v.lower() in str(actual).lower() for v in values): matches=False
                if rule.get("contains") and not self._contains(event.command_line or "",rule["contains"]): matches=False
                if rule.get("parent_in") and not self._contains(event.parent_process or "",rule["parent_in"]): matches=False
                if rule.get("domain_contains") and not self._contains(event.domain or "",rule["domain_contains"]): matches=False
                if rule.get("registry_contains") and not self._contains(event.registry_path or "",rule["registry_contains"]): matches=False
                if rule.get("file_contains") and not self._contains(event.file_path or "",rule["file_contains"]): matches=False
                for field, needles in rule.get("raw_contains",{}).items():
                    if not self._contains(str(event.raw_event.get(field,"")),needles): matches=False
                if matches: found.append(self._alert(event,rule,conf))
        unique={ (d.event_id,d.rule_id):d for d in found }
        return list(unique.values())
    def _alert(self,event,rule,confidence,evidence=None):
        name,tactic=mapping(rule["technique_id"])
        return Detection(detection_id=str(uuid4()),event_id=event.event_id,rule_id=rule["id"],rule_name=rule["name"],severity=rule["severity"],technique_id=rule["technique_id"],technique_name=name or "Unknown",tactic=tactic or "Unknown",confidence=confidence,evidence=evidence or {"host":event.host,"user":event.user,"process":event.process_name,"command_line":event.command_line,"domain":event.domain,"registry_path":event.registry_path,"file_path":event.file_path})
