from __future__ import annotations
from dataclasses import dataclass, field
from datetime import timedelta
import hashlib
from backend.models import Incident
from backend.risk.scoring import score_values

RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class IncidentState:
    incident_id: str
    first_observed: object
    last_observed: object
    hosts: set[str] = field(default_factory=set)
    users: set[str] = field(default_factory=set)
    techniques: set[str] = field(default_factory=set)
    tactics: set[str] = field(default_factory=set)
    reasons: set[str] = field(default_factory=set)
    event_ids: set[str] = field(default_factory=set)
    detection_count: int = 0
    confidence_total: float = 0
    highest_severity: str = "informational"

    def add(self, detection, event, reasons):
        self.first_observed = min(self.first_observed, event.timestamp)
        self.last_observed = max(self.last_observed, event.timestamp)
        if event.host:
            self.hosts.add(event.host)
        if event.user:
            self.users.add(event.user)
        if detection.technique_id:
            self.techniques.add(detection.technique_id)
        if detection.tactic:
            self.tactics.add(detection.tactic)
        self.reasons.update(reasons)
        self.event_ids.add(event.event_id)
        self.detection_count += 1
        self.confidence_total += detection.confidence
        if RANK.get(detection.severity, 0) > RANK.get(self.highest_severity, 0):
            self.highest_severity = detection.severity

    def model(self):
        confidence = round(self.confidence_total / max(1, self.detection_count), 2)
        result = Incident(
            incident_id=self.incident_id,
            first_observed=self.first_observed,
            last_observed=self.last_observed,
            hosts=sorted(self.hosts),
            users=sorted(self.users),
            event_count=len(self.event_ids),
            detection_count=self.detection_count,
            techniques=sorted(self.techniques),
            severity=self.highest_severity,
            confidence=confidence,
            correlation_reasons=sorted(self.reasons) or [
                "Single evidence-backed detection; not linked to unrelated activity"
            ],
        )
        result.risk_score, result.risk_label, result.risk_reasons = score_values(
            self.highest_severity, self.detection_count, len(self.tactics), confidence
        )
        return result


class StreamingCorrelator:
    """Correlate detections only through strong, time-bounded endpoint evidence."""

    def __init__(self, window_minutes=60, member_sink=None):
        self.window = timedelta(minutes=window_minutes)
        self.member_sink = member_sink
        self.states = {}
        self.index = {}
        self.last_seen = {}

    @staticmethod
    def _keys(event):
        keys = []
        # A host alone, public IP, user alone, or domain alone is not enough.
        if event.host and event.user:
            keys.append(("host_user", event.host.casefold(), event.user.casefold()))
        if event.host and event.process_id:
            keys.append(("host_process", event.host.casefold(), str(event.process_id)))
        if event.host and event.parent_process and event.process_name:
            keys.append((
                "host_process_lineage",
                event.host.casefold(),
                event.parent_process.casefold(),
                event.process_name.casefold(),
            ))
        return keys

    def add(self, detection, event):
        cutoff = event.timestamp - self.window
        # Prune stale keys so old activity cannot link new investigations.
        for key, (seen, _) in list(self.index.items()):
            if seen < cutoff:
                self.index.pop(key, None)

        candidates = {}
        for key in self._keys(event):
            active = self.index.get(key)
            if active and active[0] >= cutoff:
                candidates.setdefault(active[1], []).append(key)

        # If the evidence points to multiple incidents, do not arbitrarily merge them.
        incident_id = None
        if len(candidates) == 1:
            incident_id = next(iter(candidates))
        if incident_id is None:
            stable = hashlib.sha256(
                f"{event.event_id}|{detection.rule_id}".encode("utf-8")
            ).hexdigest()[:8].upper()
            incident_id = f"INC-{stable}"

        if incident_id not in self.states:
            self.states[incident_id] = IncidentState(
                incident_id, event.timestamp, event.timestamp
            )
        reasons = []
        if candidates.get(incident_id):
            reasons = ["Shared host and user/process evidence within correlation window"]
        state = self.states[incident_id]
        state.add(detection, event, reasons)
        if self.member_sink:
            self.member_sink(incident_id, event.event_id)

        for key in self._keys(event):
            self.index[key] = (event.timestamp, incident_id)
        return incident_id

    def incidents(self):
        return [state.model() for state in self.states.values()]


def correlate(events, detections, window_minutes=60):
    by_id = {event.event_id: event for event in events}
    members = []
    correlator = StreamingCorrelator(
        window_minutes,
        lambda incident_id, event_id: members.append((incident_id, event_id)),
    )
    ordered = sorted(
        detections,
        key=lambda item: (by_id[item.event_id].timestamp, item.event_id, item.rule_id),
    )
    for detection in ordered:
        event = by_id.get(detection.event_id)
        if event is not None:
            correlator.add(detection, event)
    results = correlator.incidents()
    for incident in results:
        incident.evidence_event_ids = sorted({
            event_id for candidate, event_id in members
            if candidate == incident.incident_id
        })
    return results
