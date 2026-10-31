from __future__ import annotations

import hashlib
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable

from backend.config import CORRELATION_WINDOW_MINUTES
from backend.models import Detection, Incident, NormalizedEvent
from backend.risk.scoring import score_values

RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

GENERIC_IPS = {
    "0.0.0.0",
    "255.255.255.255",
    "127.0.0.1",
    "::1",
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "9.9.9.9",
    "149.112.112.112",
}

GENERIC_USERS = {
    "system",
    "nt authority\\system",
    "local service",
    "network service",
    "unknown",
    "-",
    "none",
}


@dataclass
class CorrelationEdge:
    source_det_id: str
    target_det_id: str
    reason: str
    confidence: float
    relationship_type: str


@dataclass
class IncidentState:
    incident_id: str
    first_observed: datetime
    last_observed: datetime
    hosts: set[str] = field(default_factory=set)
    users: set[str] = field(default_factory=set)
    techniques: set[str] = field(default_factory=set)
    tactics: set[str] = field(default_factory=set)
    reasons: list[str] = field(default_factory=list)
    detection_count: int = 0
    event_ids: set[str] = field(default_factory=set)
    confidence_total: float = 0.0
    highest_severity: str = "informational"

    def add(self, detection: Detection, event: NormalizedEvent, reasons: list[str]) -> None:
        if self.first_observed is None or event.timestamp < self.first_observed:
            self.first_observed = event.timestamp
        if self.last_observed is None or event.timestamp > self.last_observed:
            self.last_observed = event.timestamp

        if event.host:
            self.hosts.add(event.host)
        if event.user:
            self.users.add(event.user)
        if detection.technique_id:
            self.techniques.add(detection.technique_id)
        if detection.tactic and detection.tactic != "Unknown":
            self.tactics.add(detection.tactic)

        for r in reasons:
            if r not in self.reasons:
                self.reasons.append(r)

        self.event_ids.add(event.event_id)
        self.detection_count += 1
        self.confidence_total += detection.confidence

        if RANK.get(detection.severity, 0) > RANK.get(self.highest_severity, 0):
            self.highest_severity = detection.severity

    def model(self) -> Incident:
        avg_conf = round(self.confidence_total / max(1, self.detection_count), 2)
        correlation_reasons = (
            self.reasons
            if self.reasons
            else ["Single evidence-backed detection; no strong correlation link found (potential isolated activity)"]
        )
        incident = Incident(
            incident_id=self.incident_id,
            first_observed=self.first_observed or datetime.now(),
            last_observed=self.last_observed or datetime.now(),
            hosts=sorted(self.hosts),
            users=sorted(self.users),
            event_count=len(self.event_ids),
            detection_count=self.detection_count,
            techniques=sorted(self.techniques),
            evidence_event_ids=sorted(self.event_ids),
            severity=self.highest_severity,
            confidence=avg_conf,
            correlation_reasons=correlation_reasons,
        )
        incident.risk_score, incident.risk_label, incident.risk_reasons = score_values(
            self.highest_severity, self.detection_count, len(self.tactics), avg_conf
        )
        return incident


def _clean_proc(proc: str | None) -> str:
    if not proc:
        return ""
    base = proc.split("\\")[-1].split("/")[-1].lower()
    return base[:-4] if base.endswith(".exe") else base


class StreamingCorrelator:
    """Evidence-based attack path reconstructor.

    Detections are clustered based on strong causal links (process lineage, user sequential
    tactics, direct network pivot, shared malicious indicator). Host identity alone is treated as
    weak contextual similarity and NEVER merges unrelated incidents.
    """

    def __init__(
        self,
        window_minutes: int = CORRELATION_WINDOW_MINUTES,
        member_sink: Callable[[str, str], None] | None = None,
    ):
        self.window = timedelta(minutes=window_minutes)
        self.member_sink = member_sink
        # Active detections in window: detection_id -> (Detection, NormalizedEvent)
        self.active_detections: dict[str, tuple[Detection, NormalizedEvent]] = {}
        # Inverted index lookups to avoid O(N^2) scans across thousands of active detections
        self.by_host: dict[str, set[str]] = defaultdict(set)
        self.by_ip: dict[str, set[str]] = defaultdict(set)
        self.by_domain: dict[str, set[str]] = defaultdict(set)
        self.by_reg: dict[str, set[str]] = defaultdict(set)
        # Correlation graph adjacency: detection_id -> list of CorrelationEdge
        self.graph: dict[str, list[CorrelationEdge]] = defaultdict(list)
        # Sequence of detection arrival: deque of (timestamp, detection_id)
        self.arrival_queue: deque[tuple[datetime, str]] = deque()
        # All stored detections for final deterministic incident generation
        self.all_detections: list[tuple[Detection, NormalizedEvent]] = []

    def _expire(self, current_time: datetime) -> None:
        cutoff = current_time - self.window
        while self.arrival_queue and self.arrival_queue[0][0] < cutoff:
            _, old_det_id = self.arrival_queue.popleft()
            old_item = self.active_detections.pop(old_det_id, None)
            if old_item:
                _, old_ev = old_item
                if old_ev.host:
                    self.by_host[old_ev.host.lower()].discard(old_det_id)
                if old_ev.source_ip:
                    self.by_ip[old_ev.source_ip].discard(old_det_id)
                if old_ev.destination_ip:
                    self.by_ip[old_ev.destination_ip].discard(old_det_id)
                if old_ev.domain:
                    self.by_domain[old_ev.domain.lower()].discard(old_det_id)
                if old_ev.registry_path:
                    self.by_reg[old_ev.registry_path.lower()].discard(old_det_id)

    def _evaluate_link(
        self,
        det_a: Detection,
        event_a: NormalizedEvent,
        det_b: Detection,
        event_b: NormalizedEvent,
    ) -> CorrelationEdge | None:
        """Evaluate whether a STRONG correlation link exists between two detections."""
        time_diff = abs((event_b.timestamp - event_a.timestamp).total_seconds())
        if time_diff > self.window.total_seconds():
            return None

        # 1. Process Lineage on the same host (Strong)
        if event_a.host and event_b.host and event_a.host.lower() == event_b.host.lower():
            proc_a = _clean_proc(event_a.process_name)
            parent_a = _clean_proc(event_a.parent_process)
            proc_b = _clean_proc(event_b.process_name)
            parent_b = _clean_proc(event_b.parent_process)

            if proc_a and parent_b and proc_a == parent_b:
                return CorrelationEdge(
                    det_a.detection_id,
                    det_b.detection_id,
                    f"Direct process lineage on host {event_a.host}: parent '{event_a.process_name}' spawned '{event_b.process_name}'",
                    0.95,
                    "process_lineage",
                )
            if proc_b and parent_a and proc_b == parent_a:
                return CorrelationEdge(
                    det_a.detection_id,
                    det_b.detection_id,
                    f"Direct process lineage on host {event_a.host}: parent '{event_b.process_name}' spawned '{event_a.process_name}'",
                    0.95,
                    "process_lineage",
                )

        # 2. Direct Network Pivot / Lateral Movement (Strong)
        src_a, dst_a = event_a.source_ip, event_a.destination_ip
        src_b, dst_b = event_b.source_ip, event_b.destination_ip

        if src_a and dst_a and src_a not in GENERIC_IPS and dst_a not in GENERIC_IPS:
            # Host A connects to Host B, and Host B has a detection
            if dst_a == src_b:
                return CorrelationEdge(
                    det_a.detection_id,
                    det_b.detection_id,
                    f"Observed potential lateral movement network connection: {src_a} -> {dst_a}",
                    0.90,
                    "lateral_movement",
                )
            # Both detections on same specific connection session
            if src_a == src_b and dst_a == dst_b:
                return CorrelationEdge(
                    det_a.detection_id,
                    det_b.detection_id,
                    f"Shared network connection session between {src_a} and {dst_a}",
                    0.88,
                    "shared_network_session",
                )

        # 3. Same Host AND Same User Sequential Progression (Strong)
        user_a = (event_a.user or "").lower()
        user_b = (event_b.user or "").lower()
        host_a = (event_a.host or "").lower()
        host_b = (event_b.host or "").lower()

        if (
            host_a
            and host_a == host_b
            and user_a
            and user_b
            and user_a == user_b
            and user_a not in GENERIC_USERS
        ):
            # Check for progression or related distinct actions
            if det_a.rule_id != det_b.rule_id or det_a.tactic != det_b.tactic:
                minutes = max(1, int(time_diff / 60))
                return CorrelationEdge(
                    det_a.detection_id,
                    det_b.detection_id,
                    f"Sequential suspicious activity on host {event_a.host} by user {event_a.user}: {det_a.technique_name} ({det_a.tactic}) -> {det_b.technique_name} ({det_b.tactic}) within {minutes}m",
                    0.85,
                    "user_sequential_progression",
                )

        # 4. Shared Specific Malicious Indicator / Artifact (Strong)
        domain_a = (event_a.domain or "").lower()
        domain_b = (event_b.domain or "").lower()
        if domain_a and domain_a == domain_b and not any(g in domain_a for g in ("google.", "microsoft.", "windows")):
            return CorrelationEdge(
                det_a.detection_id,
                det_b.detection_id,
                f"Shared specific suspicious domain communication: {event_a.domain}",
                0.88,
                "shared_indicator",
            )

        reg_a = (event_a.registry_path or "").lower()
        reg_b = (event_b.registry_path or "").lower()
        if reg_a and reg_a == reg_b:
            return CorrelationEdge(
                det_a.detection_id,
                det_b.detection_id,
                f"Shared specific suspicious registry modification: {event_a.registry_path}",
                0.88,
                "shared_indicator",
            )

        return None

    def add(self, detection: Detection, event: NormalizedEvent) -> str:
        """Add a detection event, evaluate correlation against active sliding window, and return tentative incident ID."""
        self._expire(event.timestamp)
        self.all_detections.append((detection, event))

        # Query candidates using inverted indexes instead of scanning all active detections
        candidate_ids: set[str] = set()
        if event.host:
            candidate_ids.update(self.by_host.get(event.host.lower(), ()))
        if event.source_ip and event.source_ip not in GENERIC_IPS:
            candidate_ids.update(self.by_ip.get(event.source_ip, ()))
        if event.destination_ip and event.destination_ip not in GENERIC_IPS:
            candidate_ids.update(self.by_ip.get(event.destination_ip, ()))
        if event.domain:
            candidate_ids.update(self.by_domain.get(event.domain.lower(), ()))
        if event.registry_path:
            candidate_ids.update(self.by_reg.get(event.registry_path.lower(), ()))

        matched_incident_edges: list[CorrelationEdge] = []
        for other_id in candidate_ids:
            if other_id == detection.detection_id:
                continue
            other_pair = self.active_detections.get(other_id)
            if not other_pair:
                continue
            other_det, other_event = other_pair
            edge = self._evaluate_link(other_det, other_event, detection, event)
            if edge:
                self.graph[detection.detection_id].append(
                    CorrelationEdge(
                        source_det_id=detection.detection_id,
                        target_det_id=other_det.detection_id,
                        reason=edge.reason,
                        confidence=edge.confidence,
                        relationship_type=edge.relationship_type,
                    )
                )
                self.graph[other_det.detection_id].append(
                    CorrelationEdge(
                        source_det_id=other_det.detection_id,
                        target_det_id=detection.detection_id,
                        reason=edge.reason,
                        confidence=edge.confidence,
                        relationship_type=edge.relationship_type,
                    )
                )
                matched_incident_edges.append(edge)

        self.active_detections[detection.detection_id] = (detection, event)
        if event.host:
            self.by_host[event.host.lower()].add(detection.detection_id)
        if event.source_ip and event.source_ip not in GENERIC_IPS:
            self.by_ip[event.source_ip].add(detection.detection_id)
        if event.destination_ip and event.destination_ip not in GENERIC_IPS:
            self.by_ip[event.destination_ip].add(detection.detection_id)
        if event.domain:
            self.by_domain[event.domain.lower()].add(detection.detection_id)
        if event.registry_path:
            self.by_reg[event.registry_path.lower()].add(detection.detection_id)

        self.arrival_queue.append((event.timestamp, detection.detection_id))

        # Generate a deterministic incident ID tag based on detection or linked detections
        connected_ids = sorted(self._get_connected_component(detection.detection_id))
        key = "|".join(connected_ids)
        incident_id = f"INC-{hashlib.sha256(key.encode()).hexdigest()[:8].upper()}"

        if self.member_sink:
            self.member_sink(incident_id, event.event_id)

        return incident_id

    def _get_connected_component(self, start_id: str) -> set[str]:
        visited = set()
        queue = [start_id]
        while queue:
            curr = queue.pop()
            if curr in visited:
                continue
            visited.add(curr)
            for edge in self.graph.get(curr, []):
                if edge.target_det_id not in visited:
                    queue.append(edge.target_det_id)
        return visited

    def incidents(self) -> list[Incident]:
        """Compute the final deterministic, disjoint incidents from all correlated detections."""
        detection_lookup = {d.detection_id: (d, e) for d, e in self.all_detections}
        visited_det_ids: set[str] = set()
        incident_states: list[IncidentState] = []

        # Sort all detections deterministically by timestamp, then detection_id
        sorted_detections = sorted(
            self.all_detections,
            key=lambda item: (item[1].timestamp, item[0].detection_id),
        )

        for detection, event in sorted_detections:
            if detection.detection_id in visited_det_ids:
                continue

            component_det_ids = self._get_connected_component(detection.detection_id)
            visited_det_ids.update(component_det_ids)

            # Generate deterministic incident ID from sorted event IDs in component
            comp_events = [detection_lookup[did][1] for did in component_det_ids if did in detection_lookup]
            sorted_comp_event_ids = sorted({ev.event_id for ev in comp_events})
            id_hash = hashlib.sha256("|".join(sorted_comp_event_ids).encode()).hexdigest()[:8].upper()
            incident_id = f"INC-{id_hash}"

            state = IncidentState(
                incident_id=incident_id,
                first_observed=event.timestamp,
                last_observed=event.timestamp,
            )

            # Gather all correlation reasons in this component
            component_reasons = []
            for did in component_det_ids:
                for edge in self.graph.get(did, []):
                    if edge.reason not in component_reasons:
                        component_reasons.append(edge.reason)

            # Populate incident state with all detections in this component
            for did in sorted(component_det_ids):
                if did in detection_lookup:
                    d, e = detection_lookup[did]
                    state.add(d, e, component_reasons)

            incident_states.append(state)

        # Sort incidents by risk score descending, then last_observed descending
        incidents = [state.model() for state in incident_states]
        incidents.sort(key=lambda inc: (inc.risk_score, inc.last_observed), reverse=True)
        return incidents


def correlate(
    events: list[NormalizedEvent],
    detections: list[Detection],
    window_minutes: int = CORRELATION_WINDOW_MINUTES,
) -> list[Incident]:
    """Pure function correlation helper for batch or test workflows."""
    by_id = {event.event_id: event for event in events}
    members: list[tuple[str, str]] = []
    correlator = StreamingCorrelator(
        window_minutes=window_minutes,
        member_sink=lambda inc_id, ev_id: members.append((inc_id, ev_id)),
    )

    # Sort detections chronologically
    sorted_dets = sorted(
        [d for d in detections if d.event_id in by_id],
        key=lambda d: (by_id[d.event_id].timestamp, d.detection_id),
    )

    for detection in sorted_dets:
        correlator.add(detection, by_id[detection.event_id])

    results = correlator.incidents()
    # Ensure evidence_event_ids are populated accurately
    for inc in results:
        inc.evidence_event_ids = sorted(
            {event_id for cand_id, event_id in members if cand_id == inc.incident_id}
            or set(inc.evidence_event_ids)
        )
    return results
