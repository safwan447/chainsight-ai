from __future__ import annotations
from collections import deque
from dataclasses import dataclass, field
from datetime import timedelta
from uuid import uuid4
from backend.models import Incident
from backend.risk.scoring import score_values

RANK={"informational":0,"low":1,"medium":2,"high":3,"critical":4}

@dataclass
class IncidentState:
    incident_id: str
    first_observed: object
    last_observed: object
    hosts: set[str]=field(default_factory=set)
    users: set[str]=field(default_factory=set)
    techniques: set[str]=field(default_factory=set)
    tactics: set[str]=field(default_factory=set)
    reasons: set[str]=field(default_factory=set)
    detection_count: int=0
    event_count: int=0
    confidence_total: float=0
    highest_severity: str="informational"
    def add(self,detection,event,reasons):
        self.first_observed=min(self.first_observed,event.timestamp); self.last_observed=max(self.last_observed,event.timestamp)
        self.hosts.update(value for value in [event.host] if value); self.users.update(value for value in [event.user] if value)
        self.techniques.add(detection.technique_id); self.tactics.add(detection.tactic); self.reasons.update(reasons)
        self.detection_count+=1; self.confidence_total+=detection.confidence
        if RANK.get(detection.severity,0)>RANK.get(self.highest_severity,0): self.highest_severity=detection.severity
    def model(self):
        confidence=round(self.confidence_total/max(1,self.detection_count),2)
        result=Incident(incident_id=self.incident_id,first_observed=self.first_observed,last_observed=self.last_observed,hosts=sorted(self.hosts),users=sorted(self.users),event_count=self.event_count,detection_count=self.detection_count,techniques=sorted(self.techniques),severity=self.highest_severity,confidence=confidence,correlation_reasons=sorted(self.reasons) or ["Single evidence-backed detection; not linked to unrelated activity"])
        result.risk_score,result.risk_label,result.risk_reasons=score_values(self.highest_severity,self.detection_count,len(self.tactics),confidence)
        return result

class StreamingCorrelator:
    """Bounded-window correlation that stores event membership externally."""
    def __init__(self,window_minutes=60,member_sink=None):
        self.window=timedelta(minutes=window_minutes); self.member_sink=member_sink
        self.states={}; self.entity_index={}; self.expiry=deque(); self.last_event_id=None
    @staticmethod
    def entities(event):
        return [("host",event.host),("user",event.user),("source IP",event.source_ip),("destination IP",event.destination_ip),("domain",event.domain)]
    def _expire(self,timestamp):
        cutoff=timestamp-self.window
        while self.expiry and self.expiry[0][0]<cutoff:
            seen,entity,incident_id=self.expiry.popleft(); current=self.entity_index.get(entity)
            if current and current==(seen,incident_id): self.entity_index.pop(entity,None)
    def add(self,detection,event):
        self._expire(event.timestamp); matches=[]; reasons=[]
        for label,value in self.entities(event):
            if not value: continue
            active=self.entity_index.get(f"{label}:{value}")
            if active:
                matches.append(active[1]); reasons.append(f"Shared {label} within {int(self.window.total_seconds()/60)} minutes")
        incident_id=matches[0] if matches else "INC-"+str(uuid4())[:8].upper()
        if incident_id not in self.states:self.states[incident_id]=IncidentState(incident_id,event.timestamp,event.timestamp)
        state=self.states[incident_id]; state.add(detection,event,reasons)
        if self.last_event_id!=event.event_id: state.event_count+=1; self.last_event_id=event.event_id
        if self.member_sink:self.member_sink(incident_id,event.event_id)
        for label,value in self.entities(event):
            if value:
                entity=f"{label}:{value}"; self.entity_index[entity]=(event.timestamp,incident_id); self.expiry.append((event.timestamp,entity,incident_id))
        return incident_id
    def incidents(self): return [state.model() for state in self.states.values()]

def correlate(events,detections,window_minutes=60):
    by_id={event.event_id:event for event in events}; members=[]; correlator=StreamingCorrelator(window_minutes,lambda incident_id,event_id:members.append((incident_id,event_id)))
    for detection in sorted(detections,key=lambda item:by_id[item.event_id].timestamp):
        if detection.event_id in by_id:correlator.add(detection,by_id[detection.event_id])
    results=correlator.incidents()
    for incident in results:incident.evidence_event_ids=sorted(event_id for candidate,event_id in members if candidate==incident.incident_id)
    return results
