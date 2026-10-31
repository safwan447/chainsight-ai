from __future__ import annotations
from datetime import timedelta
from uuid import uuid4
from backend.models import Incident
from backend.risk.scoring import score

def correlate(events, detections, window_minutes=60):
    by_id={e.event_id:e for e in events}; annotated=[(d,by_id.get(d.event_id)) for d in detections if d.event_id in by_id]; annotated.sort(key=lambda x:x[1].timestamp)
    groups=[]
    for d,event in annotated:
        best=None; reasons=[]
        for group in groups:
            last=group[-1][1]
            if event.timestamp-last.timestamp > timedelta(minutes=window_minutes): continue
            shared=[]
            for label,a,b in [("host",event.host,last.host),("user",event.user,last.user),("source IP",event.source_ip,last.source_ip),("destination IP",event.destination_ip,last.destination_ip),("domain",event.domain,last.domain)]:
                if a and a==b: shared.append(label)
            if shared: best=group; reasons=shared; break
        if best is None: groups.append([(d,event,[])])
        else: best.append((d,event,reasons))
    incidents=[]
    for group in groups:
        ds=[x[0] for x in group]; es=[x[1] for x in group]; why=sorted({f"Shared {field} within {window_minutes} minutes" for _,_,fields in group for field in fields}) or ["Single evidence-backed detection; not linked to unrelated activity"]
        sev=max((d.severity for d in ds),key=lambda x:["informational","low","medium","high","critical"].index(x) if x in ["informational","low","medium","high","critical"] else 0)
        incident=Incident(incident_id="INC-"+str(uuid4())[:8].upper(),first_observed=min(e.timestamp for e in es),last_observed=max(e.timestamp for e in es),hosts=sorted({e.host for e in es if e.host}),users=sorted({e.user for e in es if e.user}),event_count=len(es),detection_count=len(ds),techniques=sorted({d.technique_id for d in ds}),evidence_event_ids=sorted({e.event_id for e in es}),severity=sev,confidence=round(sum(d.confidence for d in ds)/len(ds),2),correlation_reasons=why)
        incident.risk_score,incident.risk_label,incident.risk_reasons=score(incident,ds)
        incidents.append(incident)
    return incidents
