from __future__ import annotations
import json, shutil, time
from pathlib import Path
from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from backend.config import DATA_DIR, CHUNK_SIZE, ROOT
from backend.ingestion.reader import stream_lines
from backend.ingestion.parser import parse_line, normalize
from backend.ingestion.storage import Storage
from backend.detection.engine import DetectionEngine
from backend.correlation.correlator import correlate
from backend.graph.attack_graph import build_graph, reachability
from backend.reporting.incident_report import report

router=APIRouter(prefix="/api")
store=Storage(); status={"state":"idle","demo_data":False,"total_records":0,"valid_records":0,"invalid_records":0,"detections":0,"incidents":0,"duration_seconds":0,"throughput_eps":0,"last_file":None,"errors":[]}

def _severity_rank(value): return {"informational":0,"low":1,"medium":2,"high":3,"critical":4}.get(value,0)
def analyse_file(path: Path):
    global status
    start=time.perf_counter(); status.update({"state":"processing","demo_data":"synthetic" in path.name.lower() or path.name.lower().startswith("edr_"),"total_records":0,"valid_records":0,"invalid_records":0,"errors":[],"last_file":path.name})
    store.clear_all()
    buffer=[]
    for line_no,line in stream_lines(path):
        status["total_records"]+=1
        try: buffer.append(normalize(parse_line(line))); status["valid_records"]+=1
        except Exception as exc:
            status["invalid_records"]+=1
            if len(status["errors"])<10: status["errors"].append(f"Line {line_no}: {exc}")
        if len(buffer)>=CHUNK_SIZE: store.insert_events(buffer); buffer.clear()
    store.insert_events(buffer); events=store.events(); store.reset_analysis(); detections=DetectionEngine().detect(events); store.save_detections(detections); incidents=correlate(events,detections); store.save_incidents(incidents)
    elapsed=max(time.perf_counter()-start,.001); status.update({"state":"complete","detections":len(detections),"incidents":len(incidents),"duration_seconds":round(elapsed,3),"throughput_eps":round(status["total_records"]/elapsed,1)})
    return status

@router.get("/health")
def health(): return {"status":"ok","service":"ChainSight AI","offline":True}
@router.post("/ingest/upload")
async def upload(file: UploadFile=File(...)):
    safe=Path(file.filename or "upload.log").name; destination=DATA_DIR/safe
    with destination.open("wb") as out:
        while chunk:=await file.read(1024*1024): out.write(chunk)
    return {"file":safe,"bytes":destination.stat().st_size,"message":"Saved locally. Start processing with /api/ingest/process."}
@router.post("/ingest/process")
def process(filename: str | None=None, source_path: str | None=None):
    if source_path:
        candidate=Path(source_path).resolve()
        allowed=[DATA_DIR.resolve(), ROOT.parent.resolve()]
        if not candidate.is_file() or not any(candidate.is_relative_to(root) for root in allowed): raise HTTPException(400,"Source file must be a local file in data/ or Downloads/")
        candidates=[candidate]
    else:
        candidates=[DATA_DIR/filename] if filename else sorted([p for p in DATA_DIR.iterdir() if p.is_file() and p.suffix.lower() in {".json",".jsonl",".log",".cef",".txt"}],key=lambda p:p.stat().st_mtime,reverse=True)
    if not candidates or not candidates[0].exists(): raise HTTPException(404,"No compatible local log file found in data/")
    return analyse_file(candidates[0])
@router.get("/ingest/status")
def ingest_status(): return status
@router.get("/dashboard/summary")
def summary():
    events=store.events(); detections=store.detections(); incidents=store.incidents()
    return {"demo_data":status["demo_data"],"total_events":len(events),"suspicious_events":len({d.event_id for d in detections}),"active_incidents":len(incidents),"critical_incidents":sum(i.risk_label=="Critical" for i in incidents),"hosts_involved":len({e.host for e in events if e.host}),"severity_counts":{x:sum(d.severity==x for d in detections) for x in ["low","medium","high","critical"]},"recent_incidents":[i.model_dump(mode="json") for i in sorted(incidents,key=lambda i:i.last_observed,reverse=True)[:8]],"processing":status}
@router.get("/events")
def events(limit:int=200, offset:int=0, severity:str|None=None):
    values=store.events();
    if severity: values=[e for e in values if e.severity==severity]
    return {"total":len(values),"items":[e.model_dump(mode="json") for e in values[offset:offset+min(limit,1000)]]}
@router.get("/incidents")
def incidents(severity:str|None=None):
    values=store.incidents();
    if severity: values=[i for i in values if i.risk_label.lower()==severity.lower() or i.severity==severity.lower()]
    return {"items":[i.model_dump(mode="json") for i in sorted(values,key=lambda x:x.risk_score,reverse=True)]}
def incident_or_404(incident_id):
    for item in store.incidents():
        if item.incident_id==incident_id:return item
    raise HTTPException(404,"Incident not found")
def incident_data(incident):
    detections=store.detections(); ids=set(incident.evidence_event_ids); events=[e for e in store.events() if e.event_id in ids]
    selected=[d for d in detections if d.event_id in {e.event_id for e in events}]
    return events,selected
@router.get("/incidents/{incident_id}")
def incident(incident_id:str): return incident_or_404(incident_id).model_dump(mode="json")
@router.get("/incidents/{incident_id}/timeline")
def timeline(incident_id:str):
    values,_=incident_data(incident_or_404(incident_id)); return {"items":[e.model_dump(mode="json") for e in values]}
@router.get("/incidents/{incident_id}/graph")
def graph(incident_id:str):
    i=incident_or_404(incident_id); ev,ds=incident_data(i); return build_graph(i,ev,ds)
@router.get("/incidents/{incident_id}/reachability")
def reachable(incident_id:str):
    i=incident_or_404(incident_id); ev,ds=incident_data(i); return {"items":reachability(build_graph(i,ev,ds))}
@router.get("/mitre/techniques")
def techniques():
    ds=store.detections(); incidents=store.incidents(); output=[]
    for technique in sorted({d.technique_id for d in ds}):
        matches=[d for d in ds if d.technique_id==technique]; output.append({"technique_id":technique,"technique_name":matches[0].technique_name,"tactic":matches[0].tactic,"frequency":len(matches),"incident_count":sum(technique in i.techniques for i in incidents),"evidence":[d.evidence for d in matches[:3]]})
    return {"items":output}
@router.get("/reports/{incident_id}")
def get_report(incident_id:str, format:str="json"):
    i=incident_or_404(incident_id); events,detections=incident_data(i); graph=build_graph(i,events,detections); payload,html=report(i,events,detections,reachability(graph))
    return HTMLResponse(html) if format=="html" else JSONResponse(payload)
