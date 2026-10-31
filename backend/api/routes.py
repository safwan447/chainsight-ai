from __future__ import annotations
import json, shutil, time, logging
from pathlib import Path
from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from backend.config import DATA_DIR, CHUNK_SIZE, ROOT
from backend.ingestion.reader import stream_lines
from backend.ingestion.parser import parse_line, normalize
from backend.ingestion.storage import Storage
from backend.detection.engine import DetectionEngine
from backend.correlation.correlator import StreamingCorrelator
from backend.graph.attack_graph import build_graph, reachability
from backend.reporting.incident_report import report

logger = logging.getLogger(__name__)
router=APIRouter(prefix="/api")
store=Storage(); status={"state":"idle","demo_data":False,"total_records":0,"valid_records":0,"invalid_records":0,"detections":0,"incidents":0,"duration_seconds":0,"throughput_eps":0,"last_file":None,"errors":[]}

def _severity_rank(value): return {"informational":0,"low":1,"medium":2,"high":3,"critical":4}.get(value,0)
def analyse_file(path: Path):
    global status
    start = time.perf_counter()
    status.update({
        "state": "processing",
        "demo_data": "synthetic" in path.name.lower() or path.name.lower().startswith("edr_"),
        "total_records": 0,
        "valid_records": 0,
        "invalid_records": 0,
        "detections": 0,
        "incidents": 0,
        "duration_seconds": 0,
        "throughput_eps": 0,
        "errors": [],
        "last_file": path.name,
    })
    snapshot_created = False
    try:
        store.snapshot_current_run()
        snapshot_created = True
        store.clear_all()
        buffer = []
        for line_no, line in stream_lines(path):
            status["total_records"] += 1
            try:
                buffer.append(normalize(parse_line(line)))
                status["valid_records"] += 1
            except Exception as exc:
                status["invalid_records"] += 1
                if len(status["errors"]) < 10:
                    status["errors"].append(f"Line {line_no}: {type(exc).__name__}")
            if len(buffer) >= CHUNK_SIZE:
                store.insert_events(buffer)
                buffer.clear()

        store.insert_events(buffer)
        store.reset_analysis()
        engine = DetectionEngine()
        detection_count = 0
        for event_batch in store.iter_events(CHUNK_SIZE):
            detections = engine.detect_batch(event_batch)
            store.save_detections(detections)
            detection_count += len(detections)

        correlator = StreamingCorrelator()
        for detected_batch in store.iter_detection_events(CHUNK_SIZE):
            members = []
            for detection, event in detected_batch:
                incident_id = correlator.add(detection, event)
                if incident_id:
                    members.append((incident_id, event.event_id))
            store.add_incident_events(members)

        incidents = correlator.incidents()
        store.save_incidents(incidents)
        elapsed = max(time.perf_counter() - start, 0.001)
        store.discard_current_run_snapshot()
        status.update({
            "state": "complete",
            "detections": detection_count,
            "incidents": len(incidents),
            "duration_seconds": round(elapsed, 3),
            "throughput_eps": round(status["total_records"] / elapsed, 1),
        })
        return status
    except Exception as exc:
        if snapshot_created:
            try:
                store.restore_current_run()
            except Exception:
                logger.exception("Failed to restore previous investigation after processing error")
        elapsed = max(time.perf_counter() - start, 0.001)
        logger.exception("Ingestion processing failed for %s", path.name)
        status.update({
            "state": "error",
            "duration_seconds": round(elapsed, 3),
            "throughput_eps": round(status["total_records"] / elapsed, 1),
            "errors": (status.get("errors", []) + [f"Processing failed: {type(exc).__name__}"])[:10],
        })
        raise HTTPException(
            status_code=500,
            detail="Processing failed. Check /api/ingest/status for the error summary.",
        ) from exc

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
    incidents=store.incidents(); counts=store.dashboard_counts(); severity_counts={x:counts["severity_counts"].get(x,0) for x in ["low","medium","high","critical"]}
    return {"demo_data":status["demo_data"],**counts,"active_incidents":len(incidents),"critical_incidents":sum(i.risk_label=="Critical" for i in incidents),"severity_counts":severity_counts,"recent_incidents":[i.model_dump(mode="json") for i in sorted(incidents,key=lambda i:i.last_observed,reverse=True)[:8]],"processing":status}
@router.get("/events")
def events(limit:int=200, offset:int=0, severity:str|None=None):
    total,values=store.event_page(min(limit,1000),offset,severity)
    return {"total":total,"items":[e.model_dump(mode="json") for e in values]}
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
    return store.events_for_incident(incident.incident_id),store.detections_for_incident(incident.incident_id)
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
    return {"items":store.mitre_summary()}
@router.get("/reports/{incident_id}")
def get_report(incident_id:str, format:str="json"):
    i=incident_or_404(incident_id); events,detections=incident_data(i); graph=build_graph(i,events,detections); payload,html=report(i,events,detections,reachability(graph))
    return HTMLResponse(html) if format=="html" else JSONResponse(payload)
