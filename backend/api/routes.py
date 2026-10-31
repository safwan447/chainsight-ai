from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse

from backend.config import CHUNK_SIZE, CORRELATION_WINDOW_MINUTES, DATA_DIR, ROOT
from backend.correlation.disk_backed import DiskBackedStreamingCorrelator
from backend.detection.engine import DetectionEngine
from backend.graph.attack_graph import build_graph, reachability
from backend.ingestion.parser import detect_format, normalize, parse_line
from backend.ingestion.reader import stream_lines
from backend.ingestion.storage import Storage
from backend.reporting.incident_report import report

router = APIRouter(prefix="/api")
store = Storage()

# Ingestion state and concurrency lock
ingestion_lock = threading.Lock()
cancel_requested = threading.Event()

current_status: dict[str, Any] = {
    "job_id": None,
    "state": "idle",
    "stage": "idle",
    "demo_data": False,
    "total_records": 0,
    "valid_records": 0,
    "invalid_records": 0,
    "duplicate_records": 0,
    "stored_records": 0,
    "detections": 0,
    "incidents": 0,
    "duration_seconds": 0.0,
    "throughput_eps": 0.0,
    "last_file": None,
    "source_path": None,
    "started_at": None,
    "completed_at": None,
    "errors": [],
}


def _reset_status_for_new_job(file_path: Path) -> str:
    global current_status
    job_id = str(uuid4())
    cancel_requested.clear()
    is_demo = "synthetic" in file_path.name.lower() or file_path.name.lower().startswith("edr_")

    current_status = {
        "job_id": job_id,
        "state": "processing",
        "stage": "starting",
        "demo_data": is_demo,
        "total_records": 0,
        "valid_records": 0,
        "invalid_records": 0,
        "duplicate_records": 0,
        "stored_records": 0,
        "detections": 0,
        "incidents": 0,
        "duration_seconds": 0.0,
        "throughput_eps": 0.0,
        "last_file": file_path.name,
        "source_path": str(file_path.resolve()),
        "started_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
        "errors": [],
    }
    store.record_run(job_id, current_status)
    return job_id


def analyse_file(path: Path) -> dict[str, Any]:
    """Execute the complete streaming log ingestion, detection, and correlation pipeline."""
    global current_status

    if not ingestion_lock.acquire(blocking=False):
        raise HTTPException(
            status_code=409,
            detail="An ingestion job is currently running. Please wait for it to complete or cancel it.",
        )

    try:
        job_id = _reset_status_for_new_job(path)
        start_time = time.perf_counter()

        # Fresh start for this investigation
        store.clear_all()

        current_status["state"] = "processing"
        current_status["stage"] = "parsing"
        store.update_run(job_id, {"stage": "parsing"})

        # Initialize detection engine and correlator
        engine = DetectionEngine()
        correlator = DiskBackedStreamingCorrelator(window_minutes=CORRELATION_WINDOW_MINUTES, temp_dir=DATA_DIR)

        event_buffer = []
        detection_buffer = []
        # Event IDs are tracked in the correlator's temporary disk database, not a RAM set.
        source_format: str | None = None
        total_detections = 0

        # 1. Stream file records in buffered chunks
        for line_no, line in stream_lines(path):
            if cancel_requested.is_set():
                current_status.update({
                    "state": "cancelled",
                    "stage": "cancelled",
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                })
                store.update_run(job_id, current_status)
                return current_status

            current_status["total_records"] += 1

            # Detect format once on first line to eliminate per-line format overhead
            if source_format is None:
                source_format = detect_format(line)

            try:
                raw_record = parse_line(line, source_format=source_format)
                event = normalize(raw_record, line_no=line_no)

                # Ensure event_id uniqueness to prevent primary key collisions while preserving identity
                original_id = event.event_id
                if correlator.has_event_id(original_id):
                    current_status["duplicate_records"] += 1
                    # Keep duplicate rows without overwriting the first event, but remember original identity.
                    event.raw_event["_original_event_id"] = original_id
                    event.event_id = f"{original_id}#dup{line_no}"
                else:
                    correlator.remember_event_id(original_id)
                event_buffer.append(event)
                current_status["valid_records"] += 1

            except Exception as exc:
                current_status["invalid_records"] += 1
                if len(current_status["errors"]) < 10:
                    current_status["errors"].append(f"Line {line_no}: {exc}")

            # Process chunk through detection and storage
            if len(event_buffer) >= CHUNK_SIZE:
                # Run detection on this in-memory chunk
                current_status["stage"] = "detecting"
                batch_detections = engine.detect_batch(event_buffer)
                event_map = {e.event_id: e for e in event_buffer}

                for det in batch_detections:
                    detection_buffer.append(det)
                    matching_event = event_map.get(det.event_id)
                    if matching_event:
                        inc_id = correlator.add(det, matching_event)

                total_detections += len(batch_detections)
                current_status["detections"] = total_detections

                # Bulk insert events and detections into DuckDB
                current_status["stage"] = "storing"
                stored, _ = store.insert_events(event_buffer)
                current_status["stored_records"] += stored

                if detection_buffer:
                    store.save_detections(detection_buffer)
                    detection_buffer.clear()

                event_buffer.clear()
                current_status["stage"] = "parsing"

                # Update live throughput
                elapsed = max(time.perf_counter() - start_time, 0.001)
                current_status["duration_seconds"] = round(elapsed, 3)
                current_status["throughput_eps"] = round(current_status["valid_records"] / elapsed, 1)

        # Flush final remaining buffer
        if event_buffer:
            current_status["stage"] = "detecting"
            batch_detections = engine.detect_batch(event_buffer)
            event_map = {e.event_id: e for e in event_buffer}

            for det in batch_detections:
                detection_buffer.append(det)
                matching_event = event_map.get(det.event_id)
                if matching_event:
                    inc_id = correlator.add(det, matching_event)

            total_detections += len(batch_detections)
            current_status["detections"] = total_detections

            current_status["stage"] = "storing"
            stored, _ = store.insert_events(event_buffer)
            current_status["stored_records"] += stored

            if detection_buffer:
                store.save_detections(detection_buffer)
                detection_buffer.clear()

            event_buffer.clear()

        # 2. Correlate into final attack path incidents
        current_status["stage"] = "correlating"
        store.update_run(job_id, {"stage": "correlating"})

        incidents = correlator.incidents()
        current_status["incidents"] = len(incidents)

        # 3. Save final incidents and relationship mappings
        current_status["stage"] = "saving_results"
        store.save_incidents(incidents)

        # Map each event in each incident's evidence_event_ids to the final incident_id
        member_batch: list[tuple[str, str]] = []
        for inc in incidents:
            for ev_id in inc.evidence_event_ids:
                member_batch.append((inc.incident_id, ev_id))
                if len(member_batch) >= CHUNK_SIZE:
                    store.add_incident_events(member_batch)
                    member_batch.clear()
        if member_batch:
            store.add_incident_events(member_batch)

        # 4. Finalize metrics
        elapsed = max(time.perf_counter() - start_time, 0.001)
        current_status.update({
            "state": "complete",
            "stage": "complete",
            "duration_seconds": round(elapsed, 3),
            "throughput_eps": round(current_status["valid_records"] / elapsed, 1),
            "completed_at": datetime.now(timezone.utc).isoformat(),
        })
        store.record_run(job_id, current_status)
        return current_status

    except Exception as exc:
        current_status.update({
            "state": "error",
            "stage": "error",
            "errors": current_status.get("errors", []) + [str(exc)],
            "completed_at": datetime.now(timezone.utc).isoformat(),
        })
        if current_status.get("job_id"):
            store.record_run(current_status["job_id"], current_status)
        raise

    finally:
        if 'correlator' in locals() and correlator is not None:
            correlator.close()
        ingestion_lock.release()


# --------------------------------------------------
# HEALTH
# --------------------------------------------------

@router.get("/health")
def health():
    return {
        "status": "ok",
        "service": "ChainSight AI",
        "offline": True,
    }


# --------------------------------------------------
# LOG UPLOAD
# --------------------------------------------------

@router.post("/ingest/upload")
async def upload(file: UploadFile = File(...)):
    safe_name = Path(file.filename or "upload.log").name
    destination = DATA_DIR / safe_name

    try:
        with destination.open("wb") as out:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                out.write(chunk)
    finally:
        await file.close()

    return {
        "file": safe_name,
        "bytes": destination.stat().st_size,
        "message": "Saved locally. Start processing with /api/ingest/process.",
    }


# --------------------------------------------------
# PROCESS LOG FILE
# --------------------------------------------------

@router.post("/ingest/process")
def process(
    filename: str | None = None,
    source_path: str | None = None,
    background: bool = False,
):
    if not filename and not source_path:
        raise HTTPException(
            status_code=400,
            detail="Filename or source_path must be explicitly provided. Automatic file selection is disabled to prevent processing unintended datasets.",
        )

    if source_path:
        candidate = Path(source_path).resolve()
        allowed_roots = [
            DATA_DIR.resolve(),
            ROOT.resolve(),
            ROOT.parent.resolve(),
            Path.home() / "Downloads",
        ]
        if not candidate.is_file() or not any(candidate.is_relative_to(root) for root in allowed_roots):
            raise HTTPException(
                status_code=400,
                detail=f"Source file must be an existing regular file inside data/ or Downloads/. Provided: {source_path}",
            )
    else:
        # filename is explicitly specified
        safe_name = Path(filename).name
        candidate = DATA_DIR / safe_name
        if not candidate.is_file():
            raise HTTPException(
                status_code=404,
                detail=f"Requested log file was not found in data directory: {safe_name}",
            )

    if background:
        # Check if already locked before launching thread
        if ingestion_lock.locked():
            raise HTTPException(
                status_code=409,
                detail="An ingestion job is currently running. Please wait for it to complete or cancel it.",
            )
        thread = threading.Thread(target=analyse_file, args=(candidate,), daemon=True)
        thread.start()
        # Brief yield to let thread acquire lock and set starting stage
        time.sleep(0.05)
        return current_status

    return analyse_file(candidate)


# --------------------------------------------------
# CANCELLATION
# --------------------------------------------------

@router.post("/ingest/cancel")
def cancel_ingest():
    if current_status.get("state") == "processing":
        cancel_requested.set()
        return {"status": "cancelling", "message": "Cancellation requested for running job."}
    return {"status": "ignored", "message": "No active ingestion job to cancel."}


# --------------------------------------------------
# INGESTION STATUS
# --------------------------------------------------

@router.get("/ingest/status")
def ingest_status():
    return current_status


# --------------------------------------------------
# DASHBOARD SUMMARY
# --------------------------------------------------

@router.get("/dashboard/summary")
def summary():
    incidents = store.incidents()
    counts = store.dashboard_counts()

    severity_counts = {
        severity: counts["severity_counts"].get(severity, 0)
        for severity in ["low", "medium", "high", "critical"]
    }

    recent_incidents = sorted(
        incidents,
        key=lambda incident: incident.last_observed,
        reverse=True,
    )[:8]

    return {
        "demo_data": current_status["demo_data"],
        **counts,
        "active_incidents": len(incidents),
        "critical_incidents": sum(incident.risk_label == "Critical" for incident in incidents),
        "severity_counts": severity_counts,
        "recent_incidents": [incident.model_dump(mode="json") for incident in recent_incidents],
        "processing": current_status,
    }


# --------------------------------------------------
# EVENTS
# --------------------------------------------------

@router.get("/events")
def events(
    limit: int = 200,
    offset: int = 0,
    severity: str | None = None,
):
    total, values = store.event_page(min(limit, 1000), offset, severity)
    return {
        "total": total,
        "items": [event.model_dump(mode="json") for event in values],
    }


# --------------------------------------------------
# INCIDENTS
# --------------------------------------------------

@router.get("/incidents")
def incidents(severity: str | None = None):
    values = store.incidents()
    if severity:
        values = [
            incident
            for incident in values
            if (incident.risk_label.lower() == severity.lower() or incident.severity == severity.lower())
        ]

    values.sort(key=lambda incident: incident.risk_score, reverse=True)
    return {"items": [incident.model_dump(mode="json") for incident in values]}


def incident_or_404(incident_id: str):
    for item in store.incidents():
        if item.incident_id == incident_id:
            return item
    raise HTTPException(status_code=404, detail="Incident not found")


def incident_data(incident):
    return (
        store.events_for_incident(incident.incident_id),
        store.detections_for_incident(incident.incident_id),
    )


@router.get("/incidents/{incident_id}")
def incident(incident_id: str):
    return incident_or_404(incident_id).model_dump(mode="json")


# --------------------------------------------------
# INCIDENT TIMELINE
# --------------------------------------------------

@router.get("/incidents/{incident_id}/timeline")
def timeline(incident_id: str):
    values, _ = incident_data(incident_or_404(incident_id))
    return {"items": [event.model_dump(mode="json") for event in values]}


# --------------------------------------------------
# ATTACK GRAPH
# --------------------------------------------------

@router.get("/incidents/{incident_id}/graph")
def graph(incident_id: str):
    item = incident_or_404(incident_id)
    evts, dets = incident_data(item)
    return build_graph(item, evts, dets)


# --------------------------------------------------
# REACHABILITY
# --------------------------------------------------

@router.get("/incidents/{incident_id}/reachability")
def reachable(incident_id: str):
    item = incident_or_404(incident_id)
    evts, dets = incident_data(item)
    attack_graph = build_graph(item, evts, dets)
    return {"items": reachability(attack_graph)}


# --------------------------------------------------
# MITRE ATT&CK TECHNIQUES
# --------------------------------------------------

@router.get("/mitre/techniques")
def techniques():
    return {"items": store.mitre_summary()}


# --------------------------------------------------
# INCIDENT REPORTS
# --------------------------------------------------

@router.get("/reports/{incident_id}")
def get_report(incident_id: str, format: str = "json"):
    item = incident_or_404(incident_id)
    evts, dets = incident_data(item)
    attack_graph = build_graph(item, evts, dets)
    payload, html = report(item, evts, dets, reachability(attack_graph))

    if format.lower() == "html":
        return HTMLResponse(html)
    return JSONResponse(payload)
