import threading
import time
from pathlib import Path
from fastapi.testclient import TestClient
from backend.main import app
from backend.api.routes import store, ingestion_lock, current_status


def test_health_endpoint():
    client = TestClient(app)
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["offline"] is True
    assert data["status"] == "ok"


def test_missing_filename_is_rejected():
    """Ensure API does not silently pick an arbitrary file when arguments are missing."""
    client = TestClient(app)
    response = client.post("/api/ingest/process")
    assert response.status_code == 400
    assert "explicitly provided" in response.json()["detail"].lower()


def test_concurrent_ingestion_rejection():
    """Ensure a second ingestion request is rejected with 409 Conflict while another is running."""
    client = TestClient(app)
    acquired = ingestion_lock.acquire(blocking=False)
    assert acquired is True
    try:
        response = client.post("/api/ingest/process?filename=edr_events.json")
        assert response.status_code == 409
        assert "currently running" in response.json()["detail"].lower()
    finally:
        ingestion_lock.release()


def test_backend_restart_recovery(tmp_path):
    """Ensure a restart recovers any interrupted runs and sets their state to error/interrupted."""
    from backend.ingestion.storage import Storage

    test_db = tmp_path / "restart_test.duckdb"
    storage = Storage(test_db)
    storage.record_run("run-interrupted", {
        "job_id": "run-interrupted",
        "state": "processing",
        "stage": "parsing",
        "total_records": 500,
    })

    # Simulate backend restart by re-initializing storage on the database file
    restarted_storage = Storage(test_db)
    latest = restarted_storage.get_latest_run()
    assert latest is not None
    assert latest["state"] == "error"
    assert latest["stage"] == "interrupted"
    assert any("restart" in err.lower() for err in latest["errors"])
    restarted_storage.close()


def test_end_to_end_processing_and_dashboard_consistency(tmp_path):
    """End-to-end processing test validating counts, detections, incidents, and relationships."""
    client = TestClient(app)

    # Ingest synthetic edr_events.json
    response = client.post("/api/ingest/process?filename=edr_events.json")
    assert response.status_code == 200
    result = response.json()
    assert result["state"] == "complete"
    assert result["valid_records"] > 0
    assert result["detections"] > 0
    assert result["incidents"] > 0

    # Verify status endpoint reflects accurate metrics
    status_resp = client.get("/api/ingest/status")
    assert status_resp.status_code == 200
    status_data = status_resp.json()
    assert status_data["state"] == "complete"
    assert status_data["valid_records"] == result["valid_records"]
    assert status_data["detections"] == result["detections"]

    # Verify dashboard summary is consistent with processed run
    dash_resp = client.get("/api/dashboard/summary")
    assert dash_resp.status_code == 200
    dash_data = dash_resp.json()
    assert dash_data["total_events"] == result["stored_records"]
    assert dash_data["active_incidents"] == result["incidents"]
    assert dash_data["suspicious_events"] <= dash_data["total_events"]

    # Verify incident and timeline relationship integrity
    incidents_resp = client.get("/api/incidents")
    assert incidents_resp.status_code == 200
    inc_list = incidents_resp.json()["items"]
    assert len(inc_list) == result["incidents"]

    first_inc = inc_list[0]
    inc_id = first_inc["incident_id"]

    # Check incident timeline
    timeline_resp = client.get(f"/api/incidents/{inc_id}/timeline")
    assert timeline_resp.status_code == 200
    timeline_items = timeline_resp.json()["items"]
    assert len(timeline_items) > 0

    # Check incident graph
    graph_resp = client.get(f"/api/incidents/{inc_id}/graph")
    assert graph_resp.status_code == 200
    graph_data = graph_resp.json()
    assert len(graph_data["nodes"]) > 0
    assert len(graph_data["edges"]) > 0

    # Check reachability
    reach_resp = client.get(f"/api/incidents/{inc_id}/reachability")
    assert reach_resp.status_code == 200

    # Check report
    report_resp = client.get(f"/api/reports/{inc_id}?format=json")
    assert report_resp.status_code == 200
    report_json = report_resp.json()
    assert "incident" in report_json
    assert "timeline" in report_json
