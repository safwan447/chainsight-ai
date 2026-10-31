from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import duckdb
from backend.config import DB_PATH, DUCKDB_MEMORY_LIMIT, DUCKDB_THREADS, DUCKDB_TEMP_DIR
from backend.models import Detection, Incident, NormalizedEvent

EVENT_COLUMNS = [
    "event_id", "timestamp", "event_kind", "category", "action", "severity",
    "host", "source_ip", "destination_ip", "user", "process_name", "process_id",
    "parent_process", "command_line", "file_path", "registry_path", "domain",
    "technique_id", "technique_name", "tactic", "raw_event",
]


class Storage:
    """Thread-safe persistent DuckDB storage with bounded engine memory."""

    def __init__(self, path: Path = DB_PATH):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        DUCKDB_TEMP_DIR.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._db: duckdb.DuckDBPyConnection | None = None
        self.initialize()
        self._repair_detection_schema()
        self.recover_interrupted_runs()

    def get_connection(self) -> duckdb.DuckDBPyConnection:
        with self._lock:
            if self._db is None:
                self._db = duckdb.connect(str(self.path))
                memory_limit = DUCKDB_MEMORY_LIMIT.replace("'", "''")
                temp_path = str(DUCKDB_TEMP_DIR.resolve()).replace("'", "''")
                self._db.execute(f"SET memory_limit = '{memory_limit}'")
                self._db.execute(f"SET threads = {DUCKDB_THREADS}")
                self._db.execute(f"SET temp_directory = '{temp_path}'")
            return self._db

    def close(self) -> None:
        with self._lock:
            if self._db is not None:
                try:
                    self._db.close()
                except Exception:
                    pass
                self._db = None

    def initialize(self) -> None:
        with self._lock:
            db = self.get_connection()
            db.execute(
                "CREATE TABLE IF NOT EXISTS events ("
                "event_id VARCHAR PRIMARY KEY, timestamp TIMESTAMP, event_kind VARCHAR, "
                "category VARCHAR, action VARCHAR, severity VARCHAR, host VARCHAR, "
                "source_ip VARCHAR, destination_ip VARCHAR, user_name VARCHAR, "
                "process_name VARCHAR, process_id VARCHAR, parent_process VARCHAR, "
                "command_line VARCHAR, file_path VARCHAR, registry_path VARCHAR, "
                "domain VARCHAR, technique_id VARCHAR, technique_name VARCHAR, "
                "tactic VARCHAR, raw_event JSON)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS detections ("
                "detection_id VARCHAR PRIMARY KEY, event_id VARCHAR, rule_id VARCHAR, "
                "rule_name VARCHAR, severity VARCHAR, technique_id VARCHAR, "
                "technique_name VARCHAR, tactic VARCHAR, confidence DOUBLE, evidence JSON)"
            )
            db.execute("CREATE TABLE IF NOT EXISTS incidents (incident_id VARCHAR PRIMARY KEY, payload JSON)")
            db.execute(
                "CREATE TABLE IF NOT EXISTS incident_events ("
                "incident_id VARCHAR, event_id VARCHAR, PRIMARY KEY (incident_id, event_id))"
            )
            db.execute("CREATE TABLE IF NOT EXISTS ingestion_runs (run_id VARCHAR PRIMARY KEY, payload JSON)")
            try:
                db.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
                db.execute("CREATE INDEX IF NOT EXISTS idx_detections_event_id ON detections(event_id)")
                db.execute("CREATE INDEX IF NOT EXISTS idx_incident_events_incident_id ON incident_events(incident_id)")
                db.execute("CREATE INDEX IF NOT EXISTS idx_incident_events_event_id ON incident_events(event_id)")
            except Exception:
                pass

    def _repair_detection_schema(self) -> None:
        with self._lock:
            db = self.get_connection()
            columns = {row[1] for row in db.execute("PRAGMA table_info('detections')").fetchall()}
            if "rule_name" not in columns and "rule_nameVARCHAR" in columns:
                db.execute("ALTER TABLE detections RENAME COLUMN rule_nameVARCHAR TO rule_name")

    def recover_interrupted_runs(self) -> None:
        with self._lock:
            db = self.get_connection()
            rows = db.execute("SELECT run_id, payload FROM ingestion_runs").fetchall()
            for run_id, payload_raw in rows:
                payload = json.loads(payload_raw) if isinstance(payload_raw, str) else payload_raw
                if payload.get("state") in ("processing", "parsing", "storing", "detecting", "correlating", "starting"):
                    payload["state"] = "error"
                    payload["stage"] = "interrupted"
                    payload["errors"] = payload.get("errors", []) + ["Job interrupted by backend restart"]
                    payload["completed_at"] = datetime.now(timezone.utc).isoformat()
                    db.execute("UPDATE ingestion_runs SET payload = ? WHERE run_id = ?", [json.dumps(payload), run_id])

    def record_run(self, run_id: str, payload: dict[str, Any]) -> None:
        with self._lock:
            self.get_connection().execute(
                "INSERT OR REPLACE INTO ingestion_runs VALUES (?, ?)",
                [run_id, json.dumps(payload, default=str)],
            )

    def update_run(self, run_id: str, updates: dict[str, Any]) -> None:
        with self._lock:
            db = self.get_connection()
            row = db.execute("SELECT payload FROM ingestion_runs WHERE run_id = ?", [run_id]).fetchone()
            if row:
                payload = json.loads(row[0]) if isinstance(row[0], str) else row[0]
                payload.update(updates)
                db.execute("UPDATE ingestion_runs SET payload = ? WHERE run_id = ?", [json.dumps(payload, default=str), run_id])

    def get_latest_run(self) -> dict[str, Any] | None:
        with self._lock:
            rows = self.get_connection().execute("SELECT payload FROM ingestion_runs ORDER BY rowid DESC LIMIT 1").fetchall()
            if rows:
                value = rows[0][0]
                return json.loads(value) if isinstance(value, str) else value
            return None

    def reset_analysis(self) -> None:
        with self._lock:
            db = self.get_connection()
            db.execute("BEGIN TRANSACTION")
            try:
                db.execute("DELETE FROM detections")
                db.execute("DELETE FROM incidents")
                db.execute("DELETE FROM incident_events")
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise

    def clear_all(self) -> None:
        with self._lock:
            db = self.get_connection()
            db.execute("BEGIN TRANSACTION")
            try:
                db.execute("DELETE FROM events")
                db.execute("DELETE FROM detections")
                db.execute("DELETE FROM incidents")
                db.execute("DELETE FROM incident_events")
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise

    def insert_events(self, events: list[NormalizedEvent]) -> tuple[int, int]:
        if not events:
            return 0, 0
        rows = []
        with self._lock:
            db = self.get_connection()
            for e in events:
                rows.append((
                    e.event_id, e.timestamp, e.event_kind, e.category, e.action, e.severity,
                    e.host, e.source_ip, e.destination_ip, e.user, e.process_name, e.process_id,
                    e.parent_process, e.command_line, e.file_path, e.registry_path, e.domain,
                    e.technique_id, e.technique_name, e.tactic, json.dumps(e.raw_event, default=str),
                ))
            try:
                app = db.appender("events")
                app.append_rows(rows)
                app.flush()
            except Exception:
                db.execute("BEGIN TRANSACTION")
                try:
                    db.executemany("INSERT OR REPLACE INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
                    db.execute("COMMIT")
                except Exception:
                    db.execute("ROLLBACK")
                    raise
        return len(rows), 0

    @staticmethod
    def _event_from_row(row: tuple[Any, ...]) -> NormalizedEvent:
        raw_val = row[20]
        parsed_raw = json.loads(raw_val) if isinstance(raw_val, str) else raw_val
        values = list(row[:9]) + [row[9]] + list(row[10:20]) + [parsed_raw or {}]
        return NormalizedEvent(**dict(zip(EVENT_COLUMNS, values)))

    def iter_events(self, batch_size: int = 2_000, where: str = "", args: tuple = ()) -> Iterator[list[NormalizedEvent]]:
        with self._lock:
            cursor = self.get_connection().execute(
                "SELECT event_id,timestamp,event_kind,category,action,severity,host,source_ip,destination_ip,"
                "user_name,process_name,process_id,parent_process,command_line,file_path,registry_path,domain,"
                "technique_id,technique_name,tactic,raw_event FROM events " + where + " ORDER BY timestamp,event_id",
                args,
            )
            while rows := cursor.fetchmany(batch_size):
                yield [self._event_from_row(row) for row in rows]

    def events(self, where: str = "", args: tuple = ()) -> list[NormalizedEvent]:
        return [event for batch in self.iter_events(where=where, args=args) for event in batch]

    def event_page(self, limit: int = 200, offset: int = 0, severity: str | None = None) -> tuple[int, list[NormalizedEvent]]:
        clause = " WHERE severity = ?" if severity else ""
        args = [severity] if severity else []
        with self._lock:
            db = self.get_connection()
            total = db.execute("SELECT COUNT(*) FROM events" + clause, args).fetchone()[0]
            rows = db.execute(
                "SELECT event_id,timestamp,event_kind,category,action,severity,host,source_ip,destination_ip,"
                "user_name,process_name,process_id,parent_process,command_line,file_path,registry_path,domain,"
                "technique_id,technique_name,tactic,raw_event FROM events" + clause +
                " ORDER BY timestamp,event_id LIMIT ? OFFSET ?", args + [limit, offset]
            ).fetchall()
        return total, [self._event_from_row(row) for row in rows]

    def save_detections(self, detections: list[Detection]) -> None:
        if not detections:
            return
        rows = [
            (d.detection_id, d.event_id, d.rule_id, d.rule_name, d.severity, d.technique_id,
             d.technique_name, d.tactic, d.confidence, json.dumps(d.evidence, default=str))
            for d in detections
        ]
        with self._lock:
            db = self.get_connection()
            try:
                app = db.appender("detections")
                app.append_rows(rows)
                app.flush()
            except Exception:
                db.execute("BEGIN TRANSACTION")
                try:
                    db.executemany("INSERT OR REPLACE INTO detections VALUES (?,?,?,?,?,?,?,?,?,?)", rows)
                    db.execute("COMMIT")
                except Exception:
                    db.execute("ROLLBACK")
                    raise

    def detections(self) -> list[Detection]:
        with self._lock:
            rows = self.get_connection().execute("SELECT * FROM detections ORDER BY severity DESC, confidence DESC").fetchall()
        return [
            Detection(
                detection_id=r[0], event_id=r[1], rule_id=r[2], rule_name=r[3], severity=r[4],
                technique_id=r[5], technique_name=r[6], tactic=r[7], confidence=r[8],
                evidence=json.loads(r[9]) if isinstance(r[9], str) else r[9],
            ) for r in rows
        ]

    def iter_detection_events(self, batch_size: int = 2_000) -> Iterator[list[tuple[Detection, NormalizedEvent]]]:
        query = (
            "SELECT d.detection_id,d.event_id,d.rule_id,d.rule_name,d.severity,d.technique_id,d.technique_name,"
            "d.tactic,d.confidence,d.evidence,e.event_id,e.timestamp,e.event_kind,e.category,e.action,e.severity,"
            "e.host,e.source_ip,e.destination_ip,e.user_name,e.process_name,e.process_id,e.parent_process,"
            "e.command_line,e.file_path,e.registry_path,e.domain,e.technique_id,e.technique_name,e.tactic,e.raw_event "
            "FROM detections d JOIN events e ON e.event_id=d.event_id ORDER BY e.timestamp,e.event_id,d.detection_id"
        )
        with self._lock:
            cursor = self.get_connection().execute(query)
            while rows := cursor.fetchmany(batch_size):
                batch = []
                for row in rows:
                    detection = Detection(
                        detection_id=row[0], event_id=row[1], rule_id=row[2], rule_name=row[3], severity=row[4],
                        technique_id=row[5], technique_name=row[6], tactic=row[7], confidence=row[8],
                        evidence=json.loads(row[9]) if isinstance(row[9], str) else row[9],
                    )
                    batch.append((detection, self._event_from_row(row[10:])))
                yield batch

    def add_incident_events(self, members: list[tuple[str, str]]) -> None:
        if not members:
            return
        with self._lock:
            db = self.get_connection()
            db.execute("BEGIN TRANSACTION")
            try:
                db.executemany("INSERT OR IGNORE INTO incident_events VALUES (?,?)", members)
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise

    def save_incidents(self, incidents: list[Incident]) -> None:
        if not incidents:
            return
        rows = [(item.incident_id, json.dumps(item.model_dump(mode="json"))) for item in incidents]
        with self._lock:
            db = self.get_connection()
            db.execute("BEGIN TRANSACTION")
            try:
                db.executemany("INSERT OR REPLACE INTO incidents VALUES (?,?)", rows)
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise

    def incidents(self) -> list[Incident]:
        with self._lock:
            rows = self.get_connection().execute("SELECT payload FROM incidents").fetchall()
        return [Incident(**(json.loads(row[0]) if isinstance(row[0], str) else row[0])) for row in rows]

    def events_for_incident(self, incident_id: str, limit: int = 1_000) -> list[NormalizedEvent]:
        query = (
            "SELECT e.event_id,e.timestamp,e.event_kind,e.category,e.action,e.severity,e.host,e.source_ip,"
            "e.destination_ip,e.user_name,e.process_name,e.process_id,e.parent_process,e.command_line,e.file_path,"
            "e.registry_path,e.domain,e.technique_id,e.technique_name,e.tactic,e.raw_event "
            "FROM events e JOIN incident_events ie ON ie.event_id=e.event_id WHERE ie.incident_id=? "
            "ORDER BY e.timestamp,e.event_id LIMIT ?"
        )
        with self._lock:
            rows = self.get_connection().execute(query, [incident_id, limit]).fetchall()
        return [self._event_from_row(row) for row in rows]

    def detections_for_incident(self, incident_id: str, limit: int = 2_000) -> list[Detection]:
        query = (
            "SELECT d.detection_id,d.event_id,d.rule_id,d.rule_name,d.severity,d.technique_id,d.technique_name,"
            "d.tactic,d.confidence,d.evidence FROM detections d JOIN incident_events ie ON ie.event_id=d.event_id "
            "WHERE ie.incident_id=? ORDER BY d.severity DESC,d.confidence DESC LIMIT ?"
        )
        with self._lock:
            rows = self.get_connection().execute(query, [incident_id, limit]).fetchall()
        return [
            Detection(
                detection_id=r[0], event_id=r[1], rule_id=r[2], rule_name=r[3], severity=r[4],
                technique_id=r[5], technique_name=r[6], tactic=r[7], confidence=r[8],
                evidence=json.loads(r[9]) if isinstance(r[9], str) else r[9],
            ) for r in rows
        ]

    def dashboard_counts(self) -> dict[str, Any]:
        with self._lock:
            db = self.get_connection()
            total = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            suspicious = db.execute("SELECT COUNT(DISTINCT event_id) FROM detections").fetchone()[0]
            hosts = db.execute("SELECT COUNT(DISTINCT host) FROM events WHERE host IS NOT NULL AND host != ''").fetchone()[0]
            severities = db.execute("SELECT severity, COUNT(*) FROM detections GROUP BY severity").fetchall()
        return {"total_events": total, "suspicious_events": suspicious, "hosts_involved": hosts,
                "severity_counts": {severity: count for severity, count in severities}}

    def mitre_summary(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.get_connection().execute(
                "SELECT technique_id, technique_name, tactic, COUNT(*) AS frequency, "
                "COUNT(DISTINCT event_id) AS incident_count, MIN(evidence) AS evidence "
                "FROM detections WHERE technique_id IS NOT NULL AND technique_id != '' "
                "GROUP BY technique_id, technique_name, tactic ORDER BY frequency DESC"
            ).fetchall()
        return [
            {"technique_id": row[0], "technique_name": row[1], "tactic": row[2], "frequency": row[3],
             "incident_count": row[4], "evidence": [json.loads(row[5]) if isinstance(row[5], str) else row[5]]}
            for row in rows
        ]
