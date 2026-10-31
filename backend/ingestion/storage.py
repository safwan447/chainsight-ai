from __future__ import annotations
import json
from pathlib import Path
import duckdb
from backend.config import DB_PATH

EVENT_COLUMNS = ["event_id","timestamp","event_kind","category","action","severity","host","source_ip","destination_ip","user","process_name","process_id","parent_process","command_line","file_path","registry_path","domain","technique_id","technique_name","tactic","raw_event"]

class Storage:
    def __init__(self, path: Path = DB_PATH):
        self.path = path; self.initialize()
    def connect(self): return duckdb.connect(str(self.path))
    def initialize(self):
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS events (event_id VARCHAR PRIMARY KEY, timestamp TIMESTAMP, event_kind VARCHAR, category VARCHAR, action VARCHAR, severity VARCHAR, host VARCHAR, source_ip VARCHAR, destination_ip VARCHAR, user_name VARCHAR, process_name VARCHAR, process_id VARCHAR, parent_process VARCHAR, command_line VARCHAR, file_path VARCHAR, registry_path VARCHAR, domain VARCHAR, technique_id VARCHAR, technique_name VARCHAR, tactic VARCHAR, raw_event JSON)")
            db.execute("CREATE TABLE IF NOT EXISTS detections (detection_id VARCHAR PRIMARY KEY, event_id VARCHAR, rule_id VARCHAR, rule_name VARCHAR, severity VARCHAR, technique_id VARCHAR, technique_name VARCHAR, tactic VARCHAR, confidence DOUBLE, evidence JSON)")
            db.execute("CREATE TABLE IF NOT EXISTS incidents (incident_id VARCHAR PRIMARY KEY, payload JSON)")
            db.execute("CREATE TABLE IF NOT EXISTS ingestion_runs (run_id VARCHAR PRIMARY KEY, payload JSON)")
    def reset_analysis(self):
        with self.connect() as db: db.execute("DELETE FROM detections"); db.execute("DELETE FROM incidents")
    def clear_all(self):
        """Start a new investigation safely instead of silently mixing source datasets."""
        with self.connect() as db:
            db.execute("DELETE FROM events"); db.execute("DELETE FROM detections"); db.execute("DELETE FROM incidents")
    def insert_events(self, events):
        rows = [(e.event_id,e.timestamp,e.event_kind,e.category,e.action,e.severity,e.host,e.source_ip,e.destination_ip,e.user,e.process_name,e.process_id,e.parent_process,e.command_line,e.file_path,e.registry_path,e.domain,e.technique_id,e.technique_name,e.tactic,json.dumps(e.raw_event)) for e in events]
        if rows:
            with self.connect() as db: db.executemany("INSERT OR REPLACE INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    def events(self, where="", args=[]):
        with self.connect() as db:
            rows=db.execute("SELECT event_id,timestamp,event_kind,category,action,severity,host,source_ip,destination_ip,user_name,process_name,process_id,parent_process,command_line,file_path,registry_path,domain,technique_id,technique_name,tactic,raw_event FROM events "+where+" ORDER BY timestamp",args).fetchall(); cols=EVENT_COLUMNS
        from backend.models import NormalizedEvent
        return [NormalizedEvent(**dict(zip(cols, list(r[:9])+[r[9]]+list(r[10:20])+[json.loads(r[20]) if isinstance(r[20],str) else r[20]]))) for r in rows]
    def save_detections(self, detections):
        rows=[(d.detection_id,d.event_id,d.rule_id,d.rule_name,d.severity,d.technique_id,d.technique_name,d.tactic,d.confidence,json.dumps(d.evidence)) for d in detections]
        if rows:
            with self.connect() as db: db.executemany("INSERT OR REPLACE INTO detections VALUES (?,?,?,?,?,?,?,?,?,?)",rows)
    def detections(self):
        from backend.models import Detection
        with self.connect() as db: rows=db.execute("SELECT * FROM detections").fetchall()
        return [Detection(detection_id=r[0],event_id=r[1],rule_id=r[2],rule_name=r[3],severity=r[4],technique_id=r[5],technique_name=r[6],tactic=r[7],confidence=r[8],evidence=json.loads(r[9]) if isinstance(r[9],str) else r[9]) for r in rows]
    def save_incidents(self, incidents):
        with self.connect() as db:
            for item in incidents: db.execute("INSERT OR REPLACE INTO incidents VALUES (?,?)",[item.incident_id,json.dumps(item.model_dump(mode="json"))])
    def incidents(self):
        from backend.models import Incident
        with self.connect() as db: rows=db.execute("SELECT payload FROM incidents").fetchall()
        return [Incident(**(json.loads(r[0]) if isinstance(r[0],str) else r[0])) for r in rows]
