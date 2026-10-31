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
            db.execute("CREATE TABLE IF NOT EXISTS incident_events (incident_id VARCHAR, event_id VARCHAR, PRIMARY KEY (incident_id, event_id))")
            db.execute("CREATE TABLE IF NOT EXISTS ingestion_runs (run_id VARCHAR PRIMARY KEY, payload JSON)")
    def reset_analysis(self):
        with self.connect() as db: db.execute("DELETE FROM detections"); db.execute("DELETE FROM incidents")
    def clear_all(self):
        """Start a new investigation safely instead of silently mixing source datasets."""
        with self.connect() as db:
            db.execute("DELETE FROM events"); db.execute("DELETE FROM detections"); db.execute("DELETE FROM incidents"); db.execute("DELETE FROM incident_events")
    def snapshot_current_run(self):
        """Create recoverable copies of the current investigation tables."""
        with self.connect() as db:
            for table in ("events", "detections", "incidents", "incident_events"):
                backup = f"_chainsight_backup_{table}"
                db.execute(f"DROP TABLE IF EXISTS {backup}")
                db.execute(f"CREATE TABLE {backup} AS SELECT * FROM {table}")

    def restore_current_run(self):
        """Restore the last snapshot after a failed replacement run."""
        with self.connect() as db:
            for table in ("events", "detections", "incidents", "incident_events"):
                backup = f"_chainsight_backup_{table}"
                exists = db.execute(
                    "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = ?",
                    [backup],
                ).fetchone()[0]
                if exists:
                    db.execute(f"DELETE FROM {table}")
                    db.execute(f"INSERT INTO {table} SELECT * FROM {backup}")
                    db.execute(f"DROP TABLE {backup}")

    def discard_current_run_snapshot(self):
        with self.connect() as db:
            for table in ("events", "detections", "incidents", "incident_events"):
                db.execute(f"DROP TABLE IF EXISTS _chainsight_backup_{table}")

    def insert_events(self, events):
        rows = [(e.event_id,e.timestamp,e.event_kind,e.category,e.action,e.severity,e.host,e.source_ip,e.destination_ip,e.user,e.process_name,e.process_id,e.parent_process,e.command_line,e.file_path,e.registry_path,e.domain,e.technique_id,e.technique_name,e.tactic,json.dumps(e.raw_event)) for e in events]
        if rows:
            with self.connect() as db: db.executemany("INSERT OR REPLACE INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    @staticmethod
    def _event_from_row(row):
        from backend.models import NormalizedEvent
        values=list(row[:9])+[row[9]]+list(row[10:20])+[json.loads(row[20]) if isinstance(row[20],str) else row[20]]
        return NormalizedEvent(**dict(zip(EVENT_COLUMNS, values)))
    def iter_events(self, batch_size=2_000, where="", args=()):
        with self.connect() as db:
            cursor=db.execute("SELECT event_id,timestamp,event_kind,category,action,severity,host,source_ip,destination_ip,user_name,process_name,process_id,parent_process,command_line,file_path,registry_path,domain,technique_id,technique_name,tactic,raw_event FROM events "+where+" ORDER BY timestamp,event_id",args)
            while rows:=cursor.fetchmany(batch_size):
                yield [self._event_from_row(row) for row in rows]
    def events(self, where="", args=()):
        return [event for batch in self.iter_events(where=where,args=args) for event in batch]
    def event_page(self, limit=200, offset=0, severity=None):
        clause=" WHERE severity = ?" if severity else ""; args=[severity] if severity else []
        with self.connect() as db:
            total=db.execute("SELECT COUNT(*) FROM events"+clause,args).fetchone()[0]
            rows=db.execute("SELECT event_id,timestamp,event_kind,category,action,severity,host,source_ip,destination_ip,user_name,process_name,process_id,parent_process,command_line,file_path,registry_path,domain,technique_id,technique_name,tactic,raw_event FROM events"+clause+" ORDER BY timestamp,event_id LIMIT ? OFFSET ?",args+[limit,offset]).fetchall()
        return total,[self._event_from_row(row) for row in rows]
    def save_detections(self, detections):
        rows=[(d.detection_id,d.event_id,d.rule_id,d.rule_name,d.severity,d.technique_id,d.technique_name,d.tactic,d.confidence,json.dumps(d.evidence)) for d in detections]
        if rows:
            with self.connect() as db: db.executemany("INSERT OR REPLACE INTO detections VALUES (?,?,?,?,?,?,?,?,?,?)",rows)
    def detections(self):
        from backend.models import Detection
        with self.connect() as db: rows=db.execute("SELECT * FROM detections").fetchall()
        return [Detection(detection_id=r[0],event_id=r[1],rule_id=r[2],rule_name=r[3],severity=r[4],technique_id=r[5],technique_name=r[6],tactic=r[7],confidence=r[8],evidence=json.loads(r[9]) if isinstance(r[9],str) else r[9]) for r in rows]
    def iter_detection_events(self, batch_size=2_000):
        from backend.models import Detection
        query="SELECT d.detection_id,d.event_id,d.rule_id,d.rule_name,d.severity,d.technique_id,d.technique_name,d.tactic,d.confidence,d.evidence,e.event_id,e.timestamp,e.event_kind,e.category,e.action,e.severity,e.host,e.source_ip,e.destination_ip,e.user_name,e.process_name,e.process_id,e.parent_process,e.command_line,e.file_path,e.registry_path,e.domain,e.technique_id,e.technique_name,e.tactic,e.raw_event FROM detections d JOIN events e ON e.event_id=d.event_id ORDER BY e.timestamp,e.event_id,d.detection_id"
        with self.connect() as db:
            cursor=db.execute(query)
            while rows:=cursor.fetchmany(batch_size):
                batch=[]
                for row in rows:
                    detection=Detection(detection_id=row[0],event_id=row[1],rule_id=row[2],rule_name=row[3],severity=row[4],technique_id=row[5],technique_name=row[6],tactic=row[7],confidence=row[8],evidence=json.loads(row[9]) if isinstance(row[9],str) else row[9])
                    batch.append((detection,self._event_from_row(row[10:])))
                yield batch
    def add_incident_events(self, members):
        """Insert incident/event memberships in one batch, ignoring duplicates."""
        rows = [(incident_id, event_id) for incident_id, event_id in members
                if incident_id and event_id]
        if not rows:
            return
        with self.connect() as db:
            db.executemany(
                "INSERT OR IGNORE INTO incident_events VALUES (?,?)",
                rows,
            )

    def add_incident_event(self, incident_id, event_id):
        self.add_incident_events([(incident_id, event_id)])
    def merge_incidents(self, source_id, target_id):
        with self.connect() as db: db.execute("UPDATE incident_events SET incident_id=? WHERE incident_id=?",[target_id,source_id])
    def save_incidents(self, incidents):
        with self.connect() as db:
            for item in incidents: db.execute("INSERT OR REPLACE INTO incidents VALUES (?,?)",[item.incident_id,json.dumps(item.model_dump(mode="json"))])
    def incidents(self):
        from backend.models import Incident
        with self.connect() as db: rows=db.execute("SELECT payload FROM incidents").fetchall()
        return [Incident(**(json.loads(r[0]) if isinstance(r[0],str) else r[0])) for r in rows]
    def events_for_incident(self, incident_id, limit=1_000):
        query="SELECT e.event_id,e.timestamp,e.event_kind,e.category,e.action,e.severity,e.host,e.source_ip,e.destination_ip,e.user_name,e.process_name,e.process_id,e.parent_process,e.command_line,e.file_path,e.registry_path,e.domain,e.technique_id,e.technique_name,e.tactic,e.raw_event FROM events e JOIN incident_events ie ON ie.event_id=e.event_id WHERE ie.incident_id=? ORDER BY e.timestamp,e.event_id LIMIT ?"
        with self.connect() as db: rows=db.execute(query,[incident_id,limit]).fetchall()
        return [self._event_from_row(row) for row in rows]
    def detections_for_incident(self, incident_id, limit=2_000):
        from backend.models import Detection
        query="SELECT d.detection_id,d.event_id,d.rule_id,d.rule_name,d.severity,d.technique_id,d.technique_name,d.tactic,d.confidence,d.evidence FROM detections d JOIN incident_events ie ON ie.event_id=d.event_id WHERE ie.incident_id=? ORDER BY d.detection_id LIMIT ?"
        with self.connect() as db: rows=db.execute(query,[incident_id,limit]).fetchall()
        return [Detection(detection_id=row[0],event_id=row[1],rule_id=row[2],rule_name=row[3],severity=row[4],technique_id=row[5],technique_name=row[6],tactic=row[7],confidence=row[8],evidence=json.loads(row[9]) if isinstance(row[9],str) else row[9]) for row in rows]
    def dashboard_counts(self):
        with self.connect() as db:
            events=db.execute("SELECT COUNT(*),COUNT(DISTINCT host) FROM events").fetchone()
            detections=db.execute("SELECT COUNT(DISTINCT event_id), severity, COUNT(*) FROM detections GROUP BY severity").fetchall()
        return {"total_events":events[0],"hosts_involved":events[1],"suspicious_events":sum(row[0] for row in detections),"severity_counts":{row[1]:row[2] for row in detections}}
    def mitre_summary(self):
        query="SELECT technique_id,technique_name,tactic,COUNT(*) FROM detections GROUP BY technique_id,technique_name,tactic ORDER BY technique_id"
        with self.connect() as db:
            rows=db.execute(query).fetchall(); result=[]
            for technique_id,name,tactic,frequency in rows:
                evidence=db.execute("SELECT evidence FROM detections WHERE technique_id=? LIMIT 3",[technique_id]).fetchall()
                incident_count=db.execute("SELECT COUNT(*) FROM incidents WHERE CAST(payload AS VARCHAR) LIKE ?",[f'%{technique_id}%']).fetchone()[0]
                result.append({"technique_id":technique_id,"technique_name":name,"tactic":tactic,"frequency":frequency,"incident_count":incident_count,"evidence":[json.loads(item[0]) if isinstance(item[0],str) else item[0] for item in evidence]})
        return result
